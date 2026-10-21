# Evaluation

Vista's evaluation compares an LLM review with a deterministic rule-based scanner on the same AWS
resources. Vista (the LLM review) and [Prowler](https://github.com/prowler-cloud/prowler) 5.44.0
(the rule-based scanner) are scored by the same rules against the same answer key, so the
comparison shows where each approach agrees with the answer key and where it does not.

## Answer key

The answer key is 40 scenarios deployed with Terraform. The scenarios, their fields, and the
baseline controls are listed in [terraform/README.md](../terraform/README.md), which is generated
from the four `terraform/modules/<service>/ground-truth.json` files.

The ground truth holds facts and published AWS Security Hub FSBP severities only. Each scenario has
a condition (`flaw`, `flaw_blocked`, `hardened`), a coverage (`fsbp`, `outside_fsbp`), and, on fsbp
scenarios, `fsbp_severity`: the highest published severity of the FSBP controls that fail because of
the scenario.

- **Condition:** reporting a `flaw` scenario counts as a detection. Reporting a `flaw_blocked`
  scenario (a misconfiguration is present but another deployed control removes the path it opens)
  is shown as a separate report rate, counted as neither a detection nor a false positive.
  Reporting a `hardened` scenario is a false positive.
- **Coverage:** `fsbp` when at least one FSBP control fails because of the scenario's
  configuration, otherwise `outside_fsbp`. `outside_fsbp` scenarios get no severity comparison.
- **Tier:** `controlled` or `realistic`; `--tier` scores one tier only.

The file is validated on load: every scenario needs condition in {flaw, flaw_blocked, hardened},
coverage in {fsbp, outside_fsbp}, `fsbp_severity` LOW..CRITICAL on fsbp and null on outside_fsbp,
and no hardened scenario may be fsbp.

## Steps

The steps need Terraform 1.11+, Prowler 5.44.0, and Bedrock access to both models; see
[getting-started.md](getting-started.md#requirements). Steps 2 and 3 use `--save-run` and
`--from-json`, described in [Repeatable runs](getting-started.md#repeatable-runs).

1. Deploy the scenarios to a sandbox account. Many are deliberately misconfigured. The root module
   deploys only EC2 by default (`enable_ec2` is true; `enable_s3`, `enable_apigateway`, and
   `enable_rds` are false) into `var.region` (default `us-east-1`); scan only that region.

   ```bash
   terraform -chdir=terraform init
   terraform -chdir=terraform apply -var enable_s3=true -var enable_apigateway=true -var enable_rds=true
   mkdir -p runs
   terraform -chdir=terraform output -json scenario_resources > runs/scenario_resources.json
   ```

2. Collect each service once with `--save-run`. Saving into the service's benchmark folder puts
   the payload where `score.py` looks for it (`RUNS/payload.json`).

   ```bash
   vista assess ec2 --regions us-east-1 --model us.anthropic.claude-opus-5 --save-run runs/ec2/benchmark
   ```

3. Replay the saved payload five times per model with `--from-json`, one new `run-N` folder per
   run.

   ```bash
   for n in 1 2 3 4 5; do
     vista assess ec2 --from-json runs/ec2/benchmark/payload.json --model us.anthropic.claude-opus-5 --save-run runs/ec2/benchmark/opus/run-$n
     vista assess ec2 --from-json runs/ec2/benchmark/payload.json --model us.openai.gpt-5.6-sol --save-run runs/ec2/benchmark/gpt/run-$n
   done
   ```

4. Run Prowler once across all four services while the scenarios are deployed, with JSON OCSF
   output. Do not pass a mutelist (`--mutelist-file`); muted (Suppressed) FAILs are still scored
   and only counted. This writes `runs/prowler/prowler-output.ocsf.json`.

   ```bash
   prowler aws --region us-east-1 --output-formats json-ocsf --output-directory runs/prowler --output-filename prowler-output
   ```

5. Score each service with `python scripts/score.py <service> RUNS MAP --prowler PATH`. For EC2:

   ```bash
   python scripts/score.py ec2 runs/ec2/benchmark runs/scenario_resources.json --prowler runs/prowler/prowler-output.ocsf.json
   ```

6. Destroy the scenarios with the same variables. Nothing has deletion protection, buckets are
   force-destroyed, and databases skip their final snapshot, so one destroy removes everything.

   ```bash
   terraform -chdir=terraform destroy -var enable_s3=true -var enable_apigateway=true -var enable_rds=true
   ```

Repeat steps 2, 3, and 5 for `s3`, `apigateway`, and `rds`. Steps 3 and 5 do not touch the
deployed resources, so they can also run after step 6.

## Run folder layout

`runs/` is gitignored. The steps above produce:

```text
runs/
  scenario_resources.json        terraform output -json scenario_resources
  prowler/
    prowler-output.ocsf.json     one Prowler scan for all four services
  ec2/
    benchmark/                   RUNS for score.py
      payload.json               the collected payload every replay reviews
      analysis.md, run.json      the collection run's own review (not scored)
      opus/                      one folder per model; the folder name labels the model
        run-1/ ... run-5/        analysis.md and run.json from --save-run
      gpt/
        run-1/ ... run-5/
  s3/, apigateway/, rds/         the same layout
```

`score.py` takes three inputs:

- `SERVICE` — `ec2`, `s3`, `apigateway`, or `rds`.
- `RUNS` — one folder per model, each with `run-1`, `run-2`, ... folders written by `--save-run`
  (`analysis.md` and `run.json`), plus an optional `RUNS/payload.json` (the payload the runs
  reviewed). `payload.json` is used to flag cited identifiers absent from the evidence and, for EC2
  and RDS, to attribute Prowler results. EC2 requires it with `--prowler`.
- `MAP` — `terraform output -json scenario_resources`: a JSON object of scenario ID -> the
  identifier Vista cites (EC2 instance ID, S3 bucket name, API Gateway API ID, RDS identifier).
  Ground-truth scenarios missing from the map are listed and not scored. The output merges every
  deployed module, so one file serves all four services.

Options:

- `--ground-truth PATH` — overrides the default `terraform/modules/<service>/ground-truth.json`.
- `--tier controlled|realistic` — score only the scenarios of one tier.
- `--max-findings N` — the review's finding cap (default 10); runs that reach it are counted.
- `--prowler PATH` — Prowler JSON OCSF output (`prowler aws --output-formats json-ocsf`).
- `--json PATH` / `--csv PATH` — also write full results (service, tier, scored IDs, per-tool runs,
  cells, and summaries) as JSON, and one CSV row per (tool, run, scenario) cell.

## How Vista findings are matched

Each review is parsed with the validator's helpers (`vista.findings`): position, title, Severity,
and the backticked identifiers in the "Affected ..." field. A scenario is scored against the
highest-severity finding citing its identifier; on a tie, the finding citing the fewest
scored-scenario resources, then the earliest. No citing finding: not reported, severity NONE. A run
is scored when `run.json` status is ok (or `run.json` is missing) and `analysis.md` exists;
otherwise it is failed and `run.json`'s error is shown.

## How Prowler results are attributed

Prowler OCSF field access (Prowler 4.x and 5.x; v4 names in the Prowler deprecation table):

- **status** — `status_code` (PASS, FAIL, MANUAL); only FAIL is used. A file where no record has
  `status_code` is rejected.
- **check** — `metadata.event_code` (CheckID); required on FAIL.
- **severity** — `severity` string (Critical, High, Medium, Low, Informational), else `severity_id`
  (1 Informational, 2 Low, 3 Medium, 4 High, 5 Critical); required on FAIL.
- **resource** — every non-empty `uid` (ResourceArn) and `name` (ResourceId) of every entry in
  `resources[]`; at least one is required on FAIL.
- **version** — `metadata.product.version` (printed; "unknown" with a warning when absent) and the
  OCSF schema `metadata.version` when present.
- **muted** — FAILs whose status is Suppressed are counted.

Any missing required field or unknown severity exits with the record index and the field name.
Informational FAILs are ignored. A scenario's Prowler severity is the highest severity among the
FAILs attributed to it, mapped one to one; none attributed means not reported (NONE). A FAIL can be
attributed to several scenarios (a shared object counts for each).

A FAIL belongs to a scenario when a resource candidate matches one of the scenario's related
identifiers. The related identifiers cover every resource whose FSBP control the answer key
attributes to the scenario (its fsbp list), so Prowler is attributed as broadly as the answer key.
Always: candidate equals the identifier. Per service:

- **ec2** — related, read from `RUNS/payload.json` (required): the instance; its EBS volumes
  (`storage.block_devices[].volume_id`); its security groups (instance and interfaces); its
  interfaces' network ACLs; its instance-profile role ARNs; and for each
  `load_balancer_relationships` entry the `listener_arn`, the `target_group_arn` (and
  `shared.target_groups[arn].arn`), the `load_balancer_arn`, that load balancer's security groups,
  and every listener in `shared.load_balancers[arn].listeners` (an HTTP redirect listener forwards
  to no instance but is still the instance's load balancer). Also matches a candidate ending in
  `/<identifier>` (volume, security group, and network ACL ARNs). Subnets, route tables, VPCs, and
  account-level checks are not attributed.
- **s3** — related: the bucket name. Also matches an ARN ending in `:::<bucket>` (any partition); a
  longer bucket name or an object ARN does not match.
- **apigateway** — related: the API ID. Also matches an ARN containing `restapis/<id>` or
  `apis/<id>` as a path segment preceded by `/` or `::` (REST, HTTP, WebSocket APIs and their
  stages, routes, integrations). Prowler writes HTTP and WebSocket API ARNs as
  `arn:aws:apigateway:<region>::apis/<id>`, with no `/` before `apis`.
- **rds** — related: the identifier and, when `payload.json` is present, from the `db_instances`,
  `db_clusters`, `db_proxies`, or `snapshots` record with that identifier: its `arn` (proxy ARNs use
  `prx-...`), its `security_group_ids`, its parameter group names (`parameter_group_refs` ->
  `shared.parameter_groups[ref].name`, `cluster_parameter_group_ref` ->
  `shared.cluster_parameter_groups[ref].name`, else the ref after `region/`), and for a snapshot its
  source identifier and the `arn` of the `db_instances` or `db_clusters` record with that
  identifier. A security group ID matches a candidate equal to it or ending in `/<sg-id>`; any other
  identifier also matches an ARN ending in
  `:(db|cluster|snapshot|cluster-snapshot|db-proxy|pg|cluster-pg):<id>`. Subnet groups, subnets,
  route tables, network ACLs, VPCs, and account-level checks are not attributed: no answer-key
  control is attributed through them, and they are shared by many scenarios.

A shared object (a security group, load balancer, listener, or parameter group referenced by
several scenarios) counts for each scenario that references it.

One Prowler column is reported: `prowler` counts every attributed FAIL, and no checks are filtered
out. Checks that fail on many scenarios stay visible in the report's per-scenario list of checks at
the top severity.

## What score.py reports

Cell, one per (tool, run, scenario): scenario, condition, coverage, reported, severity,
fsbp_severity, distance, grouped, findings_citing. `distance` = rank(severity) - rank(fsbp_severity)
on fsbp scenarios, else null, with ranks NONE 0 < LOW 1 < MEDIUM 2 < HIGH 3 < CRITICAL 4.
`grouped`: the scoring finding cites more than one scored-scenario resource.

Metrics per tool (a model pools the cells of all its scored runs; Prowler is one run), each n/N for
the groups all, fsbp, outside_fsbp:

- **detection** — reported cells over flaw cells.
- **flaw_blocked rate** — reported cells over flaw_blocked cells; neither a detection nor a false
  positive.
- **false positives** — reported cells over hardened cells.

Severity relative to FSBP, fsbp cells only (flaw and flaw_blocked; not reported = NONE): same as
FSBP (distance 0), above FSBP (> 0), below FSBP (< 0), and the mean signed distance. This describes
where each tool's severity sits relative to the FSBP control-level severity; it is not an accuracy
score. FSBP severity is fixed per control and does not reflect deployed context, and Prowler's check
severities follow FSBP's, so Prowler sits at or near FSBP by construction. The per-scenario table
shows each scenario's context so differences can be read against it. outside_fsbp cells get no
severity comparison.

Vista only (Prowler is deterministic or has no such measure):

- **consistency** — scenarios with the same severity in every scored run over scored scenarios;
  mean modal agreement (mean of modal count / scored runs); non-identical list.
- **runs** — scored and failed (with error text); retried (`tokens.attempts` > 1) with each
  `run.json` `retry_errors` entry; findings per run; runs at the `--max-findings` cap.
- **unknown ids** — AWS IDs and ARNs in `analysis.md` absent from `payload.json`, total and per run
  ("not checked" without `payload.json`).
- **grouped** — cells scored from a grouped finding, and their scenario IDs.
- **cost** — review seconds and total tokens per run.

Per scenario: condition, coverage, fsbp_severity, and each tool's severity distribution over runs.
