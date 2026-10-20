# Getting started

Vista discovers resources across an account, collects their factual configuration, and asks an
Amazon Bedrock model to identify the account's most significant security risks (public exposure or
misconfiguration) with evidence and remediation for each finding. It currently reviews **EC2**,
**S3**, **API Gateway**, and **RDS**.

## Requirements

- Python 3.10+
- AWS credentials for the account you want to scan (environment variables, a shared profile, or an
  assumed role), with the read-only permissions in [iam-permissions.md](iam-permissions.md)
- Amazon Bedrock **model access** enabled for the model you choose, in a region where it is offered
  (see [Models](#models))
- For the [evaluation](evaluation.md) only: [Terraform](https://developer.hashicorp.com/terraform)
  1.11+ and Prowler 5.44.0

Prowler can be installed with pipx:

```bash
pipx install prowler==5.44.0
prowler --version
```

An older Prowler earlier on your `PATH` can shadow it, so check that `prowler --version` reports
5.44.0.

### Models

Pass any Bedrock model or inference-profile ID to `--model`. Two known-good options:

- Claude Opus 5 — `us.anthropic.claude-opus-5`
- GPT-5.6 Sol — `us.openai.gpt-5.6-sol`

Both are US cross-region inference profiles. Use a region where the model is available and where
your account has been granted access to it. Set `BEDROCK_MODEL_ID` to avoid passing `--model` on
every run.

## Install

You do not need to clone the repository. Install it directly from GitHub, which adds a `vista`
command:

```bash
pip install "git+https://github.com/sdharamsi1/vista.git"
```

> If your system Python reports an "externally managed environment" error, add `--user` to the
> install command.

### From a local clone

Install into a virtual environment (use `python3` if `python` is not Python 3.10+ on your system):

```bash
git clone https://github.com/sdharamsi1/vista.git
cd vista
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

`-e` installs in editable mode, so code changes take effect without reinstalling. See
[development.md](development.md) for the project layout.

## Run a scan

You must already be authenticated to AWS. Credentials come from the standard AWS chain
(environment variables, `AWS_PROFILE`, SSO, or an instance role); Vista does not prompt for them.
It calls `sts:GetCallerIdentity` once and prints the account/identity to stderr before scanning.

Vista is a single subcommand, `assess`, that scans one service and prints a Bedrock review:

```bash
vista assess ec2 --all-regions --model us.anthropic.claude-opus-5
vista assess s3  --regions us-east-1 us-west-2 --model us.openai.gpt-5.6-sol
vista assess apigateway --all-regions --model us.anthropic.claude-opus-5
vista assess rds --regions us-east-1 --model us.anthropic.claude-opus-5
```

All selected regions are merged into one payload and one Bedrock call. See
[output.md](output.md) for what each service covers, how regions are scanned, and the review
format.

## Repeatable runs

To compare models, or measure how much one model varies, send the same evidence more than once.
`--save-run DIR` writes three private (0600) files and never overwrites an earlier run:

- `payload.json` — the exact JSON sent to Bedrock (live runs only).
- `analysis.md` — the model's raw Markdown review, before any terminal formatting.
- `run.json` — the model, Bedrock region, time, token usage, resource count, and a SHA-256 hash of
  the payload. A review that fails validation is recorded here with its error, and when the first
  answer fails validation but the corrective retry passes, `retry_errors` lists why.

`--from-json` then reviews a saved payload without touching AWS, so the evidence is identical
across runs and the resources can be destroyed in the meantime. It still needs AWS credentials
for Bedrock.

```bash
vista assess ec2 --regions us-east-1 --model us.anthropic.claude-opus-5 --save-run runs/ec2/opus/1
vista assess ec2 --from-json runs/ec2/opus/1/payload.json --model us.anthropic.claude-opus-5 --save-run runs/ec2/opus/2
vista assess ec2 --from-json runs/ec2/opus/1/payload.json --model us.openai.gpt-5.6-sol --save-run runs/ec2/gpt/1
```

Use a new directory for every run. Run directories can contain account IDs, ARNs, and policies,
so keep them out of version control. Vista does not set a temperature, so models use their own
defaults, and the same payload can still produce different reviews.

## CLI options

Run `vista --help` for the top-level help and `vista assess --help` for the full flag list. The
flags are:

- `service` — positional, one of `ec2`, `s3`, `apigateway`, or `rds`.
- `--regions REGION [REGION ...]` — one or more regions to scan.
- `--all-regions` — scan every region enabled for the account.
- `--from-json PATH` — skip AWS collection and review a payload saved earlier (see
  [Repeatable runs](#repeatable-runs)).
- `--model MODEL_ID` — Bedrock model or inference-profile ID (or set `BEDROCK_MODEL_ID`).
- `--profile NAME` — use a named AWS profile instead of the default credential chain.
- `--save-json PATH` — write the exact factual JSON sent to Bedrock to a private (0600) file.
- `--save-run DIR` — save the whole run to a directory (see [Repeatable runs](#repeatable-runs)).
- `--plain` — print the model's raw Markdown without terminal formatting.

Exactly one of `--regions`, `--all-regions`, or `--from-json` is required.
