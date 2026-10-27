# Evaluation results

`runs/` holds the saved benchmark for Vista's four services (EC2, S3, API Gateway, RDS): the
collected payloads, every model run, one Prowler scan, and the score reports. The steps that
produced it and how `scripts/score.py` scores it are in [docs/evaluation.md](../docs/evaluation.md).

```text
runs/
  scenario_resources.json        terraform output -json scenario_resources
  replays.log                    console output of the replays (shows the old runs/ paths)
  prowler/
    prowler-output.ocsf.json     one Prowler scan for all four services
    compliance/                  only the FSBP CSV is tracked; the other reports are gitignored
  ec2/
    score.txt, score.json, score.csv   score.py output (stdout, --json, --csv)
    benchmark/
      payload.json               the collected payload every replay reviews
      analysis.md, run.json      the collection run's own review (not scored)
      opus/run-1/ ... run-5/     analysis.md and run.json for each run
      gpt/run-1/ ... run-5/
  s3/, apigateway/, rds/         the same layout
```

To rescore a service:

```bash
python scripts/score.py ec2 evaluation/runs/ec2/benchmark evaluation/runs/scenario_resources.json --prowler evaluation/runs/prowler/prowler-output.ocsf.json
```

## Redaction

After the runs, every occurrence of the following values was replaced with an AWS documentation
placeholder:

- the sandbox AWS account ID: `111122223333`
- a second AWS account ID: `444455556666`
- an IAM access key ID: `AKIAXXXXXXXXXXXXXXXX`
- email addresses: `user@example.com`

The replacement was applied the same way in every file, so identifiers still match across
payloads, runs, the scenario map, and the Prowler scan. The scores were regenerated from the
redacted data and are identical to the scores from the unredacted data. The `payload_sha256`
values in each `run.json` refer to the payloads before redaction, so they do not match the hash of
the redacted `payload.json` files.
