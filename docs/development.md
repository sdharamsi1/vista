# Development

## From a local clone

Install from a local clone into a virtual environment as described in
[getting-started.md](getting-started.md#from-a-local-clone). `-e` installs in editable mode, so code
changes take effect without reinstalling.

## Project layout

Every service is a package under `vista/` with the same pieces, and the CLI only talks to
`service.py`:

- `collector.py` (or `scanner.py` for EC2) — turns AWS API responses into plain JSON facts.
- `normalize.py` — de-duplicates repeated objects into `shared` (RDS collects straight into
  `shared`, so it has none).
- `review.py` — a `ReviewSpec` plus the service-specific guidance for the model.
- `service.py` — `NAME`, `LABEL`, `collect()`, `count()`, and `analyze()`.
- `examples/sample-payload.json` — a full example of the JSON sent to Bedrock.

Shared modules hold everything else: `facts.py` (collector helpers), `regions.py` (parallel region
scanning and the `scan` header), `findings.py` (the review format, shared review rules, prompt
assembly, and validation), `severity.py`, `bedrock.py`, and `render.py`. To add a service, create
the package and register its `service` module in `SERVICES` in `vista/cli.py`.

Every payload starts with the same `scan` header: `account_id`, `caller_arn`, `regions`,
`started_at`, `completed_at`, and `collection_errors_by_region` (null when nothing failed). The
per-service payloads are described in [EC2](payloads/ec2.md), [S3](payloads/s3.md),
[API Gateway](payloads/apigateway.md), and [RDS](payloads/rds.md).

The evaluation harness is [`scripts/score.py`](../scripts/score.py) and the test scenarios are under
[`terraform/`](../terraform/README.md); see [evaluation.md](evaluation.md).
