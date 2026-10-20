# Scan scope and output

## Services

- **EC2** — instances and their network path, IAM, IMDS, storage, and load-balancer exposure.
- **S3** — buckets and their public-access controls (Block Public Access, policy, ACL, ownership),
  encryption, versioning, logging, replication, and CORS.
- **API Gateway** — REST, HTTP, and WebSocket APIs: per-route authorization and authorizers,
  resource policies, API keys and usage plans, the default execute-api endpoint setting, WAF,
  throttling, access/execution logging, TLS (custom domains and backends), request validation,
  caching, and CORS.
- **RDS** — DB instances, clusters, RDS Proxies, and manual snapshots: public accessibility and the
  full network path (security groups, routes, NACLs), encryption and KMS key ownership, TLS
  parameters, IAM authentication, Secrets Manager use, backups, deletion protection, associated IAM
  roles, CA expiry, engine support, and snapshot sharing.

A bucket is only included when its region is in the selected scope, so use `--all-regions` (or the
right `--regions`) to see every bucket.

The JSON sent to the model for each service is described in [payloads/ec2.md](payloads/ec2.md),
[payloads/s3.md](payloads/s3.md), [payloads/apigateway.md](payloads/apigateway.md), and
[payloads/rds.md](payloads/rds.md).

## Regions

Vista scans all selected regions, merges the facts into a single payload, and makes **one** Bedrock
call. Every service scans up to 8 regions at once (`MAX_REGION_WORKERS` in `vista/regions.py`);
calls within a region stay sequential to respect per-region API limits. S3 lists buckets globally,
so it collects buckets in parallel and scans regions in parallel only for access points. When
`--all-regions` is used, `me-south-1` and `me-central-1` are excluded from region enumeration (edit
`SKIP_REGIONS` in `vista/cli.py` to change this).

## Output

Vista prints an account-level review: a short risk summary followed by up to ten findings ordered
by severity. Each finding lists its severity, likelihood, impact, confidence, category, the affected
resources, the supporting evidence, why it matters, and a concrete remediation step. Resources are
grouped into a single finding only when they share a root cause and would get the same severity.

Every service uses the same review format and validation; only the category names differ:

| Service | Categories |
| --- | --- |
| EC2 | `INTERNET_EXPOSURE`, `SECURITY_CONFIGURATION` |
| S3, RDS | `PUBLIC_EXPOSURE`, `SECURITY_CONFIGURATION` |
| API Gateway | `ACCESS_CONTROL`, `SECURITY_CONFIGURATION` |

If a response is malformed (missing fields, a severity that doesn't match the matrix, or an
identifier that isn't in the input), Vista sends the validation error back once and asks for a
corrected review.

### Severity

Severity is **CRITICAL / HIGH / MEDIUM / LOW** and is not chosen freely — it is derived from two
axes the model scores from the collected facts:

- **Likelihood** — how reachable or exploitable the weakness is from the configuration alone (its
  attack path and how many preconditions must already hold). It is not CVE- or exploit-based;
  Vista has no vulnerability or runtime data.
- **Impact** — the blast radius if exploited (single resource up to account-wide or cross-account).

The two map to severity through a fixed matrix:

| | Impact LOW | Impact MEDIUM | Impact HIGH |
| --- | --- | --- | --- |
| **Likelihood HIGH** | MEDIUM | HIGH | CRITICAL |
| **Likelihood MEDIUM** | LOW | MEDIUM | HIGH |
| **Likelihood LOW** | LOW | LOW | MEDIUM |

**Confidence** (CONFIRMED / PARTIAL / INSUFFICIENT) is reported separately and reflects how complete
the evidence was — for example a failed collector lowers confidence rather than severity.
