# Vista

Vista is an AI-powered AWS attack surface analysis tool. It discovers resources across an account,
collects their factual configuration, and asks an Amazon Bedrock model to identify the account's
most significant security risks — public exposure or misconfiguration — with evidence and
remediation for each finding. It currently reviews **EC2** and **S3**.

## Requirements

- Python 3.10+
- AWS credentials for the account you want to scan (environment variables, a shared profile, or an
  assumed role)
- Amazon Bedrock **model access** enabled for the model you choose, in a region where it is offered

## Install

You do not need to clone the repository. Install it directly from GitHub, which adds a `vista`
command:

```bash
pip install "git+https://github.com/sdharamsi1/vista.git"
```

Then run it:

```bash
vista
```

> If your system Python reports an "externally managed environment" error, add `--user` to the
> install command.

### From a local clone (for development)

```bash
git clone https://github.com/sdharamsi1/vista.git
cd vista
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

`-e` installs in editable mode, so code changes take effect without reinstalling.

## Usage

Run the CLI:

```bash
vista
```

Vista launches an interactive shell that:

1. Authenticates to AWS (default credentials or a named profile) and shows the account/identity.
2. Presents a **main menu**: run a scan, re-authenticate, or quit — it loops so you can run
   several scans without restarting.
3. Walks you through selecting a **service**, a **Bedrock model**, and a **region scope**, with
   `b` to go back a step and `q` to quit at any prompt.

Run `vista --help` to see all options. Two useful ones:

- `--save-json PATH` — write the exact factual JSON sent to Bedrock to a private (0600) file.
- `--plain` — print the model's raw Markdown without terminal formatting.

### Services

- **EC2** — instances and their network path, IAM, IMDS, storage, and load-balancer exposure.
- **S3** — buckets and their public-access controls (Block Public Access, policy, ACL, ownership),
  encryption, versioning, logging, replication, and CORS.

A bucket is only included when its region is in the selected scope, so use `--all-regions` (or the
right `--region`) to see every bucket.

### Models

The interactive menu offers two models plus a custom entry:

- Claude Opus 5 — `us.anthropic.claude-opus-5`
- GPT-5.6 Sol — `us.openai.gpt-5.6-sol`

Both are US cross-region inference profiles. Use a region where the model is available and where
your account has been granted access to it.

### Regions

Vista scans all selected regions, merges the facts into a single payload, and makes **one** Bedrock
call. `me-south-1` and `me-central-1` are excluded from region enumeration (edit `SKIP_REGIONS` in
`vista/cli.py` to change this).

## IAM permissions

The scanning identity needs read-only access plus Bedrock invoke. Common to every scan:

- `sts:GetCallerIdentity`, `ec2:DescribeRegions`
- `bedrock:InvokeModel` on the chosen model/inference profile

For **EC2**:

- `ec2:DescribeInstances`, `ec2:DescribeSecurityGroups`, `ec2:DescribeSubnets`,
  `ec2:DescribeRouteTables`, `ec2:DescribeNetworkAcls`, `ec2:DescribeVolumes`
- `iam:GetInstanceProfile`, `iam:GetRole`, `iam:ListAttachedRolePolicies`, `iam:ListRolePolicies`,
  `iam:GetRolePolicy`, `iam:GetPolicy`, `iam:GetPolicyVersion`
- `elasticloadbalancing:DescribeLoadBalancers`, `elasticloadbalancing:DescribeListeners`,
  `elasticloadbalancing:DescribeTargetHealth`

For **S3**:

- `s3:ListAllMyBuckets`, `s3:GetBucketLocation`
- `s3:GetBucketPublicAccessBlock`, `s3:GetBucketPolicy`, `s3:GetBucketPolicyStatus`,
  `s3:GetBucketAcl`, `s3:GetBucketOwnershipControls`, `s3:GetBucketWebsite`,
  `s3:GetEncryptionConfiguration`, `s3:GetBucketVersioning`, `s3:GetBucketLogging`,
  `s3:GetReplicationConfiguration`, `s3:GetBucketObjectLockConfiguration`, `s3:GetBucketCORS`,
  `s3:GetBucketTagging`
- `s3:GetAccountPublicAccessBlock`, `s3:ListAccessPoints`, `s3:GetAccessPointPolicyStatus`

Anything denied is recorded per resource under `collection_errors` rather than aborting the scan.

## Output

Vista prints an account-level review: a short risk summary followed by up to ten findings ordered
by severity. Each finding lists its severity, category, the affected resources, the supporting
evidence, why it matters, and a concrete remediation step. Resources that share a root cause are
grouped into a single finding.

## EC2 facts payload

For each scan, Vista collects factual AWS configuration and sends it to the model as JSON. No risk
scores or classifications are computed locally; the model reasons over the raw facts.

To keep the payload compact, resources shared by multiple instances (security groups, subnets,
route tables, network ACLs, instance profiles, managed policies, load balancers, target groups) are
de-duplicated into a top-level `shared` object and referenced by ID from each instance. Only
resources attached to the scanned instances are collected — never the whole account. The payload
looks like this:

```json
{
  "scan": {
    "account_id": "...",
    "regions": ["..."],
    "collector_status_by_region": { "us-east-1": { "inventory": {}, "network": {}, "storage": {}, "iam": {}, "load_balancers": {} } }
  },
  "shared": {
    "security_groups":   { "sg-...": {} },
    "subnets":           { "subnet-...": {} },
    "route_tables":      { "rtb-...": {} },
    "network_acls":      { "acl-...": {} },
    "instance_profiles": { "arn:...:instance-profile/...": {} },
    "managed_policies":  { "arn:...:policy/...": { "document": {} } },
    "load_balancers":    { "arn:...:loadbalancer/...": {} },
    "target_groups":     { "arn:...:targetgroup/...": {} }
  },
  "instances": [
    {
      "instance_id": "...",
      "arn": "...",
      "region": "...",
      "name": "...",
      "tags": {},
      "lifecycle": { "state": "...", "launch_time": "..." },
      "compute": { "instance_type": "...", "image_id": "...", "availability_zone": "...", "launch_template": {} },
      "network": {
        "vpc_id": "...",
        "security_group_ids": ["sg-..."],
        "interfaces": [ { "subnet_id": "...", "route_table_id": "...", "network_acl_id": "...", "security_group_ids": ["sg-..."] } ],
        "load_balancer_relationships": [ { "load_balancer_arn": "...", "target_group_arn": "...", "target": {} } ]
      },
      "instance_metadata": { "http_tokens": "...", "endpoint": "...", "hop_limit": 1 },
      "iam": { "instance_profile_arn": "..." },
      "storage": { "root_device_name": "...", "block_devices": [] }
    }
  ]
}
```

- **scan** — account, regions, and per-region collector success/error status.
- **shared** — deduplicated objects keyed by ID/ARN, referenced from instances. Managed policy
  documents live here under `managed_policies` rather than being repeated inside each role.
- **instances[]** — one entry per non-terminated EC2 instance, each with:
  - **region** — the region the instance was found in.
  - **lifecycle** — state and launch details.
  - **compute** — instance type, image, AZ, and launch template.
  - **network** — interfaces, `security_group_ids`, per-interface `subnet_id`/`route_table_id`/`network_acl_id`, and load-balancer relationships (by ARN). Resolve the IDs against `shared`.
  - **instance_metadata** — IMDS configuration (e.g. IMDSv1 vs IMDSv2).
  - **iam** — `instance_profile_arn` referencing `shared.instance_profiles`.
  - **storage** — EBS volumes, encryption, and attachments.

A full populated example is in
[`vista/ec2/examples/sample-payload.json`](vista/ec2/examples/sample-payload.json).

## S3 facts payload

S3 exposure is decided by the interaction of Block Public Access, bucket policy, ACL, and object
ownership — not a network path — so the payload carries those controls plus configuration signals.
Identical bucket policies are de-duplicated into `shared.policies` and referenced by `policy_ref`.
Account-level Block Public Access is under `account` and overrides per-bucket settings.

```json
{
  "scan": { "account_id": "...", "regions": ["..."] },
  "shared": { "policies": { "pol-<hash>": { "Statement": [] } } },
  "account": {
    "public_access_block": { "BlockPublicAcls": true, "IgnorePublicAcls": true, "BlockPublicPolicy": true, "RestrictPublicBuckets": true },
    "access_points": [ { "name": "...", "bucket": "...", "network_origin": "Internet", "policy_is_public": false } ]
  },
  "buckets": [
    {
      "name": "...",
      "arn": "arn:...:s3:::...",
      "region": "...",
      "tags": {},
      "public_access_block": { "BlockPublicAcls": true, "...": true },
      "policy_ref": "pol-<hash>",
      "policy_is_public": false,
      "acl": { "grants": [], "public_grants": [] },
      "object_ownership": "BucketOwnerEnforced",
      "website": null,
      "encryption": { "sse_algorithm": "aws:kms", "kms_key_arn": "...", "bucket_key_enabled": true },
      "versioning": { "status": "Enabled", "mfa_delete": null },
      "logging": { "target_bucket": "...", "target_prefix": "..." },
      "replication": null,
      "object_lock": null,
      "cors": null,
      "collection_errors": null
    }
  ]
}
```

- **account.public_access_block** — account-level Block Public Access; overrides bucket settings.
- **buckets[]** — one entry per bucket in the selected regions, with its own Block Public Access,
  `policy_ref` (into `shared.policies`), AWS-computed `policy_is_public`, ACL (public grants
  flagged), object ownership, website, encryption, versioning, logging, replication, object lock,
  and CORS.
- **collection_errors** — per-resource map of any field that could not be read (e.g. `AccessDenied`);
  the model treats those as unknown rather than safe.
