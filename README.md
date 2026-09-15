# vista
Vista is an AI-powered AWS attack surface analysis tool that discovers exposed resources and evaluates their security risk using cloud context.

## EC2

For each scan, Vista collects factual AWS configuration and sends it to the LLM as JSON. No risk
scores or classifications are computed locally, the model reasons over the raw facts. At a high
level, the payload looks like this:

```json
{
  "scan": {
    "account_id": "...",
    "region": "...",
    "collector_status": { "inventory": {}, "network": {}, "storage": {}, "iam": {}, "load_balancers": {} }
  },
  "instances": [
    {
      "instance_id": "...",
      "arn": "...",
      "name": "...",
      "tags": {},
      "lifecycle": { "state": "...", "launch_time": "..." },
      "compute": { "instance_type": "...", "image_id": "...", "availability_zone": "...", "launch_template": {} },
      "network": { "vpc_id": "...", "interfaces": [], "security_groups": [], "load_balancer_relationships": [] },
      "instance_metadata": { "http_tokens": "...", "endpoint": "...", "hop_limit": 1 },
      "iam": { "instance_profile_arn": "...", "instance_profile": {} },
      "storage": { "root_device_name": "...", "block_devices": [] }
    }
  ]
}
```

- **scan** — account, region, and per-collector success/error status.
- **instances[]** — one entry per non-terminated EC2 instance, each with:
  - **lifecycle** — state and launch details.
  - **compute** — instance type, image, AZ, and launch template.
  - **network** — interfaces, security groups, subnets, routes, NACLs, and load-balancer relationships.
  - **instance_metadata** — IMDS configuration (e.g. IMDSv1 vs IMDSv2).
  - **iam** — instance profile, roles, trust policy, and attached/inline policies.
  - **storage** — EBS volumes, encryption, and attachments.

A full populated example is in [`ec2/examples/sample-payload.json`](ec2/examples/sample-payload.json).
