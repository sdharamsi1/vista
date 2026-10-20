# EC2 facts payload

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
    "collection_errors_by_region": null,
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
[`vista/ec2/examples/sample-payload.json`](../../vista/ec2/examples/sample-payload.json).
