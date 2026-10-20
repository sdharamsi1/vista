# RDS facts payload

Network, parameter, and key context is collected once into `shared` and referenced from each
resource, using the same security-group, subnet, route-table, and network-ACL shapes as
[EC2](ec2.md). Subnet groups and parameter groups are only unique within a region, so they are keyed
as `region/name`. Only user-modified parameters are listed; default parameter groups use engine
defaults.

```json
{
  "scan": { "account_id": "...", "regions": ["..."], "collection_errors_by_region": null },
  "shared": {
    "security_groups":          { "sg-...": {} },
    "subnet_groups":            { "us-east-1/app-db-subnets": { "vpc_id": "...", "subnet_ids": ["subnet-..."] } },
    "subnets":                  { "subnet-...": { "route_table_id": "rtb-...", "network_acl_id": "acl-..." } },
    "route_tables":             { "rtb-...": {} },
    "network_acls":             { "acl-...": {} },
    "parameter_groups":         { "us-east-1/orders-pg": { "is_default": false, "user_parameters": { "rds.force_ssl": "0" } } },
    "cluster_parameter_groups": { "us-east-1/analytics-cluster-pg": {} },
    "kms_keys":                 { "arn:...:key/...": { "key_manager": "CUSTOMER", "key_state": "Enabled" } }
  },
  "db_instances": [
    { "identifier": "...", "engine": "postgres", "publicly_accessible": true, "port": 5432, "security_group_ids": ["sg-..."], "subnet_group_ref": "us-east-1/app-db-subnets", "storage_encrypted": false, "master_user_secret": null, "ca_certificate": { "identifier": "rds-ca-rsa2048-g1", "valid_till": "..." } }
  ],
  "db_clusters": [
    { "identifier": "...", "engine": "aurora-mysql", "members": [ { "identifier": "...", "writer": true } ], "data_api_enabled": true, "associated_roles": [ { "role_arn": "...", "feature": "s3Export" } ] }
  ],
  "db_proxies": [
    { "identifier": "...", "require_tls": false, "debug_logging": true, "auth": [ { "auth_scheme": "SECRETS", "iam_auth": "DISABLED" } ] }
  ],
  "snapshots": [
    { "identifier": "...", "kind": "instance", "encrypted": false, "shared_with": ["all"] }
  ]
}
```

- **snapshots[]** — manual snapshots only. `shared_with` of `["all"]` means the snapshot is public;
  account IDs are cross-account shares; `null` means the sharing attribute could not be read.
- **db_proxies[]** — RDS Proxies, which are VPC-only, with their TLS requirement, client
  authentication, and debug logging settings.

A full populated example is in
[`vista/rds/examples/sample-payload.json`](../../vista/rds/examples/sample-payload.json).
