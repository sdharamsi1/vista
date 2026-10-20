"""RDS review spec: the service guidance and response validation for the Bedrock review."""

from __future__ import annotations

from typing import Any

from vista import findings

RESOURCE_KINDS = ("db_instances", "db_clusters", "db_proxies", "snapshots")

SPEC = findings.ReviewSpec(
    service="RDS",
    noun="resource",
    categories=("PUBLIC_EXPOSURE", "SECURITY_CONFIGURATION"),
    affected_label="Affected resources",
    affected_format=(
        "each instance, cluster, proxy, or snapshot formatted as `identifier` (type, region)"
    ),
    summary=(
        "One or two sentences on the account's overall RDS posture, the number of instances, "
        "clusters, proxies, and manual snapshots reviewed, and the regions covered."
    ),
)

GUIDANCE = """Review the supplied factual AWS RDS configuration for one AWS account, which may
span one or more regions. The JSON contains real resource identities and exact AWS API values for
every DB instance, DB cluster, RDS Proxy, and manual snapshot in the selected regions. Each record
includes its own "region" field. Make all security judgments yourself; no local security
conclusions are included.

To avoid duplication, network, parameter, and key context is de-duplicated into a top-level
"shared" object and referenced from each resource. Resolve every reference before reasoning:
- security_group_ids -> shared.security_groups[id]
- subnet_group_ref -> shared.subnet_groups[ref]; its subnet_ids (and a proxy's subnet_ids) ->
  shared.subnets[id]; each subnet's route_table_id -> shared.route_tables[id] and network_acl_id ->
  shared.network_acls[id]
- parameter_group_refs -> shared.parameter_groups[ref]; cluster_parameter_group_ref ->
  shared.cluster_parameter_groups[ref]. Only user-modified parameters are listed; a default group
  (is_default true) or an unlisted parameter uses the engine default for that engine version.
- kms_key_id -> shared.kms_keys[id]; key_manager AWS means the AWS managed aws/rds key.
- A DB instance with a cluster_identifier is a member of that db_clusters entry; for Aurora the
  cluster's encryption, IAM authentication, backup, and deletion-protection settings apply.
- A snapshot's shared_with lists the AWS account IDs it is shared with, or "all"; shared_with null
  means the sharing attribute could not be read.
- master_user_secret is set when RDS manages the master user password in AWS Secrets Manager.
A missing reference means the collector did not return that object, exactly as if it were absent.

Your task: identify the account's most significant RDS security risks, whether they arise from
public exposure or from security configuration, and report only the ones that genuinely matter.
Return at most 10 findings, and fewer when fewer real risks exist. Never manufacture findings to
reach a count. Order findings from most to least severe.

AWS behavior relevant to the supplied fields:
- publicly_accessible true means the endpoint's DNS name resolves to a public IP address from
  outside the VPC and to the private IP address from inside it; false means it resolves to a
  private IP address. For an Aurora member, publicly_accessible is set per instance.
- Connections to DB instances and RDS Proxies are filtered by their VPC security groups, which are
  stateful and contain only allow rules. A rule whose source is another security group matches
  traffic from the private IP addresses of network interfaces that have that group attached.
  10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16 are private (RFC 1918) address ranges, which are
  not routed on the public Internet.
- A resource with a public IP address in a subnet can communicate with the Internet only when the
  subnet's route table has a route to an Internet gateway. Network ACLs filter traffic entering and
  leaving a subnet.
- An RDS Proxy endpoint is created in the VPC and is not publicly accessible.
- shared_with containing "all" on a manual snapshot means any AWS account can copy or restore it.
- AWS managed KMS keys such as aws/rds cannot be used across accounts, and their key policies cannot
  be changed.
- rds.force_ssl (RDS for PostgreSQL and SQL Server) and require_secure_transport (RDS for MySQL and
  MariaDB) control whether the database accepts only SSL/TLS client connections. require_tls on an
  RDS Proxy controls whether the proxy accepts only TLS client connections.
- debug_logging true on an RDS Proxy makes the proxy include detailed information about SQL
  statements in its logs.
- associated_roles lists IAM roles attached to a DB instance or cluster for a named feature (for
  example s3Import, s3Export, or Lambda); the database uses that role's permissions to call the AWS
  service for that feature.
- engine_lifecycle_support open-source-rds-extended-support means the resource is enrolled in RDS
  Extended Support, under which RDS keeps running its major engine version past the end of standard
  support; open-source-rds-extended-support-disabled means it is not enrolled.

{SEVERITY_MODEL}

Assign each finding one Category by what it is about: PUBLIC_EXPOSURE when it is about reachability
of resources from the Internet or access to snapshots by other AWS accounts,
SECURITY_CONFIGURATION when it is about any other resource configuration.
"""


# Every instance, cluster, proxy, and snapshot identifier in the facts.
def identifiers(facts: dict[str, Any]) -> set[str]:
    return {item["identifier"] for kind in RESOURCE_KINDS for item in facts.get(kind, [])}


# Build the per-request system prompt with resource counts.
def build_system_prompt(facts: dict[str, Any]) -> str:
    counts = ", ".join(f"{len(facts.get(kind, []))} {kind}" for kind in RESOURCE_KINDS)
    return findings.build_system_prompt(SPEC, GUIDANCE, counts)


# Validate the review structure and that every cited identifier exists; raise on any defect.
def validate(text: str, facts: dict[str, Any]) -> None:
    findings.validate_review(text, SPEC, identifiers(facts))
