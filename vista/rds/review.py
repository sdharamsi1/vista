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
- kms_key_id -> shared.kms_keys[id]; key_manager AWS means the AWS-managed aws/rds key, which
  cannot be shared cross-account and whose key policy the account cannot restrict.
- A DB instance with a cluster_identifier is a member of that db_clusters entry; for Aurora the
  cluster's encryption, IAM authentication, backup, and deletion-protection settings apply.
A missing reference means the collector did not return that object, exactly as if it were absent.

Your task: identify the account's most significant RDS security risks, whether they arise from
public exposure or from security configuration, and report only the ones that genuinely matter.
Return at most 10 findings, and fewer when fewer real risks exist. Never manufacture findings to
reach a count. Order findings from most to least severe.

Group, do not repeat. When multiple resources share the same root cause (the same open security
group, the same missing encryption, the same disabled deletion protection), report them as a single
finding and list every affected resource. Do not emit one finding per resource.

Determine public exposure from evidence only:
- A DB instance is Internet-reachable only when every element holds: publicly_accessible is true,
  an attached security group allows inbound traffic on the database port from a globally routable
  source, a subnet in its subnet group routes to an Internet gateway, and the subnet's network ACL
  does not deny that traffic. For an Aurora member, publicly_accessible is set per instance.
- When publicly_accessible is false the database has no public address, so subnet routing or an
  allow-all NACL alone is not PUBLIC_EXPOSURE; mention it only as context for another finding.
- A snapshot whose shared_with contains "all" is public: any AWS account can restore it. An
  unencrypted public snapshot exposes its data outright. Account IDs in shared_with are cross-account
  shares; name them. shared_with null means the sharing attribute could not be read.
- RDS Proxies are reachable only inside their VPC; they are never Internet-exposed on their own.
- Security-group rules that reference other security groups or private CIDRs are internal access,
  not Internet exposure.

Security-configuration risks worth a finding include: storage_encrypted false, unencrypted
snapshots, TLS not enforced (rds.force_ssl or require_secure_transport off by default or by
parameter, or a proxy with require_tls false), IAM authentication disabled where it would replace
static passwords, a master password not managed by Secrets Manager (master_user_secret null),
deletion_protection false or backup_retention_days of 0 on production-looking databases, no log
exports, a proxy with debug_logging true (it logs SQL statements), the Data API enabled on a
cluster, associated_roles that let the database reach S3 or Lambda, a CA certificate past or near
valid_till, and an engine on extended support (engine_lifecycle_support open-source-rds-extended-support)
or an end-of-support version.

{SEVERITY_MODEL}

For RDS specifically: treat a confirmed Internet path to the database port from a broad source as
HIGH Likelihood, and a public snapshot as HIGH Likelihood. A narrow /32 source or a
publicly_accessible flag without an open security group or Internet-gateway route is not
automatically HIGH. Supplied approved intent may lower Likelihood, but only with the reason stated.

Assign each finding a Category: PUBLIC_EXPOSURE when the dominant risk is Internet reachability or
a public/cross-account snapshot, SECURITY_CONFIGURATION when it is encryption, TLS, authentication,
logging, backup, or lifecycle configuration.

Be evidence-specific and concise:
- Cite exact supplied facts: resource identifiers, region, engine and version, endpoint and port,
  publicly_accessible, security-group IDs with CIDRs and ports, route targets, encryption and KMS
  key manager, parameter names and values, snapshot shared_with values, and backup or deletion
  settings.
- Do not use vague labels such as "public", "open", or "insecure" without the exact supporting
  fact. Do not claim data sensitivity, exploitation, or approved intent unless supplied.

For Remediation, give a concrete fix: the exact setting, rule, parameter, or sharing attribute to
change and the acceptable end state. Recommend confirming operational need before any change that
affects connectivity or availability, such as removing public access or modifying a security group.
"""


# Every instance, cluster, proxy, and snapshot identifier in the facts.
def identifiers(facts: dict[str, Any]) -> set[str]:
    return {item["identifier"] for kind in RESOURCE_KINDS for item in facts.get(kind, [])}


# Build the per-request system prompt with resource counts and, when supplied, account intent.
def build_system_prompt(facts: dict[str, Any], intent: str | None = None) -> str:
    counts = ", ".join(f"{len(facts.get(kind, []))} {kind}" for kind in RESOURCE_KINDS)
    return findings.build_system_prompt(SPEC, GUIDANCE, counts, intent)


# Validate the review structure and that every cited identifier exists; raise on any defect.
def validate(text: str, facts: dict[str, Any]) -> None:
    findings.validate_review(text, SPEC, identifiers(facts))
