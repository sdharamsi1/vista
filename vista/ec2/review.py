"""EC2 review spec: the service guidance and response validation for the Bedrock review."""

from __future__ import annotations

from typing import Any

from vista import findings

SPEC = findings.ReviewSpec(
    service="EC2",
    noun="instance",
    categories=("INTERNET_EXPOSURE", "SECURITY_CONFIGURATION"),
    affected_label="Affected instances",
    affected_format="each instance formatted as `i-instanceid` (Name or Unnamed)",
    summary=(
        "One or two sentences on the account's overall EC2 posture, the number of "
        "instances reviewed, and the regions covered."
    ),
)

GUIDANCE = """Review the supplied factual AWS EC2 configuration for one AWS account, which may
span one or more regions. The JSON contains real resource identities and exact AWS API values for
every non-terminated instance in the account. Each instance record includes its own "region" field.
Make all security judgments yourself; no local security conclusions are included.

To avoid duplication, resources shared by multiple instances are de-duplicated into a top-level
"shared" object and referenced by ID from each instance. Resolve every reference before reasoning,
and treat the referenced data as if it were inline on the instance:
- instance.network.security_group_ids and each load balancer's security_group_ids -> shared.security_groups[id]
- each interface's subnet_id -> shared.subnets[id]; route_table_id -> shared.route_tables[id]; network_acl_id -> shared.network_acls[id]
- instance.iam.instance_profile_arn -> shared.instance_profiles[arn]; within a profile, a role's managed policy references shared.managed_policies[arn] (the policy document lives there)
- each load_balancer_relationship's load_balancer_arn -> shared.load_balancers[arn]; target_group_arn -> shared.target_groups[arn]
A missing reference means the collector did not return that object, exactly as if it were absent.

Your task: identify the account's most significant EC2 security risks, whether they arise from
Internet exposure or from security configuration, and report only the ones that genuinely matter.
Return at most 10 findings, and fewer when fewer real risks exist. Never manufacture findings to
reach a count. Order findings from most to least severe.

Group, do not repeat. When multiple instances share the same root cause (for example the same
IMDSv1 setting, the same unencrypted-volume pattern, or the same open security-group rule), report
them as a single finding and list every affected instance as evidence, even when those instances
are in different regions. Do not emit one finding per instance, and do not produce a per-instance
report.

Determine Internet exposure from evidence only:
- DIRECT requires a running instance, a public IPv4 or globally routable IPv6 address, a matching
  inbound instance-security-group rule from a globally routable source, and an active instance-subnet
  route to an Internet gateway. Every element is required.
- Egress rules, permissive NACLs, NAT gateways, transit gateways, names, and tags do not create
  DIRECT inbound exposure.
- LOAD_BALANCER requires a running instance and a registered path through an active load balancer
  whose scheme is exactly internet-facing, with an applicable listener/rule, matching public frontend
  access, and Internet-gateway-routed load-balancer subnets. An internal load balancer never creates
  Internet exposure. Internal listeners and backend target ports are not public ports.
- Report unhealthy or draining targets factually; do not call them vulnerable, and do not erase a
  configured public relationship solely because delivery is unhealthy.

Security-configuration risks worth a finding include: unencrypted EBS storage, IMDSv1 (http_tokens
optional), broad or wildcard IAM actions or resources, secret read/write or SSM remote-command
permissions, powerful cross-account role assumption, dormant public administrative security-group
rules, unhealthy public target registration, and bootstrap or prototype resources still running.
Standard AmazonSSMManagedInstanceCore permissions alone are normal management context and are not a
finding on their own.

{SEVERITY_MODEL}

For EC2 specifically: treat a confirmed public network path (DIRECT, LOAD_BALANCER, or BOTH) as at
least MEDIUM Likelihood, and HIGH when it reaches SSH, RDP, administrative, or database ports from a
broad source; ordinary public web ports, a narrow public /32 source, or an OIDC-protected ALB are
not automatically HIGH Likelihood. Never report a public path as requiring no action. Supplied
approved intent may lower a path's Likelihood, but only with the reason stated.

Assign each finding a Category: INTERNET_EXPOSURE when the dominant risk is a public network path,
SECURITY_CONFIGURATION when it is an IAM, IMDS, storage, or lifecycle weakness.

Be evidence-specific and concise:
- Cite exact supplied facts: instance IDs, region, security-group IDs, CIDRs or source groups,
  ports, listener and target ports, route targets, load-balancer scheme, IAM
  actions/resources/conditions, volume IDs, IMDS settings, lifecycle state, and target health.
  Distinguish a public listener port from a backend target port. When a finding spans multiple
  regions, name the affected region(s) in the evidence.
- Do not use vague labels such as "broad", "wildcard", "protected", or "restricted" without the
  exact supporting fact. Describe condition-limited IAM access accurately; do not present it as
  unrestricted.
- Do not claim WAF, vulnerabilities, data sensitivity, exploitability, compromise, or approved
  intent unless supplied. Empty load-balancer authentication actions mean only that no ELB-layer
  action was supplied; do not conclude the application has no authentication.

For Remediation, give a concrete fix: the exact setting, permission, rule, or control to change and
the acceptable end state. Recommend confirming approved intent or operational need before any
destructive or traffic-affecting change, such as closing a public path or terminating an instance.
"""


# Every identifier a finding may cite.
def identifiers(facts: dict[str, Any]) -> set[str]:
    return {instance["instance_id"] for instance in facts.get("instances", [])}


# Build the per-request system prompt with the instance count and, when supplied, account intent.
def build_system_prompt(facts: dict[str, Any], intent: str | None = None) -> str:
    counts = f"{len(facts.get('instances', []))} instances"
    return findings.build_system_prompt(SPEC, GUIDANCE, counts, intent)


# Validate the review structure and that every cited instance exists; raise on any defect.
def validate(text: str, facts: dict[str, Any]) -> None:
    findings.validate_review(text, SPEC, identifiers(facts))
