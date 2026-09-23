"""EC2 review spec: the system prompt and response validation for the Bedrock review."""

from __future__ import annotations

import re
from typing import Any

SEVERITIES = {"HIGH_PRIORITY", "INVESTIGATE", "INSUFFICIENT_DATA"}
CATEGORIES = {"INTERNET_EXPOSURE", "SECURITY_CONFIGURATION"}
MAX_FINDINGS = 10

EMPTY_MESSAGE = "# EC2 Security Review\n\nNo non-terminated instances found."

FINDING_LABELS = (
    "**Severity:**",
    "**Category:**",
    "**Affected instances:**",
    "**Evidence:**",
    "**Why it matters:**",
    "**Remediation:**",
)

INSTANCE_ID_PATTERN = re.compile(r"`(i-[0-9a-fA-F]+)`")
FINDING_HEADING_PATTERN = re.compile(r"^###\s+(.+)$", re.MULTILINE)

SYSTEM_PROMPT = """Review the supplied factual AWS EC2 configuration for one AWS account, which may
span one or more regions. The JSON contains real resource identities and exact AWS API values for
every non-terminated instance in the account. Each instance record includes its own "region" field.
Make all security judgments yourself; no local security conclusions are included.

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

Assign each finding a Severity:
- HIGH_PRIORITY: strong supplied evidence of likely dangerous exposure, such as a complete broad
  DIRECT path to SSH, RDP, administrative, or database ports, or a comparably severe combination.
  Ordinary public web ports, a narrow public /32 source, or an OIDC-protected ALB are not
  automatically HIGH_PRIORITY.
- INVESTIGATE: a public path exists without supplied approved intent, or a meaningful configuration
  concern such as those listed above.
- INSUFFICIENT_DATA: a relevant collector failed or essential evidence needed for a responsible
  judgment is missing. Do not use it merely because runtime or business context is absent.
- Any DIRECT, LOAD_BALANCER, or BOTH path without supplied approved owner intent is at least
  INVESTIGATE. Never report a public path as requiring no action.

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

Return only the following Markdown, and nothing else:

# EC2 Security Review

## Account Risk Summary
One or two sentences on the account's overall EC2 posture, the number of instances reviewed, and
the regions covered.

## Top Findings

### 1. Concise risk title
- **Severity:** HIGH_PRIORITY, INVESTIGATE, or INSUFFICIENT_DATA
- **Category:** INTERNET_EXPOSURE or SECURITY_CONFIGURATION
- **Affected instances:** each instance formatted as `i-instanceid` (Name or Unnamed), comma-separated
- **Evidence:** one to three concise, fact-specific sentences.
- **Why it matters:** one or two concise sentences on the concrete impact.
- **Remediation:** one or two concise sentences with a specific fix and acceptable end state.

Number the finding headings sequentially (### 1., ### 2., ...), most severe first, at most 10 blocks.

Every instance ID you cite must be one supplied in the input; never invent an ID. If no instance
presents a noteworthy risk, still return the Account Risk Summary and the "## Top Findings" heading
with no finding blocks. Do not return a table, JSON, extra headings, or a separate block for every
instance.
"""


# Build the per-request system prompt, appending the instance count.
def build_system_prompt(instances: list[dict[str, Any]]) -> str:
    count = len(instances)
    return (
        SYSTEM_PROMPT
        + f"\nThe input contains {count} instances. Return at most {MAX_FINDINGS} findings, "
        "grouping instances that share a root cause, and cite only instance IDs present in the input."
    )


# Text of one labeled field in a finding block.
def finding_field(block: str, label: str) -> str | None:
    pattern = rf"- \*\*{re.escape(label)}:\*\*\s*(.*?)(?=\n\s*- \*\*|\Z)"
    match = re.search(pattern, block, re.DOTALL)
    return match.group(1).strip() if match else None


# Enum value following a bold label in a finding block.
def enum_value(block: str, label: str) -> str | None:
    match = re.search(rf"\*\*{re.escape(label)}:\*\*\s*`?([A-Z_]+)`?", block)
    return match.group(1) if match else None


# Split into (title, block) pairs, one per finding heading.
def split_findings(text: str) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    title: str | None = None
    body: list[str] = []
    for line in text.splitlines():
        heading = FINDING_HEADING_PATTERN.match(line.strip())
        if heading:
            if title is not None:
                findings.append((title, "\n".join(body)))
            title = heading.group(1).strip()
            body = []
        elif title is not None:
            body.append(line)
    if title is not None:
        findings.append((title, "\n".join(body)))
    return findings


# Validate sections, findings, fields, enums, and instance IDs; raise on any defect.
def validate(text: str, instances: list[dict[str, Any]]) -> None:
    valid_ids = {instance["instance_id"] for instance in instances}
    details: list[str] = []

    for section in ("# EC2 Security Review", "## Top Findings"):
        if text.count(section) != 1:
            details.append(f"missing or repeated section: {section}")

    findings = split_findings(text)
    if len(findings) > MAX_FINDINGS:
        details.append(f"returned {len(findings)} findings, more than the {MAX_FINDINGS} allowed")

    unknown_ids: set[str] = set()
    for position, (title, block) in enumerate(findings, start=1):
        if not title:
            details.append(f"finding {position} has an empty title")

        missing = [label for label in FINDING_LABELS if block.count(label) != 1]
        if missing:
            details.append(
                f"finding {position} has missing or duplicated fields: " + ", ".join(missing)
            )

        severity = enum_value(block, "Severity")
        if severity not in SEVERITIES:
            details.append(f"finding {position} has an invalid Severity: {severity or 'missing'}")
        category = enum_value(block, "Category")
        if category not in CATEGORIES:
            details.append(f"finding {position} has an invalid Category: {category or 'missing'}")

        affected = finding_field(block, "Affected instances") or ""
        referenced = INSTANCE_ID_PATTERN.findall(affected)
        if not referenced:
            details.append(f"finding {position} names no affected instance ID")
        unknown_ids.update(identifier for identifier in referenced if identifier not in valid_ids)

    if unknown_ids:
        details.append("findings cite instance IDs not in the input: " + ", ".join(sorted(unknown_ids)))

    if "No non-terminated instances found" in text:
        details.append("contradictory no-instances message")

    if details:
        raise ValueError("Bedrock returned an incomplete review (" + "; ".join(details) + ").")
