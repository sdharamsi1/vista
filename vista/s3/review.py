"""S3 review spec: the system prompt and response validation for the Bedrock review."""

from __future__ import annotations

import re
from typing import Any

from vista import bedrock, severity

CATEGORIES = {"PUBLIC_EXPOSURE", "SECURITY_CONFIGURATION"}
MAX_FINDINGS = 10

EMPTY_MESSAGE = "# S3 Security Review\n\nNo buckets found in the selected region(s)."

FINDING_LABELS = (
    "**Severity:**",
    "**Likelihood:**",
    "**Impact:**",
    "**Confidence:**",
    "**Category:**",
    "**Affected buckets:**",
    "**Evidence:**",
    "**Why it matters:**",
    "**Remediation:**",
)

BUCKET_NAME_PATTERN = re.compile(r"`([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])`")
FINDING_HEADING_PATTERN = re.compile(r"^###\s+(.+)$", re.MULTILINE)

SYSTEM_PROMPT = """Review the supplied factual AWS S3 configuration for one AWS account, which may
span one or more regions. The JSON contains real bucket identities and exact AWS API values for
every bucket in the selected regions. Each bucket record includes its own "region" field. Make all
security judgments yourself; no local security conclusions are included.

Your task: identify the account's most significant S3 security risks, whether they arise from public
exposure or from security configuration, and report only the ones that genuinely matter. Return at
most 10 findings, and fewer when fewer real risks exist. Never manufacture findings to reach a
count. Order findings from most to least severe.

Group, do not repeat. When multiple buckets share the same root cause (the same public policy
pattern, the same missing encryption, the same disabled versioning), report them as a single
finding and list every affected bucket as evidence. Do not emit one finding per bucket.

S3 has no network path; public exposure is decided entirely by the interaction of Block Public
Access, bucket policy, ACL, and object ownership. Evaluate them in this precedence:
- Account-level Block Public Access is under account.public_access_block and OVERRIDES bucket
  settings. If RestrictPublicBuckets or BlockPublicPolicy is true, a public bucket policy is
  neutralized; if BlockPublicAcls/IgnorePublicAcls is true, public ACL grants are neutralized. Apply
  the union of account-level and per-bucket public_access_block.
- A bucket is publicly exposed only when an effective public grant survives Block Public Access:
  a bucket policy allowing a Principal of "*" (or AWS "*") without a restricting condition
  (aws:PrincipalOrgID, aws:SourceArn, aws:SourceVpce, aws:SourceIp), or an ACL grant to the AllUsers
  or AuthenticatedUsers group, or a public access point.
- policy_is_public is AWS's own computed verdict for the bucket policy; treat it as a factual
  signal, but still explain which grant and which Block Public Access flags produce the result.
- object_ownership of "BucketOwnerEnforced" disables ACLs entirely, so ACL grants cannot create
  exposure on that bucket. Do not cite an ACL grant as public when ownership is BucketOwnerEnforced.
- A "collection_errors" entry (for example AccessDenied on the policy) means that fact could not be
  read; treat exposure as UNKNOWN for that element rather than assuming safe or public.

Security-configuration risks worth a finding include: no default encryption, or SSE-S3 where
account standards expect SSE-KMS; a bucket policy that does not deny non-TLS access
(aws:SecureTransport false); versioning suspended/absent on data buckets; no server access or data
logging; replication to an external account (data egress); overly permissive CORS (AllowedOrigins
"*", especially with credentials); and static website hosting on a bucket not intended to be public.

{SEVERITY_MODEL}

For S3 specifically: treat a bucket that is effectively public to anonymous principals after Block
Public Access is applied as at least MEDIUM Likelihood, and HIGH when public write or delete is
possible; a public read-only static website whose public use is supplied as intended is not
automatically HIGH Likelihood. Treat a fact that could not be read (collection_errors) as lowering
Confidence, never as safe. Supplied approved intent may lower a bucket's Likelihood, but only with
the reason stated.

Assign each finding a Category: PUBLIC_EXPOSURE when the dominant risk is public access,
SECURITY_CONFIGURATION when it is encryption, versioning, logging, transport, replication, or CORS.

Be evidence-specific and concise:
- Cite exact supplied facts: bucket name, region, the specific policy statement/principal/condition,
  the effective Block Public Access flags (account and bucket), policy_is_public, ACL grantee group,
  object_ownership, SSE algorithm and KMS key, versioning status, logging target, replication
  destination, or CORS origins. Name which Block Public Access flags are or are not neutralizing a
  grant.
- Do not use vague labels such as "public", "broad", or "insecure" without the exact supporting
  fact. Do not claim data sensitivity, exploitation, or approved intent unless supplied.

For Remediation, give a concrete fix: the exact setting, policy statement, or Block Public Access
flag to change and the acceptable end state. Recommend confirming intended public use before
removing a public grant on a bucket that may serve public content.

Return only the following Markdown, and nothing else:

# S3 Security Review

## Account Risk Summary
One or two sentences on the account's overall S3 posture, the number of buckets reviewed, the
regions covered, and the account-level Block Public Access state.

## Top Findings

### 1. Concise risk title
- **Severity:** CRITICAL, HIGH, MEDIUM, or LOW (must equal the matrix result for the Likelihood and Impact below)
- **Likelihood:** HIGH, MEDIUM, or LOW
- **Impact:** HIGH, MEDIUM, or LOW
- **Confidence:** CONFIRMED, PARTIAL, or INSUFFICIENT
- **Category:** PUBLIC_EXPOSURE or SECURITY_CONFIGURATION
- **Affected buckets:** each bucket formatted as `bucket-name`, comma-separated
- **Evidence:** one to three concise, fact-specific sentences.
- **Why it matters:** one or two concise sentences on the concrete impact.
- **Remediation:** one or two concise sentences with a specific fix and acceptable end state.

Number the finding headings sequentially (### 1., ### 2., ...), ordered most to least severe
(CRITICAL, then HIGH, MEDIUM, LOW), at most 10 blocks.

Every bucket name you cite must be one supplied in the input; never invent a name. If no bucket
presents a noteworthy risk, still return the Account Risk Summary and the "## Top Findings" heading
with no finding blocks. Do not return a table, JSON, extra headings, or a separate block for every
bucket.
"""


# Build the per-request system prompt with the bucket count and, when supplied, account intent.
def build_system_prompt(buckets: list[dict[str, Any]], intent: str | None = None) -> str:
    count = len(buckets)
    prompt = (
        SYSTEM_PROMPT.replace("{SEVERITY_MODEL}", severity.SEVERITY_MODEL_PROMPT)
        + f"\nThe input contains {count} buckets. Return at most {MAX_FINDINGS} findings, grouping "
        "buckets that share a root cause, and cite only bucket names present in the input."
    )
    if intent:
        prompt += bedrock.build_intent_section(intent)
    return prompt


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


# Validate sections, findings, fields, enums, and bucket names; raise on any defect.
def validate(text: str, buckets: list[dict[str, Any]]) -> None:
    valid_names = {bucket["name"] for bucket in buckets}
    details: list[str] = []

    for section in ("# S3 Security Review", "## Top Findings"):
        if text.count(section) != 1:
            details.append(f"missing or repeated section: {section}")

    findings = split_findings(text)
    if len(findings) > MAX_FINDINGS:
        details.append(f"returned {len(findings)} findings, more than the {MAX_FINDINGS} allowed")

    unknown_names: set[str] = set()
    for position, (title, block) in enumerate(findings, start=1):
        if not title:
            details.append(f"finding {position} has an empty title")

        missing = [label for label in FINDING_LABELS if block.count(label) != 1]
        if missing:
            details.append(
                f"finding {position} has missing or duplicated fields: " + ", ".join(missing)
            )

        severity_value = enum_value(block, "Severity")
        if severity_value not in severity.SEVERITIES:
            details.append(f"finding {position} has an invalid Severity: {severity_value or 'missing'}")
        likelihood = enum_value(block, "Likelihood")
        if likelihood not in severity.LIKELIHOODS:
            details.append(f"finding {position} has an invalid Likelihood: {likelihood or 'missing'}")
        impact = enum_value(block, "Impact")
        if impact not in severity.IMPACTS:
            details.append(f"finding {position} has an invalid Impact: {impact or 'missing'}")
        confidence = enum_value(block, "Confidence")
        if confidence not in severity.CONFIDENCE:
            details.append(f"finding {position} has an invalid Confidence: {confidence or 'missing'}")
        expected = severity.derive_severity(likelihood, impact)
        if expected is not None and severity_value != expected:
            details.append(
                f"finding {position} Severity {severity_value} does not match the matrix result "
                f"{expected} for Likelihood {likelihood} x Impact {impact}"
            )
        category = enum_value(block, "Category")
        if category not in CATEGORIES:
            details.append(f"finding {position} has an invalid Category: {category or 'missing'}")

        affected = finding_field(block, "Affected buckets") or ""
        referenced = BUCKET_NAME_PATTERN.findall(affected)
        if not referenced:
            details.append(f"finding {position} names no affected bucket")
        unknown_names.update(name for name in referenced if name not in valid_names)

    if unknown_names:
        details.append("findings cite buckets not in the input: " + ", ".join(sorted(unknown_names)))

    if "No buckets found" in text:
        details.append("contradictory no-buckets message")

    if details:
        raise ValueError("Bedrock returned an incomplete review (" + "; ".join(details) + ").")
