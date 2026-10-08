"""S3 review spec: the service guidance and response validation for the Bedrock review."""

from __future__ import annotations

from typing import Any

from vista import findings

SPEC = findings.ReviewSpec(
    service="S3",
    noun="bucket",
    categories=("PUBLIC_EXPOSURE", "SECURITY_CONFIGURATION"),
    affected_label="Affected buckets",
    affected_format="each bucket formatted as `bucket-name`",
    summary=(
        "One or two sentences on the account's overall S3 posture, the number of buckets "
        "reviewed, the regions covered, and the account-level Block Public Access state."
    ),
)

GUIDANCE = """Review the supplied factual AWS S3 configuration for one AWS account, which may
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
"""


# Every identifier a finding may cite.
def identifiers(facts: dict[str, Any]) -> set[str]:
    return {bucket["name"] for bucket in facts.get("buckets", [])}


# Build the per-request system prompt with the bucket count and, when supplied, account intent.
def build_system_prompt(facts: dict[str, Any], intent: str | None = None) -> str:
    counts = f"{len(facts.get('buckets', []))} buckets"
    return findings.build_system_prompt(SPEC, GUIDANCE, counts, intent)


# Validate the review structure and that every cited bucket exists; raise on any defect.
def validate(text: str, facts: dict[str, Any]) -> None:
    findings.validate_review(text, SPEC, identifiers(facts))
