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
        "reviewed, and the regions covered."
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

How the payload is shaped:
- Account-level Block Public Access settings are under account.public_access_block; each bucket's
  own settings are under its public_access_block.
- Each bucket's policy_ref -> shared.policies[ref], the bucket policy document. A bucket with no
  policy_ref has no bucket policy, unless its collection_errors has a policy entry.
- acl.grants lists every grant in the bucket ACL; acl.public_grants lists the grants among them
  whose grantee is the AllUsers group (http://acs.amazonaws.com/groups/global/AllUsers) or the
  AuthenticatedUsers group (http://acs.amazonaws.com/groups/global/AuthenticatedUsers).
- policy_is_public is the value AWS returns from GetBucketPolicyStatus (PolicyStatus.IsPublic) for
  the bucket policy. On an access point in account.access_points, it is the value AWS returns from
  GetAccessPointPolicyStatus for that access point's policy.
- A "collection_errors" entry (for example AccessDenied on the policy) means that fact could not be
  read.

AWS behavior relevant to the supplied fields:
- S3 buckets have no security groups, subnets, or network ACLs of their own. Requests reach S3
  through its service endpoints, either directly or from a VPC through a gateway VPC endpoint or an
  interface VPC endpoint; an interface endpoint is one or more network interfaces with private IP
  addresses in subnets of the VPC. When it authorizes a request, S3 evaluates policies and settings
  including the requester's IAM policies, the bucket policy, ACLs, Block Public Access settings, and
  the object ownership setting.
- Block Public Access settings exist at the account level and the bucket level; S3 applies the most
  restrictive combination of the two.
- BlockPublicAcls rejects requests that set a public ACL; IgnorePublicAcls makes S3 ignore public
  ACLs on the bucket and its objects. BlockPublicPolicy rejects new public bucket policies;
  RestrictPublicBuckets restricts access granted by a public policy to AWS service principals and
  authorized users in the owning account.
- In a bucket policy, a Principal of "*" (or {"AWS": "*"}) matches every requester, including
  anonymous requests. aws:PrincipalOrgID matches principals in accounts that belong to the named
  AWS Organization; aws:SourceArn matches the ARN of the AWS resource making a service-to-service
  request; aws:SourceVpce matches requests that arrive through the named VPC endpoint; aws:SourceIp
  matches the requester's IP address against the listed ranges. aws:SecureTransport is false when a
  request is sent over HTTP rather than HTTPS.
- The AllUsers ACL group represents anyone, including anonymous requests; the AuthenticatedUsers
  group represents any principal authenticated to any AWS account.
- An object_ownership of BucketOwnerEnforced disables ACLs; ACLs then no longer affect access to the
  bucket or its objects.
- S3 access points are separate named endpoints for a bucket, each with its own access point
  policy.

{SEVERITY_MODEL}

Assign each finding one Category by what it is about: PUBLIC_EXPOSURE when it is about public
access to buckets or their objects, SECURITY_CONFIGURATION when it is about any other bucket
configuration.
"""


# Every identifier a finding may cite.
def identifiers(facts: dict[str, Any]) -> set[str]:
    return {bucket["name"] for bucket in facts.get("buckets", [])}


# Build the per-request system prompt with the bucket count.
def build_system_prompt(facts: dict[str, Any]) -> str:
    counts = f"{len(facts.get('buckets', []))} buckets"
    return findings.build_system_prompt(SPEC, GUIDANCE, counts)


# Validate the review structure and that every cited bucket exists; raise on any defect.
def validate(text: str, facts: dict[str, Any]) -> None:
    findings.validate_review(text, SPEC, identifiers(facts))
