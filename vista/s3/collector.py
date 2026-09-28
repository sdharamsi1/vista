"""Collect factual S3 bucket configuration for a Bedrock security review.

Exposure for S3 is policy/ACL/Block-Public-Access driven, not network driven, so this collects the
controls that together decide whether a bucket is public: account and bucket Block Public Access,
bucket policy (+ AWS's computed IsPublic), ACL, object-ownership, website hosting, and access
points, plus configuration signals (encryption, versioning, logging, replication, object lock,
CORS).
"""

from __future__ import annotations

import json
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Callable

from botocore.exceptions import BotoCoreError, ClientError

# Buckets are collected concurrently; each is ~13 sequential API calls, so parallelism helps a lot.
MAX_WORKERS = 16

# Error codes that mean "this configuration simply isn't set" rather than a real failure.
BENIGN_CODES = {
    "NoSuchBucketPolicy",
    "ServerSideEncryptionConfigurationNotFoundError",
    "NoSuchWebsiteConfiguration",
    "NoSuchCORSConfiguration",
    "ReplicationConfigurationNotFoundError",
    "ObjectLockConfigurationNotFoundError",
    "NoSuchPublicAccessBlockConfiguration",
    "NoSuchTagSet",
    "OwnershipControlsNotFoundError",
    "NoSuchConfiguration",
}

PUBLIC_ACL_GROUPS = (
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
)


# ISO 8601 string for a datetime, passing through None/other.
def _iso(value: Any) -> str | None:
    if value is None:
        return None
    return value.isoformat() if isinstance(value, datetime) else str(value)


# Run a getter, returning its value; None for "not configured", recording other errors in `errors`.
def _try(errors: dict[str, str], field: str, getter: Callable[[], Any]) -> Any:
    try:
        return getter()
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "")
        if code not in BENIGN_CODES:
            errors[field] = code
        return None
    except BotoCoreError as error:
        errors[field] = type(error).__name__
        return None


# Map an S3 LocationConstraint to a region name.
def _region_from_location(constraint: Any) -> str:
    if not constraint:
        return "us-east-1"
    if constraint == "EU":
        return "eu-west-1"
    return str(constraint)


# Flatten a bucket ACL into owner, grants, and any public-group grants.
def _normalize_acl(acl: dict[str, Any]) -> dict[str, Any]:
    grants = []
    public_grants = []
    for grant in acl.get("Grants", []):
        grantee = grant.get("Grantee") or {}
        record = {
            "grantee_type": grantee.get("Type"),
            "grantee_id": grantee.get("ID"),
            "grantee_uri": grantee.get("URI"),
            "display_name": grantee.get("DisplayName"),
            "permission": grant.get("Permission"),
        }
        grants.append(record)
        if grantee.get("URI") in PUBLIC_ACL_GROUPS:
            public_grants.append(record)
    return {
        "owner_id": (acl.get("Owner") or {}).get("ID"),
        "owner_display_name": (acl.get("Owner") or {}).get("DisplayName"),
        "grants": grants,
        "public_grants": public_grants,
    }


# Reduce a bucket's default encryption config to algorithm, KMS key, and bucket-key flag.
def _normalize_encryption(config: dict[str, Any]) -> dict[str, Any] | None:
    rules = (config.get("ServerSideEncryptionConfiguration") or {}).get("Rules", [])
    if not rules:
        return None
    default = rules[0].get("ApplyServerSideEncryptionByDefault") or {}
    return {
        "sse_algorithm": default.get("SSEAlgorithm"),
        "kms_key_arn": default.get("KMSMasterKeyID"),
        "bucket_key_enabled": rules[0].get("BucketKeyEnabled"),
    }


# Decode a bucket policy JSON string into a dict.
def _decode_policy(policy: dict[str, Any]) -> Any:
    document = policy.get("Policy")
    if not document:
        return None
    try:
        return json.loads(document)
    except (json.JSONDecodeError, TypeError):
        return None


# Collect every configuration field for a single bucket using a region-correct client.
def _collect_bucket(
    client: Any, name: str, arn: str, region: str, creation_date: Any
) -> dict[str, Any]:
    errors: dict[str, str] = {}

    bpa = _try(errors, "public_access_block", lambda: client.get_public_access_block(Bucket=name))
    policy = _try(errors, "policy", lambda: client.get_bucket_policy(Bucket=name))
    policy_status = _try(
        errors, "policy_status", lambda: client.get_bucket_policy_status(Bucket=name)
    )
    acl = _try(errors, "acl", lambda: client.get_bucket_acl(Bucket=name))
    ownership = _try(
        errors, "ownership_controls", lambda: client.get_bucket_ownership_controls(Bucket=name)
    )
    website = _try(errors, "website", lambda: client.get_bucket_website(Bucket=name))
    encryption = _try(errors, "encryption", lambda: client.get_bucket_encryption(Bucket=name))
    versioning = _try(errors, "versioning", lambda: client.get_bucket_versioning(Bucket=name))
    logging = _try(errors, "logging", lambda: client.get_bucket_logging(Bucket=name))
    replication = _try(errors, "replication", lambda: client.get_bucket_replication(Bucket=name))
    object_lock = _try(
        errors, "object_lock", lambda: client.get_object_lock_configuration(Bucket=name)
    )
    cors = _try(errors, "cors", lambda: client.get_bucket_cors(Bucket=name))
    tagging = _try(errors, "tags", lambda: client.get_bucket_tagging(Bucket=name))

    ownership_rules = (ownership or {}).get("OwnershipControls", {}).get("Rules", [])
    website_config = None
    if website:
        website_config = {
            "index_document": (website.get("IndexDocument") or {}).get("Suffix"),
            "error_document": (website.get("ErrorDocument") or {}).get("Key"),
            "redirect_all_requests_to": website.get("RedirectAllRequestsTo"),
        }
    logging_target = None
    if logging and logging.get("LoggingEnabled"):
        logging_target = {
            "target_bucket": logging["LoggingEnabled"].get("TargetBucket"),
            "target_prefix": logging["LoggingEnabled"].get("TargetPrefix"),
        }

    return {
        "name": name,
        "arn": arn,
        "region": region,
        "creation_date": _iso(creation_date),
        "tags": {
            tag["Key"]: tag.get("Value", "")
            for tag in (tagging or {}).get("TagSet", [])
            if "Key" in tag
        },
        "public_access_block": (bpa or {}).get("PublicAccessBlockConfiguration"),
        "policy": _decode_policy(policy) if policy else None,
        "policy_is_public": (
            (policy_status or {}).get("PolicyStatus", {}).get("IsPublic")
            if policy_status
            else None
        ),
        "acl": _normalize_acl(acl) if acl else None,
        "object_ownership": ownership_rules[0].get("ObjectOwnership") if ownership_rules else None,
        "website": website_config,
        "encryption": _normalize_encryption(encryption) if encryption else None,
        "versioning": {
            "status": (versioning or {}).get("Status"),
            "mfa_delete": (versioning or {}).get("MFADelete"),
        },
        "logging": logging_target,
        "replication": (replication or {}).get("ReplicationConfiguration"),
        "object_lock": (object_lock or {}).get("ObjectLockConfiguration"),
        "cors": (cors or {}).get("CORSRules"),
        "collection_errors": errors or None,
    }


# List access points for the account in one region, with each one's policy and public-access status.
def _collect_access_points(
    s3control: Any, account_id: str, region: str
) -> list[dict[str, Any]]:
    access_points = []
    paginator = s3control.get_paginator("list_access_points")
    for page in paginator.paginate(AccountId=account_id):
        for item in page.get("AccessPointList", []):
            name = item.get("Name")
            errors: dict[str, str] = {}
            policy_status = _try(
                errors,
                "policy_status",
                lambda: s3control.get_access_point_policy_status(
                    AccountId=account_id, Name=name
                ),
            )
            access_points.append(
                {
                    "name": name,
                    "region": region,
                    "bucket": item.get("Bucket"),
                    "network_origin": item.get("NetworkOrigin"),
                    "vpc_id": (item.get("VpcConfiguration") or {}).get("VpcId"),
                    "arn": item.get("AccessPointArn"),
                    "policy_is_public": (
                        (policy_status or {}).get("PolicyStatus", {}).get("IsPublic")
                        if policy_status
                        else None
                    ),
                    "collection_errors": errors or None,
                }
            )
    return access_points


# Collect S3 facts for buckets in the selected regions plus account-level context.
def collect(
    session: Any,
    regions: list[str],
    on_region: Callable[[str, int], None] | None = None,
) -> dict[str, Any]:
    started_at = datetime.now().astimezone()
    caller = session.client("sts").get_caller_identity()
    account_id = caller["Account"]
    partition = caller["Arn"].split(":", 2)[1]
    selected = set(regions)

    base = session.client("s3")
    listing = base.list_buckets()

    # boto3 clients are safe to *use* across threads but not safe to *create* concurrently.
    client_lock = threading.Lock()
    region_clients: dict[str, Any] = {}

    def client_for(region: str) -> Any:
        with client_lock:
            if region not in region_clients:
                region_clients[region] = session.client("s3", region_name=region)
            return region_clients[region]

    # Resolve each bucket's region in parallel, keeping only buckets in the selected regions.
    def locate(entry: dict[str, Any]) -> tuple[str, str, Any] | None:
        name = entry["Name"]
        try:
            location = base.get_bucket_location(Bucket=name).get("LocationConstraint")
        except (BotoCoreError, ClientError):
            return None
        region = _region_from_location(location)
        return (name, region, entry.get("CreationDate")) if region in selected else None

    entries = listing.get("Buckets", [])
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        located = [item for item in pool.map(locate, entries) if item]

    # Collect every bucket's configuration in parallel, isolating per-bucket failures.
    def collect_one(item: tuple[str, str, Any]) -> dict[str, Any]:
        name, region, created = item
        arn = f"arn:{partition}:s3:::{name}"
        try:
            return _collect_bucket(client_for(region), name, arn, region, created)
        except Exception as error:  # never let one bucket abort the whole scan
            return {
                "name": name,
                "arn": arn,
                "region": region,
                "collection_errors": {"bucket": type(error).__name__},
            }

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        buckets = list(pool.map(collect_one, located))
    buckets.sort(key=lambda bucket: (bucket["region"], bucket["name"]))

    if on_region is not None:
        counts = Counter(bucket["region"] for bucket in buckets)
        for region in sorted(selected):
            on_region(region, counts.get(region, 0))

    # Account-level Block Public Access (global, overrides bucket settings).
    control_region = regions[0] if regions else "us-east-1"
    s3control = session.client("s3control", region_name=control_region)
    account_errors: dict[str, str] = {}
    account_bpa = _try(
        account_errors,
        "public_access_block",
        lambda: s3control.get_public_access_block(AccountId=account_id),
    )
    access_points: list[dict[str, Any]] = []
    for region in sorted(selected):
        control = session.client("s3control", region_name=region)
        try:
            access_points.extend(_collect_access_points(control, account_id, region))
        except (BotoCoreError, ClientError):
            continue

    return {
        "scan": {
            "account_id": account_id,
            "caller_arn": caller.get("Arn"),
            "regions": sorted(selected),
            "started_at": started_at.isoformat(),
            "completed_at": datetime.now().astimezone().isoformat(),
        },
        "account": {
            "public_access_block": (account_bpa or {}).get("PublicAccessBlockConfiguration"),
            "access_points": access_points,
            "collection_errors": account_errors or None,
        },
        "buckets": buckets,
    }
