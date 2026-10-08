"""Shared helpers every collector uses to turn AWS API responses into plain JSON facts."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Callable, Iterable

from botocore.exceptions import BotoCoreError, ClientError


# Convert a datetime (or other value) to an ISO 8601 string, passing through None.
def isoformat(value: Any) -> str | None:
    if value is None:
        return None
    return value.isoformat() if isinstance(value, datetime) else str(value)


# Flatten AWS key/value tag pairs into a simple {key: value} dict.
def normalize_tags(tags: list[dict[str, str]] | None) -> dict[str, str]:
    return {tag["Key"]: tag.get("Value", "") for tag in tags or [] if "Key" in tag}


# Run a getter and return its value; on failure return None, recording non-benign error codes.
def safe_call(
    errors: dict[str, str],
    field: str,
    getter: Callable[[], Any],
    benign: Iterable[str] = (),
) -> Any:
    try:
        return getter()
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "")
        if code not in benign:
            errors[field] = code
        return None
    except BotoCoreError as error:
        errors[field] = type(error).__name__
        return None


# Every item from an operation, following pagination when the operation supports it.
def paginate(client: Any, operation: str, key: str, **kwargs: Any) -> list[dict[str, Any]]:
    if not client.can_paginate(operation):
        return getattr(client, operation)(**kwargs).get(key, [])
    pages = client.get_paginator(operation).paginate(**kwargs)
    return [item for page in pages for item in page.get(key, [])]


# Stable short id for a policy document based on its canonical JSON.
def policy_key(policy: Any) -> str:
    canonical = json.dumps(policy, separators=(",", ":"), sort_keys=True)
    return "pol-" + hashlib.sha1(canonical.encode("utf-8")).hexdigest()[:12]


# Move each item's "policy" into a {policy_ref: document} map, leaving "policy_ref" on the item.
def dedupe_policies(items: list[dict[str, Any]]) -> dict[str, Any]:
    policies: dict[str, Any] = {}
    for item in items:
        policy = item.pop("policy", None)
        if policy is not None:
            key = policy_key(policy)
            policies.setdefault(key, policy)
            item["policy_ref"] = key
    return policies
