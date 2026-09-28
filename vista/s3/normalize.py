"""Deduplicate shared S3 objects out of per-bucket facts into a top-level `shared` map.

S3 policies are often the same templated document applied to many buckets, so identical policy
documents are collapsed into `shared.policies` (keyed by a content hash) and referenced by
`policy_ref` from each bucket. The review prompt tells the model how to resolve the reference.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import Any


# Stable short id for a policy document based on its canonical JSON.
def _policy_key(policy: Any) -> str:
    canonical = json.dumps(policy, separators=(",", ":"), sort_keys=True)
    return "pol-" + hashlib.sha1(canonical.encode("utf-8")).hexdigest()[:12]


# Return a normalized copy of the facts with identical bucket policies deduplicated into `shared`.
def normalize(facts: dict[str, Any]) -> dict[str, Any]:
    facts = deepcopy(facts)
    policies: dict[str, Any] = {}

    for bucket in facts.get("buckets", []):
        policy = bucket.pop("policy", None)
        if policy is not None:
            key = _policy_key(policy)
            policies.setdefault(key, policy)
            bucket["policy_ref"] = key

    shared = {"policies": policies} if policies else {}
    return {
        "scan": facts.get("scan", {}),
        "shared": shared,
        "account": facts.get("account", {}),
        "buckets": facts.get("buckets", []),
    }
