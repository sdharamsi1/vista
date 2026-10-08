"""Deduplicate shared S3 objects out of per-bucket facts into a top-level `shared` map.

S3 policies are often the same templated document applied to many buckets, so identical policy
documents are collapsed into `shared.policies` (keyed by a content hash) and referenced by
`policy_ref` from each bucket. The review prompt tells the model how to resolve the reference.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from vista.facts import dedupe_policies


# Return a normalized copy of the facts with identical bucket policies deduplicated into `shared`.
def normalize(facts: dict[str, Any]) -> dict[str, Any]:
    facts = deepcopy(facts)
    policies = dedupe_policies(facts.get("buckets", []))
    return {
        "scan": facts.get("scan", {}),
        "shared": {"policies": policies} if policies else {},
        "account": facts.get("account", {}),
        "buckets": facts.get("buckets", []),
    }
