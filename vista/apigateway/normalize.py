"""Deduplicate shared API Gateway objects out of per-API facts into a top-level `shared` map.

REST API resource policies are often the same templated document applied to many APIs, so
identical documents are collapsed into `shared.policies` (keyed by a content hash) and referenced by
`policy_ref` from each API. The review prompt tells the model how to resolve the reference.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from vista.facts import dedupe_policies


# Return a normalized copy of the facts with identical resource policies deduplicated into `shared`.
def normalize(facts: dict[str, Any]) -> dict[str, Any]:
    facts = deepcopy(facts)
    policies = dedupe_policies(facts.get("apis", []))
    return {
        "scan": facts.get("scan", {}),
        "shared": {"policies": policies} if policies else {},
        "account_settings": facts.get("account_settings", []),
        "usage_plans": facts.get("usage_plans", []),
        "vpc_links": facts.get("vpc_links", []),
        "domain_names": facts.get("domain_names", []),
        "apis": facts.get("apis", []),
    }
