"""API Gateway service: collect facts across regions, merge them, and run the Bedrock review.

Implements the interface the CLI expects from every service: NAME, LABEL, collect(), count(),
and analyze().
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from vista import findings
from vista.apigateway import review
from vista.apigateway.collector import scan_region
from vista.apigateway.normalize import normalize
from vista.regions import flatten, now, progress, scan_header, scan_regions

NAME = "apigateway"
LABEL = "API Gateway"


# Scan every region in parallel and return one merged facts payload. on_region(region, count) reports progress.
def collect(
    session: Any,
    regions: list[str],
    on_region: Callable[[str, int], None] | None = None,
) -> dict[str, Any]:
    started_at = now()
    caller = session.client("sts").get_caller_identity()
    per_region = scan_regions(session, regions, scan_region, progress(on_region, count))
    errors = {facts["region"]: facts["collection_errors"] for facts in per_region}
    return {
        "scan": scan_header(caller, regions, started_at, errors),
        "account_settings": [
            facts["account_settings"] for facts in per_region if facts["account_settings"]
        ],
        "usage_plans": flatten(per_region, "usage_plans"),
        "vpc_links": flatten(per_region, "vpc_links"),
        "domain_names": flatten(per_region, "domain_names"),
        "apis": flatten(per_region, "apis"),
    }


# Number of resources (APIs) in the payload.
def count(facts: dict[str, Any]) -> int:
    return len(facts.get("apis", []))


# Run the Bedrock review for the merged API Gateway facts. Returns (markdown, usage).
def analyze(
    session: Any,
    bedrock_region: str,
    model_id: str,
    facts: dict[str, Any],
    json_path: Path | None = None,
    intent: str | None = None,
) -> tuple[str, dict[str, int]]:
    return findings.run_review(
        session, bedrock_region, model_id, review, facts, normalize(facts), count(facts),
        json_path, intent,
    )
