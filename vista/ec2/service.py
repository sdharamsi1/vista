"""EC2 service: collect facts across regions, merge them, and run the Bedrock review.

Implements the interface the CLI expects from every service: NAME, LABEL, collect(), count(),
and review().
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from vista import bedrock
from vista.ec2 import review
from vista.ec2.scanner import scan_region

NAME = "ec2"
LABEL = "EC2"


# Combine per-region fact payloads into one account-wide payload.
def _merge(per_region: list[dict[str, Any]]) -> dict[str, Any]:
    first_scan = per_region[0]["scan"]
    started = min(facts["scan"].get("started_at", "") for facts in per_region)
    completed = max(facts["scan"].get("completed_at", "") for facts in per_region)
    instances: list[dict[str, Any]] = []
    status_by_region: dict[str, dict] = {}
    for facts in per_region:
        region = facts["scan"]["region"]
        status_by_region[region] = facts["scan"].get("collector_status", {})
        instances.extend(facts.get("instances", []))
    return {
        "scan": {
            "account_id": first_scan.get("account_id"),
            "caller_arn": first_scan.get("caller_arn"),
            "regions": sorted(status_by_region),
            "started_at": started,
            "completed_at": completed,
            "collector_status_by_region": status_by_region,
        },
        "instances": instances,
    }


# Scan every region and return one merged facts payload. on_region(region, count) reports progress.
def collect(
    session: Any,
    regions: list[str],
    on_region: Callable[[str, int], None] | None = None,
) -> dict[str, Any]:
    per_region = []
    for region in regions:
        facts = scan_region(session, region)
        if on_region is not None:
            on_region(region, len(facts.get("instances", [])))
        per_region.append(facts)
    return _merge(per_region)


# Number of resources (instances) in the payload.
def count(facts: dict[str, Any]) -> int:
    return len(facts.get("instances", []))


# Run the Bedrock review for the merged EC2 facts.
def analyze(
    session: Any,
    bedrock_region: str,
    model_id: str,
    facts: dict[str, Any],
    json_path: Path | None = None,
) -> str:
    instances = facts.get("instances", [])
    return bedrock.analyze(
        session,
        bedrock_region,
        model_id,
        facts,
        system_prompt=review.build_system_prompt(instances),
        validate=lambda text: review.validate(text, instances),
        is_empty=not instances,
        empty_message=review.EMPTY_MESSAGE,
        json_path=json_path,
    )
