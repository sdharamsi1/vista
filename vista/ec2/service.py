"""EC2 service: collect facts across regions, merge them, and run the Bedrock review.

Implements the interface the CLI expects from every service: NAME, LABEL, collect(), count(),
and analyze().
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from vista import findings
from vista.ec2 import review
from vista.ec2.normalize import normalize
from vista.ec2.scanner import scan_region
from vista.regions import flatten, now, progress, scan_header, scan_regions

NAME = "ec2"
LABEL = "EC2"


# Scan every region in parallel and return one merged facts payload. on_region(region, count) reports progress.
def collect(
    session: Any,
    regions: list[str],
    on_region: Callable[[str, int], None] | None = None,
) -> dict[str, Any]:
    started_at = now()
    caller = session.client("sts").get_caller_identity()
    per_region = scan_regions(session, regions, scan_region, progress(on_region, count))
    return {
        "scan": {
            **scan_header(caller, regions, started_at),
            "collector_status_by_region": {
                facts["scan"]["region"]: facts["scan"].get("collector_status", {})
                for facts in per_region
            },
        },
        "instances": flatten(per_region, "instances"),
    }


# Number of resources (instances) in the payload.
def count(facts: dict[str, Any]) -> int:
    return len(facts.get("instances", []))


# Run the Bedrock review for the merged EC2 facts. Returns (markdown, usage). prepared=True means facts is an
# already-normalized payload saved by an earlier run, so it is sent as-is instead of normalized again.
def analyze(
    session: Any,
    bedrock_region: str,
    model_id: str,
    facts: dict[str, Any],
    json_path: Path | None = None,
    intent: str | None = None,
    prepared: bool = False,
) -> tuple[str, dict[str, Any]]:
    payload = facts if prepared else normalize(facts)
    return findings.run_review(
        session, bedrock_region, model_id, review, facts, payload, count(facts), json_path, intent
    )
