"""RDS service: collect facts across regions, merge them, and run the Bedrock review.

Implements the interface the CLI expects from every service: NAME, LABEL, collect(), count(),
and analyze().
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from vista import findings
from vista.rds import review
from vista.rds.collector import scan_region
from vista.regions import flatten, now, progress, scan_header, scan_regions

NAME = "rds"
LABEL = "RDS"

RESOURCE_KINDS = ("db_instances", "db_clusters", "db_proxies", "snapshots")


# Merge each region's shared maps; keys are IDs or region-qualified names, so they never collide.
def _merge_shared(per_region: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    shared: dict[str, dict[str, Any]] = {}
    for facts in per_region:
        for kind, table in facts["shared"].items():
            shared.setdefault(kind, {}).update(table)
    return {kind: table for kind, table in shared.items() if table}


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
        "shared": _merge_shared(per_region),
        "db_instances": flatten(per_region, "db_instances"),
        "db_clusters": flatten(per_region, "db_clusters"),
        "db_proxies": flatten(per_region, "db_proxies"),
        "snapshots": flatten(per_region, "snapshots"),
    }


# Number of resources (instances, clusters, proxies, and manual snapshots) in the payload.
def count(facts: dict[str, Any]) -> int:
    return sum(len(facts.get(kind, [])) for kind in RESOURCE_KINDS)


# Run the Bedrock review for the merged RDS facts. Returns (markdown, usage).
def analyze(
    session: Any,
    bedrock_region: str,
    model_id: str,
    facts: dict[str, Any],
    json_path: Path | None = None,
    intent: str | None = None,
) -> tuple[str, dict[str, int]]:
    return findings.run_review(
        session, bedrock_region, model_id, review, facts, facts, count(facts), json_path, intent
    )
