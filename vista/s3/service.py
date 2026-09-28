"""S3 service: collect bucket facts, normalize, and run the Bedrock review.

Implements the interface the CLI expects from every service: NAME, LABEL, collect(), count(),
and analyze().
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from vista import bedrock
from vista.s3 import review
from vista.s3.collector import collect as _collect
from vista.s3.normalize import normalize

NAME = "s3"
LABEL = "S3"


# Collect S3 facts for the selected regions. on_region(region, count) reports progress.
def collect(
    session: Any,
    regions: list[str],
    on_region: Callable[[str, int], None] | None = None,
) -> dict[str, Any]:
    return _collect(session, regions, on_region)


# Number of resources (buckets) in the payload.
def count(facts: dict[str, Any]) -> int:
    return len(facts.get("buckets", []))


# Run the Bedrock review for the S3 facts. Returns (markdown, usage).
def analyze(
    session: Any,
    bedrock_region: str,
    model_id: str,
    facts: dict[str, Any],
    json_path: Path | None = None,
) -> tuple[str, dict[str, int]]:
    buckets = facts.get("buckets", [])
    payload = normalize(facts)
    return bedrock.analyze(
        session,
        bedrock_region,
        model_id,
        payload,
        system_prompt=review.build_system_prompt(buckets),
        validate=lambda text: review.validate(text, buckets),
        is_empty=not buckets,
        empty_message=review.EMPTY_MESSAGE,
        json_path=json_path,
    )
