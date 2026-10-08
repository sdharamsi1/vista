"""Run a per-region scan across many regions concurrently."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable

# Regions scanned at once; each region's calls stay sequential to respect per-region API limits.
MAX_REGION_WORKERS = 8


# boto3 sessions are not safe to create clients from concurrently, so serialize client creation.
class LockedSession:
    def __init__(self, session: Any) -> None:
        self._session = session
        self._lock = threading.Lock()

    def client(self, *args: Any, **kwargs: Any) -> Any:
        with self._lock:
            return self._session.client(*args, **kwargs)


# Run scan(session, region) for every region in parallel, returning results in input order.
def scan_regions(
    session: Any,
    regions: list[str],
    scan: Callable[[Any, str], dict[str, Any]],
    on_done: Callable[[str, dict[str, Any]], None] | None = None,
) -> list[dict[str, Any]]:
    locked = LockedSession(session)
    results: dict[str, dict[str, Any]] = {}
    pool = ThreadPoolExecutor(max_workers=max(1, min(MAX_REGION_WORKERS, len(regions))))
    try:
        futures = {pool.submit(scan, locked, region): region for region in regions}
        for future in as_completed(futures):
            region = futures[future]
            results[region] = future.result()
            if on_done is not None:
                on_done(region, results[region])
    finally:
        # Drop queued regions on failure or Ctrl-C instead of waiting for them.
        pool.shutdown(wait=False, cancel_futures=True)
    return [results[region] for region in regions]


# Adapt an on_region(region, count) progress callback to scan_regions' on_done(region, facts).
def progress(
    on_region: Callable[[str, int], None] | None, count: Callable[[dict[str, Any]], int]
) -> Callable[[str, dict[str, Any]], None] | None:
    if on_region is None:
        return None
    return lambda region, facts: on_region(region, count(facts))


# Concatenate one list section across every region's results.
def flatten(per_region: list[dict[str, Any]], section: str) -> list[Any]:
    return [item for facts in per_region for item in facts[section]]


# Current UTC time as an ISO 8601 string.
def now() -> str:
    return datetime.now(timezone.utc).isoformat()


# The "scan" header every service payload starts with; errors_by_region maps region -> errors.
def scan_header(
    caller: dict[str, Any],
    regions: list[str],
    started_at: str,
    errors_by_region: dict[str, Any] | None = None,
) -> dict[str, Any]:
    errors = {region: errors for region, errors in (errors_by_region or {}).items() if errors}
    return {
        "account_id": caller.get("Account"),
        "caller_arn": caller.get("Arn"),
        "regions": sorted(regions),
        "started_at": started_at,
        "completed_at": now(),
        "collection_errors_by_region": errors or None,
    }
