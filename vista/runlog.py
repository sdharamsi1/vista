"""Save a complete record of one assessment run: the payload, the raw review, and run metadata.

A run directory holds payload.json (live runs only; the exact JSON sent to the model), analysis.md
(the model's Markdown, before terminal formatting), and run.json (model, timing, tokens, hashes, and
the validation error behind any corrective retry).
Files are written private (0600) and never overwrite an earlier run.
"""
from __future__ import annotations

import hashlib
import json
from importlib import metadata
from pathlib import Path
from typing import Any

from vista import bedrock

PAYLOAD_FILE = "payload.json"
ANALYSIS_FILE = "analysis.md"
RUN_FILE = "run.json"


# Create the run directory (private) if needed; existing files in it are never overwritten.
def prepare(directory: Path) -> None:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)


# Where a live run's payload is saved inside the run directory.
def payload_path(directory: Path) -> Path:
    return directory / PAYLOAD_FILE


# Hex SHA-256 of a file's bytes.
def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# Installed Vista version, or "unknown" when running from a source tree.
def _vista_version() -> str:
    try:
        return metadata.version("vista")
    except metadata.PackageNotFoundError:
        return "unknown"


# Save the model's raw Markdown review.
def write_analysis(directory: Path, analysis: str) -> None:
    bedrock.save_json(directory / ANALYSIS_FILE, analysis + "\n")


# Save run.json describing what was reviewed, by which model, and what it cost.
def write_run(
    directory: Path,
    *,
    service: str,
    model_id: str,
    bedrock_region: str,
    facts: dict[str, Any],
    resource_count: int,
    replay: bool,
    payload_file: Path | None,
    intent: str | None,
    started_at: str,
    finished_at: str,
    review_seconds: float,
    usage: dict[str, Any] | None = None,
    error: str | None = None,
) -> None:
    tokens = {key: value for key, value in usage.items() if key != "retry_errors"} if usage else usage
    has_payload = payload_file is not None and payload_file.exists()
    record = {
        "status": "error" if error else "ok",
        "error": error,
        "vista_version": _vista_version(),
        "service": service,
        "model_id": model_id,
        "bedrock_region": bedrock_region,
        "source": "replay" if replay else "live",
        "regions": (facts.get("scan") or {}).get("regions"),
        "resource_count": resource_count,
        "payload_file": str(payload_file) if has_payload else None,
        "payload_sha256": _sha256_file(payload_file) if has_payload else None,
        "intent_sha256": hashlib.sha256(intent.encode("utf-8")).hexdigest() if intent else None,
        "started_at": started_at,
        "finished_at": finished_at,
        "review_seconds": round(review_seconds, 2),
        "tokens": tokens,
        # Why each corrective retry happened. Empty when the first answer passed validation. A run
        # that failed both attempts has no entry here; its error field holds both messages.
        "retry_errors": (usage or {}).get("retry_errors", []),
    }
    bedrock.save_json(directory / RUN_FILE, json.dumps(record, indent=2, sort_keys=True) + "\n")


# Exit before any AWS or Bedrock call when the run directory already holds an earlier run's files.
def ensure_unused(directory: Path, *, check_payload: bool = True) -> None:
    names = ([PAYLOAD_FILE] if check_payload else []) + [ANALYSIS_FILE, RUN_FILE]
    taken = [name for name in names if (directory / name).exists()]
    if taken:
        raise SystemExit(
            f"Run directory {directory} already contains {', '.join(taken)}; "
            "use a new directory for each run."
        )
