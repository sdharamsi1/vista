"""Generic Amazon Bedrock review: send facts, validate, retry once on failure.

Service-specific prompts and validation live in each service package (e.g. vista/ec2/review.py).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable

from botocore.config import Config

# A validator raises ValueError with a human-readable reason when the response is malformed.
Validator = Callable[[str], None]

# Reasoning models with large payloads can run for minutes; the default 60s read timeout is too
# short. Give a generous read timeout and avoid retrying a long, expensive call on timeout.
BEDROCK_CONFIG = Config(
    connect_timeout=10,
    read_timeout=600,
    retries={"max_attempts": 1},
)


# Write the payload to a new private (0600) file.
def save_json(path: Path, content: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(content)


# Join the text parts of a Bedrock converse response.
def response_text(response: dict[str, Any]) -> str:
    content = response.get("output", {}).get("message", {}).get("content", [])
    text = "\n".join(
        item["text"].strip()
        for item in content
        if isinstance(item, dict) and isinstance(item.get("text"), str)
    ).strip()
    if not text:
        raise ValueError("Bedrock returned no text content.")
    return text


# (inputTokens, outputTokens) from a converse response, defaulting to 0.
def _usage(response: dict[str, Any]) -> tuple[int, int]:
    usage = response.get("usage") or {}
    return usage.get("inputTokens", 0), usage.get("outputTokens", 0)


# Sum per-attempt usage into a reporting dict.
def _totals(usages: list[tuple[int, int]]) -> dict[str, int]:
    return {
        "input": sum(u[0] for u in usages),
        "output": sum(u[1] for u in usages),
        "attempts": len(usages),
    }


# Send facts to Bedrock and return a validated review. Retries once with the validation error.
def analyze(
    session: Any,
    region: str,
    model_id: str,
    facts: dict[str, Any],
    *,
    system_prompt: str,
    validate: Validator,
    is_empty: bool,
    empty_message: str,
    max_tokens: int = 15000,
    json_path: Path | None = None,
) -> tuple[str, dict[str, int]]:
    payload = json.dumps(facts, separators=(",", ":"), sort_keys=True)
    if json_path is not None:
        save_json(json_path, payload)
    if is_empty:
        return empty_message, {"input": 0, "output": 0, "attempts": 0}

    client = session.client("bedrock-runtime", region_name=region, config=BEDROCK_CONFIG)
    messages = [{"role": "user", "content": [{"text": payload}]}]
    request = {
        "modelId": model_id,
        "system": [{"text": system_prompt}],
        "inferenceConfig": {"maxTokens": max_tokens},
    }

    response = client.converse(messages=list(messages), **request)
    text = response_text(response)
    usages = [_usage(response)]
    try:
        validate(text)
    except ValueError as first_error:
        assistant_message = response.get("output", {}).get("message")
        if not isinstance(assistant_message, dict):
            raise
        correction = (
            "Your previous response failed the required structural validation: "
            f"{first_error} Return a complete corrected review that resolves every issue and "
            "follows the required format exactly. Do not return a patch or an explanation."
        )
        messages.extend(
            [assistant_message, {"role": "user", "content": [{"text": correction}]}]
        )
        corrected_response = client.converse(messages=list(messages), **request)
        corrected = response_text(corrected_response)
        usages.append(_usage(corrected_response))
        try:
            validate(corrected)
        except ValueError as second_error:
            raise ValueError(
                "Bedrock returned invalid reviews twice. "
                f"First attempt: {first_error} Corrective attempt: {second_error}"
            ) from second_error
        return corrected, _totals(usages)
    return text, _totals(usages)
