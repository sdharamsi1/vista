"""Generic Amazon Bedrock review: send facts, validate, retry once on failure.

Service-specific prompts and validation live in each service package (e.g. vista/ec2/review.py).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable

# A validator raises ValueError with a human-readable reason when the response is malformed.
Validator = Callable[[str], None]


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
    max_tokens: int = 8000,
    json_path: Path | None = None,
) -> str:
    payload = json.dumps(facts, separators=(",", ":"), sort_keys=True)
    if json_path is not None:
        save_json(json_path, payload)
    if is_empty:
        return empty_message

    client = session.client("bedrock-runtime", region_name=region)
    messages = [{"role": "user", "content": [{"text": payload}]}]
    request = {
        "modelId": model_id,
        "system": [{"text": system_prompt}],
        "inferenceConfig": {"maxTokens": max_tokens},
    }

    response = client.converse(messages=list(messages), **request)
    text = response_text(response)
    try:
        validate(text)
        return text
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
        corrected = response_text(client.converse(messages=list(messages), **request))
        try:
            validate(corrected)
        except ValueError as second_error:
            raise ValueError(
                "Bedrock returned invalid reviews twice. "
                f"First attempt: {first_error} Corrective attempt: {second_error}"
            ) from second_error
        return corrected
