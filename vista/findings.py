"""Shared review contract: the Markdown format every service asks Bedrock for, and its validation.

Every review has a title, an Account Risk Summary, and a "## Top Findings" section of numbered
finding blocks with the same labeled fields. A service describes only what differs (its name,
categories, affected-resource label and format, and identifier pattern) in a ReviewSpec.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from vista import bedrock, severity

FINDING_HEADING_PATTERN = re.compile(r"^###\s+(.+)$", re.MULTILINE)

# Identifiers cited in an affected-resources field are wrapped in backticks.
BACKTICK_PATTERN = re.compile(r"`([^`\s]+)`")


@dataclass(frozen=True)
class ReviewSpec:
    service: str  # e.g. "EC2"; used in the title
    noun: str  # singular resource noun, e.g. "instance"
    categories: tuple[str, ...]
    affected_label: str  # e.g. "Affected instances"
    affected_format: str  # how to format each cited resource
    summary: str  # what the Account Risk Summary must cover
    id_pattern: re.Pattern[str] = BACKTICK_PATTERN
    max_findings: int = 10

    @property
    def title(self) -> str:
        return f"# {self.service} Security Review"

    @property
    def empty_phrase(self) -> str:
        return f"No {self.noun}s found"

    @property
    def empty_message(self) -> str:
        return f"{self.title}\n\n{self.empty_phrase} in the selected region(s)."


OUTPUT_FORMAT = """Return only the following Markdown, and nothing else:

{title}

## Account Risk Summary
{summary}

## Top Findings

### 1. Concise risk title
- **Severity:** CRITICAL, HIGH, MEDIUM, or LOW (must equal the matrix result for the Likelihood and Impact below)
- **Likelihood:** HIGH, MEDIUM, or LOW
- **Impact:** HIGH, MEDIUM, or LOW
- **Confidence:** CONFIRMED, PARTIAL, or INSUFFICIENT
- **Category:** {categories}
- **{affected_label}:** {affected_format}, comma-separated
- **Evidence:** one to three concise, fact-specific sentences.
- **Why it matters:** one or two concise sentences on the concrete impact.
- **Remediation:** one or two concise sentences with a specific fix and acceptable end state.

Number the finding headings sequentially (### 1., ### 2., ...), ordered most to least severe
(CRITICAL, then HIGH, MEDIUM, LOW), at most {max_findings} blocks.

In {affected_label}, put only identifiers inside backticks. Every identifier you cite must be one
supplied in the input; never invent one. If no {noun} presents a noteworthy risk, still return the
Account Risk Summary and the "## Top Findings" heading with no finding blocks. Do not return a
table, JSON, extra headings, or a separate block for every {noun}."""


# Full system prompt: service guidance, shared severity model, output format, counts, and intent.
def build_system_prompt(
    spec: ReviewSpec, guidance: str, counts: str, intent: str | None = None
) -> str:
    output = OUTPUT_FORMAT.format(
        title=spec.title,
        summary=spec.summary,
        categories=" or ".join(spec.categories),
        affected_label=spec.affected_label,
        affected_format=spec.affected_format,
        max_findings=spec.max_findings,
        noun=spec.noun,
    )
    prompt = (
        guidance.strip().replace("{SEVERITY_MODEL}", severity.SEVERITY_MODEL_PROMPT)
        + "\n\n"
        + output
        + f"\n\nThe input contains {counts}. Return at most {spec.max_findings} findings, grouping "
        f"{spec.noun}s that share a root cause, and cite only identifiers present in the input."
    )
    if intent:
        prompt += bedrock.build_intent_section(intent)
    return prompt


# Text of one labeled field in a finding block.
def finding_field(block: str, label: str) -> str | None:
    pattern = rf"- \*\*{re.escape(label)}:\*\*\s*(.*?)(?=\n\s*- \*\*|\Z)"
    match = re.search(pattern, block, re.DOTALL)
    return match.group(1).strip() if match else None


# Enum value following a bold label in a finding block.
def enum_value(block: str, label: str) -> str | None:
    match = re.search(rf"\*\*{re.escape(label)}:\*\*\s*`?([A-Z_]+)`?", block)
    return match.group(1) if match else None


# Split into (title, block) pairs, one per finding heading.
def split_findings(text: str) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    title: str | None = None
    body: list[str] = []
    for line in text.splitlines():
        heading = FINDING_HEADING_PATTERN.match(line.strip())
        if heading:
            if title is not None:
                findings.append((title, "\n".join(body)))
            title = heading.group(1).strip()
            body = []
        elif title is not None:
            body.append(line)
    if title is not None:
        findings.append((title, "\n".join(body)))
    return findings


# Validate sections, findings, fields, enums, severity, and cited identifiers; raise on any defect.
def validate_review(text: str, spec: ReviewSpec, valid_ids: Iterable[str]) -> None:
    valid = set(valid_ids)
    labels = (
        "Severity", "Likelihood", "Impact", "Confidence", "Category",
        spec.affected_label, "Evidence", "Why it matters", "Remediation",
    )
    allowed = {
        "Severity": severity.SEVERITIES,
        "Likelihood": severity.LIKELIHOODS,
        "Impact": severity.IMPACTS,
        "Confidence": severity.CONFIDENCE,
        "Category": set(spec.categories),
    }
    details: list[str] = []

    for section in (spec.title, "## Top Findings"):
        if text.count(section) != 1:
            details.append(f"missing or repeated section: {section}")

    findings = split_findings(text)
    if len(findings) > spec.max_findings:
        details.append(
            f"returned {len(findings)} findings, more than the {spec.max_findings} allowed"
        )

    unknown: set[str] = set()
    for position, (heading, block) in enumerate(findings, start=1):
        if not heading:
            details.append(f"finding {position} has an empty title")

        missing = [label for label in labels if block.count(f"**{label}:**") != 1]
        if missing:
            details.append(
                f"finding {position} has missing or duplicated fields: " + ", ".join(missing)
            )

        values = {label: enum_value(block, label) for label in allowed}
        for label, options in allowed.items():
            if values[label] not in options:
                details.append(
                    f"finding {position} has an invalid {label}: {values[label] or 'missing'}"
                )
        expected = severity.derive_severity(values["Likelihood"], values["Impact"])
        if expected is not None and values["Severity"] != expected:
            details.append(
                f"finding {position} Severity {values['Severity']} does not match the matrix "
                f"result {expected} for Likelihood {values['Likelihood']} x Impact {values['Impact']}"
            )

        referenced = spec.id_pattern.findall(finding_field(block, spec.affected_label) or "")
        if not referenced:
            details.append(f"finding {position} names no affected {spec.noun}")
        unknown.update(identifier for identifier in referenced if identifier not in valid)

    if unknown:
        details.append(
            f"findings cite {spec.noun}s not in the input: " + ", ".join(sorted(unknown))
        )

    if spec.empty_phrase in text:
        details.append(f"contradictory no-{spec.noun}s message")

    if details:
        raise ValueError("Bedrock returned an incomplete review (" + "; ".join(details) + ").")


# Send a service's payload to Bedrock using its review module's spec, prompt, and validator.
def run_review(
    session: Any,
    bedrock_region: str,
    model_id: str,
    review: Any,
    facts: dict[str, Any],
    payload: dict[str, Any],
    resource_count: int,
    json_path: Path | None = None,
    intent: str | None = None,
) -> tuple[str, dict[str, int]]:
    return bedrock.analyze(
        session,
        bedrock_region,
        model_id,
        payload,
        system_prompt=review.build_system_prompt(facts, intent),
        validate=lambda text: review.validate(text, facts),
        is_empty=resource_count == 0,
        empty_message=review.SPEC.empty_message,
        json_path=json_path,
    )
