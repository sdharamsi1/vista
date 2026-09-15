"""Send factual EC2 configuration to Amazon Bedrock."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

ASSESSMENTS = {
    "NO_IMMEDIATE_ACTION",
    "INVESTIGATE",
    "HIGH_PRIORITY",
    "INSUFFICIENT_DATA",
}
EXPOSURES = {"NONE", "DIRECT", "LOAD_BALANCER", "BOTH", "UNKNOWN"}

SYSTEM_PROMPT = """Review the supplied factual AWS EC2 configuration. The JSON contains real
resource identities and exact AWS API values. Make all security judgments yourself; no local
security conclusions are included.

Determine current Internet exposure first:
- DIRECT requires a running instance, a public IPv4 or globally routable IPv6 address, a
  matching inbound instance-security-group rule from a globally routable source, and an active
  instance-subnet route to an Internet gateway. Every element is required.
- Egress rules, permissive NACLs, NAT gateways, transit gateways, names, and tags do not create
  DIRECT inbound exposure.
- LOAD_BALANCER requires a running instance and a registered path through an active LB whose
  scheme is exactly internet-facing, with an applicable listener/rule, matching public frontend
  access, and Internet-gateway-routed LB subnets. An internal LB can never create Internet
  exposure. Internal listeners and backend ports are not public ports.
- Deduplicate repeated relationships that identify the same LB, listener/rule, target group,
  target ID, and target port.
- Report unhealthy or draining targets factually. Do not call them vulnerable, and do not erase
  a configured public relationship solely because delivery is unhealthy or draining.
- Use UNKNOWN only when a relevant collector failed or required path evidence is ambiguous.
  Missing owner intent, WAF, runtime service, host firewall, application auth, or vulnerability
  data does not turn a clearly absent path into UNKNOWN.

Choose Assessment only after evaluating both Internet exposure and all supplied security
context, including IAM, IMDS, storage, lifecycle state, tags, and load-balancer target health.
Internet exposure NONE does not by itself justify NO_IMMEDIATE_ACTION:
- NO_IMMEDIATE_ACTION: no current Internet path and no meaningful supplied fact requiring prompt
  investigation. Minor or accepted-looking hardening facts do not need to be listed.
- INVESTIGATE: a public path exists but approved intent is not supplied; or a meaningful supplied
  concern exists such as unhealthy public target registration, unencrypted storage, IMDSv1,
  broad secrets/IAM access, SSM remote command, wildcard IAM mutation, powerful cross-account
  role assumption, dormant public admin rules, or a bootstrap/prototype resource still running.
- HIGH_PRIORITY: reserve for strong supplied evidence of likely dangerous exposure, such as a
  complete broad DIRECT path to SSH/RDP/admin/database ports, or a similarly severe combination.
  Ordinary public web ports, narrow public /32 sources, or an OIDC-protected ALB are not
  automatically HIGH_PRIORITY.
- INSUFFICIENT_DATA: a relevant collector failed or essential evidence needed for a responsible
  assessment is missing. Do not use it merely because uncollected runtime or business context is
  absent.
- Any DIRECT, LOAD_BALANCER, or BOTH result without explicit approved owner intent must be at
  least INVESTIGATE. Never recommend no action for a public path.
- If Security concerns identifies unencrypted storage, broad or wildcard access, remote command,
  secret write, powerful cross-account access, unhealthy public targets, or dormant public admin
  rules, use at least INVESTIGATE and provide a specific next step.
- Before returning each block, verify that Assessment, Why this assessment, Security concerns, and
  Recommended investigation express one consistent decision. NO_IMMEDIATE_ACTION requires the
  exact recommendation "None based on supplied facts." Any specific next step requires an
  assessment other than NO_IMMEDIATE_ACTION.
- Standard AmazonSSMManagedInstanceCore permissions alone are normal management context and do
  not require investigation. Cite SSM as a concern only when supplied permissions enable remote
  command or materially broader actions.

IAM, IMDS, storage, tags, and non-path configuration can supply either protective controls or
security concerns and can affect Assessment, but they must never create an Internet path. Empty LB
authentication actions mean only that no ELB-layer action was supplied; do not claim the application
has no authentication. Do not claim WAF, vulnerabilities, data sensitivity, exploitability,
compromise, or approved intent unless supplied.

Make every narrative field evidence-specific while remaining concise:
- Do not use vague labels such as "broad", "consequential", "wildcard", "protected", or "restricted"
  by themselves. Immediately support them with the most relevant exact supplied action, resource ID,
  ARN/resource pattern, CIDR or source group, condition, listener/auth action, target state, volume ID,
  or lifecycle state. Describe restrictive IAM conditions accurately; do not present condition-limited
  access as unrestricted.
- Why this assessment: in one or two concise sentences, synthesize the current path result and the
  decisive reason for the Assessment. For exposure, identify the decisive supplied components such as
  public address, security-group source/port, Internet-gateway route, LB scheme, public listener port,
  source restriction, authentication action, and target health. Distinguish a public listener port
  from a backend target port. For NONE with INVESTIGATE, name the exact leading non-network concern
  rather than saying only that permissions require review.
- Protective controls: list only supplied facts that reduce exposure, privilege, or likely impact,
  such as private-only addressing, internal load balancing, narrow source ranges, an applicable OIDC
  action, IMDSv2 enforcement, encryption, or tightly scoped IAM resources/conditions. These controls
  do not erase a separately reported concern. Use "None identified in supplied facts." when none are
  present; never invent or assume a control.
- Security concerns: list only supplied facts that create or increase exposure, privilege, likely
  impact, operational uncertainty, or cleanup need. Name the strongest one or two exact concerns and
  why they matter. Do not place positive controls in this field. Use "None identified in supplied
  facts." when no meaningful concern is present.
- Recommended investigation: in one or two concise sentences, address the Security concerns by naming
  the exact resource, permission, path, or control to inspect; state what decision or evidence to
  confirm; and give a concrete next step. Do not use "review", "verify", "validate", or "ensure"
  without saying specifically what to inspect and what acceptable scope or outcome to establish.
  Recommend confirmation before destructive changes when approved intent or operational need is not
  supplied.
- Instances with identical supplied configurations may correctly receive repeated evidence and next
  steps. Do not invent differences merely to make their wording unique.

Return only this indented Markdown format, with exactly one block per supplied instance:

# EC2 Security Review

- **supplied Name or Unnamed** (`supplied-instance-id`)
  - **Assessment:** NO_IMMEDIATE_ACTION, INVESTIGATE, HIGH_PRIORITY, or INSUFFICIENT_DATA
  - **Internet exposure:** NONE, DIRECT, LOAD_BALANCER, BOTH, or UNKNOWN
  - **Why this assessment:** One or two concise, evidence-specific sentences with path state and decisive reason.
  - **Protective controls:** One or two concise sentences containing only supplied mitigating controls, or "None identified in supplied facts."
  - **Security concerns:** One or two concise sentences containing only supplied review-worthy concerns, or "None identified in supplied facts."
  - **Recommended investigation:** One or two concrete next-step sentences addressing the concerns, or "None based on supplied facts."

Preserve input order. Copy each non-null Name exactly; use Unnamed only when the Name value is
null. Format each identity exactly as `- **Name** (`instance-id`)`. Use every supplied identity
once. Do not return a table, counts, repeated evidence lists, fallback messages, extra headings,
or JSON. Never say no instances were supplied when the JSON has any.
"""


# Write the payload to a new private (0600) file, failing if it already exists.
def save_json(path: Path, content: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(content)


# Extract all enum values that follow a given bold label in the response text.
def enum_values(text: str, label: str) -> list[str]:
    pattern = rf"\*\*{re.escape(label)}:\*\*\s*`?([A-Z_]+)`?"
    return re.findall(pattern, text)


# Structurally validate the Bedrock response (identities, order, fields, enums), raising on any defect.
def validate_response(text: str, instances: list[dict[str, Any]]) -> None:
    markers = [
        f"- **{instance.get('name') or 'Unnamed'}** (`{instance['instance_id']}`)"
        for instance in instances
    ]
    invalid_ids = [
        instance["instance_id"]
        for instance, marker in zip(instances, markers)
        if text.count(marker) != 1
    ]
    positions = [text.find(marker) for marker in markers]
    invalid_order = not invalid_ids and positions != sorted(positions)

    required_labels = (
        "**Assessment:**",
        "**Internet exposure:**",
        "**Why this assessment:**",
        "**Protective controls:**",
        "**Security concerns:**",
        "**Recommended investigation:**",
    )
    incorrect_field_counts = [
        label for label in required_labels if text.count(label) != len(instances)
    ]
    assessments = enum_values(text, "Assessment")
    exposures = enum_values(text, "Internet exposure")
    invalid_assessments = sorted(set(assessments) - ASSESSMENTS)
    invalid_exposures = sorted(set(exposures) - EXPOSURES)

    invalid_block_ids = []
    if not invalid_ids and not invalid_order:
        for index, instance in enumerate(instances):
            end = positions[index + 1] if index + 1 < len(positions) else len(text)
            block = text[positions[index] : end]
            fields_valid = all(block.count(label) == 1 for label in required_labels)
            enums_valid = (
                len(enum_values(block, "Assessment")) == 1
                and len(enum_values(block, "Internet exposure")) == 1
            )
            if not fields_valid or not enums_valid:
                invalid_block_ids.append(instance["instance_id"])

    details = []
    if invalid_ids:
        details.append("identities or Names missing, repeated, or malformed: " + ", ".join(invalid_ids))
    if invalid_order:
        details.append("instances are not in input order")
    if incorrect_field_counts:
        details.append("incorrect field counts: " + ", ".join(incorrect_field_counts))
    if invalid_block_ids:
        details.append("missing, duplicated, or malformed fields in blocks: " + ", ".join(invalid_block_ids))
    if len(assessments) != len(instances) or invalid_assessments:
        details.append(
            "invalid Assessment values: "
            + (", ".join(invalid_assessments) or "count mismatch")
        )
    if len(exposures) != len(instances) or invalid_exposures:
        details.append(
            "invalid Internet exposure values: "
            + (", ".join(invalid_exposures) or "count mismatch")
        )
    if "No non-terminated instances found" in text:
        details.append("contradictory no-instances message")
    if details:
        raise ValueError("Bedrock returned an incomplete review (" + "; ".join(details) + ").")


# Serialize the facts, send them to Bedrock, validate the review, and retry once on structural failure.
def analyze_with_bedrock(
    session: Any,
    region: str,
    model_id: str,
    facts: dict[str, Any],
    json_path: Path | None = None,
) -> str:
    payload = json.dumps(facts, separators=(",", ":"), sort_keys=True)
    if json_path is not None:
        save_json(json_path, payload)

    instances = facts.get("instances", [])
    if not instances:
        return "# EC2 Security Review\n\nNo non-terminated instances found."

    count = len(instances)
    system_prompt = (
        SYSTEM_PROMPT
        + f"\nThis request contains exactly {count} instances; return exactly {count} blocks."
    )
    client = session.client("bedrock-runtime", region_name=region)
    messages = [{"role": "user", "content": [{"text": payload}]}]
    request = {
        "modelId": model_id,
        "system": [{"text": system_prompt}],
        "inferenceConfig": {"maxTokens": 4000},
    }

    # Concatenate the text segments of a Bedrock response, erroring if none are present.
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

    response = client.converse(messages=list(messages), **request)
    text = response_text(response)
    try:
        validate_response(text, instances)
    except ValueError as first_error:
        assistant_message = response.get("output", {}).get("message")
        if not isinstance(assistant_message, dict):
            raise
        correction = (
            "Your previous response failed the required structural validation: "
            f"{first_error} Return a complete corrected review for all {count} instances, "
            "not a patch or an explanation. Preserve every exact Name and instance ID, input "
            "order, and supplied fact. Resolve every reported structural defect and follow the "
            "required six-field format and enums."
        )
        messages.extend(
            [
                assistant_message,
                {"role": "user", "content": [{"text": correction}]},
            ]
        )
        corrected_response = client.converse(messages=list(messages), **request)
        corrected_text = response_text(corrected_response)
        try:
            validate_response(corrected_text, instances)
        except ValueError as second_error:
            raise ValueError(
                "Bedrock returned invalid reviews twice. "
                f"First attempt: {first_error} Corrective attempt: {second_error}"
            ) from second_error
        return corrected_text
    return text
