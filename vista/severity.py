"""Shared severity model: severity is derived from Likelihood x Impact, with a separate Confidence."""

from __future__ import annotations

LIKELIHOODS = {"LOW", "MEDIUM", "HIGH"}
IMPACTS = {"LOW", "MEDIUM", "HIGH"}
SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
CONFIDENCE = {"CONFIRMED", "PARTIAL", "INSUFFICIENT"}

# Severity from Likelihood (outer key) x Impact (inner key).
SEVERITY_MATRIX = {
    "HIGH": {"LOW": "MEDIUM", "MEDIUM": "HIGH", "HIGH": "CRITICAL"},
    "MEDIUM": {"LOW": "LOW", "MEDIUM": "MEDIUM", "HIGH": "HIGH"},
    "LOW": {"LOW": "LOW", "MEDIUM": "LOW", "HIGH": "MEDIUM"},
}


# Severity the matrix mandates for a Likelihood/Impact pair, or None if either is invalid.
def derive_severity(likelihood: str | None, impact: str | None) -> str | None:
    return SEVERITY_MATRIX.get(likelihood or "", {}).get(impact or "")


# Shared prompt block defining the two axes, the matrix, and Confidence. Inserted where each
# service prompt has a {SEVERITY_MODEL} placeholder.
SEVERITY_MODEL_PROMPT = """Score each finding on two axes and then derive its Severity.

Likelihood — how reachable or exploitable the weakness is from the supplied configuration alone,
judged by the attack path and how many preconditions must already hold. Reason only from collected
facts; never assume CVEs, running software, patch level, or active exploitation.
- HIGH: exploitable directly from the supplied evidence with no prior access (for example a
  confirmed public network path to the resource, or an anonymous public grant that survives every
  applicable control).
- MEDIUM: exploitable only after a precondition the facts do not show is already satisfied, such as
  first compromising this instance, obtaining valid credentials, or chaining a further step.
- LOW: several preconditions must hold, or the weakness is defense-in-depth only.
When supplied approved intent credibly explains that a path or capability is expected, lower its
Likelihood and say so, but never below what the evidence supports for a dangerous exposure.

Impact — the blast radius if the weakness is exploited, from the supplied facts.
- HIGH: account-wide or cross-account access, administrative control, or read/write of data
  belonging to other workloads.
- MEDIUM: meaningful access limited to the affected resource or a bounded set of resources.
- LOW: a minor or defense-in-depth weakness with little standalone consequence.

Severity — do not choose it freely. Derive it from Likelihood and Impact with this matrix, and make
the reported Severity match the result exactly:
- Likelihood HIGH:   Impact LOW -> MEDIUM,  Impact MEDIUM -> HIGH,    Impact HIGH -> CRITICAL
- Likelihood MEDIUM: Impact LOW -> LOW,     Impact MEDIUM -> MEDIUM,  Impact HIGH -> HIGH
- Likelihood LOW:    Impact LOW -> LOW,     Impact MEDIUM -> LOW,     Impact HIGH -> MEDIUM

Confidence — how complete the supplied evidence was for this judgment, reported separately from
Severity:
- CONFIRMED: all evidence needed for the judgment was present.
- PARTIAL: some relevant evidence was present but not all.
- INSUFFICIENT: a relevant collector failed or essential evidence is missing; name what is missing.
Confidence is independent of Severity. Never lower Severity merely because business or runtime
context is absent; reflect that uncertainty in Confidence instead."""
