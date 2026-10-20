#!/usr/bin/env python3
"""Score saved Vista review runs against a service's ground truth.

Each scenario is scored against the highest-severity finding that cites its resource. On a severity
tie, the finding citing the fewest scenario resources wins, then the earliest (changed 2026-10-19
after the S3 benchmark; EC2 scores are unchanged by it). A scenario no finding cites is scored NONE
and NO_ACTION. Reviews are parsed with
the same helpers the validator uses, so the harness reads them exactly as Vista does.

Usage:
    python scripts/score.py ec2 runs/ec2/benchmark runs/ec2/scenario_resources.combined.json
    python scripts/score.py ec2 RUNS MAP --tier realistic --json out.json --csv out.csv
    python scripts/score.py ec2 RUNS MAP --prowler runs/ec2/prowler/prowler-output-*.ocsf.json

RUNS holds one folder per model, each with run-1, run-2, ... folders written by `--save-run`
(analysis.md and run.json). An optional RUNS/payload.json is used to confirm every identifier a
review cites exists in the evidence. MAP is the `terraform output -json scenario_resources` file
(scenario ID -> the identifier Vista cites). Ground truth defaults to
terraform/modules/<service>/ground-truth.json.

Rules, as defined in docs and the ground-truth files:
  in range     severity is in the scenario's acceptable_severities
  exact        severity equals the expected severity (NONE when the scenario expects no finding)
  action       strict: equals expected_action. tolerant: in acceptable_actions, except that an
               expected scenario accepts REMEDIATE only at LOW severity
  category     the finding's category is the expected or an acceptable alternate (cited only)
  grouped      the scoring finding cites more than one scenario resource; reported as a flag
  consistency  share of scenarios with identical severity in every run, plus mean modal agreement

Prowler (--prowler), the deterministic comparison, is scored against the same ground truth by fixed
rules decided before the S3, API Gateway, and RDS runs:
  attribution  a FAIL result belongs to a scenario when its resource is the scenario's resource or an
               object the scenario's exposure depends on. For EC2 that is the instance, its security
               groups, its subnet's network ACL, its instance profile role, and the load balancer it
               is registered with (and that load balancer's security groups), all read from the saved
               payload. Subnets, VPCs, volumes, and account-level checks are not attributed. For the
               other services only the scenario's own resource is attributed until their rules are
               written. An object shared by two scenarios counts for both.
  severity     highest Prowler severity among the scenario's FAILs, mapped one to one (critical to
               CRITICAL, and so on); informational results are ignored; no FAIL means NONE
  action       any FAIL at MEDIUM or above means REMEDIATE, otherwise NO_ACTION; Prowler has no REVIEW
  columns      "prowler" counts every attributed FAIL (primary). "prowler-filtered" ignores any check
               that FAILs for at least half of the scored scenarios (checks that fire on nearly every
               resource); it is secondary and reported next to the primary, never instead of it
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import statistics
import sys
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vista import findings  # noqa: E402

SERVICES = ("ec2", "s3", "apigateway", "rds")
SEVERITIES = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
AFFECTED_LABEL = re.compile(r"\*\*(Affected [A-Za-z ]+):\*\*")
AWS_ID = re.compile(r"\b(?:i|sg|subnet|rtb|acl|igw|nat|vol|vpc|eni|ami|snap)-[0-9a-f]{8,17}\b")
AWS_ARN = re.compile(r"arn:aws:[A-Za-z0-9:/_.\-]+")
INTENT_WORDS = re.compile(r"\b(intended|by design)\b", re.IGNORECASE)
ASKING = re.compile(
    r"\b(confirm|whether|unless|verify|otherwise)\b|if (it is |this is )?intended|not intended",
    re.IGNORECASE,
)


# Position of a severity in the ordering NONE < LOW < MEDIUM < HIGH < CRITICAL.
def rank(severity: str) -> int:
    return SEVERITIES.index(severity)


# "n/d" as a whole-number percentage, or "-" when there is nothing to divide.
def pct(numerator: int, denominator: int) -> str:
    return f"{100 * numerator / denominator:.0f}%" if denominator else "-"


# Load scenarios from a ground-truth file, optionally keeping one tier, keyed by scenario ID.
def load_ground_truth(path: Path, tier: str | None) -> dict[str, dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return {
        scenario["id"]: scenario
        for scenario in data["scenarios"]
        if tier is None or scenario.get("tier") == tier
    }


# Find each model's run folders: {model: {run number: path}}.
def discover_runs(runs_dir: Path) -> dict[str, dict[int, Path]]:
    models: dict[str, dict[int, Path]] = {}
    for model_dir in sorted(path for path in runs_dir.iterdir() if path.is_dir()):
        runs = {
            int(path.name.split("-", 1)[1]): path
            for path in model_dir.iterdir()
            if path.is_dir() and re.fullmatch(r"run-\d+", path.name)
        }
        if runs:
            models[model_dir.name] = dict(sorted(runs.items()))
    return models


# One review's findings as dicts: position, title, enum fields, and the resources it cites.
def parse_review(text: str) -> list[dict[str, Any]]:
    parsed = []
    for position, (title, block) in enumerate(findings.split_findings(text), start=1):
        label = AFFECTED_LABEL.search(block)
        affected = findings.finding_field(block, label.group(1)) if label else ""
        parsed.append(
            {
                "position": position,
                "title": title,
                "severity": findings.enum_value(block, "Severity"),
                "likelihood": findings.enum_value(block, "Likelihood"),
                "impact": findings.enum_value(block, "Impact"),
                "confidence": findings.enum_value(block, "Confidence"),
                "category": findings.enum_value(block, "Category"),
                "action": findings.enum_value(block, "Recommended action"),
                "cited": set(findings.BACKTICK_PATTERN.findall(affected or "")),
            }
        )
    return parsed


# Score one scenario against a run's findings.
def score_scenario(
    scenario: dict[str, Any],
    identifier: str,
    parsed: list[dict[str, Any]],
    scenario_resources: set[str],
) -> dict[str, Any]:
    citing = [item for item in parsed if identifier in item["cited"]]
    # Highest severity wins; on a tie, the finding citing the fewest scenario resources (the one
    # most specific to this scenario), then the earliest.
    best = max(
        citing,
        key=lambda item: (rank(item["severity"]), -len(item["cited"] & scenario_resources), -item["position"]),
        default=None,
    )
    severity = best["severity"] if best else "NONE"
    action = best["action"] if best else "NO_ACTION"
    expected = scenario["expected"]
    expected_severity = expected["severity"] if expected else "NONE"
    categories = scenario.get("acceptable_categories") or (
        [expected["category"]] if expected else []
    )
    tolerant = action in scenario["acceptable_actions"]
    if scenario["kind"] == "expected" and action == "REMEDIATE" and severity != "LOW":
        tolerant = False
    grouped = bool(best) and len(best["cited"] & scenario_resources) > 1
    return {
        "scenario": scenario["id"],
        "kind": scenario["kind"],
        "cited": best is not None,
        "findings_citing": len(citing),
        "severity": severity,
        "expected_severity": expected_severity,
        "in_range": severity in scenario["acceptable_severities"],
        "exact": severity == expected_severity,
        "action": action,
        "expected_action": scenario["expected_action"],
        "action_strict": action == scenario["expected_action"],
        "action_tolerant": tolerant,
        "category": best["category"] if best else None,
        "category_ok": best is None or not categories or best["category"] in categories,
        "likelihood": best["likelihood"] if best else None,
        "impact": best["impact"] if best else None,
        "likelihood_ok": (best["likelihood"] == expected["likelihood"]) if best and expected else None,
        "impact_ok": (best["impact"] == expected["impact"]) if best and expected else None,
        "confidence": best["confidence"] if best else None,
        "grouped": grouped,
        "grouped_inflated": grouped and rank(severity) > rank(expected_severity),
        "missed": best is None and "NONE" not in scenario["acceptable_severities"],
        "severe_miss": expected_severity in ("HIGH", "CRITICAL") and severity in ("NONE", "LOW"),
        "safe_overrated": scenario["kind"] in ("expected", "minor") and severity not in scenario["acceptable_severities"],
    }


# Sentences that call something intended or by design without asking for confirmation. This is a
# heuristic for human review, not a verdict.
def intent_candidates(text: str) -> list[str]:
    sentences = re.split(r"(?<=[.!?])\s+", text)
    return [
        " ".join(sentence.split())
        for sentence in sentences
        if INTENT_WORDS.search(sentence) and not ASKING.search(sentence)
    ]


# AWS identifiers and ARNs in the review that do not appear in the payload.
def unknown_identifiers(text: str, payload_text: str) -> list[str]:
    cited = set(AWS_ID.findall(text)) | {token.rstrip(".,;)") for token in AWS_ARN.findall(text)}
    return sorted(token for token in cited if token not in payload_text)


# Read the failed results from a Prowler OCSF JSON file: (version, total results, failures).
def load_prowler(path: Path) -> tuple[str, int, list[dict[str, str]]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    version = "unknown"
    fails = []
    for result in data:
        version = ((result.get("metadata") or {}).get("product") or {}).get("version") or version
        if result.get("status_code") != "FAIL":
            continue
        resources = result.get("resources") or [{}]
        fails.append(
            {
                "check": (result.get("metadata") or {}).get("event_code") or "",
                "severity": str(result.get("severity") or "").upper(),
                "uid": resources[0].get("uid") or "",
            }
        )
    if not fails or not all(item["check"] for item in fails):
        raise SystemExit(f"{path} does not look like Prowler OCSF output (no FAIL results with a check ID)")
    return version, len(data), fails


# The identifiers a scenario's exposure depends on, from the saved EC2 payload: the instance, its
# security groups, its network ACLs, its instance profile roles, and its load balancers with their
# security groups.
def ec2_related(payload: dict[str, Any], mapping: dict[str, str], scored_ids: list[str]) -> dict[str, set[str]]:
    instances = {item["instance_id"]: item for item in payload["instances"]}
    shared = payload["shared"]
    related: dict[str, set[str]] = {}
    for sid in scored_ids:
        identifiers = {mapping[sid]}
        instance = instances.get(mapping[sid])
        if instance:
            network = instance["network"]
            identifiers |= set(network.get("security_group_ids") or [])
            for interface in network.get("interfaces") or []:
                identifiers |= set(interface.get("security_group_ids") or [])
                if interface.get("network_acl_id"):
                    identifiers.add(interface["network_acl_id"])
            profile = shared["instance_profiles"].get((instance.get("iam") or {}).get("instance_profile_arn") or "")
            if profile:
                identifiers |= {role["arn"] for role in profile.get("roles") or []}
            for relationship in network.get("load_balancer_relationships") or []:
                arn = relationship["load_balancer_arn"]
                identifiers.add(arn)
                identifiers |= set((shared["load_balancers"].get(arn) or {}).get("security_group_ids") or [])
        related[sid] = identifiers
    return related


# True when a Prowler resource ID is the identifier itself or ends in "/<identifier>".
def resource_matches(uid: str, identifier: str) -> bool:
    return uid == identifier or uid.endswith("/" + identifier)


PROWLER_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


# Score Prowler's failures as two baseline columns, "prowler" (every attributed FAIL) and
# "prowler-filtered" (ignoring checks that fail for at least half of the scored scenarios).
def score_prowler(
    version: str,
    total_results: int,
    fails: list[dict[str, str]],
    ground_truth: dict[str, dict[str, Any]],
    mapping: dict[str, str],
    related: dict[str, set[str]],
) -> dict[str, dict[str, Any]]:
    scored_ids = [sid for sid in ground_truth if sid in mapping]
    resources = {mapping[sid] for sid in scored_ids}
    usable = [item for item in fails if item["severity"] in PROWLER_SEVERITIES]
    hits = {sid: [item for item in usable if any(resource_matches(item["uid"], ident) for ident in related[sid])] for sid in scored_ids}
    per_check = Counter(check for sid in scored_ids for check in {item["check"] for item in hits[sid]})
    universal = sorted(check for check, count in per_check.items() if 2 * count >= len(scored_ids))
    attributed = {id(item) for sid in scored_ids for item in hits[sid]}
    columns: dict[str, dict[str, Any]] = {}
    for name, ignore in (("prowler", set()), ("prowler-filtered", set(universal))):
        cells: dict[str, Any] = {}
        drivers: dict[str, list[str]] = {}
        for sid in scored_ids:
            kept = [item for item in hits[sid] if item["check"] not in ignore]
            top = max((rank(item["severity"]) for item in kept), default=0)
            severity = SEVERITIES[top]
            action = "REMEDIATE" if top >= rank("MEDIUM") else "NO_ACTION"
            parsed = (
                [{"position": 1, "severity": severity, "likelihood": None, "impact": None, "confidence": None,
                  "category": None, "action": action, "cited": {mapping[sid]}}]
                if kept
                else []
            )
            cell = score_scenario(ground_truth[sid], mapping[sid], parsed, resources)
            cell.update(category_ok=None, likelihood_ok=None, impact_ok=None)
            cells[sid] = cell
            drivers[sid] = sorted({item["check"] for item in kept if rank(item["severity"]) == top})
        columns[name] = {
            "baseline": True,
            "info": {
                "version": version,
                "results": total_results,
                "fails": len(fails),
                "attributed_fails": len(attributed),
                "unattributed_fails": len(fails) - len(attributed),
                "universal_checks": universal,
                "drivers": drivers,
            },
            "runs": {
                1: {
                    "status": "ok", "attempts": None, "seconds": None, "tokens_total": None,
                    "findings": sum(len(hits[sid]) for sid in scored_ids), "at_cap": False,
                    "noaction_above_low": 0, "intent_candidates": [], "unknown_identifiers": None,
                    "scenarios": cells,
                }
            },
        }
    return columns


# Score every run of every model.
def score_all(
    models: dict[str, dict[int, Path]],
    ground_truth: dict[str, dict[str, Any]],
    mapping: dict[str, str],
    payload_text: str | None,
    max_findings: int,
) -> dict[str, dict[str, Any]]:
    scored_ids = [sid for sid in ground_truth if sid in mapping]
    resources = {mapping[sid] for sid in scored_ids}
    results: dict[str, dict[str, Any]] = {}
    for model, runs in models.items():
        results[model] = {"runs": {}}
        for number, folder in runs.items():
            meta = json.loads((folder / "run.json").read_text(encoding="utf-8")) if (folder / "run.json").exists() else {}
            tokens = meta.get("tokens") or {}
            entry: dict[str, Any] = {
                "status": meta.get("status", "unknown"),
                "attempts": tokens.get("attempts"),
                "seconds": meta.get("review_seconds"),
                "tokens_total": sum(tokens.get(k, 0) for k in ("input", "output", "cache_read", "cache_write")) or None,
                "scenarios": {},
            }
            analysis = folder / "analysis.md"
            if entry["status"] == "ok" and analysis.exists():
                text = analysis.read_text(encoding="utf-8")
                parsed = parse_review(text)
                entry["findings"] = len(parsed)
                entry["at_cap"] = len(parsed) >= max_findings
                entry["noaction_above_low"] = sum(1 for item in parsed if item["action"] == "NO_ACTION" and item["severity"] != "LOW")
                entry["intent_candidates"] = intent_candidates(text)
                entry["unknown_identifiers"] = unknown_identifiers(text, payload_text) if payload_text else None
                for sid in scored_ids:
                    entry["scenarios"][sid] = score_scenario(ground_truth[sid], mapping[sid], parsed, resources)
            results[model]["runs"][number] = entry
    return results


# Aggregate one model's runs into the headline numbers.
def summarize(model: dict[str, Any], ground_truth: dict[str, dict[str, Any]]) -> dict[str, Any]:
    ok_runs = {n: r for n, r in model["runs"].items() if r["scenarios"]}
    cells = [cell for run in ok_runs.values() for cell in run["scenarios"].values()]
    dangerous = [c for c in cells if c["kind"] == "dangerous"]
    ambiguous = [c for c in cells if c["kind"] == "ambiguous"]
    with_expected = [c for c in cells if c["likelihood_ok"] is not None]
    inflated = Counter(c["scenario"] for c in cells if c["grouped_inflated"])
    seconds = [r["seconds"] for r in ok_runs.values() if r["seconds"] is not None]
    tokens = [r["tokens_total"] for r in ok_runs.values() if r["tokens_total"]]
    sids = sorted(next(iter(ok_runs.values()))["scenarios"]) if ok_runs else []
    per_scenario = {}
    for sid in sids:
        severities = [run["scenarios"][sid]["severity"] for run in ok_runs.values()]
        actions = [run["scenarios"][sid]["action"] for run in ok_runs.values()]
        per_scenario[sid] = {"severities": Counter(severities), "actions": Counter(actions)}
    unanimous = [sid for sid in sids if len(per_scenario[sid]["severities"]) == 1]
    modal = [max(per_scenario[sid]["severities"].values()) / len(ok_runs) for sid in sids]
    high = [sid for sid in sids if ground_truth[sid]["expected"] and ground_truth[sid]["expected"]["severity"] in ("HIGH", "CRITICAL")]
    return {
        "runs": len(model["runs"]),
        "runs_ok": len(ok_runs),
        "runs_failed": len(model["runs"]) - len(ok_runs),
        "runs_retried": sum(1 for r in model["runs"].values() if (r["attempts"] or 1) > 1),
        "runs_at_cap": sum(1 for r in ok_runs.values() if r.get("at_cap")),
        "findings": [r["findings"] for r in ok_runs.values()],
        "cells": len(cells),
        "in_range": sum(c["in_range"] for c in cells),
        "exact": sum(c["exact"] for c in cells),
        "action_strict": sum(c["action_strict"] for c in cells),
        "action_tolerant": sum(c["action_tolerant"] for c in cells),
        "baseline": bool(model.get("baseline")),
        "info": model.get("info"),
        "category_ok": sum(bool(c["category_ok"]) for c in cells),
        "likelihood_ok": sum(c["likelihood_ok"] for c in with_expected),
        "impact_ok": sum(c["impact_ok"] for c in with_expected),
        "with_expected": len(with_expected),
        "dangerous": len(dangerous),
        "dangerous_cited": sum(c["cited"] for c in dangerous),
        "severe_misses": sum(c["severe_miss"] for c in cells),
        "missed": sum(c["missed"] for c in cells),
        "safe_overrated": sum(c["safe_overrated"] for c in cells),
        "grouped": sum(c["grouped"] for c in cells),
        "grouped_inflated": dict(sorted(inflated.items())),
        "ambiguous": len(ambiguous),
        "ambiguous_review": sum(c["action"] == "REVIEW" and c["cited"] for c in ambiguous),
        "ambiguous_omitted": sum(not c["cited"] for c in ambiguous),
        "noaction_above_low": sum(r.get("noaction_above_low", 0) for r in ok_runs.values()),
        "intent_candidates": [(n, s) for n, r in ok_runs.items() for s in r.get("intent_candidates", [])],
        "unknown_identifiers": sum(len(r["unknown_identifiers"] or []) for r in ok_runs.values()),
        "identifiers_checked": all(r["unknown_identifiers"] is not None for r in ok_runs.values()) if ok_runs else False,
        "seconds": seconds,
        "tokens": tokens,
        "per_scenario": per_scenario,
        "unanimous": unanimous,
        "not_unanimous": [sid for sid in sids if sid not in unanimous],
        "modal_agreement": statistics.mean(modal) if modal else None,
        "high_unanimous": all(sid in unanimous for sid in high),
        "high_count": len(high),
    }


# Left-align rows into a plain-text table.
def table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [max(len(str(x)) for x in column) for column in zip(headers, *rows)]
    lines = ["  ".join(str(cell).ljust(width) for cell, width in zip(row, widths)).rstrip() for row in [headers, *rows]]
    return "\n".join(lines)


# A "min-max (median)" string for a list of numbers.
def spread(values: list[float], unit: str = "") -> str:
    if not values:
        return "-"
    return f"{min(values):.0f}-{max(values):.0f}{unit} (median {statistics.median(values):.0f})"


# Compact "VALUExN" distribution string, ordered by severity where possible.
def distribution(counter: Counter) -> str:
    keys = sorted(counter, key=lambda k: (rank(k) if k in SEVERITIES else 99, k))
    return " ".join(f"{key}x{counter[key]}" for key in keys)


# Print the full human-readable report.
def report(args: argparse.Namespace, ground_truth: dict, mapping: dict, results: dict, summaries: dict) -> None:
    scored = [sid for sid in ground_truth if sid in mapping]
    skipped = [sid for sid in ground_truth if sid not in mapping]
    print(f"Service: {args.service} | runs: {args.runs} | tier: {args.tier or 'all'}")
    print(f"Scored scenarios: {len(scored)}" + (f" | in ground truth but not in the map (not scored): {', '.join(skipped)}" if skipped else ""))
    print("Models: " + ", ".join(f"{m} ({s['runs_ok']}/{s['runs']} runs scored)" for m, s in summaries.items()))

    names = list(summaries)
    rows = []

    # Add a row. `na` is shown for the Prowler columns when the measure only applies to the LLM runs.
    def add(label: str, getter, na: str | None = None) -> None:
        rows.append([label, *[na if na and summaries[m]["baseline"] else getter(summaries[m]) for m in names]])

    print("\n== Headline (all scenario-runs)")
    add("scenario-runs scored", lambda s: str(s["cells"]))
    add("dangerous scenarios cited", lambda s: f"{s['dangerous_cited']}/{s['dangerous']} ({pct(s['dangerous_cited'], s['dangerous'])})")
    add("HIGH/CRITICAL rated LOW or missed", lambda s: str(s["severe_misses"]))
    add("severity in range", lambda s: f"{s['in_range']}/{s['cells']} ({pct(s['in_range'], s['cells'])})")
    add("severity exact", lambda s: f"{s['exact']}/{s['cells']} ({pct(s['exact'], s['cells'])})")
    add("action strict", lambda s: f"{s['action_strict']}/{s['cells']} ({pct(s['action_strict'], s['cells'])})")
    add("action tolerant", lambda s: f"{s['action_tolerant']}/{s['cells']} ({pct(s['action_tolerant'], s['cells'])})")
    add("category ok", lambda s: f"{s['category_ok']}/{s['cells']} ({pct(s['category_ok'], s['cells'])})", na="n/a")
    add("likelihood matches expected", lambda s: f"{s['likelihood_ok']}/{s['with_expected']} ({pct(s['likelihood_ok'], s['with_expected'])})", na="n/a")
    add("impact matches expected", lambda s: f"{s['impact_ok']}/{s['with_expected']} ({pct(s['impact_ok'], s['with_expected'])})", na="n/a")
    add("expected/minor rated above range", lambda s: str(s["safe_overrated"]))
    add("uncited where NONE not acceptable", lambda s: str(s["missed"]))
    add("scored from a grouped finding", lambda s: str(s["grouped"]))
    add("  ...and above expected severity", lambda s: str(sum(s["grouped_inflated"].values())) + (f" {s['grouped_inflated']}" if s["grouped_inflated"] else ""))
    print(table(["measure", *names], rows))

    rows = []
    print("\n== Human-review routing (ambiguous scenarios)")
    add("ambiguous scenario-runs", lambda s: str(s["ambiguous"]))
    add("routed to REVIEW", lambda s: f"{s['ambiguous_review']}/{s['ambiguous']} ({pct(s['ambiguous_review'], s['ambiguous'])})")
    add("not reported at all", lambda s: f"{s['ambiguous_omitted']}/{s['ambiguous']} ({pct(s['ambiguous_omitted'], s['ambiguous'])})")
    print(table(["measure", *names], rows))

    rows = []
    print("\n== Consistency across runs")
    det = "deterministic"
    add("scenarios, identical severity every run", lambda s: f"{len(s['unanimous'])}/{len(s['per_scenario'])} ({pct(len(s['unanimous']), len(s['per_scenario']))})", na=det)
    add("mean modal agreement", lambda s: f"{100 * s['modal_agreement']:.0f}%" if s["modal_agreement"] is not None else "-", na=det)
    add("HIGH/CRITICAL scenarios identical", lambda s: f"{'yes' if s['high_unanimous'] else 'NO'} ({s['high_count']} scenarios)", na=det)
    add("not identical", lambda s: ", ".join(s["not_unanimous"]) or "none", na=det)
    print(table(["measure", *names], rows))

    rows = []
    print("\n== Format, cost, and behavior (LLM runs only)")
    add("runs failed", lambda s: str(s["runs_failed"]), na="n/a")
    add("runs needing a corrective retry", lambda s: f"{s['runs_retried']}/{s['runs']}", na="n/a")
    add("findings per run", lambda s: spread(s["findings"]), na="n/a")
    add(f"runs at the {args.max_findings}-finding cap", lambda s: f"{s['runs_at_cap']}/{s['runs_ok']}", na="n/a")
    add("NO_ACTION above LOW", lambda s: str(s["noaction_above_low"]), na="n/a")
    add("unknown identifiers cited", lambda s: str(s["unknown_identifiers"]) if s["identifiers_checked"] else "not checked", na="n/a")
    add("intent-claim candidates (review by hand)", lambda s: str(len(s["intent_candidates"])), na="n/a")
    add("review seconds", lambda s: spread(s["seconds"], "s"), na="n/a")
    add("total tokens per run", lambda s: spread(s["tokens"]), na="n/a")
    print(table(["measure", *names], rows))

    baselines = [m for m in names if summaries[m]["baseline"]]
    if baselines:
        info = summaries[baselines[0]]["info"]
        print(f"\n== Prowler {info['version']}: {info['results']} results, {info['fails']} FAIL across the account")
        print(f"FAIL results attributed to a scenario: {info['attributed_fails']}; not attributed (other resources, "
              f"account-level, or informational): {info['unattributed_fails']}")
        print("Checks ignored by prowler-filtered (fail for at least half of the scored scenarios): "
              + (", ".join(info["universal_checks"]) or "none"))
        print("Prowler severity is per check, not per exposure. Check(s) at the top severity, per scenario (primary column):")
        for sid in scored:
            print(f"  {sid}: {', '.join(info['drivers'][sid]) or '(no FAIL)'}")

    print("\n== Per scenario: severity over runs (expected | acceptable)")
    rows = []
    for sid in scored:
        scenario = ground_truth[sid]
        expected = scenario["expected"]["severity"] if scenario["expected"] else "NONE"
        rows.append([sid, scenario["kind"], expected, "/".join(a[:4] for a in scenario["acceptable_severities"]),
                     *[distribution(summaries[m]["per_scenario"][sid]["severities"]) for m in names]])
    print(table(["scenario", "kind", "expected", "accept", *names], rows))

    print("\n== Per scenario: recommended action over runs (expected | acceptable)")
    rows = []
    for sid in scored:
        scenario = ground_truth[sid]
        rows.append([sid, scenario["expected_action"], "/".join(a[:3] for a in scenario["acceptable_actions"]),
                     *[distribution(summaries[m]["per_scenario"][sid]["actions"]) for m in names]])
    print(table(["scenario", "expected", "accept", *names], rows))

    candidates = [(m, n, s) for m in names for n, s in summaries[m]["intent_candidates"]]
    if candidates:
        print("\n== Intent-claim candidates (heuristic: 'intended'/'by design' without asking to confirm)")
        for model, number, sentence in candidates:
            print(f"  {model} run-{number}: {sentence[:220]}")


# Write one row per model, run, and scenario.
def write_csv(path: Path, results: dict) -> None:
    columns = ["model", "run", "scenario", "kind", "cited", "severity", "expected_severity", "in_range", "exact",
               "action", "expected_action", "action_strict", "action_tolerant", "category", "category_ok", "likelihood",
               "impact", "likelihood_ok", "impact_ok", "confidence", "grouped", "grouped_inflated", "findings_citing"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for model, data in results.items():
            for number, run in data["runs"].items():
                for cell in run["scenarios"].values():
                    writer.writerow({"model": model, "run": number, **cell})


# Parse arguments, score the runs, and print (and optionally save) the results.
def main() -> int:
    parser = argparse.ArgumentParser(description="Score saved Vista review runs against ground truth.")
    parser.add_argument("service", choices=SERVICES)
    parser.add_argument("runs", type=Path, help="folder with one subfolder per model, each holding run-N folders")
    parser.add_argument("map", type=Path, help="scenario ID -> resource identifier JSON (terraform output)")
    parser.add_argument("--ground-truth", type=Path, help="override terraform/modules/<service>/ground-truth.json")
    parser.add_argument("--tier", choices=("controlled", "realistic"), help="score only this tier")
    parser.add_argument("--max-findings", type=int, default=10, help="the review's finding cap (default 10)")
    parser.add_argument("--prowler", type=Path, metavar="PATH", help="Prowler OCSF JSON to score as the rule-based comparison")
    parser.add_argument("--json", type=Path, metavar="PATH", help="also write full results as JSON")
    parser.add_argument("--csv", type=Path, metavar="PATH", help="also write one CSV row per scenario-run")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    truth_path = args.ground_truth or root / "terraform" / "modules" / args.service / "ground-truth.json"
    for label, path in (("runs folder", args.runs), ("scenario map", args.map), ("ground truth", truth_path)):
        if not path.exists():
            raise SystemExit(f"{label} not found: {path}")
    ground_truth = load_ground_truth(truth_path, args.tier)
    mapping = json.loads(args.map.read_text(encoding="utf-8"))
    models = discover_runs(args.runs)
    if not models:
        raise SystemExit(f"no model folders with run-N subfolders under {args.runs}")
    if not [sid for sid in ground_truth if sid in mapping]:
        raise SystemExit("no scenario appears in both the ground truth and the map")
    payload = args.runs / "payload.json"
    payload_text = payload.read_text(encoding="utf-8") if payload.exists() else None

    results = score_all(models, ground_truth, mapping, payload_text, args.max_findings)
    if args.prowler:
        if not args.prowler.exists():
            raise SystemExit(f"Prowler output not found: {args.prowler}")
        scored_ids = [sid for sid in ground_truth if sid in mapping]
        if args.service == "ec2":
            if payload_text is None:
                raise SystemExit(f"--prowler needs {payload} to attribute security groups, ACLs, roles, and load balancers to instances")
            related = ec2_related(json.loads(payload_text), mapping, scored_ids)
        else:
            print(f"Note: only each scenario's own resource is attributed to Prowler results for {args.service}.", file=sys.stderr)
            related = {sid: {mapping[sid]} for sid in scored_ids}
        version, total, fails = load_prowler(args.prowler)
        results.update(score_prowler(version, total, fails, ground_truth, mapping, related))
    summaries = {model: summarize(data, ground_truth) for model, data in results.items()}
    report(args, ground_truth, mapping, results, summaries)
    if args.json:
        args.json.write_text(json.dumps({"service": args.service, "results": results,
                                         "summaries": {m: {k: v for k, v in s.items() if k != "per_scenario"} for m, s in summaries.items()}},
                                        indent=2, default=lambda o: dict(o) if isinstance(o, Counter) else str(o)), encoding="utf-8")
    if args.csv:
        write_csv(args.csv, results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
