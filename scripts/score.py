#!/usr/bin/env python3
"""Score saved Vista runs and a Prowler scan against a service's ground truth.

Usage:
    python scripts/score.py SERVICE RUNS MAP [--prowler PATH] [--tier controlled|realistic]
                            [--ground-truth PATH] [--max-findings N] [--json PATH] [--csv PATH]

  SERVICE  ec2, s3, apigateway, or rds.
  RUNS     one folder per model, each holding run-N folders from `--save-run`, plus an optional
           RUNS/payload.json. EC2 needs payload.json to attribute Prowler results.
  MAP      `terraform output -json scenario_resources` (scenario ID -> identifier Vista cites).
  --prowler  Prowler JSON OCSF output, scanned without a mutelist.

Scoring:
  - Vista: a scenario is scored against the highest-severity finding that cites its identifier.
    On a tie, the finding citing the fewest scenario resources wins, then the earliest. No citing
    finding means not reported (NONE).
  - Prowler: a scenario's severity is the highest severity among the FAILs attributed to it.
    Informational FAILs are ignored. A FAIL is attributed through every resource whose FSBP
    control the answer key attributes to the scenario (rules in related_identifiers()).
  - Detection is reported over `flaw` scenarios, false positives over `hardened` ones, and
    `flaw_blocked` scenarios get their own report rate.
  - On `fsbp` scenarios, severity is compared with fsbp_severity on NONE < LOW < MEDIUM < HIGH <
    CRITICAL. This describes where a tool sits relative to FSBP's control-level severity; it is
    not an accuracy score.
  - Vista only: consistency across runs, retries, the finding cap, unknown identifiers, grouped
    findings, time, and tokens.

Full metric definitions, OCSF field access, and attribution rules: docs/evaluation.md.
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
CONDITIONS = ("flaw", "flaw_blocked", "hardened")
COVERAGES = ("fsbp", "outside_fsbp")
GROUPS = ("all", "fsbp", "outside_fsbp")
RATES = (("detection", "flaw"), ("flaw_blocked", "flaw_blocked"), ("false_positives", "hardened"))
AFFECTED_LABEL = re.compile(r"\*\*(Affected [A-Za-z ]+):\*\*")
AWS_ID = re.compile(r"\b(?:i|sg|subnet|rtb|acl|igw|nat|vol|vpc|eni|ami|snap)-[0-9a-f]{8,17}\b")
AWS_ARN = re.compile(r"arn:aws:[A-Za-z0-9:/_.\-]+")
PROWLER_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
PROWLER_SEVERITY_IDS = {1: "INFORMATIONAL", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "CRITICAL"}
RDS_ARN_TYPES = r":(?:db|cluster|snapshot|cluster-snapshot|db-proxy|pg|cluster-pg):"
RDS_SG_ID = re.compile(r"sg-[0-9a-f]{8,17}")
CELL_COLUMNS = ["scenario", "condition", "coverage", "reported", "severity", "fsbp_severity",
                "distance", "grouped", "findings_citing"]


# Position of a severity in the ordering NONE < LOW < MEDIUM < HIGH < CRITICAL.
def rank(severity: str) -> int:
    return SEVERITIES.index(severity)


# "n/d" as a whole-number percentage, or "-" when there is nothing to divide.
def pct(numerator: int, denominator: int) -> str:
    return f"{100 * numerator / denominator:.0f}%" if denominator else "-"


# "n/N (pct)", or "-" when N is zero.
def ratio(numerator: int, denominator: int) -> str:
    return f"{numerator}/{denominator} ({pct(numerator, denominator)})" if denominator else "-"


# Read a JSON file, exiting with a clear message when it does not parse.
def read_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise SystemExit(f"{label} {path} is not valid JSON: {error}") from None


# Exit unless every scenario has a known condition and coverage and a consistent fsbp_severity.
def validate_ground_truth(path: Path, data: Any) -> None:
    if not isinstance(data, dict) or not isinstance(data.get("scenarios"), list):
        raise SystemExit(f"ground truth {path}: expected an object with a scenarios list")
    for index, scenario in enumerate(data["scenarios"]):
        sid = scenario.get("id") or f"scenarios[{index}]"
        condition, coverage = scenario.get("condition"), scenario.get("coverage")
        fsbp_severity = scenario.get("fsbp_severity")
        if condition not in CONDITIONS:
            raise SystemExit(f"ground truth {path}: {sid} condition {condition!r} is not one of {', '.join(CONDITIONS)}")
        if coverage not in COVERAGES:
            raise SystemExit(f"ground truth {path}: {sid} coverage {coverage!r} is not one of {', '.join(COVERAGES)}")
        if coverage == "fsbp" and fsbp_severity not in SEVERITIES[1:]:
            raise SystemExit(f"ground truth {path}: {sid} is fsbp but fsbp_severity is {fsbp_severity!r} (expected LOW..CRITICAL)")
        if coverage == "outside_fsbp" and fsbp_severity is not None:
            raise SystemExit(f"ground truth {path}: {sid} is outside_fsbp but fsbp_severity is {fsbp_severity!r} (expected null)")
        if condition == "hardened" and coverage == "fsbp":
            raise SystemExit(f"ground truth {path}: {sid} is hardened but has coverage fsbp")


# Load and validate a ground-truth file, optionally keeping one tier, keyed by scenario ID.
def load_ground_truth(path: Path, tier: str | None) -> dict[str, dict[str, Any]]:
    data = read_json(path, "ground truth")
    validate_ground_truth(path, data)
    return {
        scenario["id"]: scenario
        for scenario in data["scenarios"]
        if tier is None or scenario.get("tier") == tier
    }


# Load the scenario map, exiting unless it is a JSON object of strings.
def load_map(path: Path) -> dict[str, str]:
    data = read_json(path, "scenario map")
    if not isinstance(data, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in data.items()):
        raise SystemExit(f"scenario map {path}: expected a JSON object of scenario ID -> identifier strings "
                         "(terraform output -json scenario_resources)")
    return data


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


# One review's findings as dicts: position, title, severity, and the resources it cites.
def parse_review(text: str) -> list[dict[str, Any]]:
    parsed = []
    for position, (title, block) in enumerate(findings.split_findings(text), start=1):
        label = AFFECTED_LABEL.search(block)
        affected = findings.finding_field(block, label.group(1)) if label else ""
        severity = findings.enum_value(block, "Severity")
        parsed.append(
            {
                "position": position,
                "title": title,
                "severity": severity if severity in SEVERITIES[1:] else "NONE",
                "cited": set(findings.BACKTICK_PATTERN.findall(affected or "")),
            }
        )
    return parsed


# Score one scenario against a run's findings: one cell.
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
    fsbp_severity = scenario["fsbp_severity"]
    return {
        "scenario": scenario["id"],
        "condition": scenario["condition"],
        "coverage": scenario["coverage"],
        "reported": best is not None,
        "severity": severity,
        "fsbp_severity": fsbp_severity,
        "distance": rank(severity) - rank(fsbp_severity) if fsbp_severity else None,
        "grouped": bool(best) and len(best["cited"] & scenario_resources) > 1,
        "findings_citing": len(citing),
    }


# AWS identifiers and ARNs in the review that do not appear in the payload.
def unknown_identifiers(text: str, payload_text: str) -> list[str]:
    cited = set(AWS_ID.findall(text)) | {token.rstrip(".,;)") for token in AWS_ARN.findall(text)}
    return sorted(token for token in cited if token not in payload_text)


# Score every run of every model.
def score_vista(
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
        results[model] = {"baseline": False, "runs": {}}
        for number, folder in runs.items():
            meta_path, analysis = folder / "run.json", folder / "analysis.md"
            meta = read_json(meta_path, "run.json") if meta_path.exists() else {}
            tokens = meta.get("tokens") or {}
            status = meta.get("status", "ok") if meta else "no run.json"
            scored = (status == "ok" or not meta) and analysis.exists()
            error = None
            if not scored:
                error = meta.get("error") or (f"status {status!r}" if status != "ok" else "analysis.md missing")
            entry: dict[str, Any] = {
                "status": status,
                "scored": scored,
                "error": error,
                "attempts": tokens.get("attempts"),
                "retry_errors": list(meta.get("retry_errors") or []),
                "seconds": meta.get("review_seconds"),
                "tokens_total": sum(tokens.get(k) or 0 for k in ("input", "output", "cache_read", "cache_write")) or None,
                "findings": None,
                "at_cap": False,
                "unknown_identifiers": None,
                "scenarios": {},
            }
            if scored:
                text = analysis.read_text(encoding="utf-8")
                parsed = parse_review(text)
                entry["findings"] = len(parsed)
                entry["at_cap"] = len(parsed) >= max_findings
                entry["unknown_identifiers"] = unknown_identifiers(text, payload_text) if payload_text is not None else None
                for sid in scored_ids:
                    entry["scenarios"][sid] = score_scenario(ground_truth[sid], mapping[sid], parsed, resources)
            results[model]["runs"][number] = entry
    return results


# Read a Prowler JSON OCSF file. Exits with the record index and field on any malformed FAIL.
def load_prowler(path: Path) -> dict[str, Any]:
    data = read_json(path, "Prowler output")
    if not isinstance(data, list) or not all(isinstance(record, dict) for record in data):
        raise SystemExit(f"{path}: expected a JSON array of Prowler OCSF Detection Finding objects "
                         "(prowler ... --output-formats json-ocsf)")
    if not any("status_code" in record for record in data):
        raise SystemExit(f"{path} does not look like Prowler OCSF output (no status_code)")
    versions: set[str] = set()
    schema_versions: set[str] = set()
    fails = []
    for index, record in enumerate(data):
        metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
        product = metadata.get("product") if isinstance(metadata.get("product"), dict) else {}
        if product.get("version"):
            versions.add(str(product["version"]))
        if metadata.get("version"):
            schema_versions.add(str(metadata["version"]))
        if record.get("status_code") != "FAIL":
            continue
        check = metadata.get("event_code")
        if not check:
            raise SystemExit(f"{path}: record {index} is a FAIL with no metadata.event_code (check ID)")
        severity = str(record.get("severity") or "").upper()
        if severity not in PROWLER_SEVERITIES:
            severity = PROWLER_SEVERITY_IDS.get(record.get("severity_id"))
            if severity is None:
                raise SystemExit(f"{path}: record {index} ({check}) has unknown severity {record.get('severity')!r} "
                                 f"and severity_id {record.get('severity_id')!r}")
        resources = record.get("resources") if isinstance(record.get("resources"), list) else []
        candidates = sorted({
            str(entry[key]) for entry in resources if isinstance(entry, dict)
            for key in ("uid", "name") if entry.get(key)
        })
        if not candidates:
            raise SystemExit(f"{path}: record {index} ({check}) is a FAIL with no resources[].uid or resources[].name")
        fails.append({"index": index, "check": check, "severity": severity, "candidates": candidates,
                      "muted": record.get("status") == "Suppressed"})
    if not versions:
        print(f"Warning: {path} has no metadata.product.version; Prowler version unknown.", file=sys.stderr)
    return {
        "versions": sorted(versions) or ["unknown"],
        "schema_versions": sorted(schema_versions),
        "results": len(data),
        "fails": fails,
        "muted": sum(item["muted"] for item in fails),
    }


# EC2: the instance, its root and attached EBS volumes, its security groups, its network ACLs, its
# instance-profile roles, and its load balancers with their security groups and every listener,
# plus the listener and target group of each load-balancer relationship, from the saved payload.
def ec2_related(payload: dict[str, Any], mapping: dict[str, str], scored_ids: list[str]) -> dict[str, set[str]]:
    instances = {item["instance_id"]: item for item in payload.get("instances") or []}
    shared = payload.get("shared") or {}
    load_balancers = shared.get("load_balancers") or {}
    target_groups = shared.get("target_groups") or {}
    related: dict[str, set[str]] = {}
    for sid in scored_ids:
        identifiers = {mapping[sid]}
        instance = instances.get(mapping[sid])
        if instance:
            for device in (instance.get("storage") or {}).get("block_devices") or []:
                volume_id = device.get("volume_id") or (device.get("volume") or {}).get("volume_id")
                if volume_id:
                    identifiers.add(volume_id)
            network = instance.get("network") or {}
            identifiers |= set(network.get("security_group_ids") or [])
            for interface in network.get("interfaces") or []:
                identifiers |= set(interface.get("security_group_ids") or [])
                if interface.get("network_acl_id"):
                    identifiers.add(interface["network_acl_id"])
            profile_arn = (instance.get("iam") or {}).get("instance_profile_arn") or ""
            profile = (shared.get("instance_profiles") or {}).get(profile_arn)
            if profile:
                identifiers |= {role["arn"] for role in profile.get("roles") or [] if role.get("arn")}
            for relationship in network.get("load_balancer_relationships") or []:
                if relationship.get("listener_arn"):
                    identifiers.add(relationship["listener_arn"])
                target_group_arn = relationship.get("target_group_arn")
                if target_group_arn:
                    identifiers.add(target_group_arn)
                    if (target_groups.get(target_group_arn) or {}).get("arn"):
                        identifiers.add(target_groups[target_group_arn]["arn"])
                arn = relationship.get("load_balancer_arn")
                if arn:
                    identifiers.add(arn)
                    load_balancer = load_balancers.get(arn) or {}
                    identifiers |= set(load_balancer.get("security_group_ids") or [])
                    identifiers |= {
                        listener["listener_arn"] for listener in load_balancer.get("listeners") or []
                        if listener.get("listener_arn")
                    }
        related[sid] = identifiers
    return related


# Parameter group names behind payload refs ("region/name"), falling back to the part after "/".
def parameter_group_names(refs: list[str], groups: dict[str, Any]) -> set[str]:
    return {(groups.get(ref) or {}).get("name") or ref.split("/", 1)[-1] for ref in refs if ref}


# RDS: the identifier plus, from the payload, the ARN of the instance, cluster, proxy, or snapshot it
# names, that record's security groups and parameter groups, and for a snapshot its source DB
# instance or cluster (identifier and ARN).
def rds_related(payload: dict[str, Any] | None, mapping: dict[str, str], scored_ids: list[str]) -> dict[str, set[str]]:
    payload = payload or {}
    shared = payload.get("shared") or {}
    records = {
        key: {record.get("identifier"): record for record in payload.get(key) or []}
        for key in ("db_instances", "db_clusters", "db_proxies", "snapshots")
    }
    related: dict[str, set[str]] = {}
    for sid in scored_ids:
        identifiers = {mapping[sid]}
        for key, by_identifier in records.items():
            record = by_identifier.get(mapping[sid])
            if not record:
                continue
            if record.get("arn"):
                identifiers.add(record["arn"])
            identifiers |= set(record.get("security_group_ids") or [])
            identifiers |= parameter_group_names(record.get("parameter_group_refs") or [], shared.get("parameter_groups") or {})
            identifiers |= parameter_group_names([record.get("cluster_parameter_group_ref") or ""],
                                                 shared.get("cluster_parameter_groups") or {})
            if key == "snapshots" and record.get("source"):
                identifiers.add(record["source"])
                for source_key in ("db_instances", "db_clusters"):
                    source = records[source_key].get(record["source"])
                    if source and source.get("arn"):
                        identifiers.add(source["arn"])
        related[sid] = identifiers
    return related


# Each scored scenario's related identifiers for Prowler attribution.
def related_identifiers(
    service: str, payload: dict[str, Any] | None, mapping: dict[str, str], scored_ids: list[str]
) -> dict[str, set[str]]:
    if service == "ec2":
        return ec2_related(payload or {}, mapping, scored_ids)
    if service == "rds":
        return rds_related(payload, mapping, scored_ids)
    return {sid: {mapping[sid]} for sid in scored_ids}


# True when a Prowler resource candidate names the identifier under the service's rule.
def matches(service: str, candidate: str, identifier: str) -> bool:
    if candidate == identifier:
        return True
    if service == "ec2":
        return candidate.endswith("/" + identifier)
    if service == "s3":
        return candidate.startswith("arn:") and candidate.endswith(":::" + identifier)
    if service == "apigateway":
        return re.search(r"/(?:restapis|apis)/" + re.escape(identifier) + r"(?:/|$)", candidate) is not None
    if service == "rds":
        if RDS_SG_ID.fullmatch(identifier):
            return candidate.endswith("/" + identifier)
        return re.search(RDS_ARN_TYPES + re.escape(identifier) + r"$", candidate) is not None
    return False


# Score Prowler's FAILs as one "prowler" column counting every attributed FAIL.
def score_prowler(
    service: str,
    prowler: dict[str, Any],
    ground_truth: dict[str, dict[str, Any]],
    mapping: dict[str, str],
    related: dict[str, set[str]],
) -> dict[str, dict[str, Any]]:
    scored_ids = [sid for sid in ground_truth if sid in mapping]
    resources = {mapping[sid] for sid in scored_ids}
    usable = [item for item in prowler["fails"] if item["severity"] != "INFORMATIONAL"]
    hits = {
        sid: [item for item in usable
              if any(matches(service, candidate, ident) for candidate in item["candidates"] for ident in related[sid])]
        for sid in scored_ids
    }
    attributed = {item["index"] for sid in scored_ids for item in hits[sid]}
    cells: dict[str, Any] = {}
    drivers: dict[str, list[str]] = {}
    for sid in scored_ids:
        kept = hits[sid]
        top = max((rank(item["severity"]) for item in kept), default=0)
        # Prowler's result for a scenario is one finding at its top severity citing only it.
        parsed = [{"position": 1, "severity": SEVERITIES[top], "cited": {mapping[sid]}}] if kept else []
        cell = score_scenario(ground_truth[sid], mapping[sid], parsed, resources)
        cell["findings_citing"] = len(kept)
        cells[sid] = cell
        drivers[sid] = sorted({item["check"] for item in kept if rank(item["severity"]) == top})
    return {
        "prowler": {
            "baseline": True,
            "info": {
                "versions": prowler["versions"],
                "schema_versions": prowler["schema_versions"],
                "results": prowler["results"],
                "fails": len(prowler["fails"]),
                "attributed_fails": len(attributed),
                "unattributed_fails": len(prowler["fails"]) - len(attributed),
                "muted_fails": prowler["muted"],
                "drivers": drivers,
            },
            "runs": {
                1: {
                    "status": "ok", "scored": True, "error": None, "attempts": None, "retry_errors": [],
                    "seconds": None, "tokens_total": None, "findings": None, "at_cap": False,
                    "unknown_identifiers": None, "scenarios": cells,
                }
            },
        }
    }


# n/N for one rate over cells of one condition, split by coverage group.
def rate_groups(cells: list[dict[str, Any]], condition: str) -> dict[str, dict[str, int]]:
    out = {}
    for group in GROUPS:
        pool = [c for c in cells if c["condition"] == condition and (group == "all" or c["coverage"] == group)]
        out[group] = {"n": sum(c["reported"] for c in pool), "N": len(pool)}
    return out


# Aggregate one tool's scored runs into its metrics.
def summarize(tool: dict[str, Any], scored_ids: list[str]) -> dict[str, Any]:
    runs = tool["runs"]
    ok_runs = {n: r for n, r in runs.items() if r["scored"]}
    cells = [cell for run in ok_runs.values() for cell in run["scenarios"].values()]
    fsbp_cells = [c for c in cells if c["distance"] is not None]
    distances = [c["distance"] for c in fsbp_cells]
    per_scenario = {sid: Counter(run["scenarios"][sid]["severity"] for run in ok_runs.values()) for sid in scored_ids}
    identical = [sid for sid in scored_ids if ok_runs and len(per_scenario[sid]) == 1]
    modal = [max(per_scenario[sid].values()) / len(ok_runs) for sid in scored_ids if ok_runs]
    unknown = {n: r["unknown_identifiers"] for n, r in ok_runs.items()}
    return {
        "baseline": tool["baseline"],
        "info": tool.get("info"),
        "runs": len(runs),
        "runs_scored": len(ok_runs),
        "cells": len(cells),
        **{name: rate_groups(cells, condition) for name, condition in RATES},
        "severity": {
            "N": len(fsbp_cells),
            "exact": sum(d == 0 for d in distances),
            "above": sum(d > 0 for d in distances),
            "below": sum(d < 0 for d in distances),
            "mean_distance": statistics.mean(distances) if distances else None,
        },
        "per_scenario": per_scenario,
        "identical": identical,
        "not_identical": [sid for sid in scored_ids if sid not in identical] if ok_runs else [],
        "modal_agreement": statistics.mean(modal) if modal else None,
        "runs_failed": [{"run": n, "status": r["status"], "error": (r["error"] or "")[:200]}
                        for n, r in runs.items() if not r["scored"]],
        "runs_retried": [{"run": n, "attempts": r["attempts"], "retry_errors": [str(e)[:200] for e in r["retry_errors"]]}
                         for n, r in runs.items() if (r["attempts"] or 1) > 1],
        "findings": [r["findings"] for r in ok_runs.values()],
        "runs_at_cap": sum(1 for r in ok_runs.values() if r["at_cap"]),
        "identifiers_checked": bool(ok_runs) and all(v is not None for v in unknown.values()),
        "unknown_identifiers": sum(len(v or []) for v in unknown.values()),
        "unknown_by_run": {n: v for n, v in unknown.items() if v},
        "grouped": sum(c["grouped"] for c in cells),
        "grouped_cells": [f"{sid} run-{n}" for n, r in ok_runs.items() for sid, c in r["scenarios"].items() if c["grouped"]],
        "seconds": [r["seconds"] for r in ok_runs.values() if r["seconds"] is not None],
        "tokens": [r["tokens_total"] for r in ok_runs.values() if r["tokens_total"]],
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


# Compact "VALUExN" distribution string, ordered by severity rank.
def distribution(counter: Counter) -> str:
    keys = sorted(counter, key=lambda k: (rank(k) if k in SEVERITIES else 99, k))
    return " ".join(f"{key}x{counter[key]}" for key in keys)


# Print the full human-readable report.
def report(args: argparse.Namespace, ground_truth: dict, mapping: dict, summaries: dict) -> None:
    scored = [sid for sid in ground_truth if sid in mapping]
    skipped = [sid for sid in ground_truth if sid not in mapping]
    names = list(summaries)
    print(f"Service: {args.service} | runs: {args.runs} | tier: {args.tier or 'all'}")
    print(f"Scored scenarios: {len(scored)}" + (f" | in ground truth but not in the map (not scored): {', '.join(skipped)}" if skipped else ""))
    print("Tools: " + ", ".join(
        f"{m} (Prowler scan)" if s["baseline"] else f"{m} ({s['runs_scored']}/{s['runs']} runs scored)"
        for m, s in summaries.items()))

    rows: list[list[str]] = []

    # Add a row. `na` is shown for the Prowler columns when the measure only applies to Vista runs.
    def add(label: str, getter, na: str | None = None) -> None:
        rows.append([label, *[na if na and summaries[m]["baseline"] else getter(summaries[m]) for m in names]])

    # Print the collected rows under a section heading and start a new table.
    def section(title: str) -> None:
        print(f"\n== {title}")
        print(table(["measure", *names], rows))
        rows.clear()

    add("cells scored", lambda s: str(s["cells"]))
    for name, label in (("detection", "detection (flaw)"), ("flaw_blocked", "flaw_blocked report rate"),
                        ("false_positives", "false positives (hardened)")):
        for group in GROUPS:
            add(f"{label}, {group}", lambda s, name=name, group=group: ratio(s[name][group]["n"], s[name][group]["N"]))
    section("Detection and false positives")

    add("fsbp cells", lambda s: str(s["severity"]["N"]))
    for key, label in (("exact", "same as FSBP"), ("above", "above FSBP"), ("below", "below FSBP")):
        add(label, lambda s, key=key: ratio(s["severity"][key], s["severity"]["N"]))
    add("mean signed distance", lambda s: f"{s['severity']['mean_distance']:.2f}" if s["severity"]["mean_distance"] is not None else "-")
    section("Severity relative to FSBP (fsbp scenarios; not reported = NONE)")
    print("FSBP severity is fixed per control and does not reflect deployed context; Prowler's check "
          "severities follow FSBP's. This describes where each tool sits, not accuracy.")

    det = "deterministic"
    add("scored runs", lambda s: str(s["runs_scored"]), na=det)
    add("scenarios, identical severity every run", lambda s: ratio(len(s["identical"]), len(scored)) if s["runs_scored"] else "-", na=det)
    add("mean modal agreement", lambda s: f"{s['modal_agreement']:.3f} ({100 * s['modal_agreement']:.0f}%)" if s["modal_agreement"] is not None else "-", na=det)
    add("not identical", lambda s: ", ".join(s["not_identical"]) or "none", na=det)
    section("Consistency across runs (Vista)")

    add("runs scored", lambda s: f"{s['runs_scored']}/{s['runs']}", na="n/a")
    add("findings per run", lambda s: spread(s["findings"]), na="n/a")
    add(f"runs at the {args.max_findings}-finding cap", lambda s: f"{s['runs_at_cap']}/{s['runs_scored']}", na="n/a")
    add("unknown identifiers cited", lambda s: str(s["unknown_identifiers"]) if s["identifiers_checked"] else "not checked", na="n/a")
    add("cells scored from a grouped finding", lambda s: str(s["grouped"]), na="n/a")
    add("review seconds", lambda s: spread(s["seconds"], "s"), na="n/a")
    add("total tokens per run", lambda s: spread(s["tokens"]), na="n/a")
    section("Runs, format, and cost (Vista)")
    for model in names:
        for number, identifiers in summaries[model]["unknown_by_run"].items():
            print(f"  unknown identifiers, {model} run-{number}: {', '.join(identifiers)}")
        if summaries[model]["grouped_cells"]:
            print(f"  grouped, {model}: {', '.join(summaries[model]['grouped_cells'])}")

    print("\n== Retries and failures")
    for model in names:
        s = summaries[model]
        if s["baseline"]:
            continue
        print(f"{model}: runs failed {len(s['runs_failed'])}/{s['runs']}; runs retried {len(s['runs_retried'])}/{s['runs']}")
        for item in s["runs_failed"]:
            print(f"  failed {model} run-{item['run']} (status {item['status']}): {item['error']}")
        for item in s["runs_retried"]:
            print(f"  retried {model} run-{item['run']} ({item['attempts']} attempts)")
            for error in item["retry_errors"]:
                print(f"    {model} run-{item['run']}: {error}")

    baselines = [m for m in names if summaries[m]["baseline"]]
    if baselines:
        info = summaries[baselines[0]]["info"]
        print(f"\n== Prowler {', '.join(info['versions'])}")
        if info["schema_versions"]:
            print(f"OCSF schema version: {', '.join(info['schema_versions'])}")
        print(f"Results: {info['results']}; FAIL: {info['fails']}; FAILs attributed to a scenario: {info['attributed_fails']}; "
              f"not attributed (other resources, account-level, or informational): {info['unattributed_fails']}; "
              f"muted (Suppressed, still scored): {info['muted_fails']}")
        print("Check(s) at the top severity, per scenario:")
        for sid in scored:
            print(f"  {sid}: {', '.join(info['drivers'][sid]) or '(no FAIL)'}")

    print("\n== Per scenario (severity over runs)")
    rows = [[sid, ground_truth[sid]["condition"], ground_truth[sid]["coverage"], ground_truth[sid]["fsbp_severity"] or "-",
             *[distribution(summaries[m]["per_scenario"][sid]) or "-" for m in names],
             " ".join((ground_truth[sid].get("context") or "-").split())] for sid in scored]
    print(table(["scenario", "condition", "coverage", "fsbp_severity", *names, "context"], rows))


# Write one row per tool, run, and scenario.
def write_csv(path: Path, results: dict) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["tool", "run", *CELL_COLUMNS])
        writer.writeheader()
        for tool, data in results.items():
            for number, run in data["runs"].items():
                for cell in run["scenarios"].values():
                    writer.writerow({"tool": tool, "run": number, **cell})


# Parse arguments, score Vista and Prowler, and print (and optionally save) the results.
def main() -> int:
    parser = argparse.ArgumentParser(description="Score saved Vista review runs and a Prowler scan against ground truth.")
    parser.add_argument("service", choices=SERVICES)
    parser.add_argument("runs", type=Path, help="folder with one subfolder per model, each holding run-N folders")
    parser.add_argument("map", type=Path, help="scenario ID -> resource identifier JSON (terraform output)")
    parser.add_argument("--ground-truth", type=Path, help="override terraform/modules/<service>/ground-truth.json")
    parser.add_argument("--tier", choices=("controlled", "realistic"), help="score only this tier")
    parser.add_argument("--max-findings", type=int, default=10, help="the review's finding cap (default 10)")
    parser.add_argument("--prowler", type=Path, metavar="PATH", help="Prowler JSON OCSF output to score as the rule-based comparison")
    parser.add_argument("--json", type=Path, metavar="PATH", help="also write full results as JSON")
    parser.add_argument("--csv", type=Path, metavar="PATH", help="also write one CSV row per tool, run, and scenario")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    truth_path = args.ground_truth or root / "terraform" / "modules" / args.service / "ground-truth.json"
    for label, path in (("runs folder", args.runs), ("scenario map", args.map), ("ground truth", truth_path)):
        if not path.exists():
            raise SystemExit(f"{label} not found: {path}")
    ground_truth = load_ground_truth(truth_path, args.tier)
    mapping = load_map(args.map)
    models = discover_runs(args.runs)
    if not models:
        raise SystemExit(f"no model folders with run-N subfolders under {args.runs}")
    scored_ids = [sid for sid in ground_truth if sid in mapping]
    if not scored_ids:
        raise SystemExit("no scenario appears in both the ground truth and the map")
    payload_path = args.runs / "payload.json"
    payload_text = payload_path.read_text(encoding="utf-8") if payload_path.exists() else None

    results = score_vista(models, ground_truth, mapping, payload_text, args.max_findings)
    if args.prowler:
        if not args.prowler.exists():
            raise SystemExit(f"Prowler output not found: {args.prowler}")
        payload = read_json(payload_path, "payload") if payload_text is not None else None
        if args.service == "ec2" and payload is None:
            raise SystemExit(f"--prowler needs {payload_path} to attribute security groups, network ACLs, roles, "
                             "volumes, load balancers, listeners, and target groups to instances")
        if args.service == "rds" and payload is None:
            print(f"Note: no {payload_path}; security groups, parameter groups, snapshot source instances, "
                  "and proxy ARNs (prx-...) cannot be resolved to scenarios.", file=sys.stderr)
        prowler = load_prowler(args.prowler)
        related = related_identifiers(args.service, payload, mapping, scored_ids)
        results.update(score_prowler(args.service, prowler, ground_truth, mapping, related))
    summaries = {tool: summarize(data, scored_ids) for tool, data in results.items()}
    report(args, ground_truth, mapping, summaries)
    if args.json:
        output = {
            "service": args.service,
            "tier": args.tier,
            "scored": scored_ids,
            "skipped": [sid for sid in ground_truth if sid not in mapping],
            "tools": {tool: {**results[tool], "summary": summaries[tool]} for tool in results},
        }
        args.json.write_text(json.dumps(output, indent=2, default=lambda o: dict(o) if isinstance(o, Counter) else sorted(o)) + "\n",
                             encoding="utf-8")
    if args.csv:
        write_csv(args.csv, results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
