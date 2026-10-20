#!/usr/bin/env python3
"""Vista CLI: assess an AWS service and print an Amazon Bedrock security review.

Usage:
    vista assess ec2 --all-regions --model us.anthropic.claude-opus-5
    vista assess s3  --regions us-east-1 us-west-2 --model us.openai.gpt-5.6-sol
    vista assess apigateway --all-regions --model us.anthropic.claude-opus-5
    vista assess rds --regions us-east-1 --model us.anthropic.claude-opus-5

    # Record a run, then review the same saved evidence again (also with another model):
    vista assess ec2 --regions us-east-1 --model MODEL --save-run runs/ec2/opus/1
    vista assess ec2 --from-json runs/ec2/opus/1/payload.json --model MODEL --save-run runs/ec2/opus/2

Credentials come from the standard AWS chain (environment variables, AWS_PROFILE,
SSO, or an instance role). Pass --profile to use a named profile. Vista assumes
you are already authenticated and never prompts for credentials.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    ConnectTimeoutError,
    NoCredentialsError,
    NoRegionError,
    PartialCredentialsError,
    ProfileNotFound,
    ReadTimeoutError,
)

from vista import runlog, ui
from vista.apigateway import service as apigateway_service
from vista.ec2 import service as ec2_service
from vista.rds import service as rds_service
from vista.regions import now
from vista.render import Spinner, render_review
from vista.s3 import service as s3_service

# Service registry: name -> service module. Add new services here.
SERVICES = {
    service.NAME: service
    for service in (ec2_service, s3_service, apigateway_service, rds_service)
}

# Region for the initial STS/DescribeRegions calls when a scope isn't pinned.
DEFAULT_BOOTSTRAP_REGION = "us-east-1"

# Regions never enumerated.
SKIP_REGIONS = {"me-south-1", "me-central-1"}

# Largest accepted intent file, to bound token cost.
MAX_INTENT_BYTES = 16 * 1024


# Build the top-level argument parser and its subcommands.
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vista",
        description=(
            "AI-powered AWS attack surface analysis. Collect a service's factual "
            "configuration and ask Amazon Bedrock to review it for security risks."
        ),
        epilog=(
            "examples:\n"
            "  vista assess ec2 --all-regions --model us.anthropic.claude-opus-5\n"
            "  vista assess s3 --regions us-east-1 us-west-2 --model us.openai.gpt-5.6-sol\n"
            "  vista assess apigateway --all-regions --model us.anthropic.claude-opus-5\n"
            "  vista assess rds --regions us-east-1 --model us.anthropic.claude-opus-5\n"
            "\n"
            "Credentials come from the standard AWS chain; pass --profile for a named\n"
            "profile. You must already be authenticated."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    assess = subparsers.add_parser(
        "assess",
        help="scan a service and print a Bedrock security review",
        description=(
            "Scan an AWS service across one or more regions and print an "
            "account-level Bedrock security review."
        ),
        epilog=(
            "examples:\n"
            "  vista assess ec2 --all-regions --model us.anthropic.claude-opus-5\n"
            "  vista assess s3 --regions us-east-1 --model us.openai.gpt-5.6-sol"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    assess.add_argument(
        "service",
        choices=list(SERVICES),
        help="AWS service to evaluate",
    )
    scope = assess.add_mutually_exclusive_group()
    scope.add_argument(
        "--regions",
        nargs="+",
        metavar="REGION",
        help="one or more AWS regions to scan (e.g. --regions us-east-1 us-west-2)",
    )
    scope.add_argument(
        "--all-regions",
        action="store_true",
        help="scan every region enabled for the account",
    )
    scope.add_argument(
        "--from-json",
        type=Path,
        metavar="PATH",
        help=(
            "skip AWS collection and review a payload saved earlier by --save-json or "
            "--save-run, so the same evidence can be sent to a model again"
        ),
    )
    assess.add_argument(
        "--model",
        default=os.getenv("BEDROCK_MODEL_ID"),
        metavar="MODEL_ID",
        help="Bedrock model or inference-profile ID (or set BEDROCK_MODEL_ID)",
    )
    assess.add_argument(
        "--profile",
        metavar="NAME",
        help="named AWS profile to use (defaults to the standard credential chain)",
    )
    assess.add_argument(
        "--intent",
        type=Path,
        metavar="PATH",
        help="text file describing the account's purpose; sent to Bedrock as extra context",
    )
    assess.add_argument(
        "--save-json",
        type=Path,
        metavar="PATH",
        help="write the exact factual JSON sent to Bedrock to a private (0600) file",
    )
    assess.add_argument(
        "--save-run",
        type=Path,
        metavar="DIR",
        help=(
            "save this run to DIR: payload.json (live runs), analysis.md (the model's raw "
            "Markdown), and run.json (model, timing, tokens, hashes); existing runs are never "
            "overwritten"
        ),
    )
    assess.add_argument(
        "--plain",
        action="store_true",
        help="print the model's raw Markdown without terminal formatting",
    )
    return parser


# Check flag combinations argparse can't express; exits through parser.error on a bad combination.
def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if not (args.regions or args.all_regions or args.from_json):
        parser.error("one of the arguments --regions --all-regions --from-json is required")
    if args.from_json and args.save_json:
        parser.error("--save-json cannot be used with --from-json; the payload already exists")
    if args.save_run and args.save_json and not args.from_json:
        parser.error("use either --save-json or --save-run; --save-run already saves the payload")


# Read a payload saved by --save-json or --save-run; exits with a clear message when unusable.
def load_payload(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except (FileNotFoundError, IsADirectoryError, PermissionError, UnicodeDecodeError, OSError) as error:
        raise SystemExit(f"Could not read payload {path}: {error}")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as error:
        raise SystemExit(f"Payload {path} is not valid JSON: {error}")
    if not isinstance(payload, dict):
        raise SystemExit(f"Payload {path} must be a JSON object saved by Vista.")
    return payload


# Region used for the bootstrap STS/DescribeRegions calls.
def bootstrap_region(args: argparse.Namespace) -> str:
    if args.regions:
        return args.regions[0]
    return (
        os.getenv("AWS_REGION")
        or os.getenv("AWS_DEFAULT_REGION")
        or DEFAULT_BOOTSTRAP_REGION
    )


# Read and validate the optional intent file; returns its text or None when no path is given.
def load_intent(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        raw = path.read_bytes()
    except (FileNotFoundError, IsADirectoryError, PermissionError, OSError) as error:
        raise SystemExit(f"Could not read intent file {path}: {error}")
    if len(raw) > MAX_INTENT_BYTES:
        raise SystemExit(
            f"Intent file {path} is {len(raw)} bytes; the limit is {MAX_INTENT_BYTES}."
        )
    try:
        intent = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise SystemExit(f"Intent file {path} is not valid UTF-8 text.")
    if not intent:
        raise SystemExit(f"Intent file {path} is empty.")
    return intent


# Enabled regions minus SKIP_REGIONS.
def list_enabled_regions(session: boto3.Session, region: str) -> list[str]:
    response = session.client("ec2", region_name=region).describe_regions()
    return sorted(
        item["RegionName"]
        for item in response.get("Regions", [])
        if item["RegionName"] not in SKIP_REGIONS
    )


# Format the review for the terminal, falling back to plain Markdown.
def format_analysis(analysis: str, plain: bool) -> str:
    if plain or not sys.stdout.isatty():
        return analysis
    use_color = "NO_COLOR" not in os.environ and os.getenv("TERM") != "dumb"
    try:
        return render_review(analysis, use_color=use_color)
    except Exception as error:
        print(
            f"Terminal formatting failed; printing plain Markdown: {error}",
            file=sys.stderr,
        )
        return analysis


# Send facts to Bedrock, print the review, and optionally record the run. replay_path is set when the
# facts are an already-normalized payload loaded from a file, which is then sent without collecting.
def review_facts(
    service: Any,
    session: boto3.Session,
    facts: dict[str, Any],
    model_id: str,
    bedrock_region: str,
    save_json: Path | None,
    plain: bool,
    intent: str | None = None,
    *,
    save_run: Path | None = None,
    replay_path: Path | None = None,
) -> int:
    total = service.count(facts)
    if total == 0:
        if replay_path is not None:
            print(
                f"{replay_path} contains no {service.LABEL} resources; "
                "was it saved from a different service?",
                file=sys.stderr,
            )
            return 1
        print(f"No {service.LABEL} resources found in the selected region(s).")
        return 0

    replay = replay_path is not None
    payload_file = replay_path
    if save_run is not None:
        runlog.prepare(save_run)
        if not replay:
            save_json = payload_file = runlog.payload_path(save_run)

    started_at = now()
    began = time.monotonic()

    def record(usage: dict[str, Any] | None, error: str | None = None) -> None:
        runlog.write_run(
            save_run,
            service=service.NAME,
            model_id=model_id,
            bedrock_region=bedrock_region,
            facts=facts,
            resource_count=total,
            replay=replay,
            payload_file=payload_file,
            intent=intent,
            started_at=started_at,
            finished_at=now(),
            review_seconds=time.monotonic() - began,
            usage=usage,
            error=error,
        )

    spinner_enabled = sys.stderr.isatty() and os.getenv("TERM") != "dumb"
    try:
        with Spinner(
            f"Waiting for Bedrock review of {total} resources",
            done_message="✓ Bedrock review received",
            stream=sys.stderr,
            enabled=spinner_enabled,
        ):
            analysis, usage = service.analyze(
                session, bedrock_region, model_id, facts, save_json, intent, prepared=replay
            )
    except Exception as error:
        if save_run is not None:
            try:
                record(None, str(error))
            except OSError:
                pass  # Keep the original failure; the run record is best-effort here.
        raise

    if save_run is not None:
        runlog.write_analysis(save_run, analysis)
        record(usage)
        ui.info(f"Run saved to {save_run}")

    if usage.get("input") or usage.get("output"):
        note = f"  ({usage['attempts']} attempts)" if usage["attempts"] > 1 else ""
        cached = usage.get("cache_read", 0) + usage.get("cache_write", 0)
        cache_note = (
            f"  cache_read={usage.get('cache_read', 0)}  cache_write={usage.get('cache_write', 0)}"
            if cached
            else ""
        )
        ui.info(
            ui.style(
                f"Tokens  input={usage['input']}  output={usage['output']}{cache_note}  "
                f"total={usage['input'] + usage['output'] + cached}{note}",
                "dim",
            )
        )
    print(format_analysis(analysis, plain))
    return 0


# Collect facts for a service across regions, run the review, and print it.
def run_scan(
    service: Any,
    session: boto3.Session,
    regions: list[str],
    model_id: str,
    bedrock_region: str,
    save_json: Path | None,
    plain: bool,
    intent: str | None = None,
    save_run: Path | None = None,
) -> int:
    multi = len(regions) > 1
    on_region = None
    if multi:
        ui.info(f"Collecting {service.LABEL} facts across {len(regions)} regions...")
        on_region = lambda region, count: ui.info(f"  {region}: {count} resource(s)")

    facts = service.collect(session, regions, on_region)
    return review_facts(
        service, session, facts, model_id, bedrock_region, save_json, plain, intent,
        save_run=save_run,
    )


# Review a payload saved by an earlier run instead of collecting from AWS.
def run_replay(
    service: Any,
    session: boto3.Session,
    path: Path,
    model_id: str,
    bedrock_region: str,
    plain: bool,
    intent: str | None = None,
    save_run: Path | None = None,
) -> int:
    facts = load_payload(path)
    ui.info(f"Reviewing saved payload {path} (no AWS collection)")
    return review_facts(
        service, session, facts, model_id, bedrock_region, None, plain, intent,
        save_run=save_run, replay_path=path,
    )


# Run the `assess` subcommand from parsed flags.
def run_assess(args: argparse.Namespace) -> int:
    if not args.model:
        raise SystemExit("No Bedrock model given; pass --model or set BEDROCK_MODEL_ID.")

    intent = load_intent(args.intent)
    if args.save_run is not None:
        runlog.ensure_unused(args.save_run, check_payload=not args.from_json)
        runlog.prepare(args.save_run)

    bootstrap = bootstrap_region(args)
    session = boto3.Session(profile_name=args.profile, region_name=bootstrap)
    identity = session.client("sts", region_name=bootstrap).get_caller_identity()
    ui.status(identity)
    if intent:
        ui.info(f"Using account intent from {args.intent} ({len(intent)} chars)")

    service = SERVICES[args.service]
    if args.from_json:
        return run_replay(
            service, session, args.from_json, args.model, bootstrap, args.plain, intent,
            args.save_run,
        )
    if args.all_regions:
        regions = list_enabled_regions(session, bootstrap)
        if not regions:
            print("No enabled regions were returned for this account.", file=sys.stderr)
            return 1
    else:
        regions = args.regions

    return run_scan(
        service, session, regions, args.model, bootstrap, args.save_json, args.plain, intent,
        args.save_run,
    )


# Entry point: dispatch the subcommand and map errors to exit codes.
def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help(sys.stderr)
        return 0
    validate_args(parser, args)

    try:
        return run_assess(args)
    except KeyboardInterrupt:
        print("\nReview cancelled.", file=sys.stderr)
        return 130
    except (NoCredentialsError, PartialCredentialsError, ProfileNotFound) as error:
        print(f"AWS credentials are unavailable or incomplete: {error}", file=sys.stderr)
        return 1
    except NoRegionError:
        print(
            "No AWS region configured; pass --regions/--all-regions or set AWS_REGION.",
            file=sys.stderr,
        )
        return 1
    except (ReadTimeoutError, ConnectTimeoutError) as error:
        print(
            f"Bedrock request timed out: {error}\n"
            "The model may be slow on a large payload; try a faster model or a smaller region scope.",
            file=sys.stderr,
        )
        return 1
    except OSError as error:
        print(f"Could not write output file: {error}", file=sys.stderr)
        return 1
    except (BotoCoreError, ClientError, ValueError) as error:
        print(f"Review failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
