#!/usr/bin/env python3
"""Vista CLI: authenticate, pick a service and model, scan, and print a Bedrock review."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    NoRegionError,
    PartialCredentialsError,
    ProfileNotFound,
)

from vista import ui
from vista.ec2 import service as ec2_service
from vista.render import Spinner, render_review

# Service registry: name -> service module. Add new services here.
SERVICES = {ec2_service.NAME: ec2_service}

# Model menu: (label, id). A None id means prompt for a custom one.
MODELS: list[tuple[str, str | None]] = [
    ("Claude Opus 5 (Anthropic)", "us.anthropic.claude-opus-5"),
    ("GPT-5.6 Sol (OpenAI)", "us.openai.gpt-5.6-sol"),
    ("Other (enter a model ID)", None),
]

# Region for the initial STS/DescribeRegions calls.
DEFAULT_BOOTSTRAP_REGION = "us-east-1"

# Regions never enumerated.
SKIP_REGIONS = {"me-south-1", "me-central-1"}

AUTH_ERRORS = (
    NoCredentialsError,
    PartialCredentialsError,
    ProfileNotFound,
    BotoCoreError,
    ClientError,
)


# Parse CLI arguments.
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect AWS facts and ask Amazon Bedrock to review them."
    )
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument(
        "--region",
        help="A single AWS region to scan (prompted for if neither this nor "
        "--all-regions is given)",
    )
    scope.add_argument(
        "--all-regions",
        action="store_true",
        help="Scan every region enabled for the account",
    )
    parser.add_argument(
        "--service",
        choices=list(SERVICES),
        help="AWS service to evaluate (prompted for if omitted)",
    )
    parser.add_argument(
        "--bedrock-model",
        default=os.getenv("BEDROCK_MODEL_ID"),
        help="Bedrock model or inference-profile ID (prompted for if omitted; "
        "or set BEDROCK_MODEL_ID)",
    )
    parser.add_argument(
        "--save-json",
        type=Path,
        help="Create a private file with the exact factual JSON sent to Bedrock "
        "(one merged payload across all scanned regions)",
    )
    parser.add_argument(
        "--plain",
        action="store_true",
        help="Print the original Bedrock Markdown without terminal formatting",
    )
    return parser.parse_args()


# Region used before scan targets are chosen.
def bootstrap_region(args: argparse.Namespace) -> str:
    return (
        args.region
        or os.getenv("AWS_REGION")
        or os.getenv("AWS_DEFAULT_REGION")
        or DEFAULT_BOOTSTRAP_REGION
    )


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


# Collect facts for a service across regions, run the review, and print it.
def run_scan(
    service: Any,
    session: boto3.Session,
    regions: list[str],
    model_id: str,
    bedrock_region: str,
    save_json: Path | None,
    plain: bool,
) -> int:
    multi = len(regions) > 1
    on_region = None
    if multi:
        ui.info(f"Collecting {service.LABEL} facts across {len(regions)} regions...")
        on_region = lambda region, count: ui.info(f"  {region}: {count} resource(s)")

    facts = service.collect(session, regions, on_region)
    total = service.count(facts)
    if total == 0:
        print(f"No {service.LABEL} resources found in the selected region(s).")
        return 0

    spinner_enabled = sys.stderr.isatty() and os.getenv("TERM") != "dumb"
    with Spinner(
        f"Waiting for Bedrock review of {total} resources",
        done_message="✓ Bedrock review received",
        stream=sys.stderr,
        enabled=spinner_enabled,
    ):
        analysis = service.analyze(session, bedrock_region, model_id, facts, save_json)
    print(format_analysis(analysis, plain))
    return 0


# True when flags fully specify a run, so the shell can be skipped.
def fully_specified(args: argparse.Namespace) -> bool:
    return bool(args.bedrock_model) and bool(args.region or args.all_regions)


# Run once from flags.
def one_shot(args: argparse.Namespace) -> int:
    bootstrap = bootstrap_region(args)
    session = boto3.Session(region_name=bootstrap)
    identity = session.client("sts", region_name=bootstrap).get_caller_identity()
    print(
        f"Authenticated as {identity['Arn']} (account {identity['Account']}).",
        file=sys.stderr,
    )
    service = SERVICES[args.service] if args.service else next(iter(SERVICES.values()))
    model_id = args.bedrock_model
    if not model_id:
        raise SystemExit("No Bedrock model given; pass --bedrock-model or set BEDROCK_MODEL_ID.")
    if args.all_regions:
        regions = list_enabled_regions(session, bootstrap)
    elif args.region:
        regions = [args.region]
    else:
        raise SystemExit("No region scope given; pass --region or --all-regions.")
    return run_scan(
        service, session, regions, model_id, bootstrap, args.save_json, args.plain
    )


# Interactive auth; returns (session, identity) or None if cancelled.
def authenticate_interactive(
    bootstrap: str, *, allow_cancel: bool
) -> tuple[boto3.Session, dict[str, str]] | None:
    exit_label = "Cancel" if allow_cancel else "Quit"
    while True:
        choice = ui.menu(
            "Authenticate to AWS",
            ["Use default credentials", "Use a named profile", exit_label],
            allow_quit=False,
        )
        if choice is ui.QUIT or choice == 2:
            return None
        profile: str | None = None
        if choice == 1:
            entered = ui.prompt_text("Profile name", allow_back=True)
            if entered is ui.BACK or entered is ui.QUIT:
                continue
            profile = entered
        try:
            session = boto3.Session(profile_name=profile, region_name=bootstrap)
            identity = session.client("sts", region_name=bootstrap).get_caller_identity()
        except AUTH_ERRORS as error:
            ui.error(f"Authentication failed: {error}")
            continue
        ui.success("Authenticated")
        ui.status(identity)
        return session, identity


# Pick region scope; returns a region list or BACK/QUIT.
def choose_regions_interactive(
    session: boto3.Session, bootstrap: str
) -> list[str] | ui.Sentinel:
    while True:
        scope = ui.menu(
            "Region scope",
            ["All enabled regions", "A specific region"],
            allow_back=True,
        )
        if scope is ui.QUIT:
            return ui.QUIT
        if scope is ui.BACK:
            return ui.BACK
        try:
            regions = list_enabled_regions(session, bootstrap)
        except (BotoCoreError, ClientError) as error:
            ui.error(f"Could not list regions: {error}")
            return ui.BACK
        if not regions:
            ui.warn("No enabled regions were returned for this account.")
            return ui.BACK
        if scope == 0:
            return regions
        selected = ui.menu("Select a region", regions, allow_back=True)
        if selected is ui.QUIT:
            return ui.QUIT
        if selected is ui.BACK:
            continue
        return [regions[selected]]


# Guided service/model/region selection with back navigation, then scan.
def scan_flow(
    session: boto3.Session, bootstrap: str, args: argparse.Namespace
) -> ui.Sentinel | None:
    service_modules = list(SERVICES.values())
    model_labels = [label for label, _ in MODELS]
    step = 0
    service: Any = None
    model_id = ""
    regions: list[str] = []

    while True:
        if step == 0:
            choice = ui.menu(
                "Select a service to evaluate",
                [module.LABEL for module in service_modules],
                allow_back=True,
            )
            if choice is ui.QUIT:
                return ui.QUIT
            if choice is ui.BACK:
                return None
            service = service_modules[choice]
            step = 1
        elif step == 1:
            choice = ui.menu("Select a Bedrock model", model_labels, allow_back=True)
            if choice is ui.QUIT:
                return ui.QUIT
            if choice is ui.BACK:
                step = 0
                continue
            candidate = MODELS[choice][1]
            if candidate is None:
                entered = ui.prompt_text("Model or inference-profile ID", allow_back=True)
                if entered is ui.QUIT:
                    return ui.QUIT
                if entered is ui.BACK:
                    continue
                candidate = entered
            model_id = candidate
            step = 2
        elif step == 2:
            result = choose_regions_interactive(session, bootstrap)
            if result is ui.QUIT:
                return ui.QUIT
            if result is ui.BACK:
                step = 1
                continue
            regions = result
            step = 3
        else:
            ui.info()
            ui.info(
                "Ready to scan  "
                + ui.style(service.LABEL, "bold")
                + ui.style(f"  ·  {model_id}", "dim")
                + ui.style(f"  ·  {len(regions)} region(s)", "dim")
            )
            confirm = ui.menu("Proceed?", ["Run scan", "Change region"], allow_back=True)
            if confirm is ui.QUIT:
                return ui.QUIT
            if confirm is ui.BACK:
                return None
            if confirm == 1:
                step = 2
                continue
            run_scan(
                service, session, regions, model_id, bootstrap, args.save_json, args.plain
            )
            ui.info()
            ui.success("Scan complete.")
            return None


# Top-level loop: authenticate, then scan / re-authenticate / quit.
def interactive_shell(args: argparse.Namespace) -> int:
    ui.banner("AWS attack surface review")
    bootstrap = bootstrap_region(args)
    auth = authenticate_interactive(bootstrap, allow_cancel=False)
    if auth is None:
        ui.info("Goodbye.")
        return 0
    session, _identity = auth

    while True:
        choice = ui.menu(
            "Main menu",
            ["Run a scan", "Re-authenticate", "Quit"],
            allow_quit=False,
        )
        if choice is ui.QUIT or choice == 2:
            ui.info("Goodbye.")
            return 0
        if choice == 1:
            auth = authenticate_interactive(bootstrap, allow_cancel=True)
            if auth is not None:
                session, _identity = auth
            continue
        if scan_flow(session, bootstrap, args) is ui.QUIT:
            ui.info("Goodbye.")
            return 0


# Entry point: choose interactive or one-shot mode and map errors to exit codes.
def main() -> int:
    args = parse_args()
    interactive = sys.stdin.isatty() and sys.stderr.isatty()
    try:
        if interactive and not fully_specified(args):
            return interactive_shell(args)
        return one_shot(args)
    except KeyboardInterrupt:
        print("\nReview cancelled.", file=sys.stderr)
        return 130
    except (NoCredentialsError, PartialCredentialsError, ProfileNotFound) as error:
        print(f"AWS credentials are unavailable or incomplete: {error}", file=sys.stderr)
        return 1
    except NoRegionError:
        print(
            "No AWS region configured; pass --region/--all-regions or set AWS_REGION.",
            file=sys.stderr,
        )
        return 1
    except OSError as error:
        print(f"JSON output failed: {error}", file=sys.stderr)
        return 1
    except (BotoCoreError, ClientError, ValueError) as error:
        print(f"Review failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
