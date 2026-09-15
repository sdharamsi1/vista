#!/usr/bin/env python3
"""Collect factual EC2 configuration and ask Amazon Bedrock to review it."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import boto3
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    PartialCredentialsError,
)

from ec2.bedrock import analyze_with_bedrock
from ec2.scanner import scan_region
from ec2.terminal import Spinner, render_review


# Define and parse the command-line arguments, requiring a region and a Bedrock model.
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect EC2 facts and ask Amazon Bedrock to review them."
    )
    parser.add_argument("--region", required=True, help="AWS region to scan")
    parser.add_argument(
        "--bedrock-model",
        default=os.getenv("BEDROCK_MODEL_ID"),
        help="Bedrock model or inference-profile ID (or set BEDROCK_MODEL_ID)",
    )
    parser.add_argument(
        "--save-json",
        type=Path,
        help="Create a private file with the exact factual JSON sent to Bedrock",
    )
    parser.add_argument(
        "--plain",
        action="store_true",
        help="Print the original Bedrock Markdown without terminal formatting",
    )
    args = parser.parse_args()
    if not args.bedrock_model:
        parser.error("set BEDROCK_MODEL_ID or provide --bedrock-model")
    return args


# Orchestrate the full workflow: scan the region, run the Bedrock review, and print the result.
def main() -> int:
    args = parse_args()
    session = boto3.Session(region_name=args.region)
    try:
        facts = scan_region(session, args.region)
        spinner_enabled = (
            sys.stderr.isatty() and os.getenv("TERM") != "dumb"
        )
        with Spinner(
            "Waiting for Bedrock review",
            done_message="✓ Bedrock review received",
            stream=sys.stderr,
            enabled=spinner_enabled,
        ):
            analysis = analyze_with_bedrock(
                session,
                args.region,
                args.bedrock_model,
                facts,
                args.save_json,
            )
    except KeyboardInterrupt:
        print("EC2 review cancelled.", file=sys.stderr)
        return 130
    except (NoCredentialsError, PartialCredentialsError) as error:
        print(f"AWS credentials are unavailable or incomplete: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"JSON output failed: {error}", file=sys.stderr)
        return 1
    except (BotoCoreError, ClientError, ValueError) as error:
        print(f"EC2 review failed: {error}", file=sys.stderr)
        return 1

    if args.plain or not sys.stdout.isatty():
        output = analysis
    else:
        use_color = "NO_COLOR" not in os.environ and os.getenv("TERM") != "dumb"
        try:
            output = render_review(analysis, use_color=use_color)
        except Exception as error:
            print(
                f"Terminal formatting failed; printing plain Markdown: {error}",
                file=sys.stderr,
            )
            output = analysis
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
