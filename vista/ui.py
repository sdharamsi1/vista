"""Terminal output helpers. All output goes to stderr so stdout stays clean for the report."""

from __future__ import annotations

import os
import sys
from typing import TextIO

RESET = "\033[0m"
_CODES = {
    "bold": "1",
    "dim": "2",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
}


# Whether to emit ANSI color on the stream.
def use_color(stream: TextIO = sys.stderr) -> bool:
    return stream.isatty() and "NO_COLOR" not in os.environ and os.getenv("TERM") != "dumb"


# Apply ANSI styles, or return text unchanged when color is off.
def style(text: str, *names: str, stream: TextIO = sys.stderr) -> str:
    if not use_color(stream) or not names:
        return text
    codes = ";".join(_CODES[name] for name in names)
    return f"\033[{codes}m{text}{RESET}"


# Authenticated account/identity line.
def status(identity: dict[str, str], stream: TextIO = sys.stderr) -> None:
    dot = style("●", "green", stream=stream)
    account = style(identity.get("Account", "?"), "bold", stream=stream)
    arn = style(identity.get("Arn", "?"), "dim", stream=stream)
    print(f"  {dot} account {account}  ·  {arn}", file=stream)


def info(message: str = "", stream: TextIO = sys.stderr) -> None:
    print(f"  {message}" if message else "", file=stream)


def success(message: str, stream: TextIO = sys.stderr) -> None:
    print("  " + style(f"✓ {message}", "green", stream=stream), file=stream)


def warn(message: str, stream: TextIO = sys.stderr) -> None:
    print("  " + style(f"! {message}", "yellow", stream=stream), file=stream)


def error(message: str, stream: TextIO = sys.stderr) -> None:
    print("  " + style(f"✗ {message}", "red", stream=stream), file=stream)
