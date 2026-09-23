"""Interactive terminal UI helpers. All output goes to stderr so stdout stays clean for the report."""

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


class Sentinel:
    """Navigation result: BACK or QUIT."""

    def __init__(self, name: str) -> None:
        self.name = name

    def __repr__(self) -> str:
        return f"<{self.name}>"


BACK = Sentinel("BACK")
QUIT = Sentinel("QUIT")


# Whether to emit ANSI color on the stream.
def use_color(stream: TextIO = sys.stderr) -> bool:
    return stream.isatty() and "NO_COLOR" not in os.environ and os.getenv("TERM") != "dumb"


# Apply ANSI styles, or return text unchanged when color is off.
def style(text: str, *names: str, stream: TextIO = sys.stderr) -> str:
    if not use_color(stream) or not names:
        return text
    codes = ";".join(_CODES[name] for name in names)
    return f"\033[{codes}m{text}{RESET}"


# Prompt on stderr, read a line from stdin.
def _read(prompt: str, stream: TextIO = sys.stderr) -> str:
    stream.write(prompt)
    stream.flush()
    return input()


# Header banner.
def banner(subtitle: str, stream: TextIO = sys.stderr) -> None:
    print(file=stream)
    print(
        "  "
        + style("VISTA", "bold", "cyan", stream=stream)
        + style(f"  ·  {subtitle}", "dim", stream=stream),
        file=stream,
    )
    print("  " + style("─" * 46, "dim", stream=stream), file=stream)


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


# Numbered menu; returns the chosen index, BACK, or QUIT.
def menu(
    title: str,
    options: list[str],
    *,
    hint: str | None = None,
    allow_back: bool = False,
    allow_quit: bool = True,
    stream: TextIO = sys.stderr,
) -> int | Sentinel:
    if not sys.stdin.isatty():
        raise SystemExit("Interactive menu requires a terminal.")
    print(file=stream)
    print("  " + style(title, "bold", "cyan", stream=stream), file=stream)
    if hint:
        print("  " + style(hint, "dim", stream=stream), file=stream)
    for index, label in enumerate(options, start=1):
        print(f"    {style(str(index), 'bold', stream=stream)}) {label}", file=stream)
    controls = []
    if allow_back:
        controls.append(style("b", "bold", stream=stream) + " back")
    if allow_quit:
        controls.append(style("q", "bold", stream=stream) + " quit")
    if controls:
        print("  " + style("· ", "dim", stream=stream) + "   ".join(controls), file=stream)

    valid = ["1-" + str(len(options)) if len(options) > 1 else "1"]
    if allow_back:
        valid.append("b")
    if allow_quit:
        valid.append("q")
    hint_text = ", ".join(valid)
    while True:
        try:
            raw = _read("  " + style("›", "cyan", stream=stream) + " ", stream).strip().lower()
        except EOFError:
            return QUIT
        if not raw:
            continue
        if allow_back and raw in ("b", "back"):
            return BACK
        if allow_quit and raw in ("q", "quit"):
            return QUIT
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return int(raw) - 1
        error(f"Please enter {hint_text}.", stream=stream)


# Free-text prompt; returns the text, or BACK/QUIT.
def prompt_text(
    label: str,
    *,
    allow_back: bool = True,
    stream: TextIO = sys.stderr,
) -> str | Sentinel:
    if not sys.stdin.isatty():
        raise SystemExit("Interactive input requires a terminal.")
    suffix = style(" (b to go back)", "dim", stream=stream) if allow_back else ""
    while True:
        try:
            raw = _read(
                "  " + style(label, "bold", stream=stream) + suffix + ": ", stream
            ).strip()
        except EOFError:
            return QUIT
        if allow_back and raw.lower() in ("b", "back"):
            return BACK
        if raw:
            return raw
