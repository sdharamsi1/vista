"""Render validated EC2 reviews for an interactive terminal."""

from __future__ import annotations

import itertools
import re
import shutil
import sys
import textwrap
import threading
from typing import Any, TextIO

RESET = "\033[0m"
BOLD = "1"
DIM = "2"
RED = "31"
GREEN = "32"
YELLOW = "33"
BLUE = "34"
MAGENTA = "35"
CYAN = "36"

IDENTITY_PATTERN = re.compile(
    r"^- \*\*(?P<name>.+)\*\* \(`(?P<instance_id>[^`]+)`\)$"
)
FIELD_PATTERN = re.compile(
    r"^\s*- \*\*(?P<label>Assessment|Internet exposure|Why this assessment|"
    r"Protective controls|Security concerns|Recommended investigation):\*\*\s*"
    r"(?P<value>.*)$"
)
ASSESSMENT_STYLES = {
    "NO_IMMEDIATE_ACTION": ("✓", GREEN),
    "INVESTIGATE": ("!", YELLOW),
    "HIGH_PRIORITY": ("!!", RED),
    "INSUFFICIENT_DATA": ("?", MAGENTA),
}
EXPOSURE_STYLES = {
    "NONE": ("○", GREEN),
    "DIRECT": ("●", YELLOW),
    "LOAD_BALANCER": ("●", YELLOW),
    "BOTH": ("●", RED),
    "UNKNOWN": ("?", MAGENTA),
}
SPINNER_FRAMES = ("◐", "◓", "◑", "◒")


class Spinner:
    """Animate a single-line status message on an interactive stream."""

    # Store the spinner's message, stream, and animation settings.
    def __init__(
        self,
        message: str,
        *,
        done_message: str | None = None,
        stream: TextIO | None = None,
        enabled: bool = True,
        interval: float = 0.12,
    ) -> None:
        self.message = message
        self.done_message = done_message
        self.stream = stream or sys.stderr
        self.enabled = enabled
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._line_length = 0

    # Loop through spinner frames, redrawing the status line until stopped.
    def _animate(self) -> None:
        for frame in itertools.cycle(SPINNER_FRAMES):
            status = f"{frame} {self.message}"
            self._line_length = max(self._line_length, len(status))
            try:
                self.stream.write("\r" + status)
                self.stream.flush()
            except (OSError, ValueError):
                return
            if self._stop.wait(self.interval):
                return

    # Erase the spinner line from the stream.
    def _clear(self) -> None:
        try:
            self.stream.write("\r" + (" " * self._line_length) + "\r")
            self.stream.flush()
        except (OSError, ValueError):
            pass

    # Start the background animation thread when entering the context.
    def __enter__(self) -> Spinner:
        if self.enabled:
            self._thread = threading.Thread(target=self._animate, daemon=True)
            self._thread.start()
        return self

    # Stop the animation, clear the line, and print the done message on clean exit.
    def __exit__(
        self,
        exception_type: object,
        _exception: object,
        _traceback: object,
    ) -> None:
        if not self.enabled:
            return
        self._stop.set()
        if self._thread is not None:
            self._thread.join()
        self._clear()
        if exception_type is None and self.done_message:
            try:
                self.stream.write(self.done_message + "\n")
                self.stream.flush()
            except (OSError, ValueError):
                pass


# Wrap text in the given ANSI codes, or return it unchanged when color is disabled.
def _style(text: str, use_color: bool, *codes: str) -> str:
    if not use_color:
        return text
    return f"\033[{';'.join(codes)}m{text}{RESET}"


# Strip backticks and surrounding whitespace from a value.
def _plain(text: str) -> str:
    return text.replace("`", "").strip()


# Parse the Bedrock Markdown into per-instance field blocks plus any leading preamble lines.
def _parse_blocks(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    blocks: list[dict[str, Any]] = []
    preamble: list[str] = []
    current: dict[str, Any] | None = None
    current_field: str | None = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line == "# EC2 Security Review":
            continue

        identity = IDENTITY_PATTERN.match(line)
        if identity:
            if current is not None:
                blocks.append(current)
            current = {
                "name": identity.group("name"),
                "instance_id": identity.group("instance_id"),
                "fields": {},
            }
            current_field = None
            continue

        field = FIELD_PATTERN.match(line)
        if field and current is not None:
            current_field = field.group("label")
            current["fields"][current_field] = field.group("value").strip()
            continue

        if current is None:
            preamble.append(line)
        elif current_field is not None:
            current["fields"][current_field] += " " + line

    if current is not None:
        blocks.append(current)
    return blocks, preamble


# Word-wrap a value to the available width and apply a left indent to each line.
def _wrap(value: str, width: int, indent: int = 4) -> list[str]:
    available = max(20, width - indent)
    parts = textwrap.wrap(
        _plain(value),
        width=available,
        break_long_words=True,
        break_on_hyphens=False,
    )
    return [(" " * indent) + part for part in (parts or [""])]


# Format a labeled status row with the symbol and color mapped to its enum value.
def _status_row(
    label: str,
    value: str,
    styles: dict[str, tuple[str, str]],
    use_color: bool,
) -> str:
    symbol, color = styles.get(value, ("?", MAGENTA))
    label_text = _style(f"{label:<20}", use_color, BOLD)
    value_text = _style(f"{symbol} {value}", use_color, BOLD, color)
    return f"  {label_text}{value_text}"


# Append a titled, wrapped narrative section to the output lines.
def _section(
    lines: list[str],
    label: str,
    value: str,
    symbol: str,
    color: str,
    width: int,
    use_color: bool,
) -> None:
    lines.append("")
    lines.append("  " + _style(f"{symbol} {label}", use_color, BOLD, color))
    lines.extend(_wrap(value, width))


# Turn validated Bedrock Markdown into compact, color-coded terminal cards per instance.
def render_review(text: str, *, use_color: bool = True, width: int | None = None) -> str:
    """Return a compact terminal rendering of validated Bedrock Markdown."""
    terminal_width = width or shutil.get_terminal_size((100, 24)).columns
    terminal_width = max(40, min(terminal_width, 120))
    rule = "─" * terminal_width
    blocks, preamble = _parse_blocks(text)

    lines = [
        _style("EC2 Security Review", use_color, BOLD, CYAN),
        _style("═" * min(terminal_width, 80), use_color, CYAN),
    ]
    if not blocks:
        lines.extend(["", *(preamble or ["No review content returned."])])
        return "\n".join(lines)

    if preamble:
        lines.extend(["", _style("Additional model output", use_color, BOLD, MAGENTA)])
        for message in preamble:
            lines.extend(_wrap(message, terminal_width, indent=2))

    for index, block in enumerate(blocks):
        if index:
            lines.append("")
        fields = block["fields"]
        assessment = _plain(fields.get("Assessment", "UNKNOWN"))
        exposure = _plain(fields.get("Internet exposure", "UNKNOWN"))

        name = block["name"]
        raw_instance_id = block["instance_id"]
        identity = _style(name, use_color, BOLD, CYAN)
        instance_id = _style(raw_instance_id, use_color, DIM)
        if len(name) + len(raw_instance_id) + 2 <= terminal_width:
            identity_lines = [f"{identity}  {instance_id}"]
        else:
            name_parts = textwrap.wrap(
                name,
                width=terminal_width,
                break_long_words=True,
                break_on_hyphens=False,
            ) or [name]
            identity_lines = [
                _style(part, use_color, BOLD, CYAN) for part in name_parts
            ]
            identity_lines.append(f"  {instance_id}")
        lines.extend(
            [
                "",
                *identity_lines,
                _style(rule, use_color, DIM),
                _status_row(
                    "Assessment", assessment, ASSESSMENT_STYLES, use_color
                ),
                _status_row(
                    "Internet exposure", exposure, EXPOSURE_STYLES, use_color
                ),
            ]
        )
        _section(
            lines,
            "Why this assessment",
            fields.get("Why this assessment", "Not supplied."),
            "◆",
            CYAN,
            terminal_width,
            use_color,
        )
        _section(
            lines,
            "Protective controls",
            fields.get("Protective controls", "None identified in supplied facts."),
            "+",
            GREEN,
            terminal_width,
            use_color,
        )

        concerns = fields.get(
            "Security concerns", "None identified in supplied facts."
        )
        no_concerns = concerns.casefold().rstrip(".") == (
            "none identified in supplied facts"
        )
        _section(
            lines,
            "Security concerns",
            concerns,
            "✓" if no_concerns else "!",
            GREEN if no_concerns else YELLOW,
            terminal_width,
            use_color,
        )

        recommendation = fields.get(
            "Recommended investigation", "None based on supplied facts."
        )
        no_recommendation = recommendation.casefold().rstrip(".") == (
            "none based on supplied facts"
        )
        _section(
            lines,
            "Recommended investigation",
            recommendation,
            "—" if no_recommendation else "→",
            GREEN if no_recommendation else BLUE,
            terminal_width,
            use_color,
        )

    return "\n".join(lines)
