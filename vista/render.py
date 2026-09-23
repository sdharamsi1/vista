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

HEADING_PATTERN = re.compile(r"^#\s+EC2 Security Review$")
SECTION_PATTERN = re.compile(r"^##\s+(?P<name>.+)$")
FINDING_PATTERN = re.compile(r"^###\s+(?P<title>.+)$")
FIELD_PATTERN = re.compile(
    r"^\s*- \*\*(?P<label>Severity|Category|Affected instances|Evidence|"
    r"Why it matters|Remediation):\*\*\s*(?P<value>.*)$"
)
SEVERITY_STYLES = {
    "HIGH_PRIORITY": ("!!", RED),
    "INVESTIGATE": ("!", YELLOW),
    "INSUFFICIENT_DATA": ("?", MAGENTA),
}
CATEGORY_STYLES = {
    "INTERNET_EXPOSURE": ("●", YELLOW),
    "SECURITY_CONFIGURATION": ("▲", BLUE),
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


# Parse the review into summary and findings.
def _parse_review(
    text: str,
) -> tuple[list[str], list[dict[str, Any]]]:
    summary: list[str] = []
    findings: list[dict[str, Any]] = []
    section: str | None = None
    current: dict[str, Any] | None = None
    current_field: str | None = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or HEADING_PATTERN.match(line):
            continue

        section_match = SECTION_PATTERN.match(line)
        if section_match:
            if current is not None:
                findings.append(current)
                current = None
                current_field = None
            name = section_match.group("name").casefold()
            if name.startswith("account risk summary"):
                section = "summary"
            elif name.startswith("top findings"):
                section = "findings"
            else:
                section = None
            continue

        finding = FINDING_PATTERN.match(line)
        if finding and section == "findings":
            if current is not None:
                findings.append(current)
            current = {"title": finding.group("title").strip(), "fields": {}}
            current_field = None
            continue

        field = FIELD_PATTERN.match(line)
        if field and current is not None:
            current_field = field.group("label")
            current["fields"][current_field] = field.group("value").strip()
            continue

        if section == "summary":
            summary.append(line)
        elif current is not None and current_field is not None:
            current["fields"][current_field] += " " + line

    if current is not None:
        findings.append(current)
    return summary, findings


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


# Render one finding card.
def _render_finding(
    lines: list[str],
    position: int,
    finding: dict[str, Any],
    rule: str,
    width: int,
    use_color: bool,
) -> None:
    fields = finding["fields"]
    severity = _plain(fields.get("Severity", "INSUFFICIENT_DATA"))
    category = _plain(fields.get("Category", ""))

    title = finding["title"]
    if not re.match(r"^\d+\.", title):
        title = f"{position}. {title}"
    lines.append("")
    for part in textwrap.wrap(
        title, width=width, break_long_words=True, break_on_hyphens=False
    ) or [title]:
        lines.append(_style(part, use_color, BOLD, CYAN))
    lines.append(_style(rule, use_color, DIM))
    lines.append(_status_row("Severity", severity, SEVERITY_STYLES, use_color))
    if category:
        lines.append(_status_row("Category", category, CATEGORY_STYLES, use_color))

    _section(
        lines,
        "Affected instances",
        fields.get("Affected instances", "Not supplied."),
        "▪",
        CYAN,
        width,
        use_color,
    )
    _section(
        lines,
        "Evidence",
        fields.get("Evidence", "Not supplied."),
        "◆",
        CYAN,
        width,
        use_color,
    )
    _section(
        lines,
        "Why it matters",
        fields.get("Why it matters", "Not supplied."),
        "!",
        YELLOW,
        width,
        use_color,
    )
    _section(
        lines,
        "Remediation",
        fields.get("Remediation", "Not supplied."),
        "→",
        BLUE,
        width,
        use_color,
    )


# Render the full review for the terminal.
def render_review(text: str, *, use_color: bool = True, width: int | None = None) -> str:
    """Return a compact terminal rendering of validated Bedrock Markdown."""
    terminal_width = width or shutil.get_terminal_size((100, 24)).columns
    terminal_width = max(40, min(terminal_width, 120))
    rule = "─" * terminal_width
    summary, findings = _parse_review(text)

    lines = [
        _style("EC2 Security Review", use_color, BOLD, CYAN),
        _style("═" * min(terminal_width, 80), use_color, CYAN),
    ]

    if summary:
        lines.append("")
        for message in summary:
            lines.extend(_wrap(message, terminal_width, indent=2))

    if findings:
        for position, finding in enumerate(findings, start=1):
            _render_finding(lines, position, finding, rule, terminal_width, use_color)
    else:
        lines.extend(
            [
                "",
                _style(
                    "  ✓ No noteworthy EC2 risks identified in supplied facts.",
                    use_color,
                    BOLD,
                    GREEN,
                ),
            ]
        )

    if not summary and not findings:
        lines.extend(["", "No review content returned."])

    return "\n".join(lines)
