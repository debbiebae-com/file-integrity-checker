#!/usr/bin/env python3
"""
FileWatch log parser and reporting engine
=========================================

Week 4 of the FileWatch project. This module reads the ``filewatch.log`` file
written by ``python main.py watch`` and turns it into structured data that the
dashboard (``dashboard.py``) and the report generator can use.

It is deliberately **self-contained, read-only and side-effect free**:

* it never writes to the log, the baseline, or any monitored file,
* it imports nothing from ``main.py``, so it cannot break Week 1-3 behaviour,
* it is pure standard library, so it can be tested without Streamlit installed.

What a log line looks like
--------------------------
``main.py`` configures logging with::

    fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    datefmt="%Y-%m-%d %H:%M:%S"

so a real line is::

    2026-11-25 16:25:11 | WARNING  | filewatch | ADDED file: added.txt

Recognised events
-----------------
Five "change" event types are derived from the message text:

===========  ==========================================================
Event        Log line produced by ``watch``
===========  ==========================================================
``ADDED``    ``WARNING | ... | ADDED file: <path>``
``MODIFIED`` ``WARNING | ... | MODIFIED file: <path>``
``DELETED``  ``WARNING | ... | DELETED file: <path>``
``UNREADABLE`` ``ERROR | ... | Unreadable file (...): <path>``
``ERROR``    any other ``ERROR``/``CRITICAL`` line (startup failures, ...)
===========  ==========================================================

``INFO`` and ``DEBUG`` lines are counted as *informational* and are not shown as
integrity events, because "no changes" and "watch started" are not changes. They
are still tallied so the dashboard can show how much monitoring happened.

Malformed input
---------------
``filewatch.log`` is a plain text file on the local disk: it can be truncated by
a crash, interleaved by two processes, edited by hand, or replaced by binary
junk. The parser therefore never raises on bad data - it counts unparsable
lines and reports them, because *a burst of malformed lines is itself a signal
that something touched the log* (see the README's limitations section).
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

#: Default log file, at the project root (same default as ``main.py``).
DEFAULT_LOG_PATH = Path("filewatch.log")

#: Event types that represent a change to the monitored folder.
CHANGE_EVENTS: Tuple[str, ...] = ("ADDED", "MODIFIED", "DELETED")

#: Every event type the parser can emit.
EVENT_TYPES: Tuple[str, ...] = CHANGE_EVENTS + ("UNREADABLE", "ERROR")

#: Order used for display and for report tables.
EVENT_ORDER: Tuple[str, ...] = ("ADDED", "MODIFIED", "DELETED", "UNREADABLE", "ERROR")

#: Pattern for one structured log line, with the severity left-padded by %-8s.
LOG_LINE_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
    r"\s*\|\s*(?P<level>[A-Za-z]+)\s*"
    r"\|\s*(?P<logger>[^|]*?)\s*"
    r"\|\s*(?P<message>.*)$"
)

#: Message patterns, checked in order. The first match decides the event type.
MESSAGE_PATTERNS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("ADDED", re.compile(r"^ADDED file:\s*(?P<path>.+?)\s*$")),
    ("MODIFIED", re.compile(r"^MODIFIED file:\s*(?P<path>.+?)\s*$")),
    ("DELETED", re.compile(r"^DELETED file:\s*(?P<path>.+?)\s*$")),
    ("UNREADABLE", re.compile(
        r"^Unreadable file[^:]*:\s*(?P<path>.+?)\s*$")),
)

#: Levels that count as a security-relevant event even without a file path.
EVENT_LEVELS = ("ERROR", "CRITICAL")

#: Maximum size we will read from the log (256 MiB) - a guard against a
#: runaway or deliberately inflated file eating all memory.
MAX_LOG_BYTES = 256 * 1024 * 1024


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class LogEvent:
    """One parsed log line that represents an integrity event.

    Attributes
    ----------
    timestamp:  naive local ``datetime`` (as written by the logger).
    level:      the severity as written in the log (``WARNING``, ``ERROR`` ...).
    event_type: one of :data:`EVENT_TYPES`.
    path:       the relative file path the event is about, if there is one.
    message:    the full original message text.
    line_number: 1-based line number in the log file (for traceability).
    """

    timestamp: datetime
    level: str
    event_type: str
    path: Optional[str]
    message: str
    line_number: int

    def to_dict(self) -> dict:
        """JSON-friendly representation (timestamp as ISO-8601 string)."""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat(sep=" ", timespec="seconds")
        return data


@dataclass
class ParseResult:
    """Everything the parser learned from one log file."""

    events: List[LogEvent] = field(default_factory=list)
    counts: Dict[str, int] = field(default_factory=lambda: {t: 0 for t in EVENT_TYPES})
    total_lines: int = 0
    parsed_lines: int = 0
    malformed_lines: int = 0
    skipped_lines: int = 0          # blank lines / comments
    info_lines: int = 0             # INFO + DEBUG (monitoring activity)
    malformed_samples: List[str] = field(default_factory=list)
    source: Optional[str] = None
    error: Optional[str] = None     # set when the file could not be read at all
    truncated: bool = False         # hit MAX_LOG_BYTES while reading

    # -- convenience -------------------------------------------------------
    @property
    def is_empty(self) -> bool:
        """True when there is nothing to show (missing, empty or no events)."""
        return not self.events

    @property
    def has_error(self) -> bool:
        return self.error is not None

    @property
    def change_count(self) -> int:
        """Total number of ADDED + MODIFIED + DELETED events."""
        return sum(self.counts.get(name, 0) for name in CHANGE_EVENTS)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "error": self.error,
            "total_lines": self.total_lines,
            "parsed_lines": self.parsed_lines,
            "malformed_lines": self.malformed_lines,
            "skipped_lines": self.skipped_lines,
            "info_lines": self.info_lines,
            "truncated": self.truncated,
            "counts": dict(self.counts),
            "change_count": self.change_count,
            "events": [event.to_dict() for event in self.events],
        }


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_log_line(line: str, line_number: int = 0) -> Tuple[Optional[LogEvent], str]:
    """Parse a single log line.

    Returns ``(event, status)`` where ``status`` is one of:

    * ``"event"``     - an integrity event was produced,
    * ``"info"``      - a well-formed INFO/DEBUG line (no event),
    * ``"malformed"`` - the line does not match the expected format,
    * ``"skipped"``   - blank line or comment (nothing to report).

    Never raises.
    """
    stripped = line.strip()

    if not stripped or stripped.startswith("#"):
        return None, "skipped"

    match = LOG_LINE_RE.match(stripped)
    if not match:
        return None, "malformed"

    try:
        timestamp = datetime.strptime(match.group("timestamp"), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None, "malformed"

    level = match.group("level").upper()
    message = match.group("message").strip()
    if not message:
        return None, "malformed"

    # 1) Change events carry a file path.
    for event_type, pattern in MESSAGE_PATTERNS:
        found = pattern.match(message)
        if found:
            return LogEvent(
                timestamp=timestamp,
                level=level,
                event_type=event_type,
                path=found.group("path") or None,
                message=message,
                line_number=line_number,
            ), "event"

    # 2) Any other ERROR/CRITICAL line is an event without a file path.
    if level in EVENT_LEVELS:
        return LogEvent(
            timestamp=timestamp,
            level=level,
            event_type="ERROR",
            path=None,
            message=message,
            line_number=line_number,
        ), "event"

    # 3) Everything else (INFO/DEBUG/WARNING without a known message) is noise
    #    for reporting purposes, but still counted as activity.
    return None, "info"


def parse_log_text(text: str, source: Optional[str] = None) -> ParseResult:
    """Parse a whole log file's contents (as a string)."""
    result = ParseResult(source=source)

    for index, raw_line in enumerate(text.splitlines(), start=1):
        result.total_lines += 1

        # A traceback from `logger.exception()` spans several lines; they are
        # counted as malformed rather than silently dropped, so the dashboard
        # can show "some lines were not understood".
        event, status = parse_log_line(raw_line, index)

        if status == "event" and event is not None:
            result.events.append(event)
            result.counts[event.event_type] = result.counts.get(event.event_type, 0) + 1
            result.parsed_lines += 1
        elif status == "info":
            result.info_lines += 1
            result.parsed_lines += 1
        elif status == "skipped":
            result.skipped_lines += 1
        else:
            result.malformed_lines += 1
            if len(result.malformed_samples) < 5:
                result.malformed_samples.append(raw_line[:200])

    return result


def parse_log_file(path=DEFAULT_LOG_PATH) -> ParseResult:
    """Read and parse ``filewatch.log``, tolerating every realistic failure.

    * missing file      -> empty result with a friendly ``error`` message,
    * empty file        -> empty result, no error,
    * permission error  -> empty result with an ``error`` message,
    * binary/undecodable -> decoded with ``errors="replace"`` and parsed,
    * huge file         -> only the last :data:`MAX_LOG_BYTES` are read.

    The returned object is always usable: ``result.events`` is a list (possibly
    empty) and ``result.error`` explains anything that went wrong.
    """
    target = Path(path)

    try:
        if not target.exists():
            return ParseResult(source=str(target),
                               error=f"Log file not found: {target}")
        if target.is_dir():
            return ParseResult(source=str(target),
                               error=f"Expected a log file but found a directory: {target}")
        size = target.stat().st_size
    except OSError as exc:
        return ParseResult(source=str(target), error=f"Cannot stat {target}: {exc}")

    truncated = False
    try:
        with open(target, "rb") as handle:
            if size > MAX_LOG_BYTES:
                handle.seek(size - MAX_LOG_BYTES)
                handle.readline()  # discard the partial first line
                truncated = True
            raw = handle.read()
    except PermissionError:
        return ParseResult(source=str(target),
                           error=f"Permission denied while reading {target}")
    except OSError as exc:
        return ParseResult(source=str(target), error=f"Cannot read {target}: {exc}")

    # Decode leniently: a log with a stray binary byte should still be readable.
    text = raw.decode("utf-8", errors="replace")

    result = parse_log_text(text, source=str(target))
    result.truncated = truncated
    return result


# ---------------------------------------------------------------------------
# Aggregation helpers used by the dashboard and the reports
# ---------------------------------------------------------------------------

def recent_events(result: ParseResult, limit: int = 20) -> List[LogEvent]:
    """Return the ``limit`` most recent events, newest first."""
    ordered = sorted(result.events,
                     key=lambda event: (event.timestamp, event.line_number),
                     reverse=True)
    return ordered[:max(0, limit)]


def filter_events(result: ParseResult,
                  event_types: Optional[Iterable[str]] = None) -> List[LogEvent]:
    """Return events whose type is in ``event_types`` (all types by default)."""
    if event_types is None:
        return list(result.events)
    wanted = {name.upper() for name in event_types}
    return [event for event in result.events if event.event_type in wanted]


def event_counts(result: ParseResult) -> Dict[str, int]:
    """Return ``{event_type: count}`` for the change events (plus extras)."""
    return {name: int(result.counts.get(name, 0)) for name in EVENT_ORDER}


def timeline(result: ParseResult, bucket: str = "minute") -> List[Dict[str, object]]:
    """Aggregate change events into time buckets for the dashboard chart.

    ``bucket`` is ``"minute"``, ``"hour"`` or ``"day"``. Returns a list of
    ``{"bucket": "2026-11-25 16:25", "ADDED": 2, "MODIFIED": 1, "DELETED": 0}``
    sorted chronologically. Returns an empty list when there is nothing to plot,
    which lets the dashboard show its "no events" message.
    """
    formats = {"minute": "%Y-%m-%d %H:%M", "hour": "%Y-%m-%d %H:00",
               "day": "%Y-%m-%d"}
    if bucket not in formats:
        raise ValueError(f"Unsupported bucket {bucket!r}; "
                         f"choose from {', '.join(formats)}")
    fmt = formats[bucket]

    buckets: Dict[str, Dict[str, int]] = {}
    for event in result.events:
        if event.event_type not in CHANGE_EVENTS:
            continue
        key = event.timestamp.strftime(fmt)
        row = buckets.setdefault(key, {name: 0 for name in EVENT_TYPES})
        row[event.event_type] += 1

    return [{"bucket": key, **buckets[key]} for key in sorted(buckets)]


def timeline_rows(result: ParseResult, bucket: str = "minute") -> List[Dict[str, object]]:
    """``timeline()`` shaped for charts: one row per bucket with a total."""
    rows = []
    for row in timeline(result, bucket):
        rows.append({**row, "total": sum(row[name] for name in CHANGE_EVENTS)})
    return rows


def events_as_rows(result: ParseResult,
                   limit: Optional[int] = None) -> List[Dict[str, str]]:
    """Return events as flat dictionaries - ideal for a table or a CSV export."""
    events = result.events if limit is None else recent_events(result, limit)
    return [
        {
            "Timestamp": event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "Event": event.event_type,
            "Level": event.level,
            "File": event.path or "-",
            "Details": event.message,
        }
        for event in events
    ]


def summarize(result: ParseResult) -> str:
    """One-line, human-readable summary of a parse result."""
    if result.has_error:
        return result.error or "Unknown error"
    if not result.events:
        return ("No log events available. "
                f"({result.total_lines} line(s) read, none were integrity events)")
    return (f"{result.change_count} change event(s): "
            f"{result.counts.get('ADDED', 0)} added, "
            f"{result.counts.get('MODIFIED', 0)} modified, "
            f"{result.counts.get('DELETED', 0)} deleted"
            + (f", {result.counts.get('UNREADABLE', 0)} unreadable"
               if result.counts.get("UNREADABLE") else "")
            + (f", {result.counts.get('ERROR', 0)} error(s)"
               if result.counts.get("ERROR") else ""))


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _generated_at() -> str:
    """Local timestamp for the report header."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _top_paths(result: ParseResult, limit: int = 10) -> List[Tuple[str, int]]:
    """The most frequently touched paths, for the report's summary table."""
    tally: Dict[str, int] = {}
    for event in result.events:
        if event.path and event.event_type in CHANGE_EVENTS:
            tally[event.path] = tally.get(event.path, 0) + 1
    return sorted(tally.items(), key=lambda pair: (-pair[1], pair[0]))[:limit]


def build_report_data(result: ParseResult,
                      recent_limit: int = 20,
                      log_path=DEFAULT_LOG_PATH) -> Dict[str, object]:
    """Collect everything both report formats need, in one plain dictionary.

    Keeping the data separate from the rendering makes the formats consistent
    and lets tests check the *content* without parsing HTML or Markdown.
    """
    return {
        "generated_at": _generated_at(),
        "log_path": str(log_path),
        "log_exists": Path(log_path).exists(),
        "error": result.error,
        "counts": event_counts(result),
        "change_count": result.change_count,
        "total_lines": result.total_lines,
        "parsed_lines": result.parsed_lines,
        "malformed_lines": result.malformed_lines,
        "info_lines": result.info_lines,
        "truncated": result.truncated,
        "recent": events_as_rows(result, limit=recent_limit),
        "top_paths": _top_paths(result),
        "first_event": (result.events[0].timestamp.strftime("%Y-%m-%d %H:%M:%S")
                        if result.events else None),
        "last_event": (max(e.timestamp for e in result.events).strftime("%Y-%m-%d %H:%M:%S")
                       if result.events else None),
    }


_LEGAL_NOTICE = (
    "Scanning or attacking systems you do not own or have written permission to "
    "test is illegal. This tool only monitors your own test folder."
)

_EDUCATIONAL_NOTE = (
    "FileWatch is an educational, local file integrity monitor. It detects "
    "changes to files inside one folder you control. It does not prevent, block "
    "or stop an attack, and it is not a network scanner or penetration-testing "
    "tool. This report was generated from a local log file that the tool itself "
    "does not protect against tampering."
)


# ---------------------------------------------------------------------------
# WEEK 4 ENHANCED: SQLite-backed report data
# ---------------------------------------------------------------------------

def result_from_events(events, source: Optional[str] = None,
                       error: Optional[str] = None) -> ParseResult:
    """Build a :class:`ParseResult` from already-structured event dictionaries.

    Lets the Week 4 renderers (``render_markdown`` / ``render_html``) produce
    reports from SQLite without duplicating either renderer. Event dictionaries
    are the ones ``database.query_events`` returns: ``timestamp`` ISO-8601 UTC,
    ``event_type``, ``path``, optionally ``old_hash``/``new_hash``/``source``.

    A single bad record never aborts the report - it is counted as malformed so
    the document can say so honestly instead of failing to render.
    """
    result = ParseResult(source=source, error=error)
    for index, record in enumerate(events, start=1):
        result.total_lines += 1
        if not isinstance(record, dict):
            result.malformed_lines += 1
            continue

        event_type = str(record.get("event_type") or "").upper()
        if event_type not in EVENT_TYPES:
            result.malformed_lines += 1
            if len(result.malformed_samples) < 5:
                result.malformed_samples.append(f"row {index}: unknown event type")
            continue

        moment = event_logger_timestamp(record.get("timestamp"))
        if moment is None:
            result.malformed_lines += 1
            if len(result.malformed_samples) < 5:
                result.malformed_samples.append(f"row {index}: bad timestamp")
            continue

        path = record.get("path")
        message = f"{event_type} file: {path}" if path else event_type
        if event_type in EVENT_LEVELS:
            level = event_type
        elif event_type == "UNREADABLE" or event_type == "ERROR":
            level = "WARNING"
        else:
            level = "WARNING"

        result.events.append(LogEvent(
            timestamp=moment,
            level=level,
            event_type=event_type,
            path=str(path) if path else None,
            message=message,
            line_number=index,
        ))
        result.parsed_lines += 1
        result.counts[event_type] = result.counts.get(event_type, 0) + 1

    # Newest first keeps the "recent events" table consistent with the log view.
    result.events.sort(key=lambda event: event.timestamp)
    return result


def event_logger_timestamp(value) -> Optional[datetime]:
    """Parse an ISO-8601 UTC timestamp into a naive datetime for the renderers.

    The renderers were built for ``filewatch.log``'s naive timestamps, so the
    UTC marker is dropped after conversion. ``None`` means "unparsable".
    """
    if isinstance(value, datetime):
        moment = value
    elif value is None:
        return None
    else:
        text = str(value).strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            moment = datetime.fromisoformat(text)
        except ValueError:
            return None
    if moment.tzinfo is not None:
        moment = moment.astimezone(timezone.utc).replace(tzinfo=None)
    return moment


def render_markdown(report: Dict[str, object]) -> str:
    """Render a report dictionary as a Markdown document."""
    counts = report["counts"]
    lines: List[str] = []

    lines.append("# FileWatch - File Integrity Report")
    lines.append("")
    lines.append(f"**Generated:** {report['generated_at']}  ")
    lines.append(f"**Data source:** {report.get('data_source') or 'Text log'}  ")
    lines.append(f"**Location:** `{report['log_path']}`  ")
    if report.get("filters"):
        lines.append(f"**Filters:** {', '.join(str(f) for f in report['filters'])}  ")
    lines.append(f"**Events analysed:** {report['change_count']} change event(s)")
    lines.append("")

    if report.get("error"):
        lines.append("## ⚠️ No log data available"
                     if report.get("source") != "db"
                     else "## ⚠️ No database events available")
        lines.append("")
        lines.append(f"> {report['error']}")
        lines.append("")
        lines.append("Create events first, then import them for SQLite reports:")
        lines.append("")
        lines.append("```bash")
        lines.append("python3 main.py baseline")
        lines.append("python3 main.py watch --interval 5")
        lines.append("python3 main.py import-events")
        lines.append("```")
        lines.append("")
        lines.append(_EDUCATIONAL_NOTE)
        lines.append("")
        lines.append(f"> **LEGAL AND ETHICAL NOTICE:** {_LEGAL_NOTICE}")
        lines.append("")
        return "\n".join(lines)

    lines.append("## Event summary")
    lines.append("")
    lines.append("| Event type | Count |")
    lines.append("| --- | ---: |")
    for name in EVENT_ORDER:
        lines.append(f"| {name} | {counts.get(name, 0)} |")
    lines.append(f"| **Total changes** | **{report['change_count']}** |")
    lines.append("")
    if report.get("source") == "db" and not report["change_count"]:
        lines.append("> **No events in this view.** The database was read "
                     "successfully but no rows matched. Widen the date range "
                     "or clear the filters, and re-run "
                     "`python3 main.py import-events` if nothing has been "
                     "imported yet.")
        lines.append("")

    lines.append("## Log health")
    lines.append("")
    lines.append(f"- Lines read: **{report['total_lines']}**")
    lines.append(f"- Recognised lines: **{report['parsed_lines']}**")
    lines.append(f"- Informational lines (INFO/DEBUG): **{report['info_lines']}**")
    lines.append(f"- Malformed lines: **{report['malformed_lines']}**")
    if report.get("truncated"):
        lines.append("- **Note:** the log was larger than the read limit; only "
                     "the most recent portion was analysed.")
    if report.get("malformed_lines"):
        lines.append("")
        lines.append("> Malformed lines can mean a crash, two processes writing at "
                     "once, or someone editing the log. Investigate before "
                     "trusting this report.")
    lines.append("")

    if report.get("first_event"):
        lines.append(f"**First event:** {report['first_event']}  ")
        lines.append(f"**Last event:** {report['last_event']}")
        lines.append("")

    lines.append("## Recent changes")
    lines.append("")
    if report["recent"]:
        lines.append("| Timestamp | Event | File | Level |")
        lines.append("| --- | --- | --- | --- |")
        for row in report["recent"]:
            lines.append(f"| {row['Timestamp']} | {row['Event']} | "
                         f"`{row['File']}` | {row['Level']} |")
    else:
        lines.append("No change events were found in the log.")
    lines.append("")

    if report["top_paths"]:
        lines.append("## Most frequently changed files")
        lines.append("")
        lines.append("| File | Events |")
        lines.append("| --- | ---: |")
        for path, count in report["top_paths"]:
            lines.append(f"| `{path}` | {count} |")
        lines.append("")

    lines.append("## Interpretation and limitations")
    lines.append("")
    lines.append(_EDUCATIONAL_NOTE)
    lines.append("")
    lines.append("Keep in mind:")
    lines.append("")
    lines.append("1. **Detection, not prevention.** Every event below already "
                 "happened; FileWatch does not block writes.")
    lines.append("2. **The baseline can be rewritten.** An attacker with write "
                 "access to `baseline.json` can make changes look normal. "
                 "Mitigate with `baseline --sign` and `check --require-signature`.")
    lines.append("3. **The HMAC key can be stolen.** Anyone holding the key can "
                 "re-sign a forged baseline. Keep the key outside the project "
                 "and rotate it if in doubt.")
    lines.append("4. **This log is not tamper-proof.** It is a local text file; "
                 "ship copies off the machine if you need durable evidence.")
    lines.append("")
    lines.append(f"> **LEGAL AND ETHICAL NOTICE:** {_LEGAL_NOTICE}")
    lines.append("")
    return "\n".join(lines)


def render_html(report: Dict[str, object]) -> str:
    """Render a report dictionary as a standalone HTML document.

    All dynamic values are escaped with :func:`html.escape`, so a file name
    such as ``<script>alert(1)</script>.txt`` appears as text and not as markup.
    """
    counts = report["counts"]
    escaped_notice = html.escape(_LEGAL_NOTICE)
    escaped_educational = html.escape(_EDUCATIONAL_NOTE)

    parts: List[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en"><head><meta charset="utf-8">')
    parts.append("<title>FileWatch - File Integrity Report</title>")
    parts.append(
        "<style>"
        "body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;"
        "max-width:960px;margin:2rem auto;padding:0 1rem;color:#1a1a1a;"
        "line-height:1.5}"
        "h1{border-bottom:3px solid #2b6cb0;padding-bottom:.4rem}"
        "h2{margin-top:2rem;color:#2b6cb0}"
        "table{border-collapse:collapse;width:100%;margin:.6rem 0 1.2rem}"
        "th,td{border:1px solid #cbd5e0;padding:.45rem .6rem;text-align:left;"
        "font-size:.94rem}"
        "th{background:#edf2f7}"
        "td.num,th.num{text-align:right}"
        ".meta{color:#4a5568;font-size:.92rem}"
        ".notice{border-left:5px solid #c53030;background:#fff5f5;"
        "padding:.8rem 1rem;margin:1.4rem 0}"
        ".notice strong{color:#c53030}"
        ".warn{background:#fffaf0;border-left:5px solid #dd6b20;"
        "padding:.8rem 1rem;margin:1rem 0}"
        ".empty{background:#f7fafc;border:1px dashed #a0aec0;padding:1.2rem;"
        "text-align:center;color:#4a5568}"
        "code{background:#edf2f7;padding:.1rem .3rem;border-radius:3px}"
        ".count-ADDED{color:#276749;font-weight:600}"
        ".count-MODIFIED{color:#b7791f;font-weight:600}"
        ".count-DELETED{color:#c53030;font-weight:600}"
        "footer{margin-top:3rem;font-size:.85rem;color:#718096;"
        "border-top:1px solid #e2e8f0;padding-top:1rem}"
        "</style>"
    )
    parts.append("</head><body>")
    parts.append("<h1>FileWatch &mdash; File Integrity Report</h1>")
    filters_html = ""
    if report.get("filters"):
        filters_html = ("<br>Filters: <code>"
                        + html.escape(", ".join(str(f) for f in report["filters"]))
                        + "</code>")
    parts.append('<p class="meta">'
                 f"Generated: <strong>{html.escape(str(report['generated_at']))}</strong><br>"
                 "Data source: "
                 f"<strong>{html.escape(str(report.get('data_source') or 'Text log'))}</strong>"
                 f"<br>Location: <code>{html.escape(str(report['log_path']))}</code>"
                 f"{filters_html}<br>"
                 f"Events analysed: <strong>{int(report['change_count'])}</strong> "
                 "change event(s)</p>")

    if report.get("error"):
        heading = ("No log data available" if report.get("source") != "db"
                   else "No database events available")
        if report.get("source") == "db":
            hint = ("<p>Create events, then import them:<br>"
                    "<code>python3 main.py baseline</code><br>"
                    "<code>python3 main.py watch --interval 5</code><br>"
                    "<code>python3 main.py import-events</code></p>")
        else:
            hint = ("<p>Run the monitor first:<br>"
                    "<code>python3 main.py baseline</code><br>"
                    "<code>python3 main.py watch --interval 5</code></p>")
        parts.append(f'<div class="empty"><strong>{heading}</strong>'
                     f"<p>{html.escape(str(report['error']))}</p>"
                     f"{hint}</div>")
        parts.append(f'<div class="notice"><strong>LEGAL AND ETHICAL NOTICE:</strong> '
                     f"{escaped_notice}</div>")
        parts.append(f"<p>{escaped_educational}</p>")
        parts.append("</body></html>")
        return "\n".join(parts)

    # --- event summary -----------------------------------------------------
    parts.append("<h2>Event summary</h2>")
    parts.append("<table><thead><tr><th>Event type</th>"
                 '<th class="num">Count</th></tr></thead><tbody>')
    for name in EVENT_ORDER:
        parts.append(f'<tr><td class="count-{name}">{name}</td>'
                     f'<td class="num">{counts.get(name, 0)}</td></tr>')
    parts.append(f'<tr><td><strong>Total changes</strong></td>'
                 f'<td class="num"><strong>{int(report["change_count"])}'
                 "</strong></td></tr>")
    parts.append("</tbody></table>")

    # --- log health --------------------------------------------------------
    parts.append("<h2>Log health</h2><ul>")
    parts.append(f"<li>Lines read: <strong>{int(report['total_lines'])}</strong></li>")
    parts.append(f"<li>Recognised lines: <strong>{int(report['parsed_lines'])}</strong></li>")
    parts.append(f"<li>Informational (INFO/DEBUG): "
                 f"<strong>{int(report['info_lines'])}</strong></li>")
    parts.append(f"<li>Malformed lines: <strong>{int(report['malformed_lines'])}</strong></li>")
    if report.get("truncated"):
        parts.append("<li><strong>Only the most recent portion of a very large "
                     "log was analysed.</strong></li>")
    parts.append("</ul>")

    if report.get("malformed_lines"):
        parts.append('<div class="warn">Malformed lines can mean a crash, two '
                     "processes writing at once, or someone editing the log. "
                     "Investigate before trusting this report.</div>")

    if report.get("first_event"):
        parts.append('<p class="meta">'
                     f"First event: {html.escape(str(report['first_event']))} &middot; "
                     f"Last event: {html.escape(str(report['last_event']))}</p>")

    # --- recent changes ----------------------------------------------------
    parts.append("<h2>Recent changes</h2>")
    if report["recent"]:
        parts.append("<table><thead><tr><th>Timestamp</th><th>Event</th>"
                     "<th>File</th><th>Level</th></tr></thead><tbody>")
        for row in report["recent"]:
            parts.append(
                "<tr>"
                f"<td>{html.escape(str(row['Timestamp']))}</td>"
                f"<td>{html.escape(str(row['Event']))}</td>"
                f"<td><code>{html.escape(str(row['File']))}</code></td>"
                f"<td>{html.escape(str(row['Level']))}</td>"
                "</tr>")
        parts.append("</tbody></table>")
    else:
        parts.append('<div class="empty">No change events were found in the log.'
                     "</div>")

    # --- top paths ---------------------------------------------------------
    if report["top_paths"]:
        parts.append("<h2>Most frequently changed files</h2>")
        parts.append("<table><thead><tr><th>File</th>"
                     '<th class="num">Events</th></tr></thead><tbody>')
        for path, count in report["top_paths"]:
            parts.append(f"<tr><td><code>{html.escape(str(path))}</code></td>"
                         f'<td class="num">{count}</td></tr>')
        parts.append("</tbody></table>")

    # --- limitations -------------------------------------------------------
    parts.append("<h2>Interpretation and limitations</h2>")
    parts.append(f"<p>{escaped_educational}</p>")
    parts.append("<ol>")
    parts.append("<li><strong>Detection, not prevention.</strong> Every event "
                 "listed already happened; FileWatch does not block writes.</li>")
    parts.append("<li><strong>The baseline can be rewritten.</strong> An attacker "
                 "with write access to <code>baseline.json</code> can make changes "
                 "look normal. Mitigate with <code>baseline --sign</code> and "
                 "<code>check --require-signature</code>.</li>")
    parts.append("<li><strong>The HMAC key can be stolen.</strong> Anyone holding "
                 "the key can re-sign a forged baseline. Keep the key outside the "
                 "project and rotate it if in doubt.</li>")
    parts.append("<li><strong>This log is not tamper-proof.</strong> It is a local "
                 "text file; ship copies off the machine if you need durable "
                 "evidence.</li>")
    parts.append("</ol>")

    parts.append(f'<div class="notice"><strong>LEGAL AND ETHICAL NOTICE:</strong> '
                 f"{escaped_notice}</div>")
    parts.append("<footer>Generated by FileWatch (educational use). "
                 "No secrets or keys are included in this report.</footer>")
    parts.append("</body></html>")
    return "\n".join(parts)


def write_report(report: Dict[str, object], output_path,
                 fmt: Optional[str] = None) -> Path:
    """Write a report to ``output_path``.

    ``fmt`` is inferred from the file extension (``.md``/``.markdown`` or
    ``.html``/``.htm``) when not given. Returns the path written and raises
    :class:`ValueError` for an unsupported format and :class:`OSError` if the
    file cannot be written - the CLI turns those into clean error messages.
    """
    target = Path(output_path)
    chosen = (fmt or target.suffix.lstrip(".")).lower()

    if chosen in ("md", "markdown"):
        content = render_markdown(report)
    elif chosen in ("html", "htm"):
        content = render_html(report)
    else:
        raise ValueError(
            f"Unsupported report format {chosen!r}. Use .md or .html")

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content + "\n", encoding="utf-8")
    return target


def render_report(result: ParseResult, fmt: str = "md", **kwargs) -> str:
    """Convenience wrapper: parse result -> rendered report string."""
    report = build_report_data(result, **kwargs)
    return render_markdown(report) if fmt == "md" else render_html(report)
