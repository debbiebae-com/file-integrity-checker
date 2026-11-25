#!/usr/bin/env python3
"""
FileWatch reporting CLI
=======================

Week 4 command-line front-end for :mod:`logger_parser`.

    python3 report.py events                 # parsed events as a table
    python3 report.py report --format md     # Markdown integrity report
    python3 report.py report --format html   # HTML integrity report
    python3 report.py report --format both   # both, at once

Week 4 enhanced adds a SQLite source, so the same reports can be built from
``filewatch.db`` instead of the text log:

    python3 report.py report --source db --start 2026-11-01 --end 2026-11-30
    python3 report.py report --source db --format both --type MODIFIED

Design notes
------------
* **Standard library only.** The ``table`` output is rendered by hand rather
  than with a third-party library, so this works on a machine where nothing
  has been pip-installed (the Week 1-3 guarantee).
* **Read-only.** Nothing here writes to the log, the baseline or the monitored
  folder. The only files written are the report files you ask for, and those
  default to the ``reports/`` directory.
* **Never crashes on bad input.** A missing, empty or malformed log produces a
  clear message and a report that says so, with a non-zero exit code so scripts
  can react.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional, Sequence

import logger_parser as lp

#: Where reports are written by default.
DEFAULT_REPORT_DIR = Path("reports")

#: Default names for the two report formats.
DEFAULT_REPORT_STEM = "integrity-report"

EXIT_OK = 0
EXIT_FAILURE = 1


# ---------------------------------------------------------------------------
# Console table rendering (no dependencies)
# ---------------------------------------------------------------------------

def render_table(headers: Sequence[str],
                 rows: Sequence[Sequence[str]],
                 max_widths: Optional[Sequence[int]] = None) -> str:
    """Render a plain-text table with aligned columns.

    Long cells are truncated with an ellipsis so a deeply nested path cannot
    blow the layout apart on a narrow terminal.
    """
    if not rows:
        return "(no rows)"

    headers = list(headers)
    string_rows = [[str(cell) for cell in row] for row in rows]

    widths = [len(header) for header in headers]
    for row in string_rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    if max_widths:
        for index, cap in enumerate(max_widths):
            widths[index] = min(widths[index], cap)

    def fit(cell: str, width: int) -> str:
        return cell if len(cell) <= width else cell[: max(0, width - 1)] + "…"

    header_line = "  ".join(fit(h, w).ljust(w) for h, w in zip(headers, widths))
    separator = "  ".join("-" * w for w in widths)

    body = [
        "  ".join(fit(c, w).ljust(w) for c, w in zip(row, widths))
        for row in string_rows
    ]
    return "\n".join([header_line, separator] + body)


def print_events(result: lp.ParseResult, limit: Optional[int] = None) -> int:
    """Print parsed events in a structured table. Returns an exit code."""
    if result.has_error:
        print(f"  [ERROR] {result.error}", file=sys.stderr)
        print("  Hint: run `python3 main.py baseline` then "
              "`python3 main.py watch --interval 5` to create log events.",
              file=sys.stderr)
        return EXIT_FAILURE

    print("=" * 92)
    print("FILEWATCH - PARSED LOG EVENTS".center(92))
    print("=" * 92)
    print(f"Log file   : {result.source}")
    print(f"Lines read : {result.total_lines}  "
          f"(recognised {result.parsed_lines}, malformed {result.malformed_lines})")
    print(f"Summary    : {lp.summarize(result)}")
    print("-" * 92)

    if not result.events:
        print()
        print("  No log events available.")
        print("  The log exists but contains no ADDED/MODIFIED/DELETED/ERROR lines.")
        print("  Run the monitor and change a file in test_folder to create some:")
        print("      python3 main.py watch --interval 5")
        print("-" * 92)
        return EXIT_OK

    counts = lp.event_counts(result)
    print("Event counts:")
    for name in lp.EVENT_ORDER:
        print(f"  {name:<12} {counts.get(name, 0)}")
    print("-" * 92)

    events = lp.recent_events(result, limit) if limit else result.events
    rows = [
        [
            event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            event.event_type,
            event.level,
            event.path or "-",
        ]
        for event in events
    ]
    print(render_table(["Timestamp", "Event", "Level", "File"], rows,
                       max_widths=[19, 11, 8, 46]))
    print("-" * 92)
    print(f"Showing {len(rows)} event(s)"
          + (f" (most recent {limit})" if limit and limit < len(result.events) else ""))

    if result.malformed_lines:
        print()
        print(f"  [WARNING] {result.malformed_lines} line(s) could not be parsed. "
              "First few:")
        for sample in result.malformed_samples[:3]:
            print(f"      {sample}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

#: Where the SQLite database lives by default (Week 4 enhanced).
DEFAULT_DB_PATH = Path("filewatch.db")


def _db_result(db_path, start: Optional[str] = None, end: Optional[str] = None,
               event_type: Optional[str] = None, path: Optional[str] = None,
               limit: Optional[int] = None) -> "lp.ParseResult":
    """Read events from SQLite and shape them like a parsed log.

    A missing, empty or corrupt database yields an *empty* result carrying a
    human-readable ``error`` string: the report still gets written, and it says
    plainly where the data was meant to come from and what went wrong.
    """
    try:
        import database
    except ImportError as exc:  # pragma: no cover - defensive
        return lp.result_from_events([], source=str(db_path),
                                     error=f"SQLite support unavailable: {exc}")

    target = Path(db_path)
    if not target.exists():
        return lp.result_from_events(
            [], source=str(db_path),
            error=(f"No database at {target}. Create it with "
                   "`python3 main.py import-events`."),
        )

    try:
        rows = database.query_events(
            target, start_date=start, end_date=end, event_type=event_type,
            path=path, limit=limit, newest_first=False,
        )
    except ValueError as exc:
        return lp.result_from_events([], source=str(db_path), error=str(exc))
    except Exception as exc:  # noqa: BLE001 - sqlite3.Error and friends
        return lp.result_from_events([], source=str(db_path),
                                     error=f"Could not read database: {exc}")

    return lp.result_from_events(rows, source=str(db_path))


def generate_reports(log_path=lp.DEFAULT_LOG_PATH,
                     output_dir=DEFAULT_REPORT_DIR,
                     fmt: str = "md",
                     recent_limit: int = 20,
                     source: str = "log",
                     db_path=DEFAULT_DB_PATH,
                     start: Optional[str] = None,
                     end: Optional[str] = None,
                     event_type: Optional[str] = None,
                     path: Optional[str] = None,
                     stem: Optional[str] = None) -> List[Path]:
    """Build report(s) from the log **or** the SQLite database.

    ``source="log"`` keeps the Week 4 behaviour byte for byte.
    ``source="db"`` reads ``filewatch.db`` with optional date/type/path filters.
    """
    if source not in ("log", "db"):
        raise ValueError(f"Unsupported source {source!r}; use log or db.")

    if source == "db":
        result = _db_result(db_path, start=start, end=end,
                            event_type=event_type, path=path)
        report = lp.build_report_data(result, recent_limit=recent_limit,
                                      log_path=db_path)
    else:
        result = lp.parse_log_file(log_path)
        report = lp.build_report_data(result, recent_limit=recent_limit,
                                      log_path=log_path)

    # Make the data source unmistakable in the document itself.
    report["source"] = source
    report["data_source"] = (
        f"SQLite database ({db_path})" if source == "db"
        else f"Text log ({log_path})"
    )
    if source == "db":
        active = [f"{name}={value}" for name, value in
                  (("start", start), ("end", end), ("type", event_type),
                   ("path", path)) if value]
        report["filters"] = active

    output_dir = Path(output_dir)
    written: List[Path] = []
    base = stem or (DEFAULT_REPORT_STEM if source == "log"
                    else f"{DEFAULT_REPORT_STEM}-db")

    if fmt in ("md", "both"):
        written.append(lp.write_report(report, output_dir / f"{base}.md"))
    if fmt in ("html", "both"):
        written.append(lp.write_report(report, output_dir / f"{base}.html"))
    if not written:
        raise ValueError(f"Unsupported format {fmt!r}; use md, html or both.")

    return written


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point for ``python3 report.py``."""
    parser = argparse.ArgumentParser(
        prog="report.py",
        description=("FileWatch reporting: show parsed log events or generate an "
                     "integrity report from filewatch.log."),
        epilog=("Examples:\n"
                "  python3 report.py events\n"
                "  python3 report.py report --format md\n"
                "  python3 report.py report --format html\n"
                "  python3 report.py report --format both --out reports\n"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("command", nargs="?", default="events",
                        choices=["events", "report"],
                        help="'events' prints the parsed table, 'report' writes a file")
    parser.add_argument("--log", default="filewatch.log", metavar="PATH",
                        help="log file to parse (default: filewatch.log)")
    parser.add_argument("--format", default="md", choices=["md", "html", "both"],
                        dest="fmt", help="report format (default: md)")
    parser.add_argument("--out", default=str(DEFAULT_REPORT_DIR), metavar="DIR",
                        help=f"directory for generated reports (default: {DEFAULT_REPORT_DIR})")
    parser.add_argument("--limit", type=int, default=None, metavar="N",
                        help="'events': show only the N most recent events")
    parser.add_argument("--recent", type=int, default=20, metavar="N",
                        help="'report': number of recent changes to include (default: 20)")
    # --- Week 4 enhanced: SQLite source -----------------------------------------
    parser.add_argument("--source", default="log", choices=["log", "db"],
                        help="where to read events from (default: log)")
    parser.add_argument("--db", default=str(DEFAULT_DB_PATH), metavar="PATH",
                        help=f"SQLite database for --source db (default: {DEFAULT_DB_PATH})")
    parser.add_argument("--start", default=None, metavar="DATE",
                        help="'--source db': inclusive start date/time, e.g. 2026-11-01")
    parser.add_argument("--end", default=None, metavar="DATE",
                        help="'--source db': inclusive end date/time")
    parser.add_argument("--type", dest="event_type", default=None,
                        choices=["ADDED", "MODIFIED", "DELETED"],
                        help="'--source db': only this event type")
    parser.add_argument("--path", default=None, metavar="TEXT",
                        help="'--source db': only paths containing this text")

    args = parser.parse_args(argv)

    if args.command == "events":
        if args.source == "db":
            result = _db_result(args.db, start=args.start, end=args.end,
                                event_type=args.event_type, path=args.path)
            if result.error:
                print(f"  [WARNING] {result.error}", file=sys.stderr)
        else:
            result = lp.parse_log_file(args.log)
        return print_events(result, limit=args.limit)

    # -- report ---------------------------------------------------------
    if args.source == "db":
        result = _db_result(args.db, start=args.start, end=args.end,
                            event_type=args.event_type, path=args.path)
    else:
        result = lp.parse_log_file(args.log)
    if result.has_error:
        # Still write a report: a report that says "no data" is more useful
        # than no report at all, and it makes the failure explicit.
        print(f"  [WARNING] {result.error}", file=sys.stderr)

    try:
        written = generate_reports(args.log, args.out, args.fmt, args.recent,
                                   source=args.source, db_path=args.db,
                                   start=args.start, end=args.end,
                                   event_type=args.event_type, path=args.path)
    except (OSError, ValueError) as exc:
        print(f"  [ERROR] Could not write report: {exc}", file=sys.stderr)
        return EXIT_FAILURE

    print("=" * 74)
    print("FILEWATCH - INTEGRITY REPORT".center(74))
    print("=" * 74)
    if args.source == "db":
        print(f"Source   : SQLite database {args.db}")
        active = [f"{name}={value}" for name, value in
                  (("start", args.start), ("end", args.end),
                   ("type", args.event_type), ("path", args.path)) if value]
        print(f"Filters  : {', '.join(active) if active else 'none'}")
    else:
        print(f"Log file : {args.log}")
    print(f"Summary  : {lp.summarize(result)}")
    for path in written:
        print(f"Written  : {path}  ({path.stat().st_size} bytes)")
    print("=" * 74)

    if result.malformed_lines:
        print(f"  [WARNING] {result.malformed_lines} malformed line(s) were "
              "skipped while parsing.")

    return EXIT_FAILURE if result.has_error else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
