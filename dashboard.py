#!/usr/bin/env python3
"""
FileWatch Streamlit dashboard
=============================

Week 4 introduced this read-only web dashboard over ``filewatch.log``.
Week 4 enhanced adds a **SQLite backend** (``filewatch.db``) with date and event-type
filters, a refresh control and graceful handling of a missing database.

Both sources stay available - pick one in the sidebar; ``log`` behaves exactly
as it did in Week 4.

Run it with::

    python3 -m pip install -r requirements.txt
    python3 -m streamlit run dashboard.py

What it shows
-------------
* headline metrics: total changes, plus ADDED / MODIFIED / DELETED counts,
* a timeline chart of changes over time (plotly via Streamlit, with a
  matplotlib fallback and a plain-table fallback so it degrades gracefully),
* the most recent integrity events as a table,
* an optional filtered view and CSV download,
* a **Refresh** button, plus an auto-refresh toggle for hands-off monitoring,
* (Week 4 enhanced) a ``db``/``log`` source switch, inclusive start/end date filters and
  event-type filters backed by indexed SQL queries.

Design notes
------------
* **Read-only.** The dashboard never writes to the log, the baseline or the
  monitored folder. The only place it can write is the report download button,
  which is generated in memory.
* **No secrets.** It displays log events only. HMAC keys are never read, shown
  or logged here.
* **Degrades without optional packages.** Streamlit itself requires
  ``pandas``; if neither plotly nor matplotlib is available, the timeline is
  drawn with Streamlit's built-in ``bar_chart`` instead of failing.
* **Import-safe.** All Streamlit calls happen inside :func:`main`, so the module
  can be imported (and tested) without a Streamlit runtime.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import logger_parser as lp

#: Default log file location, next to this script.
DEFAULT_LOG_PATH = Path(__file__).resolve().parent / "filewatch.log"

#: How the page is laid out and titled.
PAGE_TITLE = "FileWatch - File Integrity Dashboard"

#: Default SQLite database location, next to this script (Week 4 enhanced).
DEFAULT_DB_PATH = Path(__file__).resolve().parent / "filewatch.db"

#: Never load more rows than this into the browser in one go.
MAX_ROWS = 5000

#: Colour scheme used consistently in charts and metric deltas.
EVENT_COLOURS = {
    "ADDED": "#2f855a",      # green
    "MODIFIED": "#b7791f",   # amber
    "DELETED": "#c53030",    # red
    "UNREADABLE": "#805ad5", # purple
    "ERROR": "#4a5568",      # grey
}


# ---------------------------------------------------------------------------
# Pure helpers (no Streamlit) - easy to unit-test
# ---------------------------------------------------------------------------

def resolve_log_path(log_path: Optional[str] = None) -> Path:
    """Return the log path to read.

    Precedence: explicit argument -> ``FILEWATCH_LOG`` environment variable ->
    ``filewatch.log`` next to this file. Relative paths are resolved against the
    project directory so the dashboard behaves the same from any cwd.
    """
    import os

    if log_path:
        candidate = Path(log_path)
    elif os.environ.get("FILEWATCH_LOG"):
        candidate = Path(os.environ["FILEWATCH_LOG"])
    else:
        candidate = DEFAULT_LOG_PATH

    if not candidate.is_absolute():
        candidate = Path(__file__).resolve().parent / candidate
    return candidate


def resolve_db_path(db_path: Optional[str] = None) -> Path:
    """Return the SQLite database path to read.

    Precedence: explicit argument -> ``FILEWATCH_DB`` environment variable ->
    ``filewatch.db`` next to this file. Relative paths resolve against the
    project directory, matching :func:`resolve_log_path`.
    """
    import os

    if db_path:
        candidate = Path(db_path)
    elif os.environ.get("FILEWATCH_DB"):
        candidate = Path(os.environ["FILEWATCH_DB"])
    else:
        candidate = DEFAULT_DB_PATH

    if not candidate.is_absolute():
        candidate = Path(__file__).resolve().parent / candidate
    return candidate


def load_db_dashboard_data(db_path: Optional[str] = None,
                           start: Optional[str] = None,
                           end: Optional[str] = None,
                           event_type: Optional[str] = None,
                           path_filter: Optional[str] = None,
                           bucket: str = "hour",
                           limit: int = 200) -> dict:
    """Read filtered events from SQLite and shape them for the dashboard.

    Never raises: a missing database, a corrupt file, a locked file or a bad
    date all come back as an ``error`` string with empty results, so the UI can
    explain the problem instead of crashing.

    Queries are always bounded - ``limit`` is clamped to :data:`MAX_ROWS` - so
    the dashboard never pulls an entire table into memory.
    """
    target = resolve_db_path(db_path)
    data = {
        "path": target,
        "source": "db",
        "events": [],
        "counts": {name: 0 for name in lp.EVENT_TYPES},
        "timeline_rows": [],
        "recent_rows": [],
        "total": 0,
        "error": None,
        "first": None,
        "last": None,
        "has_events": False,
    }

    if not target.exists():
        data["error"] = (
            f"No database at {target}. Create one with "
            "`python3 main.py watch` then `python3 main.py import-events`."
        )
        return data

    try:
        import database
    except ImportError as exc:  # pragma: no cover - defensive
        data["error"] = f"SQLite support unavailable: {exc}"
        return data

    safe_limit = max(1, min(int(limit), MAX_ROWS))
    try:
        data["counts"] = database.count_by_type(
            target, start_date=start, end_date=end,
            event_type=event_type, path=path_filter,
        )
        data["total"] = sum(data["counts"].get(name, 0)
                            for name in lp.CHANGE_EVENTS)
        data["events"] = database.query_events(
            target, start_date=start, end_date=end, event_type=event_type,
            path=path_filter, limit=safe_limit, newest_first=True,
        )
        data["timeline_rows"] = database.timeline_counts(
            target, start_date=start, end_date=end, event_type=event_type,
            path=path_filter, bucket=bucket,
        )
        data["first"], data["last"] = database.date_range(target)
    except ValueError as exc:          # bad date / bad event type
        data["error"] = str(exc)
        return data
    except Exception as exc:           # noqa: BLE001 - sqlite3.Error etc.
        data["error"] = f"Could not read database {target}: {exc}"
        return data

    rows = []
    for event in data["events"]:
        rows.append({
            "Timestamp": str(event.get("timestamp", "")),
            "Event": str(event.get("event_type", "")),
            "File": str(event.get("path", "")),
            "Source": str(event.get("source", "")),
            "Old hash": (str(event.get("old_hash"))[:16] + "…"
                         if event.get("old_hash") else ""),
            "New hash": (str(event.get("new_hash"))[:16] + "…"
                         if event.get("new_hash") else ""),
        })
    data["recent_rows"] = rows
    data["has_events"] = bool(data["events"])
    return data


def load_dashboard_data(log_path: Optional[str] = None,
                        bucket: str = "minute") -> dict:
    """Parse the log and return everything the dashboard renders.

    Returns a dictionary with ``parse_result``, ``counts``, ``timeline_rows``,
    ``recent_rows`` and ``summary``. Never raises for a missing/broken log -
    the parse result carries the error instead.
    """
    path = resolve_log_path(log_path)
    result = lp.parse_log_file(path)

    return {
        "path": path,
        "parse_result": result,
        "counts": lp.event_counts(result),
        "timeline_rows": lp.timeline_rows(result, bucket=bucket),
        "recent_rows": lp.events_as_rows(result, limit=50),
        "summary": lp.summarize(result),
        "has_events": bool(result.events),
        "error": result.error,
    }


def events_to_csv(rows: List[dict]) -> str:
    """Convert event rows to CSV text (used by the download button)."""
    if not rows:
        return ""
    headers = list(rows[0])
    lines = [",".join(headers)]
    for row in rows:
        cells = []
        for header in headers:
            value = str(row.get(header, "")).replace('"', '""')
            cells.append(f'"{value}"')
        lines.append(",".join(cells))
    return "\n".join(lines) + "\n"


def empty_state_message(log_path: Path, result: lp.ParseResult) -> str:
    """A helpful message for the 'nothing to show' case."""
    if result.error:
        return (
            f"**{result.error}**\n\n"
            "Start the monitor to create events:\n\n"
            "```bash\n"
            "python3 main.py baseline\n"
            "python3 main.py watch --interval 5\n"
            "```\n\n"
            f"The dashboard is looking for: `{log_path}`"
        )
    return (
        "**No log events available.**\n\n"
        f"`{log_path}` exists but contains no ADDED, MODIFIED, DELETED or ERROR "
        "events yet. Change a file inside `test_folder` while the monitor is "
        "running, then press **Refresh**."
    )


# ---------------------------------------------------------------------------
# Streamlit UI
# ---------------------------------------------------------------------------

def _stretch_kwargs(st) -> dict:
    """Return the correct "full width" keyword for this Streamlit version.

    Streamlit renamed ``use_container_width`` to ``width="stretch"``; the old
    name still works but emits a deprecation warning and will be removed. This
    keeps the dashboard quiet on both old and new versions.
    """
    version = getattr(st, "__version__", "0")
    try:
        major, minor = (int(part) for part in version.split(".")[:2])
    except (ValueError, AttributeError):  # pragma: no cover - odd version string
        return {}
    if (major, minor) >= (1, 49):
        return {"width": "stretch"}
    return {"use_container_width": True}


def _render_timeline(st, rows: List[dict]) -> None:
    """Draw the timeline chart, degrading gracefully without plotly/matplotlib."""
    if not rows:
        st.info("No changes to plot yet - the timeline appears once events exist.")
        return

    # 1) Preferred: plotly, which Streamlit ships with in most installs.
    try:
        import plotly.graph_objects as go

        figure = go.Figure()
        for name in lp.CHANGE_EVENTS:
            figure.add_trace(go.Bar(
                x=[row["bucket"] for row in rows],
                y=[row[name] for row in rows],
                name=name,
                marker_color=EVENT_COLOURS.get(name),
            ))
        figure.update_layout(
            barmode="stack",
            height=380,
            margin=dict(l=10, r=10, t=30, b=10),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0),
            yaxis_title="Events",
            xaxis_title="Time",
        )
        st.plotly_chart(figure, **_stretch_kwargs(st))
        return
    except Exception:  # pragma: no cover - optional dependency
        pass

    # 2) Fallback: Streamlit's built-in bar chart (needs only pandas).
    try:
        import pandas as pd

        frame = pd.DataFrame(rows).set_index("bucket")[list(lp.CHANGE_EVENTS)]
        st.bar_chart(frame)
        return
    except Exception:  # pragma: no cover - optional dependency
        pass

    # 3) Last resort: a plain table, so the data is never hidden.
    st.table(rows)


def main() -> None:
    """Entry point used by ``streamlit run dashboard.py``."""
    import streamlit as st

    st.set_page_config(page_title=PAGE_TITLE, page_icon="🛡️", layout="wide")

    st.title("🛡️ FileWatch - File Integrity Dashboard")
    st.caption(
        "Local, read-only view of `filewatch.log`. "
        "FileWatch detects changes to files you own - it does not prevent attacks."
    )

    # --- sidebar controls --------------------------------------------------
    with st.sidebar:
        st.header("Controls")
        if st.button("🔄 Refresh",
                     help="Re-read filewatch.log and redraw the dashboard",
                     **_stretch_kwargs(st)):
            st.rerun()

        auto = st.checkbox("Auto-refresh", value=False,
                           help="Re-read the log every few seconds")
        interval = st.slider("Refresh interval (seconds)", 2, 60, 5,
                             disabled=not auto)

        st.divider()
        st.subheader("Filters")
        chosen_types = st.multiselect(
            "Event types",
            options=list(lp.EVENT_ORDER),
            default=list(lp.CHANGE_EVENTS),
            help="Which event types to show in the table below",
        )
        bucket = st.selectbox("Timeline bucket", ["minute", "hour", "day"],
                              index=0)
        recent_limit = st.slider("Rows in the event table", 5, 200, 25)

        st.divider()
        st.subheader("Data source")
        source = st.radio(
            "Read events from",
            options=["log", "db"],
            index=0,
            horizontal=True,
            format_func=lambda value: ("Text log" if value == "log"
                                       else "SQLite database"),
            help=("'Text log' parses filewatch.log (Week 4 behaviour). "
                  "'SQLite database' reads filewatch.db with indexed filters."),
        )

        db_start = db_end = None
        db_types: List[str] = []
        db_path_filter = ""
        if source == "db":
            st.caption("Inclusive dates (UTC). Leave blank for no limit.")
            db_start = st.text_input("Start date (YYYY-MM-DD)", value="",
                                     placeholder="2026-11-01") or None
            db_end = st.text_input("End date (YYYY-MM-DD)", value="",
                                   placeholder="2026-11-30") or None
            db_types = st.multiselect(
                "Event types (database)",
                options=list(lp.CHANGE_EVENTS),
                default=list(lp.CHANGE_EVENTS),
                help="Leave all selected for every type. Multi-selects combine "
                     "with the date range.",
            )
            db_path_filter = st.text_input(
                "Path contains (optional)", value="",
                placeholder="documents/") or None
            bucket = st.selectbox("Timeline bucket (database)", ["hour", "date"],
                                  index=0)
            recent_limit = st.slider("Rows in the event table", 5, 500, 50)

        st.divider()
        # Empty by default so $FILEWATCH_LOG (or the project default) applies;
        # typing a name here overrides both.
        log_override = st.text_input(
            "Log file (optional)", value="",
            placeholder=str(DEFAULT_LOG_PATH.name),
            help=("Path to the log to read. Leave blank to use $FILEWATCH_LOG, "
                  "then filewatch.log next to this file."),
        )
        db_override = st.text_input(
            "Database file (optional)", value="",
            placeholder=str(DEFAULT_DB_PATH.name),
            help=("Path to filewatch.db. Leave blank to use $FILEWATCH_DB, "
                  "then filewatch.db next to this file."),
        )

    # --- load data ---------------------------------------------------------
    if source == "db":
        _render_database_view(st, db_override or None, db_start, db_end,
                              db_types, db_path_filter, bucket, recent_limit)
    else:
        _render_log_view(st, log_override or None, bucket, chosen_types,
                         recent_limit)

    # --- footer ------------------------------------------------------------
    st.divider()
    st.caption(
        "**Limitations:** FileWatch detects changes but does not prevent attacks. "
        "The baseline can be rewritten, the HMAC key can be stolen, and both the "
        "log file and the local SQLite database are not tamper-proof. "
        "See README section 40+ for mitigations."
    )
    st.caption(
        "Scanning or attacking systems you do not own or have written permission "
        "to test is illegal. This tool only monitors your own test folder."
    )

    if auto:
        import time

        time.sleep(interval)
        st.rerun()


def _render_log_view(st, log_path, bucket, chosen_types, recent_limit) -> None:
    """Week 4 view, unchanged: everything derived from filewatch.log."""
    data = load_dashboard_data(log_path, bucket)
    result: lp.ParseResult = data["parse_result"]
    counts = data["counts"]

    st.markdown(f"**Source:** text log `{data['path']}`")
    st.markdown(f"**Summary:** {data['summary']}")

    # --- metrics -----------------------------------------------------------
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total changes", data["parse_result"].change_count)
    col2.metric("➕ Added", counts.get("ADDED", 0))
    col3.metric("✏️ Modified", counts.get("MODIFIED", 0))
    col4.metric("➖ Deleted", counts.get("DELETED", 0))

    if counts.get("UNREADABLE") or counts.get("ERROR"):
        st.warning(
            f"Attention: {counts.get('UNREADABLE', 0)} unreadable file event(s) "
            f"and {counts.get('ERROR', 0)} error event(s) in the log."
        )

    if result.malformed_lines:
        st.info(
            f"{result.malformed_lines} log line(s) could not be parsed "
            "(crash, concurrent writers, or hand-editing). "
            "Treat this as a signal worth investigating."
        )

    # --- timeline ----------------------------------------------------------
    st.subheader("Timeline of changes")
    _render_timeline(st, data["timeline_rows"])

    # --- recent events -----------------------------------------------------
    st.subheader("Recent integrity events")

    if not data["has_events"]:
        st.warning(empty_state_message(data["path"], result))
    else:
        filtered = lp.filter_events(result, chosen_types or None)
        rows = lp.events_as_rows(
            lp.ParseResult(events=filtered,
                           counts=result.counts,
                           source=result.source),
            limit=recent_limit,
        )

        if not rows:
            st.warning("No events match the current filters.")
        else:
            try:
                import pandas as pd

                st.dataframe(pd.DataFrame(rows), hide_index=True,
                             **_stretch_kwargs(st))
            except Exception:  # pragma: no cover - pandas missing
                st.table(rows)

            st.download_button(
                "⬇️ Download these events as CSV",
                data=events_to_csv(rows),
                file_name="filewatch-events.csv",
                mime="text/csv",
            )

            with st.expander("Generate a full integrity report"):
                report = lp.build_report_data(result, recent_limit=recent_limit,
                                              log_path=data["path"])
                st.download_button("⬇️ Markdown report",
                                   data=lp.render_markdown(report),
                                   file_name="integrity-report.md",
                                   mime="text/markdown")
                st.download_button("⬇️ HTML report",
                                   data=lp.render_html(report),
                                   file_name="integrity-report.html",
                                   mime="text/html")



def _render_database_view(st, db_path, start, end, types, path_filter,
                          bucket, limit) -> None:
    """Week 4 enhanced view: indexed SQLite queries with date/type/path filters."""
    # A multiselect of all three types means "no type filter"; anything else is
    # passed through as a comma-separated list understood by database.py.
    event_type = None
    if types and len(types) < len(lp.CHANGE_EVENTS):
        event_type = ",".join(types)
    elif types == []:
        st.warning("No event types selected - choose at least one to see rows.")
        return

    data = load_db_dashboard_data(db_path, start=start, end=end,
                                  event_type=event_type, path_filter=path_filter,
                                  bucket=bucket, limit=limit)

    st.markdown(f"**Source:** SQLite database `{data['path']}`")
    if data["error"]:
        st.error(data["error"])
        st.info(
            "The dashboard stays read-only and keeps working with the text log. "
            "Switch **Data source** in the sidebar to *Text log* if you have a "
            "filewatch.log."
        )
        return

    counts = data["counts"]
    span = (f"{data['first']} .. {data['last']}" if data["first"]
            else "no events stored")

    st.caption(f"Stored range (all events): {span}")
    active = [f"{name}={value}" for name, value in
              (("start", start), ("end", end), ("type", event_type),
               ("path", path_filter)) if value]
    st.caption("Active filters: " + (", ".join(active) if active else "none"))

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Matching changes", data["total"])
    col2.metric("➕ Added", counts.get("ADDED", 0))
    col3.metric("✏️ Modified", counts.get("MODIFIED", 0))
    col4.metric("➖ Deleted", counts.get("DELETED", 0))

    st.subheader(f"Timeline of changes (per {bucket})")
    _render_timeline(st, data["timeline_rows"])

    st.subheader("Most recent events")
    if not data["has_events"]:
        st.info(
            "No events match the current filters. Widen the date range, clear "
            "the path filter, or import more events with "
            "`python3 main.py import-events`."
        )
        return

    rows = data["recent_rows"]
    try:
        import pandas as pd

        st.dataframe(pd.DataFrame(rows), hide_index=True,
                     **_stretch_kwargs(st))
    except Exception:  # pragma: no cover - pandas missing
        st.table(rows)

    st.download_button(
        "⬇️ Download these events as CSV",
        data=events_to_csv(rows),
        file_name="filewatch-events-db.csv",
        mime="text/csv",
    )

    with st.expander("Generate a report from this database view"):
        # Reuse the Week 4 renderers through the shared adapter, so figures in
        # the report always match what is on screen.
        result = lp.result_from_events(
            list(reversed(data["events"])), source=str(data["path"]))
        report = lp.build_report_data(result, recent_limit=limit,
                                      log_path=data["path"])
        report["source"] = "db"
        report["data_source"] = f"SQLite database ({data['path']})"
        report["filters"] = active
        st.download_button("⬇️ Markdown report",
                           data=lp.render_markdown(report),
                           file_name="integrity-report-db.md",
                           mime="text/markdown")
        st.download_button("⬇️ HTML report",
                           data=lp.render_html(report),
                           file_name="integrity-report-db.html",
                           mime="text/html")


if __name__ == "__main__":
    # `streamlit run` executes this file as a script.
    main()
else:
    # Also render when Streamlit imports the module in its own runner.
    try:
        from streamlit.runtime import exists as _st_runtime_exists

        if _st_runtime_exists():
            main()
    except Exception:
        pass
