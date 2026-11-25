#!/usr/bin/env python3
"""
FileWatch Streamlit dashboard
=============================

Week 4 of the FileWatch project. A read-only web dashboard over
``filewatch.log``.

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
* a **Refresh** button, plus an auto-refresh toggle for hands-off monitoring.

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
        # Empty by default so $FILEWATCH_LOG (or the project default) applies;
        # typing a name here overrides both.
        log_override = st.text_input(
            "Log file (optional)", value="",
            placeholder=str(DEFAULT_LOG_PATH.name),
            help=("Path to the log to read. Leave blank to use $FILEWATCH_LOG, "
                  "then filewatch.log next to this file."),
        )

    # --- load data ---------------------------------------------------------
    data = load_dashboard_data(log_override or None, bucket)
    result: lp.ParseResult = data["parse_result"]
    counts = data["counts"]

    st.markdown(f"**Log file:** `{data['path']}`")
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

    # --- footer ------------------------------------------------------------
    st.divider()
    st.caption(
        "**Limitations:** FileWatch detects changes but does not prevent attacks. "
        "The baseline can be rewritten, the HMAC key can be stolen, and this log "
        "is a local text file that is not tamper-proof. "
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
