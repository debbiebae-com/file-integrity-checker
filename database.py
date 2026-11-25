#!/usr/bin/env python3
"""
FileWatch SQLite event store
============================

Persistent, queryable storage for the structured events produced by
``event_logger.py``. Uses only :mod:`sqlite3` from the standard library.

Design
------
* **Optional.** Weeks 1-4 monitoring, baselines and HMAC signing never require
  this module. If it is unused, nothing changes.
* **Idempotent.** The schema is created with ``CREATE TABLE IF NOT EXISTS`` and
  existing rows are never deleted by normal startup.
* **Duplicate-proof.** Every event has a deterministic ``event_id`` (a SHA-256
  over the identifying fields). It is ``UNIQUE``, and imports use
  ``INSERT OR IGNORE``, so importing the same JSONL file twice adds nothing.
  This is the documented uniqueness strategy - it needs no mutable counter and
  survives re-encoding of the JSON.
* **Parameterised SQL only.** No query is ever built by string concatenation of
  user data. Filtering uses named parameters.
* **Transactional.** Imports run in a single transaction; a failure rolls the
  whole batch back, so you never get half an import.
* **Thread-safe by construction.** Each call opens its own connection
  (``sqlite3.connect`` is cheap), which keeps the module safe for Streamlit,
  for the CLI and for tests without sharing cursors.

Schema
------
::

    CREATE TABLE events (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id   TEXT    NOT NULL UNIQUE,   -- stable dedupe key (sha256 hex)
        timestamp  TEXT    NOT NULL,          -- ISO 8601 UTC, e.g. 2026-11-25T18:07:16Z
        event_type TEXT    NOT NULL,          -- ADDED | MODIFIED | DELETED
        path       TEXT    NOT NULL,          -- relative, POSIX separators
        algorithm  TEXT,                      -- sha256 | sha1 | NULL
        old_hash   TEXT,                      -- NULL for ADDED
        new_hash   TEXT,                      -- NULL for DELETED
        source     TEXT    NOT NULL,          -- watch | import | ...
        imported_at TEXT   NOT NULL           -- when this row was inserted (UTC)
    );

    CREATE INDEX idx_events_timestamp  ON events(timestamp);
    CREATE INDEX idx_events_type       ON events(event_type);
    CREATE INDEX idx_events_path       ON events(path);

Timezone handling
-----------------
Timestamps are stored **only** in UTC ISO 8601 ``Z`` form, so string comparison
is chronological comparison - which is what makes ``BETWEEN`` filtering correct
and fast. :func:`normalise_bound` accepts either a date (``2026-11-25``) or a
full timestamp, and always converts to UTC:

* ``start`` dates are inclusive, anchored at ``00:00:00Z`` of that day,
* ``end`` dates are inclusive, anchored at ``23:59:59Z`` of that day (so
  ``--end 2026-11-25`` includes everything that happened on the 25th),
* an offset such as ``+02:00`` is converted to UTC before comparison.
"""

from __future__ import annotations

import hashlib
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

import event_logger as el

#: Default database file, at the project root.
DEFAULT_DB_PATH = Path("filewatch.db")

#: Schema version, recorded in ``PRAGMA user_version``.
SCHEMA_VERSION = 1

#: Columns of the events table, in order (used for inserts and row mapping).
COLUMNS: Tuple[str, ...] = (
    "event_id", "timestamp", "event_type", "path",
    "algorithm", "old_hash", "new_hash", "source", "imported_at",
)

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id    TEXT NOT NULL UNIQUE,
    timestamp   TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    path        TEXT NOT NULL,
    algorithm   TEXT,
    old_hash    TEXT,
    new_hash    TEXT,
    source      TEXT NOT NULL,
    imported_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type      ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_path      ON events(path);
"""


# ---------------------------------------------------------------------------
# Connections
# ---------------------------------------------------------------------------

@contextmanager
def connect(db_path=DEFAULT_DB_PATH) -> Iterator[sqlite3.Connection]:
    """Open a connection, yield it inside a transaction, and always close it.

    ``isolation_level=None`` would disable transactions, so it is left at the
    default: writes are grouped and committed explicitly by the caller (or by
    this context manager on success).
    """
    target = Path(db_path)
    if target.parent and str(target.parent) not in ("", "."):
        target.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(str(target))
    connection.row_factory = sqlite3.Row
    try:
        # Durable and safe defaults: WAL improves concurrent reads (the
        # dashboard reading while watch writes), and foreign_keys stays on for
        # future tables.
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db(db_path=DEFAULT_DB_PATH) -> Path:
    """Create the database file and schema if they do not exist yet.

    Safe to call on every startup: it never drops tables and never deletes rows.
    Returns the database path.
    """
    target = Path(db_path)
    with connect(target) as connection:
        connection.executescript(_SCHEMA_SQL)
        connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
    return target


# ---------------------------------------------------------------------------
# Event identity (dedupe strategy)
# ---------------------------------------------------------------------------

def compute_event_id(record: Dict[str, object]) -> str:
    """Return the stable identifier for an event.

    The id is a SHA-256 over the fields that define the event itself -
    timestamp, type, path, algorithm and both hashes. ``source`` and
    ``imported_at`` are deliberately excluded so that the same real change
    imported from two different paths (say ``watch`` and a later re-import)
    is recognised as one event.

    The value is a hash, not a secret: it contains no key material and cannot
    be reversed into the original fields.
    """
    parts = [
        str(record.get("timestamp") or ""),
        str(record.get("event_type") or "").upper(),
        str(record.get("path") or ""),
        str(record.get("algorithm") or ""),
        str(record.get("old_hash") or ""),
        str(record.get("new_hash") or ""),
    ]
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()
    return digest


def _row_values(record: Dict[str, object]) -> Tuple[object, ...]:
    """Map a schema record to the column tuple used by INSERT."""
    return (
        compute_event_id(record),
        str(record.get("timestamp")),
        str(record.get("event_type")).upper(),
        str(record.get("path")),
        record.get("algorithm"),
        record.get("old_hash"),
        record.get("new_hash"),
        str(record.get("source") or "unknown"),
        el.utc_now_iso(),
    )


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------

def insert_events(records: Iterable[Dict[str, object]],
                  db_path=DEFAULT_DB_PATH) -> Dict[str, int]:
    """Insert events, skipping duplicates. Returns ``{"inserted": n, "duplicates": n}``.

    Invalid records (failing :func:`event_logger.validate_event`) are counted as
    ``rejected`` rather than aborting the batch. The whole valid batch is one
    transaction: if the insert fails, nothing is written and the exception
    propagates to the caller.
    """
    init_db(db_path)

    inserted = 0
    duplicates = 0
    rejected = 0

    with connect(db_path) as connection:
        for record in records:
            ok, _problems = el.validate_event(record)
            if not ok:
                rejected += 1
                continue

            cursor = connection.execute(
                "INSERT OR IGNORE INTO events "
                "(event_id, timestamp, event_type, path, algorithm, "
                " old_hash, new_hash, source, imported_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                _row_values(record),
            )
            if cursor.rowcount:
                inserted += 1
            else:
                duplicates += 1

    return {"inserted": inserted, "duplicates": duplicates, "rejected": rejected}


def import_jsonl(events_path=el.DEFAULT_EVENTS_PATH,
                 db_path=DEFAULT_DB_PATH) -> Dict[str, object]:
    """Import a JSONL file into SQLite.

    Returns a summary dictionary::

        {"source": "...", "inserted": 3, "duplicates": 0, "rejected": 0,
         "malformed_lines": 0, "parse_errors": [...], "missing": False}

    Missing or empty input is reported, never raised. Malformed lines are
    skipped and listed, so an operator can fix them instead of losing them
    silently.
    """
    parsed = el.read_events(events_path)
    summary: Dict[str, object] = {
        "source": str(events_path),
        "database": str(db_path),
        "missing": parsed["missing"],
        "inserted": 0,
        "duplicates": 0,
        "rejected": 0,
        "malformed_lines": len(parsed["errors"]),  # type: ignore[arg-type]
        "parse_errors": parsed["errors"],
    }

    events = parsed["events"]  # type: ignore[assignment]
    if not events:
        return summary

    counts = insert_events(events, db_path)  # type: ignore[arg-type]
    summary.update(counts)
    return summary


# ---------------------------------------------------------------------------
# Time filters
# ---------------------------------------------------------------------------

def normalise_bound(value: Optional[str], end: bool = False) -> Optional[str]:
    """Turn a user-supplied date/time into a UTC ISO string for comparison.

    * ``None`` or empty  -> ``None`` (no bound),
    * ``YYYY-MM-DD``     -> ``T00:00:00Z`` (start) or ``T23:59:59Z`` (end),
    * full ISO 8601      -> converted to UTC and normalised,
    * unparsable         -> ``ValueError`` (callers show a clear message).

    Inclusive by design: an end date of ``2026-11-25`` includes the whole day.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None

    # A bare date gets a whole-day anchor.
    if len(text) == 10 and text[4] == "-" and text[7] == "-":
        suffix = "T23:59:59Z" if end else "T00:00:00Z"
        try:
            datetime.strptime(text, "%Y-%m-%d")
        except ValueError as exc:
            raise ValueError(f"Invalid date {value!r}: expected YYYY-MM-DD") from exc
        return text + suffix

    moment = el.parse_timestamp(text)
    if moment is None:
        raise ValueError(
            f"Invalid timestamp {value!r}: use YYYY-MM-DD or ISO 8601 "
            f"(e.g. 2026-11-25T18:00:00Z)"
        )
    return el.format_timestamp(moment)


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------

def _build_filters(start_date: Optional[str] = None,
                   end_date: Optional[str] = None,
                   event_type: Optional[str] = None,
                   path: Optional[str] = None,
                   source: Optional[str] = None
                   ) -> Tuple[str, Dict[str, object]]:
    """Build the WHERE clause and parameters (never by string concatenation)."""
    clauses: List[str] = []
    params: Dict[str, object] = {}

    start = normalise_bound(start_date, end=False)
    end = normalise_bound(end_date, end=True)
    if start:
        clauses.append("timestamp >= :start")
        params["start"] = start
    if end:
        clauses.append("timestamp <= :end")
        params["end"] = end

    if event_type:
        types = [item.strip().upper() for item in str(event_type).split(",") if item.strip()]
        unknown = [item for item in types if item not in el.EVENT_TYPES]
        if unknown:
            raise ValueError(
                f"Invalid event_type {unknown[0]!r}; "
                f"choose from {', '.join(el.EVENT_TYPES)}"
            )
        placeholders = ", ".join(f":type{i}" for i in range(len(types)))
        clauses.append(f"event_type IN ({placeholders})")
        for index, item in enumerate(types):
            params[f"type{index}"] = item

    if path:
        # Single-character ESCAPE clause: SQLite rejects anything longer.
        clauses.append("path LIKE :path ESCAPE '\\'")
        escaped = str(path).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        params["path"] = f"%{escaped}%"

    if source:
        clauses.append("source = :source")
        params["source"] = source

    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


def query_events(db_path=DEFAULT_DB_PATH,
                 start_date: Optional[str] = None,
                 end_date: Optional[str] = None,
                 event_type: Optional[str] = None,
                 path: Optional[str] = None,
                 source: Optional[str] = None,
                 limit: Optional[int] = 100,
                 offset: int = 0,
                 newest_first: bool = True) -> List[Dict[str, object]]:
    """Query stored events with optional filters.

    All filters are combinable. ``limit=None`` returns everything (use with
    care); the dashboard always passes a limit so it never loads an unbounded
    result set into memory.

    Returns a list of dictionaries with the :data:`COLUMNS` plus ``id``.
    A missing database yields an empty list rather than an error.
    """
    if not Path(db_path).exists():
        return []

    where, params = _build_filters(start_date, end_date, event_type, path, source)
    order = "DESC" if newest_first else "ASC"
    sql = f"SELECT id, {', '.join(COLUMNS)} FROM events{where} ORDER BY timestamp {order}, id {order}"

    if limit is not None:
        sql += " LIMIT :limit OFFSET :offset"
        params["limit"] = max(0, int(limit))
        params["offset"] = max(0, int(offset))

    with connect(db_path) as connection:
        rows = connection.execute(sql, params).fetchall()

    return [dict(row) for row in rows]


def count_by_type(db_path=DEFAULT_DB_PATH,
                  start_date: Optional[str] = None,
                  end_date: Optional[str] = None,
                  event_type: Optional[str] = None,
                  path: Optional[str] = None,
                  source: Optional[str] = None) -> Dict[str, int]:
    """Return ``{event_type: count}`` for the given filters.

    Always includes all three event types (zero when absent), so callers can
    render stable metrics.
    """
    counts = {name: 0 for name in el.EVENT_TYPES}
    if not Path(db_path).exists():
        return counts

    where, params = _build_filters(start_date, end_date, event_type, path, source)
    sql = f"SELECT event_type, COUNT(*) AS n FROM events{where} GROUP BY event_type"

    with connect(db_path) as connection:
        for row in connection.execute(sql, params):
            counts[str(row["event_type"])] = int(row["n"])
    return counts


def total_events(db_path=DEFAULT_DB_PATH,
                 start_date: Optional[str] = None,
                 end_date: Optional[str] = None,
                 event_type: Optional[str] = None,
                 path: Optional[str] = None) -> int:
    """Return the total number of events matching the filters."""
    if not Path(db_path).exists():
        return 0

    where, params = _build_filters(start_date, end_date, event_type, path)
    with connect(db_path) as connection:
        row = connection.execute(f"SELECT COUNT(*) AS n FROM events{where}", params).fetchone()
    return int(row["n"]) if row else 0


def timeline_counts(db_path=DEFAULT_DB_PATH,
                    start_date: Optional[str] = None,
                    end_date: Optional[str] = None,
                    event_type: Optional[str] = None,
                    path: Optional[str] = None,
                    bucket: str = "hour") -> List[Dict[str, object]]:
    """Aggregate counts per time bucket for charts.

    ``bucket`` is ``"hour"`` (default) or ``"date"``. Aggregation happens in
    SQLite (``substr`` on the UTC ISO string), so the dashboard never has to
    pull every row into Python.
    """
    if bucket not in ("hour", "date"):
        raise ValueError("bucket must be 'hour' or 'date'")
    if not Path(db_path).exists():
        return []

    where, params = _build_filters(start_date, end_date, event_type, path)
    length = 13 if bucket == "hour" else 10  # "YYYY-MM-DDTHH" or "YYYY-MM-DD"
    sql = (
        f"SELECT substr(timestamp, 1, {length}) AS bucket, event_type, COUNT(*) AS n "
        f"FROM events{where} GROUP BY bucket, event_type ORDER BY bucket ASC"
    )

    grouped: Dict[str, Dict[str, object]] = {}
    with connect(db_path) as connection:
        for row in connection.execute(sql, params):
            key = str(row["bucket"])
            entry = grouped.setdefault(
                key, {"bucket": key, **{name: 0 for name in el.EVENT_TYPES}, "total": 0}
            )
            entry[str(row["event_type"])] = int(row["n"])  # type: ignore[index]
            entry["total"] = int(entry["total"]) + int(row["n"])  # type: ignore[operator]

    return [grouped[key] for key in sorted(grouped)]


def date_range(db_path=DEFAULT_DB_PATH) -> Tuple[Optional[str], Optional[str]]:
    """Return the (earliest, latest) stored timestamps, or ``(None, None)``."""
    if not Path(db_path).exists():
        return (None, None)
    with connect(db_path) as connection:
        row = connection.execute(
            "SELECT MIN(timestamp) AS lo, MAX(timestamp) AS hi FROM events"
        ).fetchone()
    if not row or row["lo"] is None:
        return (None, None)
    return (str(row["lo"]), str(row["hi"]))


def database_status(db_path=DEFAULT_DB_PATH) -> Dict[str, object]:
    """Small health summary used by the dashboard and the CLI."""
    target = Path(db_path)
    status: Dict[str, object] = {
        "path": str(target),
        "exists": target.exists(),
        "size_bytes": target.stat().st_size if target.exists() else 0,
        "events": 0,
        "first": None,
        "last": None,
        "error": None,
    }
    if not target.exists():
        return status
    try:
        status["events"] = total_events(target)
        first, last = date_range(target)
        status["first"], status["last"] = first, last
    except sqlite3.Error as exc:  # corrupt file, not a database, ...
        status["error"] = f"Could not read database: {exc}"
    return status


def events_as_rows(events: Iterable[Dict[str, object]]) -> List[Dict[str, str]]:
    """Shape database rows for a table / CSV export (same keys as the log view)."""
    return [
        {
            "Timestamp": str(event.get("timestamp", "")),
            "Event": str(event.get("event_type", "")),
            "File": str(event.get("path", "")),
            "Algorithm": str(event.get("algorithm") or "-"),
            "Old hash": (str(event["old_hash"])[:12] + "…") if event.get("old_hash") else "-",
            "New hash": (str(event["new_hash"])[:12] + "…") if event.get("new_hash") else "-",
            "Source": str(event.get("source", "")),
        }
        for event in events
    ]
