#!/usr/bin/env python3
"""
FileWatch structured event log (JSON Lines)
===========================================

Weeks 1-4 wrote a human-readable ``filewatch.log``. That format is preserved
exactly - it is never changed by this module, so existing users keep working.

This module adds a **second, machine-readable** record alongside it:
``events.jsonl``, one self-contained JSON object per line.

Why both?
---------
* ``filewatch.log`` is for humans: timestamps, levels, readable messages.
* ``events.jsonl`` is for tools: a fixed schema that SQLite, the dashboard and
  the reports can consume without re-parsing prose.

Schema (version 1)
------------------
Every line is a complete JSON object with these fields:

===========  ===========================================================
Field        Meaning
===========  ===========================================================
timestamp    ISO 8601 **UTC**, e.g. ``2026-11-25T18:07:16Z``
event_type   ``ADDED``, ``MODIFIED`` or ``DELETED``
path         relative path of the affected file (POSIX separators)
algorithm    hashing algorithm, where applicable (``sha256`` / ``sha1``)
old_hash     previous digest (``MODIFIED``/``DELETED``), else ``null``
new_hash     current digest (``ADDED``/``MODIFIED``), else ``null``
source       which operation produced it (``watch``, ``import``, ...)
===========  ===========================================================

Hashes are lowercase hex. Paths are relative to the monitored folder and never
absolute, so a JSONL file can be shared without leaking your home directory.

Guarantees
----------
* **Append-only.** Records are opened with mode ``"a"``; previous lines are
  never rewritten or truncated.
* **One object per line, always.** A single ``write()`` per record, so a crash
  can at worst leave one truncated final line - and readers skip bad lines
  instead of dying (see :func:`read_events`).
* **No secrets.** Only the fields above are written. Keys, tokens and
  environment variables are never recorded.
* **Never fatal.** Every failure is returned/reported, never raised into the
  monitoring loop, so a full disk cannot stop integrity monitoring.

Compatibility note
------------------
The JSONL file is *additive*. ``logger_parser.py`` continues to parse
``filewatch.log`` unchanged; nothing in this module alters that file or its
format.
"""

from __future__ import annotations

import json
import re
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

#: Default structured event file, at the project root.
DEFAULT_EVENTS_PATH = Path("events.jsonl")

#: Schema version written into nothing but documented here for future use.
SCHEMA_VERSION = 1

#: The only event types this schema defines.
EVENT_TYPES: Tuple[str, ...] = ("ADDED", "MODIFIED", "DELETED")

#: Field order used when serialising (nice for humans reading the file).
FIELD_ORDER: Tuple[str, ...] = (
    "timestamp", "event_type", "path", "algorithm",
    "old_hash", "new_hash", "source",
)

#: Maximum number of events returned by one monitoring cycle, as a guard
#: against a pathological first scan writing millions of lines.
MAX_EVENTS_PER_SCAN = 10_000

#: A hex digest is the only hash representation we accept (sha256 = 64 chars).
HASH_RE = re.compile(r"^[0-9a-f]{8,128}$")


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    """Return the current time as ``YYYY-MM-DDTHH:MM:SSZ`` (UTC, second precision)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def format_timestamp(moment: datetime) -> str:
    """Format a ``datetime`` as the schema's UTC ISO 8601 form.

    A naive datetime is assumed to be UTC (the monitoring engine only ever uses
    UTC internally); an aware one is converted to UTC first.
    """
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_timestamp(text: str) -> Optional[datetime]:
    """Parse a schema timestamp into an **aware UTC** datetime.

    Accepts the canonical ``...Z`` form and common ISO 8601 variants
    (``+00:00`` offsets, fractional seconds, missing timezone = UTC).
    Returns ``None`` for anything unparsable - callers decide what to do.
    """
    if not isinstance(text, str) or not text.strip():
        return None

    candidate = text.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        # Fall back to a couple of explicit layouts for older/odd inputs.
        for layout in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
                       "%Y-%m-%dT%H:%M:%S.%f"):
            try:
                parsed = datetime.strptime(candidate, layout)
                break
            except ValueError:
                continue
        else:
            return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# Record construction and validation
# ---------------------------------------------------------------------------

def make_event(event_type: str,
               path: str,
               algorithm: Optional[str] = None,
               old_hash: Optional[str] = None,
               new_hash: Optional[str] = None,
               source: str = "watch",
               timestamp: Optional[str] = None) -> Dict[str, object]:
    """Build one schema-conformant event dictionary.

    Raises :class:`ValueError` for an unknown event type or an empty path -
    those are programming errors, not runtime conditions.
    """
    normalised_type = str(event_type).strip().upper()
    if normalised_type not in EVENT_TYPES:
        raise ValueError(
            f"Unsupported event_type {event_type!r}; "
            f"expected one of {', '.join(EVENT_TYPES)}"
        )
    if not str(path).strip():
        raise ValueError("path must not be empty")

    return {
        "timestamp": timestamp or utc_now_iso(),
        "event_type": normalised_type,
        "path": Path(str(path)).as_posix(),
        "algorithm": algorithm.lower() if isinstance(algorithm, str) else None,
        "old_hash": old_hash,
        "new_hash": new_hash,
        "source": source,
    }


def validate_event(record: object) -> Tuple[bool, List[str]]:
    """Check a parsed record against the schema.

    Returns ``(ok, problems)``. ``problems`` lists every issue found, so an
    importer can report *why* a line was rejected instead of silently dropping
    it. This function never raises.
    """
    problems: List[str] = []

    if not isinstance(record, dict):
        return False, ["record is not a JSON object"]

    for field in FIELD_ORDER:
        if field not in record:
            problems.append(f"missing field: {field}")

    event_type = record.get("event_type")
    if event_type is not None and str(event_type).upper() not in EVENT_TYPES:
        problems.append(f"invalid event_type: {event_type!r}")

    path = record.get("path")
    if path is not None and (not isinstance(path, str) or not path.strip()):
        problems.append("invalid path: must be a non-empty string")

    timestamp = record.get("timestamp")
    if timestamp is not None and parse_timestamp(str(timestamp)) is None:
        problems.append(f"invalid timestamp: {timestamp!r}")

    for hash_field in ("old_hash", "new_hash"):
        value = record.get(hash_field)
        if value is None:
            continue
        if not isinstance(value, str):
            problems.append(f"invalid {hash_field}: must be a string or null")
        elif not HASH_RE.match(value):
            problems.append(f"invalid {hash_field}: not a lowercase hex digest")

    return (not problems), problems


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------

def serialise_event(record: Dict[str, object]) -> str:
    """Serialise one event to a single JSON line (no trailing newline).

    Key order follows :data:`FIELD_ORDER` for readability, unknown keys are
    dropped, and the output is compact so one record is unambiguously one line.
    ``ensure_ascii=False`` keeps non-ASCII paths readable; the file is UTF-8.
    """
    ordered = {key: record.get(key) for key in FIELD_ORDER}
    return json.dumps(ordered, ensure_ascii=False, separators=(",", ":"))


def append_events(records: Iterable[Dict[str, object]],
                  events_path=DEFAULT_EVENTS_PATH) -> Tuple[int, Optional[str]]:
    """Append events to ``events.jsonl``. Returns ``(written, error)``.

    * opens in **append** mode, so nothing already on disk is destroyed,
    * writes UTF-8, one object per line, one ``write()`` per record,
    * creates the parent directory if needed,
    * returns an error string instead of raising, so a read-only or full disk
      cannot stop the monitoring loop.

    The monitoring engine treats a non-``None`` error as a warning: the events
    are still reported on the terminal and in ``filewatch.log``, and they can be
    re-imported later from the human log if necessary.
    """
    records = [record for record in records if record is not None]
    if not records:
        return 0, None

    target = Path(events_path)
    try:
        if target.parent and str(target.parent) not in ("", "."):
            target.parent.mkdir(parents=True, exist_ok=True)
        # newline="\n" keeps the format identical on every platform, so a file
        # written on Windows still parses on Linux.
        with open(target, "a", encoding="utf-8", newline="\n") as handle:
            written = 0
            for record in records[:MAX_EVENTS_PER_SCAN]:
                handle.write(serialise_event(record) + "\n")
                written += 1
            handle.flush()
            os.fsync(handle.fileno())
        return written, None
    except (OSError, TypeError, ValueError) as exc:
        return 0, f"Could not append to {target}: {exc}"


def events_from_result(result: Dict[str, list],
                       current: Optional[Dict[str, dict]] = None,
                       baseline: Optional[Dict[str, dict]] = None,
                       algorithm: str = "sha256",
                       source: str = "watch",
                       timestamp: Optional[str] = None) -> List[Dict[str, object]]:
    """Convert one comparison result into schema events.

    ``current`` and ``baseline`` provide the hashes:

    * ``ADDED``    -> ``new_hash``  from the current snapshot,
    * ``MODIFIED`` -> ``old_hash``  from the baseline reference,
                      ``new_hash``  from the current snapshot,
    * ``DELETED``  -> ``old_hash``  from the baseline reference.

    Unreadable and skipped files are **not** emitted: their content is unknown,
    so any record would be a guess. They remain visible in ``filewatch.log`` and
    on the terminal, which is the honest place for them.
    """
    def digest(entry: Optional[dict]) -> Optional[str]:
        if not entry:
            return None
        if isinstance(entry, str):
            return entry
        if isinstance(entry, dict):
            value = entry.get(algorithm)
            return value if isinstance(value, str) else None
        return None

    events: List[Dict[str, object]] = []
    stamp = timestamp or utc_now_iso()

    for name in result.get("added", []):
        events.append(make_event("ADDED", name, algorithm=algorithm,
                                 old_hash=None,
                                 new_hash=digest((current or {}).get(name)),
                                 source=source, timestamp=stamp))

    for name in result.get("modified", []):
        events.append(make_event("MODIFIED", name, algorithm=algorithm,
                                 old_hash=digest((baseline or {}).get(name)),
                                 new_hash=digest((current or {}).get(name)),
                                 source=source, timestamp=stamp))

    for name in result.get("deleted", []):
        events.append(make_event("DELETED", name, algorithm=algorithm,
                                 old_hash=digest((baseline or {}).get(name)),
                                 new_hash=None,
                                 source=source, timestamp=stamp))

    return events


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------

def parse_event_line(line: str) -> Tuple[Optional[Dict[str, object]], Optional[str]]:
    """Parse and validate one JSONL line.

    Returns ``(record, error)``. On success ``record`` is a normalised event
    (timestamp canonicalised to UTC ``Z`` form). On failure ``record`` is
    ``None`` and ``error`` explains why. Never raises.
    """
    stripped = line.strip()
    if not stripped:
        return None, "empty line"

    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON: {exc.msg} (line {exc.lineno}, col {exc.colno})"

    ok, problems = validate_event(payload)
    if not ok:
        return None, "; ".join(problems)

    # Normalise: uppercase type, canonical timestamp, POSIX path, lowercase hash.
    moment = parse_timestamp(str(payload["timestamp"]))
    normalised = {
        "timestamp": format_timestamp(moment),
        "event_type": str(payload["event_type"]).upper(),
        "path": Path(str(payload["path"])).as_posix(),
        "algorithm": (str(payload["algorithm"]).lower()
                      if payload.get("algorithm") else None),
        "old_hash": payload.get("old_hash"),
        "new_hash": payload.get("new_hash"),
        "source": payload.get("source") or "unknown",
    }
    return normalised, None


def read_events(events_path=DEFAULT_EVENTS_PATH,
                limit: Optional[int] = None) -> Dict[str, object]:
    """Read and parse a JSONL event file.

    Returns a dictionary (never raises)::

        {
          "events":   [ {...}, ... ],       # valid, normalised records
          "errors":   [ "line 3: ..." ],    # one entry per rejected line
          "total":    42,                   # lines seen (excluding blanks)
          "source":   "events.jsonl",
          "missing":  False,                # True if the file does not exist
        }

    ``limit`` keeps only the **most recent** N events (the file is append-only,
    so the newest records are at the end).
    """
    target = Path(events_path)
    outcome: Dict[str, object] = {
        "events": [], "errors": [], "total": 0,
        "source": str(target), "missing": False,
    }

    if not target.exists():
        outcome["missing"] = True
        return outcome

    try:
        with open(target, "r", encoding="utf-8", errors="replace", newline="") as handle:
            for index, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                outcome["total"] = int(outcome["total"]) + 1
                record, error = parse_event_line(line)
                if record is not None:
                    outcome["events"].append(record)  # type: ignore[union-attr]
                else:
                    outcome["errors"].append(f"line {index}: {error}")  # type: ignore[union-attr]
    except OSError as exc:
        outcome["errors"].append(f"could not read {target}: {exc}")  # type: ignore[union-attr]

    if limit is not None and limit >= 0:
        outcome["events"] = outcome["events"][-limit:] if limit else []  # type: ignore[index]

    return outcome


def count_events(events_path=DEFAULT_EVENTS_PATH) -> int:
    """Return the number of valid events in the file (0 when missing)."""
    return len(read_events(events_path)["events"])  # type: ignore[arg-type]
