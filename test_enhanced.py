#!/usr/bin/env python3
"""
Week 4 enhanced tests: structured JSONL events, SQLite storage, DB-backed reports and
the DB-backed dashboard view.

Run with::

    python3 -m pytest test_enhanced.py -q
    python3 -m unittest test_enhanced -v

Every test works inside ``tmp_path`` / ``tempfile``. Nothing here touches the
real ``baseline.json``, ``filewatch.log``, ``events.jsonl``, ``filewatch.db``
or the sample files in ``test_folder``.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import dashboard
import database
import event_logger as el
import logger_parser as lp
import main
import report as rp

PROJECT_ROOT = Path(__file__).resolve().parent
MAIN_PY = PROJECT_ROOT / "main.py"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_events(path: Path, count: int = 3) -> Path:
    """Write a small, valid JSONL file and return its path."""
    records = [
        el.make_event("ADDED", "new.txt", new_hash="a" * 64,
                      timestamp="2026-11-01T09:00:00Z"),
        el.make_event("MODIFIED", "docs/notes.txt", old_hash="a" * 64,
                      new_hash="b" * 64, timestamp="2026-11-02T10:30:00Z"),
        el.make_event("DELETED", "docs/old.txt", old_hash="b" * 64,
                      timestamp="2026-11-03T23:59:59Z"),
    ][:count]
    written, error = el.append_events(records, path)
    assert error is None, error
    assert written == len(records)
    return path


def cli(*args, cwd=None):
    """Run main.py in a subprocess so argument parsing is exercised end to end."""
    return subprocess.run(
        [sys.executable, str(MAIN_PY), *args],
        capture_output=True, text=True, cwd=str(cwd or PROJECT_ROOT), timeout=120,
    )


# ---------------------------------------------------------------------------
# 1. JSONL event log
# ---------------------------------------------------------------------------

def test_jsonl_file_has_one_valid_object_per_line(tmp_path):
    path = make_events(tmp_path / "events.jsonl")
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) == 3
    for line in lines:
        record = json.loads(line)  # raises if not valid JSON
        assert set(record) == set(el.FIELD_ORDER)


def test_jsonl_timestamps_are_iso8601_utc(tmp_path):
    path = make_events(tmp_path / "events.jsonl")
    for record in el.read_events(path)["events"]:
        assert record["timestamp"].endswith("Z")
        assert el.parse_timestamp(record["timestamp"]) is not None


def test_jsonl_is_append_only(tmp_path):
    path = tmp_path / "events.jsonl"
    make_events(path, 1)
    before = path.read_text(encoding="utf-8")
    el.append_events([el.make_event("ADDED", "second.txt", new_hash="c" * 64)], path)
    after = path.read_text(encoding="utf-8")
    assert after.startswith(before), "existing records must never be rewritten"
    assert len(el.read_events(path)["events"]) == 2


def test_jsonl_contains_no_secret_material(tmp_path):
    path = make_events(tmp_path / "events.jsonl")
    text = path.read_text(encoding="utf-8")
    low = text.lower()
    for token in ("password", "api_key", "apikey", "secret", "token", "hmac"):
        assert token not in low


def test_jsonl_malformed_line_is_skipped_and_reported(tmp_path):
    path = tmp_path / "events.jsonl"
    make_events(path, 1)
    with path.open("a", encoding="utf-8") as handle:
        handle.write("{this is not json\n")
        handle.write("\n")                       # blank line
        handle.write('{"incomplete": \n')        # truncated object
    parsed = el.read_events(path)
    assert len(parsed["events"]) == 1
    assert parsed["errors"], "malformed input must be reported, not silently dropped"


def test_jsonl_missing_field_is_rejected(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(json.dumps({
        "timestamp": "2026-11-01T09:00:00Z",
        "event_type": "ADDED",
        # path missing
        "algorithm": "sha256", "old_hash": None,
        "new_hash": "a" * 64, "source": "watch",
    }) + "\n", encoding="utf-8")

    parsed = el.read_events(path)
    assert parsed["events"] == []
    assert parsed["errors"]


def test_jsonl_invalid_timestamp_is_rejected(tmp_path):
    path = tmp_path / "events.jsonl"
    bad = el.make_event("ADDED", "x.txt", new_hash="a" * 64)
    bad["timestamp"] = "not-a-timestamp"
    path.write_text(json.dumps(bad) + "\n", encoding="utf-8")

    parsed = el.read_events(path)
    assert parsed["events"] == []
    assert any("timestamp" in error.lower() for error in parsed["errors"])


def test_validate_event_rejects_unknown_type_and_bad_hash():
    ok, problems = el.validate_event(el.make_event("ADDED", "a.txt",
                                                   new_hash="a" * 64))
    assert ok and not problems

    # make_event refuses an unknown type outright (a programming error) ...
    with unittest.TestCase().assertRaises(ValueError):
        el.make_event("RENAMED", "a.txt", new_hash="a" * 64)
    # ... and a record built by hand is caught by the validator.
    ok, problems = el.validate_event({"timestamp": "2026-11-01T00:00:00Z",
                                      "event_type": "RENAMED", "path": "a.txt",
                                      "algorithm": None, "old_hash": None,
                                      "new_hash": "a" * 64, "source": "watch"})
    assert not ok and problems

    bad_hash = el.make_event("ADDED", "a.txt", new_hash="zzzz")
    ok, problems = el.validate_event(bad_hash)
    assert not ok and problems, "a non-hex digest must be rejected"


def test_missing_jsonl_file_is_not_an_error(tmp_path):
    parsed = el.read_events(tmp_path / "nothing.jsonl")
    assert parsed["events"] == [] and parsed["errors"] == []
    assert el.count_events(tmp_path / "nothing.jsonl") == 0


# ---------------------------------------------------------------------------
# 2. SQLite schema, insertion, persistence
# ---------------------------------------------------------------------------

def test_database_is_created_with_expected_schema(tmp_path):
    db = tmp_path / "fw.db"
    assert not db.exists()
    database.init_db(db)
    assert db.exists()

    with database.connect(db) as connection:
        columns = {row["name"] for row in
                   connection.execute("PRAGMA table_info(events)")}
        indexes = {row["name"] for row in
                   connection.execute("PRAGMA index_list(events)")}

    assert {"id", "timestamp", "event_type", "path", "algorithm",
            "old_hash", "new_hash", "source"} <= columns
    assert {"idx_events_timestamp", "idx_events_type", "idx_events_path"} <= indexes


def test_insert_and_read_back(tmp_path):
    db = tmp_path / "fw.db"
    records = [el.make_event("ADDED", "a.txt", new_hash="a" * 64),
               el.make_event("DELETED", "b.txt", old_hash="b" * 64)]
    counts = database.insert_events(records, db)

    assert counts["inserted"] == 2 and counts["duplicates"] == 0
    rows = database.query_events(db, newest_first=False)
    assert [row["path"] for row in rows] == ["a.txt", "b.txt"]
    assert database.total_events(db) == 2


def test_database_persists_across_connections(tmp_path):
    db = tmp_path / "fw.db"
    database.insert_events([el.make_event("ADDED", "keep.txt",
                                          new_hash="a" * 64)], db)
    # A brand-new connection (new process-like state) still sees the row.
    assert database.total_events(db) == 1
    assert database.query_events(db)[0]["path"] == "keep.txt"


def test_duplicate_import_is_a_no_op(tmp_path):
    db = tmp_path / "fw.db"
    path = make_events(tmp_path / "events.jsonl")

    first = database.import_jsonl(path, db)
    second = database.import_jsonl(path, db)

    assert first["inserted"] == 3 and first["duplicates"] == 0
    assert second["inserted"] == 0 and second["duplicates"] == 3
    assert database.total_events(db) == 3, "re-import must never duplicate rows"


def test_event_id_is_stable_and_content_based():
    record = el.make_event("MODIFIED", "docs/a.txt", old_hash="a" * 64,
                           new_hash="b" * 64, timestamp="2026-11-01T00:00:00Z")
    first = database.compute_event_id(record)
    assert first == database.compute_event_id(dict(record))
    changed = dict(record, new_hash="c" * 64)
    assert database.compute_event_id(changed) != first


def test_reimport_never_deletes_existing_rows(tmp_path):
    db = tmp_path / "fw.db"
    database.insert_events([el.make_event("ADDED", "original.txt",
                                          new_hash="a" * 64)], db)
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    database.import_jsonl(empty, db)
    assert database.total_events(db) == 1


def test_sql_uses_parameters_not_concatenation(tmp_path):
    """A hostile path is stored and matched literally, never executed."""
    db = tmp_path / "fw.db"
    hostile = "x'; DROP TABLE events;--"
    database.insert_events([el.make_event("ADDED", hostile,
                                          new_hash="a" * 64)], db)
    rows = database.query_events(db, path="'; DROP", newest_first=False)
    assert [row["path"] for row in rows] == [hostile]
    assert database.total_events(db) == 1, "table must still exist"


def test_like_wildcards_in_path_filter_are_literal(tmp_path):
    db = tmp_path / "fw.db"
    database.insert_events([
        el.make_event("ADDED", "100%_done.txt", new_hash="a" * 64),
        el.make_event("ADDED", "plain.txt", new_hash="b" * 64),
    ], db)
    rows = database.query_events(db, path="%_done")
    assert [row["path"] for row in rows] == ["100%_done.txt"]


def test_empty_and_missing_database_are_handled(tmp_path):
    missing = tmp_path / "nope.db"
    assert database.query_events(missing) == []
    assert database.total_events(missing) == 0
    assert database.count_by_type(missing) == {"ADDED": 0, "MODIFIED": 0,
                                               "DELETED": 0}
    assert database.database_status(missing)["exists"] is False

    empty = tmp_path / "empty.db"
    database.init_db(empty)
    assert database.query_events(empty) == []      # schema exists, no rows
    assert database.database_status(empty)["events"] == 0


def test_corrupt_database_is_reported_not_raised(tmp_path):
    bad = tmp_path / "corrupt.db"
    bad.write_text("definitely not a sqlite file", encoding="utf-8")
    status = database.database_status(bad)
    assert status["error"], "a corrupt file must yield an error message"
    assert dashboard.load_db_dashboard_data(bad)["error"]


def test_malformed_jsonl_is_imported_partially(tmp_path):
    db = tmp_path / "fw.db"
    path = tmp_path / "events.jsonl"
    good = el.make_event("ADDED", "good.txt", new_hash="a" * 64,
                         timestamp="2026-11-01T09:00:00Z")
    path.write_text(
        json.dumps(good) + "\n"
        + "not json at all\n"
        + json.dumps({"event_type": "ADDED"}) + "\n",
        encoding="utf-8",
    )
    summary = database.import_jsonl(path, db)
    assert summary["inserted"] == 1
    assert summary["malformed_lines"] >= 1
    assert database.total_events(db) == 1


def test_import_of_missing_file_reports_cleanly(tmp_path):
    summary = database.import_jsonl(tmp_path / "absent.jsonl", tmp_path / "fw.db")
    assert summary["missing"] is True
    assert summary["inserted"] == 0
    assert not (tmp_path / "fw.db").exists(), "don't create a DB for nothing"


# ---------------------------------------------------------------------------
# 3. Filtering: dates (inclusive), type, combined
# ---------------------------------------------------------------------------

def _filter_db(tmp_path) -> Path:
    db = tmp_path / "fw.db"
    database.insert_events([
        el.make_event("ADDED", "a.txt", new_hash="a" * 64,
                      timestamp="2026-11-01T00:00:00Z"),
        el.make_event("MODIFIED", "docs/b.txt", old_hash="a" * 64,
                      new_hash="b" * 64, timestamp="2026-11-02T12:00:00Z"),
        el.make_event("DELETED", "docs/c.txt", old_hash="b" * 64,
                      timestamp="2026-11-03T23:59:59Z"),
    ], db)
    return db


def test_date_filters_are_inclusive_of_the_whole_day(tmp_path):
    db = _filter_db(tmp_path)
    rows = database.query_events(db, start_date="2026-11-01", end_date="2026-11-01",
                                 newest_first=False)
    assert [row["path"] for row in rows] == ["a.txt"]

    rows = database.query_events(db, start_date="2026-11-03", end_date="2026-11-03",
                                 newest_first=False)
    assert [row["path"] for row in rows] == ["docs/c.txt"], \
        "23:59:59 must still be inside an inclusive end date"


def test_start_only_and_end_only_filters(tmp_path):
    db = _filter_db(tmp_path)
    assert len(database.query_events(db, start_date="2026-11-02")) == 2
    assert len(database.query_events(db, end_date="2026-11-02")) == 2


def test_type_filter(tmp_path):
    db = _filter_db(tmp_path)
    rows = database.query_events(db, event_type="MODIFIED")
    assert [row["path"] for row in rows] == ["docs/b.txt"]


def test_multiple_types_filter(tmp_path):
    db = _filter_db(tmp_path)
    rows = database.query_events(db, event_type="ADDED,DELETED")
    assert sorted(row["event_type"] for row in rows) == ["ADDED", "DELETED"]


def test_path_filter(tmp_path):
    db = _filter_db(tmp_path)
    rows = database.query_events(db, path="docs/")
    assert sorted(row["path"] for row in rows) == ["docs/b.txt", "docs/c.txt"]


def test_combined_filters(tmp_path):
    db = _filter_db(tmp_path)
    rows = database.query_events(db, start_date="2026-11-01", end_date="2026-11-03",
                                 event_type="MODIFIED", path="docs/")
    assert [row["path"] for row in rows] == ["docs/b.txt"]


def test_date_outside_range_returns_nothing(tmp_path):
    db = _filter_db(tmp_path)
    assert database.query_events(db, start_date="2020-01-01",
                                 end_date="2020-12-31") == []


def test_invalid_date_raises_value_error(tmp_path):
    db = _filter_db(tmp_path)
    for bad in ("nonsense", "2026-13-01", "2026-11-32"):
        try:
            database.query_events(db, start_date=bad)
        except ValueError:
            continue
        raise AssertionError(f"{bad!r} should raise ValueError")


def test_normalise_bound_documents_utc_handling():
    assert database.normalise_bound(None) is None
    assert database.normalise_bound("") is None
    assert database.normalise_bound("2026-11-25") == "2026-11-25T00:00:00Z"
    assert database.normalise_bound("2026-11-25", end=True) == "2026-11-25T23:59:59Z"
    # An explicit offset is converted to UTC before comparison.
    assert database.normalise_bound("2026-11-25T12:00:00+02:00") == "2026-11-25T10:00:00Z"


def test_count_by_type_and_timeline(tmp_path):
    db = _filter_db(tmp_path)
    assert database.count_by_type(db) == {"ADDED": 1, "MODIFIED": 1, "DELETED": 1}

    hourly = database.timeline_counts(db, bucket="hour")
    assert [row["bucket"] for row in hourly] == [
        "2026-11-01T00", "2026-11-02T12", "2026-11-03T23",
    ]
    daily = database.timeline_counts(db, bucket="date")
    assert [row["bucket"] for row in daily] == [
        "2026-11-01", "2026-11-02", "2026-11-03",
    ]


def test_timeline_rejects_unknown_bucket(tmp_path):
    db = _filter_db(tmp_path)
    try:
        database.timeline_counts(db, bucket="week")
    except ValueError:
        return
    raise AssertionError("unknown bucket should raise ValueError")


# ---------------------------------------------------------------------------
# 4. Monitor -> JSONL -> SQLite integration
# ---------------------------------------------------------------------------

def _watched_folder(tmp_path) -> Path:
    folder = tmp_path / "watched"
    (folder / "sub").mkdir(parents=True)
    (folder / "a.txt").write_text("alpha\n", encoding="utf-8")
    (folder / "b.txt").write_text("beta\n", encoding="utf-8")
    (folder / "sub" / "c.txt").write_text("gamma\n", encoding="utf-8")
    return folder


def test_watch_once_writes_structured_events(tmp_path):
    folder = _watched_folder(tmp_path)
    baseline = tmp_path / "baseline.json"
    log = tmp_path / "filewatch.log"
    events = tmp_path / "events.jsonl"

    assert main.command_baseline(folder, baseline_path=baseline) == main.EXIT_OK
    # Nothing changed yet: no events file, and that is not an error.
    main.command_watch(folder, baseline_path=baseline, interval=0.01, log_path=log,
                       max_scans=1, events_path=str(events), logger=None)
    assert not events.exists() or events.read_text().strip() == ""

    (folder / "a.txt").write_text("alpha changed\n", encoding="utf-8")
    (folder / "d.txt").write_text("delta\n", encoding="utf-8")
    (folder / "b.txt").unlink()

    code = main.command_watch(folder, baseline_path=baseline, interval=0.01,
                              log_path=log, max_scans=1,
                              events_path=str(events), logger=None)
    assert code == main.EXIT_OK

    records = el.read_events(events)["events"]
    by_type = {record["event_type"]: record for record in records}
    assert set(by_type) == {"ADDED", "MODIFIED", "DELETED"}
    assert by_type["ADDED"]["path"] == "d.txt"
    assert by_type["MODIFIED"]["path"] == "a.txt"
    assert by_type["DELETED"]["path"] == "b.txt"

    # Hash columns must describe the real transition.
    assert by_type["ADDED"]["old_hash"] is None
    assert len(by_type["ADDED"]["new_hash"]) == 64
    assert len(by_type["MODIFIED"]["old_hash"]) == 64
    assert len(by_type["MODIFIED"]["new_hash"]) == 64
    assert by_type["MODIFIED"]["old_hash"] != by_type["MODIFIED"]["new_hash"]
    assert by_type["DELETED"]["new_hash"] is None
    assert all(record["source"] == "watch" for record in records)


def test_watch_events_do_not_change_the_log_format(tmp_path):
    folder = _watched_folder(tmp_path)
    baseline = tmp_path / "baseline.json"
    log = tmp_path / "filewatch.log"
    events = tmp_path / "events.jsonl"

    main.command_baseline(folder, baseline_path=baseline)
    (folder / "a.txt").write_text("changed\n", encoding="utf-8")
    main.command_watch(folder, baseline_path=baseline, interval=0.01,
                       log_path=log, max_scans=1, events_path=str(events))

    log_lines = [line for line in log.read_text(encoding="utf-8").splitlines() if line]
    assert log_lines, "the human-readable log must still be written"
    # The Week 3/4 parser still understands every line.
    parsed = lp.parse_log_file(log)
    assert parsed.error is None
    assert parsed.counts["MODIFIED"] >= 1
    assert "MODIFIED file: a.txt" in log.read_text(encoding="utf-8")


def test_watch_can_disable_events_for_week1_to_4_behaviour(tmp_path):
    folder = _watched_folder(tmp_path)
    baseline = tmp_path / "baseline.json"
    log = tmp_path / "filewatch.log"

    main.command_baseline(folder, baseline_path=baseline)
    (folder / "a.txt").write_text("changed\n", encoding="utf-8")
    assert main.command_watch(folder, baseline_path=baseline, interval=0.01,
                              log_path=log, max_scans=1, events_path=None) == main.EXIT_OK
    assert log.exists()
    assert not (tmp_path / "events.jsonl").exists()


def test_unreadable_file_does_not_emit_a_guessed_event(tmp_path):
    """Unknown content must never be recorded as a fabricated hash."""
    result = {"added": [], "modified": [], "deleted": ["gone.txt"],
              "unreadable": ["locked.txt"], "counts": {}}
    records = el.events_from_result(result, current={}, baseline={})
    paths = [record["path"] for record in records]
    assert "locked.txt" not in paths
    assert paths == ["gone.txt"]


def test_watch_recovery_by_reimport(tmp_path):
    """A failed import is recoverable: re-running it picks up the events."""
    folder = _watched_folder(tmp_path)
    baseline = tmp_path / "baseline.json"
    events = tmp_path / "events.jsonl"
    db = tmp_path / "fw.db"

    main.command_baseline(folder, baseline_path=baseline)
    (folder / "a.txt").write_text("changed\n", encoding="utf-8")
    main.command_watch(folder, baseline_path=baseline, interval=0.01,
                       log_path=tmp_path / "filewatch.log", max_scans=1,
                       events_path=str(events))

    first = database.import_jsonl(events, db)
    assert first["inserted"] >= 1
    # Simulate an operator losing the DB and re-importing the same JSONL.
    db.unlink()
    second = database.import_jsonl(events, db)
    assert second["inserted"] == first["inserted"]
    assert database.total_events(db) == first["inserted"]


# ---------------------------------------------------------------------------
# 5. CLI: import-events / query-events
# ---------------------------------------------------------------------------

def test_cli_import_events(tmp_path):
    events = make_events(tmp_path / "events.jsonl")
    db = tmp_path / "fw.db"

    result = cli("import-events", "--events", str(events), "--db", str(db))
    assert result.returncode == 0, result.stderr
    assert "Imported   : 3" in result.stdout
    assert database.total_events(db) == 3

    again = cli("import-events", "--events", str(events), "--db", str(db))
    assert again.returncode == 0
    assert "Imported   : 0" in again.stdout
    assert "Duplicates : 3" in again.stdout


def test_cli_import_events_with_missing_file(tmp_path):
    result = cli("import-events", "--events", str(tmp_path / "none.jsonl"),
                 "--db", str(tmp_path / "fw.db"))
    assert result.returncode == 0
    assert "nothing to import" in result.stdout.lower()


def test_cli_query_events_filters(tmp_path):
    events = make_events(tmp_path / "events.jsonl")
    db = tmp_path / "fw.db"
    cli("import-events", "--events", str(events), "--db", str(db))

    result = cli("query-events", "--db", str(db))
    assert result.returncode == 0
    assert "ADDED 1, MODIFIED 1, DELETED 1" in result.stdout

    typed = cli("query-events", "--db", str(db), "--type", "MODIFIED")
    assert "docs/notes.txt" in typed.stdout
    assert "new.txt" not in typed.stdout

    dated = cli("query-events", "--db", str(db), "--start", "2026-11-01",
                "--end", "2026-11-01")
    assert "new.txt" in dated.stdout
    assert "docs/old.txt" not in dated.stdout

    combined = cli("query-events", "--db", str(db), "--start", "2026-11-01",
                   "--end", "2026-11-03", "--type", "DELETED")
    assert "docs/old.txt" in combined.stdout
    assert "new.txt" not in combined.stdout


def test_cli_query_events_without_database(tmp_path):
    result = cli("query-events", "--db", str(tmp_path / "absent.db"))
    assert result.returncode == 0
    assert "import-events" in result.stdout


def test_cli_query_events_rejects_bad_date(tmp_path):
    events = make_events(tmp_path / "events.jsonl")
    db = tmp_path / "fw.db"
    cli("import-events", "--events", str(events), "--db", str(db))
    result = cli("query-events", "--db", str(db), "--start", "31-12-2026")
    assert result.returncode == main.EXIT_FAILURE
    assert "Invalid timestamp" in result.stdout


# ---------------------------------------------------------------------------
# 6. DB-sourced reports
# ---------------------------------------------------------------------------

def test_markdown_report_from_database(tmp_path):
    events = make_events(tmp_path / "events.jsonl")
    db = tmp_path / "fw.db"
    database.import_jsonl(events, db)

    written = rp.generate_reports(output_dir=tmp_path / "reports", fmt="md",
                                  source="db", db_path=db)
    text = written[0].read_text(encoding="utf-8")

    assert written[0].name == "integrity-report-db.md"
    assert "Data source" in text and "SQLite" in text
    assert "| ADDED | 1 |" in text
    assert "docs/notes.txt" in text
    assert "LEGAL AND ETHICAL NOTICE" in text
    assert "does not prevent" in text


def test_html_report_from_database_is_escaped(tmp_path):
    db = tmp_path / "fw.db"
    database.insert_events([
        el.make_event("ADDED", "<script>alert('x')</script>.txt",
                      new_hash="a" * 64, timestamp="2026-11-01T10:00:00Z"),
    ], db)

    written = rp.generate_reports(output_dir=tmp_path / "reports", fmt="html",
                                  source="db", db_path=db)
    html_text = written[0].read_text(encoding="utf-8")

    assert "<script>alert" not in html_text
    assert "&lt;script&gt;" in html_text


def test_reports_honour_date_and_type_filters(tmp_path):
    events = make_events(tmp_path / "events.jsonl")
    db = tmp_path / "fw.db"
    database.import_jsonl(events, db)

    written = rp.generate_reports(output_dir=tmp_path / "reports", fmt="md",
                                  source="db", db_path=db,
                                  start="2026-11-02", end="2026-11-02")
    text = written[0].read_text(encoding="utf-8")
    assert "start=2026-11-02" in text
    assert "docs/notes.txt" in text
    assert "new.txt" not in text

    typed = rp.generate_reports(output_dir=tmp_path / "reports2", fmt="md",
                                source="db", db_path=db, event_type="DELETED")
    assert "docs/old.txt" in typed[0].read_text(encoding="utf-8")


def test_report_from_empty_database_still_written(tmp_path):
    db = tmp_path / "fw.db"
    database.init_db(db)
    written = rp.generate_reports(output_dir=tmp_path / "reports", fmt="both",
                                  source="db", db_path=db)
    assert len(written) == 2
    text = written[0].read_text(encoding="utf-8")
    assert "No events in this view" in text
    assert "| ADDED | 0 |" in text


def test_report_from_missing_database_explains_itself(tmp_path):
    written = rp.generate_reports(output_dir=tmp_path / "reports", fmt="md",
                                  source="db", db_path=tmp_path / "none.db")
    text = written[0].read_text(encoding="utf-8")
    assert "import-events" in text
    assert "No database events available" in text


def test_log_based_reporting_still_works(tmp_path):
    """Week 4 behaviour must be untouched by the enhanced additions."""
    log = tmp_path / "filewatch.log"
    log.write_text(
        "2026-11-01 10:00:00 | WARNING  | filewatch | ADDED file: a.txt\n"
        "2026-11-01 10:05:00 | WARNING  | filewatch | MODIFIED file: b.txt\n",
        encoding="utf-8",
    )
    written = rp.generate_reports(log, tmp_path / "reports", "md", source="log")
    text = written[0].read_text(encoding="utf-8")
    assert written[0].name == "integrity-report.md"
    assert "Text log" in text
    assert "| ADDED | 1 |" in text


def test_report_cli_source_db(tmp_path):
    events = make_events(tmp_path / "events.jsonl")
    db = tmp_path / "fw.db"
    database.import_jsonl(events, db)

    result = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "report.py"), "report",
         "--source", "db", "--db", str(db), "--format", "both",
         "--out", str(tmp_path / "reports"), "--type", "ADDED"],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "reports" / "integrity-report-db.md").exists()
    assert (tmp_path / "reports" / "integrity-report-db.html").exists()
    assert "SQLite database" in result.stdout


# ---------------------------------------------------------------------------
# 7. Dashboard data layer (pure functions - no Streamlit runtime needed)
# ---------------------------------------------------------------------------

def test_dashboard_reads_database(tmp_path):
    db = _filter_db(tmp_path)
    data = dashboard.load_db_dashboard_data(db)
    assert data["error"] is None
    assert data["total"] == 3
    assert data["has_events"] is True
    assert len(data["recent_rows"]) == 3
    assert set(data["recent_rows"][0]) >= {"Timestamp", "Event", "File"}


def test_dashboard_date_and_type_filters(tmp_path):
    db = _filter_db(tmp_path)

    dated = dashboard.load_db_dashboard_data(db, start="2026-11-02",
                                             end="2026-11-02")
    assert [row["File"] for row in dated["recent_rows"]] == ["docs/b.txt"]

    typed = dashboard.load_db_dashboard_data(db, event_type="DELETED")
    assert [row["File"] for row in typed["recent_rows"]] == ["docs/c.txt"]
    assert typed["counts"]["ADDED"] == 0

    combined = dashboard.load_db_dashboard_data(db, start="2026-11-01",
                                                end="2026-11-03",
                                                event_type="ADDED",
                                                path_filter="a.txt")
    assert [row["File"] for row in combined["recent_rows"]] == ["a.txt"]


def test_dashboard_timeline_buckets(tmp_path):
    db = _filter_db(tmp_path)
    hours = dashboard.load_db_dashboard_data(db, bucket="hour")["timeline_rows"]
    days = dashboard.load_db_dashboard_data(db, bucket="date")["timeline_rows"]
    assert len(hours) == 3 and len(days) == 3
    assert all("ADDED" in row for row in hours)


def test_dashboard_handles_missing_and_empty_database(tmp_path):
    missing = dashboard.load_db_dashboard_data(tmp_path / "none.db")
    assert missing["error"] and "No database" in missing["error"]
    assert missing["total"] == 0

    empty_db = tmp_path / "empty.db"
    database.init_db(empty_db)
    empty = dashboard.load_db_dashboard_data(empty_db)
    assert empty["error"] is None
    assert empty["has_events"] is False
    assert empty["total"] == 0


def test_dashboard_handles_corrupt_database(tmp_path):
    bad = tmp_path / "corrupt.db"
    bad.write_text("not sqlite", encoding="utf-8")
    data = dashboard.load_db_dashboard_data(bad)
    assert data["error"] and "database" in data["error"].lower()


def test_dashboard_bad_date_is_reported_not_raised(tmp_path):
    db = _filter_db(tmp_path)
    data = dashboard.load_db_dashboard_data(db, start="not-a-date")
    assert data["error"]
    assert data["total"] == 0


def test_dashboard_query_is_bounded(tmp_path):
    db = tmp_path / "fw.db"
    database.insert_events(
        [el.make_event("ADDED", f"f{i}.txt", new_hash="a" * 64,
                       timestamp="2026-11-01T00:00:00Z") for i in range(50)], db)
    data = dashboard.load_db_dashboard_data(db, limit=10)
    assert len(data["recent_rows"]) == 10
    assert data["total"] == 50, "counts still reflect the full filtered set"

    clamped = dashboard.load_db_dashboard_data(db, limit=10 ** 9)
    assert len(clamped["recent_rows"]) <= dashboard.MAX_ROWS


def test_dashboard_report_download_paths_render(tmp_path):
    """The in-dashboard report buttons use the same renderers as the CLI."""
    db = _filter_db(tmp_path)
    data = dashboard.load_db_dashboard_data(db)
    result = lp.result_from_events(list(reversed(data["events"])),
                                  source=str(db))
    report = lp.build_report_data(result, recent_limit=25, log_path=db)
    report["source"] = "db"
    report["data_source"] = f"SQLite database ({db})"

    assert "| ADDED | 1 |" in lp.render_markdown(report)
    assert "<html" in lp.render_html(report).lower()


def test_dashboard_log_view_still_works(tmp_path):
    log = tmp_path / "filewatch.log"
    log.write_text("2026-11-01 10:00:00 | WARNING  | filewatch | "
                   "ADDED file: x.txt\n", encoding="utf-8")
    data = dashboard.load_dashboard_data(str(log))
    assert data["counts"]["ADDED"] == 1
    assert data["error"] is None


def test_dashboard_csv_export(tmp_path):
    db = _filter_db(tmp_path)
    rows = dashboard.load_db_dashboard_data(db)["recent_rows"]
    csv_text = dashboard.events_to_csv(rows)
    assert csv_text.startswith("Timestamp,Event,File")
    assert len(csv_text.strip().splitlines()) == len(rows) + 1


# ---------------------------------------------------------------------------
# 8. Week 1-4 features must remain intact
# ---------------------------------------------------------------------------

def test_sqlite_is_not_mandatory_for_core_commands(tmp_path):
    folder = _watched_folder(tmp_path)
    baseline = tmp_path / "baseline.json"

    assert main.command_baseline(folder, baseline_path=baseline) == main.EXIT_OK
    assert main.command_check(folder, baseline_path=baseline) == main.EXIT_OK

    (folder / "a.txt").write_text("changed\n", encoding="utf-8")
    assert main.command_check(folder, baseline_path=baseline) == main.EXIT_CHANGES


def test_existing_log_parser_reads_week3_logs(tmp_path):
    """Older filewatch.log files (no JSONL, no SQLite) still parse."""
    log = tmp_path / "old.log"
    log.write_text(
        "2026-01-01 00:00:00 | INFO     | filewatch | Watch started: files=3\n"
        "2026-01-01 00:00:05 | WARNING  | filewatch | ADDED file: a.txt\n"
        "2026-01-01 00:00:10 | WARNING  | filewatch | DELETED file: b.txt\n",
        encoding="utf-8",
    )
    parsed = lp.parse_log_file(log)
    assert parsed.counts["ADDED"] == 1 and parsed.counts["DELETED"] == 1
    assert parsed.error is None


def test_real_test_folder_untouched_by_enhanced_tests():
    """Guard: this suite must never write into the sample folder."""
    folder = PROJECT_ROOT / "test_folder"
    before = {path: path.stat().st_mtime for path in folder.rglob("*") if path.is_file()}
    make_events(Path(tempfile.mkdtemp()) / "events.jsonl")
    after = {path: path.stat().st_mtime for path in folder.rglob("*") if path.is_file()}
    assert before == after


# ---------------------------------------------------------------------------
# unittest bridge
# ---------------------------------------------------------------------------

def load_tests(loader, tests, pattern):  # noqa: ARG001 - unittest protocol
    """Run the function-style tests under ``python3 -m unittest test_enhanced``.

    The suite is written in pytest's plain-function style because that reads
    best for these scenarios. Rather than duplicate ~60 tests in a TestCase
    class, each function is wrapped on the fly; functions that declare a
    ``tmp_path`` parameter get a fresh temporary directory, so both runners
    execute exactly the same assertions.
    """
    import inspect
    import shutil

    suite = unittest.TestSuite()
    module = sys.modules[__name__]

    for name in sorted(dir(module)):
        if not name.startswith("test_"):
            continue
        function = getattr(module, name)
        if not inspect.isfunction(function):
            continue
        wants_tmp = "tmp_path" in inspect.signature(function).parameters

        def _make(func=function, needs_dir=wants_tmp):
            def _test(self):
                if needs_dir:
                    path = Path(tempfile.mkdtemp(prefix="fw5-"))
                    try:
                        func(path)
                    finally:
                        shutil.rmtree(path, ignore_errors=True)
                else:
                    func()
            _test.__name__ = func.__name__
            return _test

        case = type(f"Enhanced_{name}", (unittest.TestCase,), {name: _make()})
        suite.addTest(case(name))

    return suite


if __name__ == "__main__":
    unittest.main(verbosity=2)
