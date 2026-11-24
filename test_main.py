#!/usr/bin/env python3
"""
Automated tests for the SHA-256 File Integrity Checker.
======================================================

Run with:

    python -m unittest -v
    python test_main.py

Standard library only (``unittest``), so nothing needs installing.

All file work happens in throw-away temporary directories, so the real
``test_folder`` is never modified by the test suite.
"""

from __future__ import annotations

import builtins
import contextlib
import hashlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import main


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def reference_hash(data: bytes, algorithm: str = "sha256") -> str:
    """Independent reference digest, used to check ``hash_file`` output."""
    return hashlib.new(algorithm, data).hexdigest()


class TempFolderTestCase(unittest.TestCase):
    """Base class giving each test a fresh temporary folder."""

    def setUp(self) -> None:
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.folder = Path(self._tmp_dir.name)

    def tearDown(self) -> None:
        self._tmp_dir.cleanup()

    def write_file(self, name: str, content: bytes | str) -> Path:
        """Create a file inside the temporary folder and return its path."""
        path = self.folder / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, str):
            path.write_bytes(content.encode("utf-8"))
        else:
            path.write_bytes(content)
        return path

    def quiet(self):
        """Silence stdout/stderr while a noisy function runs."""
        return contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO())


# ---------------------------------------------------------------------------
# 1-5: hashing correctness
# ---------------------------------------------------------------------------

class TestHashFile(TempFolderTestCase):
    """Tests 1, 2, 3, 4, 5: correctness of the hashing function."""

    def test_01_sha256_hashing_is_correct(self) -> None:
        """Test 1: SHA-256 digest matches an independent computation."""
        payload = b"SHA-256 file integrity checker\n"
        path = self.write_file("sample.txt", payload)

        digest = main.hash_file(path)  # default algorithm

        self.assertEqual(digest, reference_hash(payload, "sha256"))
        self.assertEqual(len(digest), 64)  # SHA-256 -> 256 bits -> 64 hex chars

    def test_02_sha1_hashing_is_correct(self) -> None:
        """Test 2: SHA-1 digest matches an independent computation."""
        payload = b"SHA-1 comparison sample\n"
        path = self.write_file("sample.txt", payload)

        digest = main.hash_file(path, algorithm="sha1")

        self.assertEqual(digest, reference_hash(payload, "sha1"))
        self.assertEqual(len(digest), 40)  # SHA-1 -> 160 bits -> 40 hex chars

    def test_03_identical_files_produce_identical_hashes(self) -> None:
        """Test 3: same bytes in two different files -> same digest."""
        first = self.write_file("one.txt", "identical content\n")
        second = self.write_file("two.txt", "identical content\n")

        with contextlib.redirect_stderr(io.StringIO()):
            first_hash = main.hash_file(first)
            second_hash = main.hash_file(second)

        self.assertEqual(first_hash, second_hash)

    def test_04_one_character_change_changes_the_hash(self) -> None:
        """Test 4: one changed character -> a totally different digest."""
        original = self.write_file("original.txt", "The quick brown fox jumps.\n")
        modified = self.write_file("modified.txt", "The quick brown fax jumps.\n")

        with contextlib.redirect_stderr(io.StringIO()):
            original_hash = main.hash_file(original)
            modified_hash = main.hash_file(modified)

        self.assertNotEqual(original_hash, modified_hash)
        # The avalanche effect should flip roughly half of the hex digits.
        differing = sum(a != b for a, b in zip(original_hash, modified_hash))
        self.assertGreater(differing, len(original_hash) // 4)

    def test_05_empty_file_hashing(self) -> None:
        """Test 5: an empty file hashes to the well-known empty digest."""
        path = self.write_file("empty.txt", b"")

        digest = main.hash_file(path)

        self.assertEqual(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        self.assertEqual(digest, reference_hash(b"", "sha256"))


# ---------------------------------------------------------------------------
# 6: chunked reading of a large file
# ---------------------------------------------------------------------------

class TestChunkedReading(TempFolderTestCase):
    """Test 6: large files are read in 4096-byte chunks."""

    def test_06_large_file_is_read_in_chunks(self) -> None:
        """Test 6: a multi-chunk file hashes correctly and is read in chunks."""
        payload = bytes(range(256)) * 2048  # 512 KiB, far more than 4096 bytes
        path = self.write_file("large.bin", payload)

        real_open = builtins.open
        read_sizes: list[int] = []

        class ReadSpy:
            """Wraps a file object and records the size of each read() call."""

            def __init__(self, handle):
                self._handle = handle

            def read(self, size: int = -1):
                read_sizes.append(size)
                return self._handle.read(size)

            def __enter__(self):
                return self

            def __exit__(self, *exc_info):
                self._handle.close()
                return False

            def __getattr__(self, item):
                return getattr(self._handle, item)

        def spying_open(file, mode="r", *args, **kwargs):
            handle = real_open(file, mode, *args, **kwargs)
            if "b" in mode:
                return ReadSpy(handle)
            return handle

        with mock.patch("builtins.open", side_effect=spying_open):
            with contextlib.redirect_stderr(io.StringIO()):
                digest = main.hash_file(path)

        self.assertEqual(digest, reference_hash(payload, "sha256"))
        # Every read must request exactly CHUNK_SIZE bytes.
        self.assertTrue(read_sizes)
        self.assertEqual(set(read_sizes), {main.CHUNK_SIZE})
        self.assertGreater(len(read_sizes), 1)  # proves chunking happened

    def test_06b_chunk_size_is_4096(self) -> None:
        """The published chunk size must stay 4096 bytes."""
        self.assertEqual(main.CHUNK_SIZE, 4096)


# ---------------------------------------------------------------------------
# 7-8: error handling
# ---------------------------------------------------------------------------

class TestErrorHandling(TempFolderTestCase):
    """Tests 7 and 8: missing and unreadable files."""

    def test_07_missing_file_returns_none(self) -> None:
        """Test 7: a non-existent file returns None instead of raising."""
        missing = self.folder / "does_not_exist.txt"

        with contextlib.redirect_stderr(io.StringIO()) as captured:
            result = main.hash_file(missing)

        self.assertIsNone(result)
        self.assertIn("not found", captured.getvalue().lower())

    def test_08_unreadable_file_returns_none(self) -> None:
        """Test 8: a PermissionError is caught and reported as None."""
        path = self.write_file("locked.txt", "secret\n")

        with mock.patch(
            "builtins.open", side_effect=PermissionError(13, "Permission denied")
        ):
            with contextlib.redirect_stderr(io.StringIO()) as captured:
                result = main.hash_file(path)

        self.assertIsNone(result)
        self.assertIn("permission", captured.getvalue().lower())

    def test_08b_other_oserror_returns_none(self) -> None:
        """An arbitrary OSError (simulated I/O failure) is also handled."""
        path = self.write_file("broken.txt", "data\n")

        with mock.patch("builtins.open", side_effect=OSError(5, "Input/output error")):
            with contextlib.redirect_stderr(io.StringIO()) as captured:
                result = main.hash_file(path)

        self.assertIsNone(result)
        self.assertIn("could not read", captured.getvalue().lower())

    def test_08c_directory_path_returns_none(self) -> None:
        """Passing a directory path is handled, not crashed on."""
        with contextlib.redirect_stderr(io.StringIO()):
            result = main.hash_file(self.folder)

        self.assertIsNone(result)

    def test_08d_permission_error_during_scan_does_not_stop_it(self) -> None:
        """One unreadable file must not abort the whole folder scan."""
        self.write_file("good.txt", "readable\n")
        self.write_file("bad.txt", "unreadable\n")

        real_open = builtins.open

        def selective_open(file, mode="r", *args, **kwargs):
            if Path(file).name == "bad.txt":
                raise PermissionError(13, "Permission denied")
            return real_open(file, mode, *args, **kwargs)

        with mock.patch("builtins.open", side_effect=selective_open):
            with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                results = main.monitor_folder(self.folder)

        self.assertIn("good.txt", results)
        self.assertNotIn("bad.txt", results)
        self.assertEqual(len(results), 1)


# ---------------------------------------------------------------------------
# 9-12: folder monitoring
# ---------------------------------------------------------------------------

class TestMonitorFolder(TempFolderTestCase):
    """Tests 9, 10, 11 and 12: folder scanning behaviour."""

    def test_09_empty_folder_is_handled(self) -> None:
        """Test 9: an empty folder produces an empty result, no crash."""
        with contextlib.redirect_stdout(io.StringIO()) as captured:
            results = main.monitor_folder(self.folder)

        self.assertEqual(results, {})
        self.assertIn("no regular files", captured.getvalue().lower())

    def test_09b_missing_folder_is_handled(self) -> None:
        """A folder that does not exist is reported, not crashed on."""
        missing = self.folder / "no_such_folder"

        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main.list_regular_files(missing), [])

    def test_10_directories_are_skipped(self) -> None:
        """Test 10: sub-directories are skipped, regular files are not."""
        self.write_file("real.txt", "content\n")
        (self.folder / "subdir").mkdir()
        (self.folder / "subdir" / "nested.txt").write_bytes(b"nested\n")

        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            results = main.monitor_folder(self.folder)

        self.assertEqual(list(results), ["real.txt"])
        self.assertNotIn("nested.txt", results)

    @unittest.skipUnless(hasattr(os, "symlink"), "symbolic links not supported here")
    def test_11_symbolic_links_are_skipped(self) -> None:
        """Test 11: symbolic links are skipped even when valid."""
        target = self.write_file("target.txt", "target content\n")
        link = self.folder / "link.txt"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError) as exc:  # pragma: no cover
            self.skipTest(f"cannot create symlinks here: {exc}")

        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            results = main.monitor_folder(self.folder)

        self.assertIn("target.txt", results)
        self.assertNotIn("link.txt", results)

    @unittest.skipUnless(hasattr(os, "symlink"), "symbolic links not supported here")
    def test_11b_symlink_to_outside_folder_is_skipped(self) -> None:
        """Test 11b: a link pointing outside the folder is never followed."""
        outside = Path(self._tmp_dir.name).parent / "outside_secret.txt"
        link = self.folder / "escape.txt"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError) as exc:  # pragma: no cover
            self.skipTest(f"cannot create symlinks here: {exc}")

        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            results = main.monitor_folder(self.folder)

        self.assertNotIn("escape.txt", results)

    def test_12_monitoring_stays_inside_the_folder(self) -> None:
        """Test 12: nothing outside the monitored folder is ever hashed."""
        outside_file = self.folder.parent / "outside_do_not_scan.txt"
        outside_file.write_bytes(b"outside content\n")
        self.addCleanup(lambda: outside_file.unlink(missing_ok=True))

        self.write_file("inside.txt", "inside content\n")

        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            results = main.monitor_folder(self.folder)

        self.assertEqual(list(results), ["inside.txt"])
        self.assertNotIn("outside_do_not_scan.txt", results)

    def test_12b_all_files_get_the_requested_algorithm(self) -> None:
        """The scan honours --algorithm for every file."""
        self.write_file("a.txt", "alpha\n")
        self.write_file("b.txt", "bravo\n")

        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            sha1_results = main.monitor_folder(self.folder, algorithm="sha1")
            sha256_results = main.monitor_folder(self.folder, algorithm="sha256")

        self.assertTrue(all(len(value) == 40 for value in sha1_results.values()))
        self.assertTrue(all(len(value) == 64 for value in sha256_results.values()))

    def test_12c_demo_copies_are_not_reported(self) -> None:
        """Leftover demonstration copies are excluded from scan results."""
        self.write_file("sample.txt", "content\n")
        self.write_file(f"{main.DEMO_PREFIX}sample_1.txt", "content modified\n")

        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            results = main.monitor_folder(self.folder)

        self.assertEqual(list(results), ["sample.txt"])


# ---------------------------------------------------------------------------
# 13-14: demonstration mode
# ---------------------------------------------------------------------------

class TestDemonstration(TempFolderTestCase):
    """Tests 13 and 14: safety and cleanup of the demonstration."""

    def test_13_demo_changes_only_the_temporary_copy(self) -> None:
        """Test 13: the original sample file stays byte-for-byte identical."""
        original = self.write_file("sample.txt", "Original sample content.\n")
        original_bytes = original.read_bytes()
        original_hash = reference_hash(original_bytes, "sha256")

        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            result = main.demonstrate_avalanche(self.folder)

        self.assertIsNotNone(result)
        self.assertTrue(result["changed"])
        self.assertNotEqual(result["original_hash"], result["modified_hash"])
        self.assertEqual(result["original_hash"], original_hash)

        # The original file must be untouched.
        self.assertEqual(original.read_bytes(), original_bytes)
        self.assertEqual(reference_hash(original.read_bytes(), "sha256"), original_hash)

        # Only the one original file should remain in the folder.
        self.assertEqual([p.name for p in self.folder.iterdir()], ["sample.txt"])

    def test_13b_one_character_helper_changes_exactly_one_character(self) -> None:
        """The helper really changes a single character."""
        text = "hello world"
        changed = main._change_one_character(text)

        self.assertEqual(len(changed), len(text))
        self.assertEqual(sum(a != b for a, b in zip(text, changed)), 1)

    def test_13c_demo_works_with_sha1(self) -> None:
        """The demonstration supports SHA-1 too."""
        self.write_file("sample.txt", "SHA-1 demo content.\n")

        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            result = main.demonstrate_avalanche(self.folder, algorithm="sha1")

        self.assertIsNotNone(result)
        self.assertTrue(result["changed"])
        self.assertEqual(len(result["original_hash"]), 40)

    def test_14_temporary_files_are_cleaned_up_after_success(self) -> None:
        """Test 14: no temporary copy survives a successful run."""
        self.write_file("sample.txt", "content\n")

        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            main.demonstrate_avalanche(self.folder)

        leftovers = [p.name for p in self.folder.iterdir() if p.name.startswith(main.DEMO_PREFIX)]
        self.assertEqual(leftovers, [])

    def test_14b_temporary_files_are_cleaned_up_after_an_error(self) -> None:
        """Test 14b: the finally-block cleanup also runs when hashing fails."""
        original = self.write_file("sample.txt", "content\n")
        original_bytes = original.read_bytes()
        real_open = builtins.open

        def failing_open(file, mode="r", *args, **kwargs):
            # Fail only when the temporary copy is being read.
            if main.DEMO_PREFIX in Path(file).name and "b" in mode:
                raise OSError(5, "Input/output error")
            return real_open(file, mode, *args, **kwargs)

        with mock.patch("builtins.open", side_effect=failing_open):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                result = main.demonstrate_avalanche(self.folder)

        self.assertIsNone(result)  # the demo reports failure ...
        leftovers = [p.name for p in self.folder.iterdir() if p.name.startswith(main.DEMO_PREFIX)]
        self.assertEqual(leftovers, [])  # ... but still cleans up
        self.assertEqual(original.read_bytes(), original_bytes)

    def test_14c_demo_with_no_text_files_is_skipped_safely(self) -> None:
        """An empty folder makes the demonstration skip, not crash."""
        with contextlib.redirect_stdout(io.StringIO()) as captured:
            result = main.demonstrate_avalanche(self.folder)

        self.assertIsNone(result)
        self.assertIn("skipped", captured.getvalue().lower())


# ---------------------------------------------------------------------------
# 15: algorithm validation + CLI
# ---------------------------------------------------------------------------

class TestAlgorithmValidation(TempFolderTestCase):
    """Test 15: unsupported algorithms are rejected with a clear error."""

    def test_15_unsupported_algorithm_raises_value_error(self) -> None:
        """Test 15: hash_file rejects md5, sha512, garbage, empty strings."""
        path = self.write_file("sample.txt", "content\n")
        for bad in ("md5", "sha512", "crc32", "", "  ", "not-a-hash"):
            with self.subTest(algorithm=bad):
                with self.assertRaises(ValueError) as ctx:
                    main.hash_file(path, algorithm=bad)
                self.assertIn("unsupported", str(ctx.exception).lower())

    def test_15b_non_string_algorithm_raises_value_error(self) -> None:
        """A non-string algorithm is a ValueError too, not a TypeError."""
        path = self.write_file("sample.txt", "content\n")
        with self.assertRaises(ValueError):
            main.hash_file(path, algorithm=None)  # type: ignore[arg-type]

    def test_15c_supported_algorithms_are_accepted_case_insensitively(self) -> None:
        """SHA256, Sha1 ... are normalised before use."""
        path = self.write_file("sample.txt", "content\n")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(len(main.hash_file(path, "SHA256")), 64)
            self.assertEqual(len(main.hash_file(path, " Sha1 ")), 40)


class TestCommandLine(unittest.TestCase):
    """The argparse layer: defaults, choices and error messages."""

    def test_default_algorithm_is_sha256(self) -> None:
        args = main.parse_args([])
        self.assertEqual(args.algorithm, "sha256")
        self.assertFalse(args.demo)
        self.assertEqual(main.DEFAULT_ALGORITHM, "sha256")

    def test_algorithm_and_demo_flags_parse(self) -> None:
        args = main.parse_args(["--algorithm", "SHA1", "--demo"])
        self.assertEqual(args.algorithm, "sha1")
        self.assertTrue(args.demo)

    def test_invalid_algorithm_exits_with_helpful_error(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()) as captured:
            with self.assertRaises(SystemExit) as ctx:
                main.parse_args(["--algorithm", "md5"])
        self.assertEqual(ctx.exception.code, 2)  # argparse usage-error code
        self.assertIn("unsupported algorithm", captured.getvalue().lower())
        self.assertIn("sha256", captured.getvalue().lower())

    def test_unknown_option_exits_with_error(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                main.parse_args(["--bogus"])

    def test_main_runs_and_returns_zero(self) -> None:
        """An end-to-end run of the CLI against a temporary folder."""
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "one.txt").write_bytes(b"hello\n")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                exit_code = main.main(["--folder", tmp, "--demo"])
        self.assertEqual(exit_code, 0)


# ---------------------------------------------------------------------------
# The shipped sample folder
# ---------------------------------------------------------------------------

class TestShippedSampleFolder(unittest.TestCase):
    """Integration checks against the real test_folder in the project."""

    def setUp(self) -> None:
        self.project_root = Path(__file__).resolve().parent
        self.sample_folder = self.project_root / "test_folder"

    def test_all_eight_sample_files_exist(self) -> None:
        self.assertTrue(self.sample_folder.is_dir(), "test_folder is missing")
        for number in range(1, 9):
            candidate = self.sample_folder / f"file{number}.txt"
            self.assertTrue(candidate.is_file(), f"{candidate.name} is missing")
            self.assertGreater(candidate.stat().st_size, 0, f"{candidate.name} is empty")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            results = main.monitor_folder(self.sample_folder)
        self.assertEqual(len(results), 8)

    def test_sample_files_are_distinct(self) -> None:
        """Different content must produce different digests."""
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            results = main.monitor_folder(self.sample_folder)
        self.assertEqual(len(set(results.values())), len(results))


# ===========================================================================
# WEEK 2 TESTS - pytest, using the tmp_path fixture
# ===========================================================================
#
# These are plain module-level functions, which means BOTH runners work:
#
#     pytest -v                 # recommended for the Week 2 tests
#     python -m unittest -v     # Week 1 runner, still fully supported
#
# Every test works inside pytest's `tmp_path`, so the real test_folder and the
# real baseline.json are never touched.
#
# Install requirement (testing only - the tool itself needs nothing):
#     python -m pip install pytest

import json

import pytest  # noqa: E402  (imported here next to the Week 2 tests)


# ---------------------------------------------------------------------------
# Week 2 helpers
# ---------------------------------------------------------------------------

def _make_folder(root, files):
    """Create files inside ``root``; keys may contain sub-folders."""
    for name, content in files.items():
        target = Path(root) / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, str):
            target.write_bytes(content.encode("utf-8"))
        else:
            target.write_bytes(content)
    return Path(root)


def _quiet(func, *args, **kwargs):
    """Call ``func`` while swallowing its console output; return its result."""
    with contextlib.redirect_stdout(io.StringIO()), \
            contextlib.redirect_stderr(io.StringIO()):
        return func(*args, **kwargs)


# ---------------------------------------------------------------------------
# 1. Creating a baseline
# ---------------------------------------------------------------------------

def test_pytest_create_baseline_writes_readable_json(tmp_path):
    """Test 1: `baseline` writes baseline.json with hashes, size and mtime."""
    folder = _make_folder(tmp_path / "test_folder", {
        "file1.txt": "Alpha sample document.\n",
        "file2.txt": "Bravo sample document.\n",
    })
    baseline_path = tmp_path / "baseline.json"

    exit_code = _quiet(main.command_baseline, folder, baseline_path=baseline_path)

    assert exit_code == main.EXIT_OK
    assert baseline_path.is_file()

    raw_text = baseline_path.read_text(encoding="utf-8")
    assert "\n  " in raw_text, "JSON should be indented, not one long line"

    data = json.loads(raw_text)
    assert data["algorithm"] == "sha256"
    assert data["file_count"] == 2
    assert data["schema_version"] == main.BASELINE_SCHEMA_VERSION

    files = data["files"]
    assert set(files) == {"file1.txt", "file2.txt"}
    for name, entry in files.items():
        expected = hashlib.sha256((folder / name).read_bytes()).hexdigest()
        assert entry["sha256"] == expected
        assert entry["size"] == (folder / name).stat().st_size
        assert isinstance(entry["mtime"], float)


def test_pytest_build_snapshot_returns_hashes_keyed_by_relative_path(tmp_path):
    """build_snapshot() maps relative paths -> {hash, size, mtime}."""
    folder = _make_folder(tmp_path / "test_folder", {"file1.txt": "hello\n"})

    snapshot = _quiet(main.build_snapshot, folder)

    assert snapshot["file1.txt"]["sha256"] == hashlib.sha256(b"hello\n").hexdigest()
    assert snapshot["file1.txt"]["size"] == 6
    assert "mtime" in snapshot["file1.txt"]


# ---------------------------------------------------------------------------
# 2-5. The four comparison categories
# ---------------------------------------------------------------------------

def test_pytest_detects_added_file(tmp_path):
    """Test 2: a new file is reported as ADDED."""
    folder = _make_folder(tmp_path / "test_folder", {"file1.txt": "one\n"})
    baseline_path = tmp_path / "baseline.json"
    _quiet(main.command_baseline, folder, baseline_path=baseline_path)

    (folder / "brand_new.txt").write_bytes(b"surprise\n")

    exit_code = _quiet(main.command_check, folder, baseline_path=baseline_path)
    result = _quiet(main.compare_snapshots,
                    _quiet(main.load_baseline, baseline_path),
                    _quiet(main.build_snapshot, folder))

    assert exit_code == main.EXIT_CHANGES
    assert result["added"] == ["brand_new.txt"]
    assert result["modified"] == []
    assert result["deleted"] == []
    assert result["unchanged"] == ["file1.txt"]


def test_pytest_detects_modified_file(tmp_path):
    """Test 3: changed content is reported as MODIFIED with both hashes."""
    folder = _make_folder(tmp_path / "test_folder", {"file1.txt": "original\n"})
    baseline_path = tmp_path / "baseline.json"
    _quiet(main.command_baseline, folder, baseline_path=baseline_path)

    (folder / "file1.txt").write_bytes(b"original but tampered\n")

    baseline = _quiet(main.load_baseline, baseline_path)
    current = _quiet(main.build_snapshot, folder)
    result = _quiet(main.compare_snapshots, baseline, current)

    assert result["modified"] == ["file1.txt"]
    assert result["added"] == [] and result["deleted"] == []
    assert main.get_hash(baseline["file1.txt"]) != main.get_hash(current["file1.txt"])


def test_pytest_detects_deleted_file(tmp_path):
    """Test 4: a removed file is reported as DELETED."""
    folder = _make_folder(tmp_path / "test_folder", {
        "file1.txt": "one\n",
        "file2.txt": "two\n",
    })
    baseline_path = tmp_path / "baseline.json"
    _quiet(main.command_baseline, folder, baseline_path=baseline_path)

    (folder / "file2.txt").unlink()

    exit_code = _quiet(main.command_check, folder, baseline_path=baseline_path)
    result = _quiet(main.compare_snapshots,
                    _quiet(main.load_baseline, baseline_path),
                    _quiet(main.build_snapshot, folder))

    assert exit_code == main.EXIT_CHANGES
    assert result["deleted"] == ["file2.txt"]
    assert result["unchanged"] == ["file1.txt"]


def test_pytest_reports_no_changes_when_folder_unchanged(tmp_path, capsys):
    """Test 5: an untouched folder prints the exact 'no changes' sentence."""
    folder = _make_folder(tmp_path / "test_folder", {
        "file1.txt": "one\n",
        "file2.txt": "two\n",
    })
    baseline_path = tmp_path / "baseline.json"
    _quiet(main.command_baseline, folder, baseline_path=baseline_path)

    exit_code = main.command_check(folder, baseline_path=baseline_path)
    captured = capsys.readouterr().out

    assert exit_code == main.EXIT_OK
    assert "No changes detected. Folder integrity verified." in captured
    assert "ADDED files (0)" in captured
    assert "UNCHANGED files (2)" in captured


def test_pytest_no_changes_detected_by_comparison(tmp_path):
    """has_changes() is False for two identical snapshots."""
    folder = _make_folder(tmp_path / "test_folder", {"a.txt": "a\n", "b.txt": "b\n"})
    snapshot = _quiet(main.build_snapshot, folder)

    result = _quiet(main.compare_snapshots, snapshot, dict(snapshot))

    assert not main.has_changes(result)
    assert result["unchanged"] == ["a.txt", "b.txt"]


# ---------------------------------------------------------------------------
# 6. Sub-folder support
# ---------------------------------------------------------------------------

def test_pytest_detects_files_inside_subfolders(tmp_path):
    """Test 6: the walk is recursive, including deeply nested files."""
    folder = _make_folder(tmp_path / "test_folder", {
        "file1.txt": "top level\n",
        "subfolder/file3.txt": "one level down\n",
        "subfolder/deeper/file4.txt": "two levels down\n",
    })

    snapshot = _quiet(main.build_snapshot, folder)

    assert "file1.txt" in snapshot
    assert "subfolder/file3.txt" in snapshot
    assert "subfolder/deeper/file4.txt" in snapshot
    assert len(snapshot) == 3


def test_pytest_detects_changes_inside_subfolders(tmp_path):
    """Added, modified and deleted files in sub-folders are all detected."""
    folder = _make_folder(tmp_path / "test_folder", {
        "subfolder/file3.txt": "one\n",
        "subfolder/file4.txt": "two\n",
        "subfolder/deeper/file5.txt": "three\n",
    })
    baseline_path = tmp_path / "baseline.json"
    _quiet(main.command_baseline, folder, baseline_path=baseline_path)

    (folder / "subfolder" / "file3.txt").write_bytes(b"one, but changed\n")
    (folder / "subfolder" / "file4.txt").unlink()
    (folder / "subfolder" / "deeper" / "brand_new.txt").write_bytes(b"new\n")

    result = _quiet(main.compare_snapshots,
                    _quiet(main.load_baseline, baseline_path),
                    _quiet(main.build_snapshot, folder))

    assert result["added"] == ["subfolder/deeper/brand_new.txt"]
    assert result["modified"] == ["subfolder/file3.txt"]
    assert result["deleted"] == ["subfolder/file4.txt"]
    assert result["unchanged"] == ["subfolder/deeper/file5.txt"]


# ---------------------------------------------------------------------------
# 7-8. Baseline problems
# ---------------------------------------------------------------------------

def test_pytest_missing_baseline_is_handled(tmp_path, capsys):
    """Test 7: a missing baseline gives a helpful error and exit code 1."""
    folder = _make_folder(tmp_path / "test_folder", {"file1.txt": "one\n"})
    baseline_path = tmp_path / "does_not_exist.json"

    exit_code = main.command_check(folder, baseline_path=baseline_path)
    captured = capsys.readouterr()

    assert exit_code == main.EXIT_FAILURE
    assert "No baseline found" in captured.err
    assert "python main.py baseline" in captured.err
    assert not baseline_path.exists(), "check must never create a baseline"
    assert _quiet(main.load_baseline, baseline_path) is None


def test_pytest_invalid_json_is_handled_and_not_overwritten(tmp_path, capsys):
    """Test 8: invalid JSON is reported and the file is left untouched."""
    folder = _make_folder(tmp_path / "test_folder", {"file1.txt": "one\n"})
    baseline_path = tmp_path / "baseline.json"
    broken_content = '{ "files": { "file1.txt": '   # deliberately truncated
    baseline_path.write_text(broken_content, encoding="utf-8")

    exit_code = main.command_check(folder, baseline_path=baseline_path)
    captured = capsys.readouterr()

    assert exit_code == main.EXIT_FAILURE
    assert "not valid JSON" in captured.err
    assert baseline_path.read_text(encoding="utf-8") == broken_content


def test_pytest_wrong_baseline_structure_is_handled(tmp_path, capsys):
    """A JSON array (or a non-object 'files' value) is rejected cleanly."""
    folder = _make_folder(tmp_path / "test_folder", {"file1.txt": "one\n"})

    array_baseline = tmp_path / "array.json"
    array_baseline.write_text("[1, 2, 3]", encoding="utf-8")
    assert main.command_check(folder, baseline_path=array_baseline) == main.EXIT_FAILURE
    assert "unexpected structure" in capsys.readouterr().err

    bad_files = tmp_path / "bad_files.json"
    bad_files.write_text('{"files": "not-an-object"}', encoding="utf-8")
    assert main.command_check(folder, baseline_path=bad_files) == main.EXIT_FAILURE


def test_pytest_baseline_command_rejects_missing_folder(tmp_path):
    """`baseline` fails cleanly when the monitored folder does not exist."""
    missing = tmp_path / "no_such_folder"

    exit_code = _quiet(main.command_baseline, missing,
                       baseline_path=tmp_path / "baseline.json")

    assert exit_code == main.EXIT_FAILURE
    assert not (tmp_path / "baseline.json").exists()


def test_pytest_baseline_update_reports_updated(tmp_path, capsys):
    """Running `baseline` twice updates (not duplicates) the file."""
    folder = _make_folder(tmp_path / "test_folder", {"file1.txt": "one\n"})
    baseline_path = tmp_path / "baseline.json"

    _quiet(main.command_baseline, folder, baseline_path=baseline_path)
    (folder / "file2.txt").write_bytes(b"two\n")
    main.command_baseline(folder, baseline_path=baseline_path)
    captured = capsys.readouterr().out

    assert "Baseline updated: 2 file(s)" in captured
    assert json.loads(baseline_path.read_text())["file_count"] == 2


# ---------------------------------------------------------------------------
# 9. Relative paths
# ---------------------------------------------------------------------------

def test_pytest_baseline_stores_relative_paths_only(tmp_path):
    """Test 9: no absolute paths are stored, and keys use forward slashes."""
    folder = _make_folder(tmp_path / "test_folder", {
        "file1.txt": "top\n",
        "subfolder/file2.txt": "nested\n",
    })
    baseline_path = tmp_path / "baseline.json"
    _quiet(main.command_baseline, folder, baseline_path=baseline_path)

    keys = list(json.loads(baseline_path.read_text())["files"])
    assert keys == ["file1.txt", "subfolder/file2.txt"]

    for key in keys:
        assert not key.startswith("/"), "keys must never be absolute"
        assert ":" not in key, "no Windows drive letters in keys"
        assert str(tmp_path) not in key
        assert not Path(key).is_absolute()


def test_pytest_relative_keys_survive_folder_move(tmp_path):
    """A baseline still matches after the project folder is moved."""
    folder = _make_folder(tmp_path / "original" / "test_folder", {
        "file1.txt": "content\n",
        "subfolder/file2.txt": "nested\n",
    })
    baseline_path = tmp_path / "baseline.json"
    _quiet(main.command_baseline, folder, baseline_path=baseline_path)

    moved = tmp_path / "moved_elsewhere" / "test_folder"
    moved.parent.mkdir(parents=True)
    folder.rename(moved)

    result = _quiet(main.compare_snapshots,
                    _quiet(main.load_baseline, baseline_path),
                    _quiet(main.build_snapshot, moved))

    assert not main.has_changes(result)
    assert result["unchanged"] == ["file1.txt", "subfolder/file2.txt"]


# ---------------------------------------------------------------------------
# 10. Size / mtime metadata (stretch goal)
# ---------------------------------------------------------------------------

def test_pytest_metadata_records_size_and_mtime(tmp_path):
    """Test 10: size in bytes and mtime are recorded per file."""
    folder = _make_folder(tmp_path / "test_folder", {"file1.txt": "0123456789"})

    entry = _quiet(main.build_snapshot, folder)["file1.txt"]

    assert entry["size"] == 10
    assert entry["mtime"] == pytest.approx((folder / "file1.txt").stat().st_mtime)
    assert entry["size"] == (folder / "file1.txt").stat().st_size


def test_pytest_timestamp_change_alone_is_not_a_modification(tmp_path):
    """A touched file (new mtime, same content) stays UNCHANGED.

    This is the key rule: SHA-256 decides, metadata is informational only.
    """
    folder = _make_folder(tmp_path / "test_folder", {"file1.txt": "stable content\n"})
    baseline_path = tmp_path / "baseline.json"
    _quiet(main.command_baseline, folder, baseline_path=baseline_path)

    # Rewrite the identical bytes and push the mtime two hours into the future.
    target = folder / "file1.txt"
    original_bytes = target.read_bytes()
    target.write_bytes(original_bytes)
    new_mtime = target.stat().st_mtime + 7200
    os.utime(target, (new_mtime, new_mtime))

    baseline = _quiet(main.load_baseline, baseline_path)
    current = _quiet(main.build_snapshot, folder)
    result = _quiet(main.compare_snapshots, baseline, current)

    assert current["file1.txt"]["mtime"] != baseline["file1.txt"]["mtime"]
    assert current["file1.txt"]["size"] == baseline["file1.txt"]["size"]
    assert result["modified"] == []
    assert result["unchanged"] == ["file1.txt"]
    assert not main.has_changes(result)


def test_pytest_metadata_helpers_format_output(tmp_path):
    """_human_size() and _format_mtime() produce readable strings."""
    assert main._human_size(0) == "0 B"
    assert main._human_size(999) == "999 B"
    assert main._human_size(2048) == "2.0 KiB"
    assert main._human_size(None) == "unknown size"
    assert main._format_mtime(None) == "unknown mtime"
    assert len(main._format_mtime(0)) == 19  # YYYY-MM-DD HH:MM:SS


# ---------------------------------------------------------------------------
# Safety: boundaries, symlinks, CLI wiring
# ---------------------------------------------------------------------------

def test_pytest_no_symlinks_are_followed(tmp_path):
    """Symbolic links are skipped, including links pointing outside the folder."""
    folder = _make_folder(tmp_path / "test_folder", {"real.txt": "real\n"})
    outside = tmp_path / "outside_secret.txt"
    outside.write_bytes(b"must never be hashed\n")

    try:
        (folder / "link.txt").symlink_to(outside)
        (folder / "link_dir").symlink_to(tmp_path)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover
        pytest.skip(f"cannot create symlinks here: {exc}")

    snapshot = _quiet(main.build_snapshot, folder)

    assert list(snapshot) == ["real.txt"]
    hashes = [main.get_hash(entry) for entry in snapshot.values()]
    assert hashlib.sha256(b"must never be hashed\n").hexdigest() not in hashes


def test_pytest_demo_copies_are_excluded_from_baseline(tmp_path):
    """A leftover demo_copy_* file is never recorded in the baseline."""
    folder = _make_folder(tmp_path / "test_folder", {
        "file1.txt": "real\n",
        f"{main.DEMO_PREFIX}file1_999.txt": "temporary\n",
    })

    snapshot = _quiet(main.build_snapshot, folder)

    assert list(snapshot) == ["file1.txt"]


def test_pytest_unreadable_file_does_not_break_baseline(tmp_path):
    """An unreadable file is skipped; the rest of the snapshot still works."""
    folder = _make_folder(tmp_path / "test_folder", {
        "good.txt": "readable\n",
        "bad.txt": "unreadable\n",
    })
    real_open = builtins.open

    def selective_open(file, mode="r", *args, **kwargs):
        if Path(file).name == "bad.txt":
            raise PermissionError(13, "Permission denied")
        return real_open(file, mode, *args, **kwargs)

    with mock.patch("builtins.open", side_effect=selective_open):
        snapshot = _quiet(main.build_snapshot, folder)

    assert list(snapshot) == ["good.txt"]


def test_pytest_cli_baseline_and_check_end_to_end(tmp_path, capsys):
    """The argparse layer wires `baseline` and `check` to the right functions."""
    folder = _make_folder(tmp_path / "test_folder", {"file1.txt": "one\n"})
    baseline_path = tmp_path / "cli_baseline.json"

    assert main.main(["--folder", str(folder), "--baseline", str(baseline_path),
                      "baseline"]) == main.EXIT_OK
    assert baseline_path.is_file()

    assert main.main(["--folder", str(folder), "--baseline", str(baseline_path),
                      "check"]) == main.EXIT_OK

    (folder / "file2.txt").write_bytes(b"two\n")
    assert main.main(["--folder", str(folder), "--baseline", str(baseline_path),
                      "check"]) == main.EXIT_CHANGES
    assert "ADDED files (1)" in capsys.readouterr().out


def test_pytest_cli_default_command_is_still_week1_scan(tmp_path, capsys):
    """`python main.py` (no command) keeps the Week 1 scanning behaviour."""
    folder = _make_folder(tmp_path / "test_folder", {"file1.txt": "one\n"})

    exit_code = main.main(["--folder", str(folder)])
    captured = capsys.readouterr().out

    assert exit_code == main.EXIT_OK
    assert "SHA-256 FILE INTEGRITY CHECKER" in captured
    assert hashlib.sha256(b"one\n").hexdigest() in captured


def test_pytest_cli_rejects_unknown_command(tmp_path):
    """An unknown command is an argparse usage error (exit code 2)."""
    with contextlib.redirect_stderr(io.StringIO()):
        with pytest.raises(SystemExit) as excinfo:
            main.parse_args(["frobnicate"])
    assert excinfo.value.code == 2


def test_pytest_cli_sha1_baseline_and_check(tmp_path):
    """SHA-1 still works end to end for baseline + check."""
    folder = _make_folder(tmp_path / "test_folder", {"file1.txt": "one\n"})
    baseline_path = tmp_path / "sha1.json"

    _quiet(main.command_baseline, folder, baseline_path=baseline_path,
           algorithm="sha1")
    stored = json.loads(baseline_path.read_text())["files"]["file1.txt"]["sha1"]
    assert stored == hashlib.sha1(b"one\n").hexdigest()
    assert len(stored) == 40

    assert _quiet(main.command_check, folder, baseline_path=baseline_path,
                  algorithm="sha1") == main.EXIT_OK


# ---------------------------------------------------------------------------
# Week 2 integration test against the shipped project folder
# ---------------------------------------------------------------------------

def test_pytest_shipped_baseline_matches_shipped_test_folder():
    """The committed baseline.json must match the shipped sample files."""
    project_root = Path(__file__).resolve().parent
    baseline_path = project_root / main.BASELINE_FILENAME
    if not baseline_path.is_file():
        pytest.skip("baseline.json is not shipped with this copy")

    result = _quiet(main.compare_snapshots,
                    _quiet(main.load_baseline, baseline_path),
                    _quiet(main.build_snapshot, project_root / "test_folder"))

    assert not main.has_changes(result), (
        f"shipped baseline is stale: added={result['added']} "
        f"modified={result['modified']} deleted={result['deleted']}"
    )
    assert result["unchanged"], "expected the sample files to be covered"


if __name__ == "__main__":
    unittest.main(verbosity=2)
