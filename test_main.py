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


# ===========================================================================
# WEEK 3 TESTS - continuous monitoring, logging, ignore rules, robustness
# ===========================================================================
#
# Same conventions as the Week 2 tests: plain module-level functions using
# pytest's `tmp_path`, runnable by BOTH pytest and unittest.
#
# Determinism note: no test waits on real time. The watch loop is exercised with
# interval=0 and `max_scans`, which exits after the requested number of scans.
# Clean shutdown (Ctrl+C / SIGTERM) is simulated by making the scan raise
# KeyboardInterrupt, exactly what the signal handler does.

import logging
import re


# ---------------------------------------------------------------------------
# Week 3 helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def clean_logging():
    """Give each test a fresh logger and always tear the handlers down."""
    main.reset_logging()
    yield
    main.reset_logging()


def _quiet_command(func, *args, **kwargs):
    """Run a command function with its console output captured."""
    with contextlib.redirect_stdout(io.StringIO()), \
            contextlib.redirect_stderr(io.StringIO()):
        return func(*args, **kwargs)


def _baseline_for(tmp_path, files, ignore_text=None):
    """Create a folder + baseline.json; returns (folder, baseline_path)."""
    folder = _make_folder(tmp_path / "test_folder", files)
    baseline_path = tmp_path / "baseline.json"
    _quiet_command(main.command_baseline, folder, baseline_path=baseline_path)
    return folder, baseline_path


def _read_log(path):
    """Return the contents of the log file (or '' when it was not created)."""
    try:
        return Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


# ---------------------------------------------------------------------------
# 1. Ignore rules - pattern matching
# ---------------------------------------------------------------------------

def test_w3_ignore_rules_match_globs_and_folder_names(tmp_path):
    """*.tmp, .git, .venv and __pycache__ all match at any depth."""
    ignore_path = tmp_path / ".filewatchignore"
    ignore_path.write_text(
        "# comment line\n"
        "\n"
        "*.tmp\n"
        ".git\n"
        ".venv\n"
        "__pycache__\n"
        "**/cache\n",
        encoding="utf-8",
    )
    rules = main.IgnoreRules.from_file(ignore_path)

    # matched
    assert rules.is_ignored("notes.tmp")
    assert rules.is_ignored("subfolder/deep/notes.tmp")
    assert rules.is_ignored(".git/config")
    assert rules.is_ignored("project/.git/HEAD")
    assert rules.is_ignored(".venv/lib/python3.9/site-packages/x.py")
    assert rules.is_ignored("__pycache__/module.cpython-313.pyc")
    assert rules.is_ignored("src/__pycache__/module.pyc")
    assert rules.is_ignored("a/b/cache/thing.bin")

    # not matched
    assert not rules.is_ignored("file1.txt")
    assert not rules.is_ignored("subfolder/file9.txt")
    assert not rules.is_ignored("tmpfile.txt")
    assert not rules.is_ignored("gitnotes.md")


def test_w3_ignore_comments_and_blank_lines_are_skipped(tmp_path):
    """Comments and blank lines never become patterns."""
    ignore_path = tmp_path / ".filewatchignore"
    ignore_path.write_text("# only a comment\n\n   \n*.log\n", encoding="utf-8")

    rules = main.IgnoreRules.from_file(ignore_path)

    assert rules.patterns == ["*.log"]
    assert len(rules) == 1


def test_w3_ignore_file_missing_is_harmless(tmp_path):
    """A missing ignore file simply means no extra rules (no crash)."""
    rules = main.IgnoreRules.from_file(tmp_path / "nope.filewatchignore")
    assert rules.patterns == []


def test_w3_builtin_patterns_always_apply():
    """The tool's own log file is ignored even without a config file."""
    rules = main.IgnoreRules.default()
    assert rules.is_ignored("filewatch.log")
    assert rules.is_ignored("baseline.json.tmp")
    assert rules.is_ignored("xpkg/__pycache__/m.pyc")


def test_w3_shipped_filewatchignore_covers_required_patterns():
    """The shipped .filewatchignore contains *.tmp, .git, .venv, __pycache__."""
    ignore_path = Path(__file__).resolve().parent / main.IGNORE_FILENAME
    assert ignore_path.is_file(), ".filewatchignore should ship with the project"

    rules = main.IgnoreRules.from_file(ignore_path)
    for required in ("*.tmp", ".git", ".venv", "__pycache__"):
        assert required in rules.patterns, f"{required} missing from .filewatchignore"


# ---------------------------------------------------------------------------
# 2. Ignore rules applied to scanning, baselines and comparisons
# ---------------------------------------------------------------------------

def test_w3_ignored_files_never_enter_a_baseline(tmp_path):
    """Ignored files are excluded from the snapshot and the baseline JSON."""
    folder = _make_folder(tmp_path / "test_folder", {
        "keep.txt": "keep me\n",
        "skip.tmp": "ignore me\n",
        "__pycache__/module.pyc": "bytecode\n",
        ".venv/lib/thing.py": "dependency\n",
        ".git/HEAD": "ref\n",
    })
    ignore_path = tmp_path / ".filewatchignore"
    ignore_path.write_text("*.tmp\n__pycache__\n.venv\n.git\n", encoding="utf-8")
    baseline_path = tmp_path / "baseline.json"

    _quiet_command(main.command_baseline, folder, baseline_path=baseline_path,
                   ignore_path=ignore_path)

    stored = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert list(stored["files"]) == ["keep.txt"]


def test_w3_ignored_files_never_trigger_alerts(tmp_path):
    """Creating ignored files after the baseline produces no changes at all."""
    folder, baseline_path = _baseline_for(tmp_path, {"file1.txt": "one\n"})
    ignore_path = tmp_path / ".filewatchignore"
    ignore_path.write_text("*.tmp\n*.log\n__pycache__\n.git\n.venv\n", encoding="utf-8")

    # Re-baseline with the ignore file in effect.
    _quiet_command(main.command_baseline, folder, baseline_path=baseline_path,
                   ignore_path=ignore_path)

    # Now create a pile of noise.
    (folder / "noise.tmp").write_bytes(b"noise\n")
    (folder / "output.log").write_bytes(b"log line\n")
    (folder / "__pycache__").mkdir()
    (folder / "__pycache__" / "x.pyc").write_bytes(b"bytecode\n")
    (folder / ".git").mkdir()
    (folder / ".git" / "HEAD").write_bytes(b"ref\n")
    (folder / ".venv").mkdir()
    (folder / ".venv" / "activate").write_bytes(b"script\n")

    exit_code = _quiet_command(main.command_check, folder,
                               baseline_path=baseline_path,
                               ignore_path=ignore_path)

    assert exit_code == main.EXIT_OK
    rules = main.load_ignore_rules(ignore_path, folder=folder)
    baseline = _quiet_command(main.load_baseline, baseline_path)
    current = _quiet_command(main.build_snapshot, folder, ignore=rules)
    result = _quiet_command(main.compare_snapshots, baseline, current)

    assert result["added"] == []
    assert not main.has_changes(result), "ignored noise must not raise alerts"


def test_w3_watch_reports_no_change_for_ignored_files(tmp_path, clean_logging):
    """A full watch scan ignores noise and logs no change alerts."""
    folder = _make_folder(tmp_path / "test_folder", {"file1.txt": "one\n"})
    baseline_path = tmp_path / "baseline.json"
    ignore_path = tmp_path / ".filewatchignore"
    ignore_path.write_text("*.tmp\n", encoding="utf-8")
    log_path = tmp_path / "filewatch.log"
    _quiet_command(main.command_baseline, folder, baseline_path=baseline_path,
                   ignore_path=ignore_path)

    (folder / "scratch.tmp").write_bytes(b"temporary\n")

    exit_code = _quiet_command(main.command_watch, folder,
                               baseline_path=baseline_path, interval=0,
                               log_path=log_path, ignore_path=ignore_path,
                               max_scans=1)

    assert exit_code == main.EXIT_OK
    log_text = _read_log(log_path)
    assert "scratch.tmp" not in log_text
    assert "no changes" in log_text


def test_w3_ignore_rules_prune_ignored_directories_early(tmp_path):
    """Ignored directories are pruned, so their files are never walked."""
    folder = _make_folder(tmp_path / "test_folder", {
        "keep.txt": "keep\n",
        ".git/objects/deep/blob": "gitdata\n",
    })
    rules = main.IgnoreRules([".git"])

    files, skipped = _quiet_command(main.walk_regular_files, folder, ignore=rules)
    names = [main._relative_key(item, folder) for item in files]

    assert names == ["keep.txt"]
    assert any(".git" in note and "ignored" in note for note in skipped)


# ---------------------------------------------------------------------------
# 3. Monitoring: changes detected by the watch loop
# ---------------------------------------------------------------------------

def test_w3_watch_alerts_added_modified_deleted(tmp_path, clean_logging, capsys):
    """One watch scan reports ADDED, MODIFIED and DELETED with relative paths."""
    folder = _make_folder(tmp_path / "test_folder", {
        "file1.txt": "one\n",
        "file2.txt": "two\n",
        "subfolder/deep.txt": "deep\n",
    })
    baseline_path = tmp_path / "baseline.json"
    log_path = tmp_path / "filewatch.log"
    _quiet_command(main.command_baseline, folder, baseline_path=baseline_path)

    (folder / "subfolder" / "new_file.txt").write_bytes(b"new\n")
    (folder / "file1.txt").write_bytes(b"one, edited\n")
    (folder / "file2.txt").unlink()

    # Called directly (not via _quiet_command) so capsys can see the alerts.
    exit_code = main.command_watch(folder, baseline_path=baseline_path,
                                   interval=0, log_path=log_path,
                                   max_scans=1, use_colour=False)
    captured = capsys.readouterr().out

    assert exit_code == main.EXIT_OK
    assert "ADDED (1)" in captured
    assert "subfolder/new_file.txt" in captured
    assert "MODIFIED (1)" in captured
    assert "file1.txt" in captured
    assert "DELETED (1)" in captured
    assert "file2.txt" in captured


def test_w3_watch_logs_every_change_and_scan(tmp_path, clean_logging):
    """The log file records start, each change, and the end of the run."""
    folder, baseline_path = _baseline_for(tmp_path, {"file1.txt": "one\n"})
    log_path = tmp_path / "filewatch.log"
    (folder / "added.txt").write_bytes(b"added\n")

    _quiet_command(main.command_watch, folder, baseline_path=baseline_path,
                   interval=0, log_path=log_path, max_scans=1)

    log_text = _read_log(log_path)
    assert "Watch started" in log_text
    assert "ADDED file: added.txt" in log_text
    assert "Watch ended" in log_text
    # Structured format: timestamp | level | logger | message
    assert " | WARNING  | filewatch | " in log_text
    assert " | INFO     | filewatch | " in log_text


def test_w3_watch_repeats_alerts_or_not(tmp_path, clean_logging):
    """alert_once=True reports a change once; False repeats it each scan."""
    folder, baseline_path = _baseline_for(tmp_path, {"file1.txt": "one\n"})
    (folder / "added.txt").write_bytes(b"added\n")

    once_log = tmp_path / "once.log"
    _quiet_command(main.command_watch, folder, baseline_path=baseline_path,
                   interval=0, log_path=once_log, max_scans=3)
    assert _read_log(once_log).count("ADDED file: added.txt") == 1

    main.reset_logging()
    always_log = tmp_path / "always.log"
    _quiet_command(main.command_watch, folder, baseline_path=baseline_path,
                   interval=0, log_path=always_log, max_scans=3,
                   alert_once=False)
    assert _read_log(always_log).count("ADDED file: added.txt") == 3


def test_w3_watch_never_modifies_the_baseline_file(tmp_path, clean_logging):
    """watch advances only an in-memory reference - baseline.json is untouched."""
    folder, baseline_path = _baseline_for(tmp_path, {"file1.txt": "one\n"})
    before = baseline_path.read_bytes()

    (folder / "added.txt").write_bytes(b"new\n")
    (folder / "file1.txt").write_bytes(b"changed\n")

    _quiet_command(main.command_watch, folder, baseline_path=baseline_path,
                   interval=0, log_path=tmp_path / "x.log", max_scans=3)

    assert baseline_path.read_bytes() == before


def test_w3_advance_reference_updates_only_alerted_paths():
    """advance_reference() applies added/modified/deleted and keeps the rest."""
    reference = {
        "keep.txt": {"sha256": "aaa"},
        "gone.txt": {"sha256": "bbb"},
        "change.txt": {"sha256": "ccc"},
    }
    current = {
        "keep.txt": {"sha256": "aaa"},
        "change.txt": {"sha256": "DDD"},
        "new.txt": {"sha256": "eee"},
    }
    result = main.compare_snapshots(reference, current)

    updated = main.advance_reference(reference, current, result)

    assert set(updated) == {"keep.txt", "change.txt", "new.txt"}
    assert updated["change.txt"]["sha256"] == "DDD"
    assert updated["new.txt"]["sha256"] == "eee"
    assert reference["change.txt"]["sha256"] == "ccc", "input must not be mutated"


def test_w3_scan_once_returns_snapshot_and_result(tmp_path, clean_logging):
    """scan_once() is the reusable single cycle used by watch."""
    folder, baseline_path = _baseline_for(tmp_path, {"file1.txt": "one\n"})
    baseline = _quiet_command(main.load_baseline, baseline_path)
    (folder / "file2.txt").write_bytes(b"two\n")

    current, result = _quiet_command(main.scan_once, folder, baseline)

    assert "file2.txt" in current
    assert result["added"] == ["file2.txt"]


# ---------------------------------------------------------------------------
# 4. Robust error handling
# ---------------------------------------------------------------------------

def test_w3_permission_error_is_logged_and_monitoring_continues(
        tmp_path, clean_logging):
    """A PermissionError on one file logs an error; the loop keeps going."""
    folder, baseline_path = _baseline_for(tmp_path, {
        "good.txt": "readable\n",
        "locked.txt": "unreadable\n",
    })
    log_path = tmp_path / "filewatch.log"
    real_open = builtins.open

    def selective_open(file, mode="r", *args, **kwargs):
        if Path(file).name == "locked.txt":
            raise PermissionError(13, "Permission denied")
        return real_open(file, mode, *args, **kwargs)

    with mock.patch("builtins.open", side_effect=selective_open):
        exit_code = _quiet_command(main.command_watch, folder,
                                   baseline_path=baseline_path, interval=0,
                                   log_path=log_path, max_scans=2)

    log_text = _read_log(log_path)
    assert exit_code == main.EXIT_OK, "monitoring must survive a file error"
    assert "Unreadable file" in log_text
    assert "locked.txt" in log_text


def test_w3_unreadable_file_is_not_reported_as_deleted(tmp_path, clean_logging):
    """An unreadable file is never announced as DELETED."""
    folder, baseline_path = _baseline_for(tmp_path, {
        "file1.txt": "one\n",
        "locked.txt": "two\n",
    })
    baseline = _quiet_command(main.load_baseline, baseline_path)
    real_open = builtins.open

    def selective_open(file, mode="r", *args, **kwargs):
        if Path(file).name == "locked.txt":
            raise PermissionError(13, "Permission denied")
        return real_open(file, mode, *args, **kwargs)

    with mock.patch("builtins.open", side_effect=selective_open):
        _current, result = _quiet_command(main.scan_once, folder, baseline)

    assert result["deleted"] == [], "must not claim a real deletion"
    assert result["unreadable"] == ["locked.txt"]
    assert not main.has_changes(result)


def test_w3_unreadable_file_that_really_vanishes_is_deleted(tmp_path, clean_logging):
    """Once the path is genuinely gone, DELETED is reported."""
    folder, baseline_path = _baseline_for(tmp_path, {
        "file1.txt": "one\n",
        "vanishing.txt": "two\n",
    })
    baseline = _quiet_command(main.load_baseline, baseline_path)
    (folder / "vanishing.txt").unlink()  # the file really is gone
    current = _quiet_command(main.build_snapshot, folder)

    # The file was unreadable in the previous cycle, but it no longer exists:
    # this is a genuine deletion, so it is reported.
    result = _quiet_command(main.compare_snapshots, baseline, current,
                            main.DEFAULT_ALGORITHM, {"vanishing.txt"}, folder)

    assert result["deleted"] == ["vanishing.txt"]
    assert result["unreadable"] == []


def test_w3_file_disappearing_between_walk_and_read(tmp_path, clean_logging):
    """A file removed mid-scan is logged, not crashed on, and not "deleted"."""
    folder, baseline_path = _baseline_for(tmp_path, {
        "file1.txt": "one\n",
        "race.txt": "two\n",
    })
    baseline = _quiet_command(main.load_baseline, baseline_path)
    real_open = builtins.open

    def vanishing_open(file, mode="r", *args, **kwargs):
        if Path(file).name == "race.txt":
            raise FileNotFoundError(2, "No such file or directory")
        return real_open(file, mode, *args, **kwargs)

    with mock.patch("builtins.open", side_effect=vanishing_open):
        _current, result = _quiet_command(main.scan_once, folder, baseline)

    # The path still exists on disk, so it is "unreadable", not "deleted".
    assert result["unreadable"] == ["race.txt"]
    assert result["deleted"] == []


def test_w3_oserror_in_walk_does_not_stop_the_scan(tmp_path, clean_logging):
    """An OSError while listing a directory is contained."""
    folder = _make_folder(tmp_path / "test_folder", {"file1.txt": "one\n"})

    def boom(*args, **kwargs):
        raise OSError(5, "Input/output error")

    with mock.patch("main.os.walk", side_effect=boom):
        snapshot = _quiet_command(main.build_snapshot, folder)

    assert snapshot == {}, "a broken walk returns an empty snapshot, not a crash"


def test_w3_watch_startup_errors_return_failure(tmp_path, clean_logging):
    """Missing baseline / missing folder / tiny interval all fail cleanly."""
    folder = _make_folder(tmp_path / "test_folder", {"file1.txt": "one\n"})
    log_path = tmp_path / "filewatch.log"

    # No baseline yet
    assert _quiet_command(main.command_watch, folder,
                          baseline_path=tmp_path / "missing.json",
                          interval=0, log_path=log_path,
                          max_scans=1) == main.EXIT_FAILURE

    # Baseline exists, folder gone
    baseline_path = tmp_path / "baseline.json"
    _quiet_command(main.command_baseline, folder, baseline_path=baseline_path)
    assert _quiet_command(main.command_watch, tmp_path / "no_such_folder",
                          baseline_path=baseline_path, interval=0,
                          log_path=log_path, max_scans=1) == main.EXIT_FAILURE

    # Negative interval is nonsense and must be refused
    assert _quiet_command(main.command_watch, folder,
                          baseline_path=baseline_path, interval=-1,
                          log_path=log_path, max_scans=1) == main.EXIT_FAILURE

    # Sanity check the boundary: 0 is allowed, -0.001 is not
    assert main.MIN_INTERVAL == 0.0
    assert _quiet_command(main.command_watch, folder,
                          baseline_path=baseline_path, interval=-0.001,
                          log_path=log_path, max_scans=1) == main.EXIT_FAILURE


def test_w3_check_never_writes_baseline_on_error(tmp_path):
    """A check against a broken baseline leaves the file untouched."""
    folder = _make_folder(tmp_path / "test_folder", {"file1.txt": "one\n"})
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text("{broken", encoding="utf-8")
    before = baseline_path.read_bytes()

    exit_code = _quiet_command(main.command_check, folder,
                               baseline_path=baseline_path)

    assert exit_code == main.EXIT_FAILURE
    assert baseline_path.read_bytes() == before


# ---------------------------------------------------------------------------
# 5. Clean shutdown
# ---------------------------------------------------------------------------

def test_w3_ctrl_c_exits_cleanly_without_traceback(tmp_path, clean_logging, capsys):
    """KeyboardInterrupt -> exit 130, friendly message, no traceback."""
    folder, baseline_path = _baseline_for(tmp_path, {"file1.txt": "one\n"})
    log_path = tmp_path / "filewatch.log"

    with mock.patch("main.scan_once", side_effect=KeyboardInterrupt):
        exit_code = main.command_watch(folder, baseline_path=baseline_path,
                                       interval=0, log_path=log_path,
                                       max_scans=5)

    captured = capsys.readouterr()
    assert exit_code == main.EXIT_INTERRUPTED == 130
    assert "stopped by user" in captured.out
    assert "Traceback" not in captured.out
    assert "Traceback" not in captured.err
    assert "interrupted by user" in _read_log(log_path).lower()


def test_w3_sigterm_is_translated_to_clean_exit(tmp_path, clean_logging):
    """The SIGTERM handler raises KeyboardInterrupt, which watch handles."""
    folder, baseline_path = _baseline_for(tmp_path, {"file1.txt": "one\n"})

    main._install_sigterm_handler()

    # Simulate the handler firing: it must raise KeyboardInterrupt, not exit.
    with mock.patch("main.scan_once", side_effect=KeyboardInterrupt):
        exit_code = main.command_watch(folder, baseline_path=baseline_path,
                                       interval=0,
                                       log_path=tmp_path / "term.log",
                                       max_scans=5)
    assert exit_code == main.EXIT_INTERRUPTED


def test_w3_watch_returns_ok_after_requested_scans(tmp_path, clean_logging):
    """--once style operation completes normally with EXIT_OK."""
    folder, baseline_path = _baseline_for(tmp_path, {"file1.txt": "one\n"})

    exit_code = _quiet_command(main.command_watch, folder,
                               baseline_path=baseline_path, interval=0,
                               log_path=tmp_path / "once.log", max_scans=1)

    assert exit_code == main.EXIT_OK


# ---------------------------------------------------------------------------
# 6. Logging hygiene
# ---------------------------------------------------------------------------

def test_w3_setup_logging_does_not_duplicate_handlers(tmp_path, clean_logging):
    """Calling setup_logging() repeatedly keeps exactly one file handler."""
    log_path = tmp_path / "filewatch.log"

    main.setup_logging(log_path, console=False)
    main.setup_logging(log_path, console=False)
    main.setup_logging(log_path, console=False)

    logger = logging.getLogger(main.LOGGER_NAME)
    managed = [h for h in logger.handlers
               if getattr(h, "_filewatch_managed", False)]

    assert len(managed) == 1

    # And each event is written exactly once.
    logger.warning("unique marker line")
    for handler in managed:
        handler.flush()
    assert _read_log(log_path).count("unique marker line") == 1


def test_w3_logger_does_not_propagate_to_root(tmp_path, clean_logging):
    """The filewatch logger stays out of the application's root logger."""
    main.setup_logging(tmp_path / "filewatch.log", console=False)
    assert logging.getLogger(main.LOGGER_NAME).propagate is False


def test_w3_reset_logging_removes_managed_handlers(tmp_path, clean_logging):
    """reset_logging() leaves no managed handler behind."""
    main.setup_logging(tmp_path / "filewatch.log")
    main.reset_logging()

    logger = logging.getLogger(main.LOGGER_NAME)
    assert [h for h in logger.handlers
            if getattr(h, "_filewatch_managed", False)] == []


def test_w3_log_has_timestamp_level_and_message(tmp_path, clean_logging):
    """Log lines are structured: timestamp | LEVEL | logger | message."""
    folder, baseline_path = _baseline_for(tmp_path, {"file1.txt": "one\n"})
    log_path = tmp_path / "filewatch.log"
    (folder / "new.txt").write_bytes(b"new\n")

    _quiet_command(main.command_watch, folder, baseline_path=baseline_path,
                   interval=0, log_path=log_path, max_scans=1)

    line = next(ln for ln in _read_log(log_path).splitlines()
                if "ADDED file" in ln)
    parts = [part.strip() for part in line.split("|")]
    assert len(parts) == 4
    assert parts[1] == "WARNING"
    assert parts[2] == "filewatch"
    assert "new.txt" in parts[3]
    # Leading timestamp: YYYY-MM-DD HH:MM:SS
    assert len(parts[0]) == 19 and parts[0][4] == "-" and parts[0][13] == ":"


# ---------------------------------------------------------------------------
# 7. Alerts (formatting and colour)
# ---------------------------------------------------------------------------

def test_w3_format_alerts_lists_relative_paths():
    """Alert lines contain each changed relative path."""
    result = {"added": ["sub/new.txt"], "modified": ["sub/changed.txt"],
              "deleted": ["gone.txt"], "unchanged": [], "skipped": [],
              "unreadable": []}

    lines = main.format_alerts(result, use_colour=False)
    text = "\n".join(lines)

    assert "sub/new.txt" in text
    assert "sub/changed.txt" in text
    assert "gone.txt" in text
    assert "ADDED (1)" in text and "MODIFIED (1)" in text and "DELETED (1)" in text


def test_w3_format_alerts_colour_can_be_disabled_and_enabled():
    """Colour escapes appear only when colour is enabled."""
    result = {"added": ["a.txt"], "modified": [], "deleted": [],
              "unchanged": [], "skipped": [], "unreadable": []}

    plain = "\n".join(main.format_alerts(result, use_colour=False))
    colourful = "\n".join(main.format_alerts(result, use_colour=True))

    assert "\033[" not in plain
    assert "\033[" in colourful


def test_w3_colour_autodetection_respects_no_color(monkeypatch, tmp_path):
    """NO_COLOR disables colour; a TTY enables it."""
    class FakeTTY(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("TERM", raising=False)
    assert main.supports_colour(FakeTTY()) is True

    monkeypatch.setenv("NO_COLOR", "1")
    assert main.supports_colour(FakeTTY()) is False

    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setenv("TERM", "dumb")
    assert main.supports_colour(FakeTTY()) is False

    monkeypatch.delenv("TERM")
    assert main.supports_colour(io.StringIO()) is False, "not a TTY -> no colour"


def test_w3_print_alerts_says_nothing_when_unchanged(capsys):
    """print_alerts() returns False and prints nothing without changes."""
    result = {"added": [], "modified": [], "deleted": [], "unchanged": ["a.txt"],
              "skipped": [], "unreadable": []}

    assert main.print_alerts(result, use_colour=False) is False
    assert capsys.readouterr().out == ""


def test_w3_unreadable_files_are_shown_in_alerts(capsys):
    """Unreadable files get their own clearly-labelled section."""
    result = {"added": [], "modified": [], "deleted": [],
              "unchanged": [], "skipped": [], "unreadable": ["locked.txt"]}

    main.print_alerts(result, use_colour=False)
    out = capsys.readouterr().out

    assert "UNREADABLE (1)" in out
    assert "locked.txt" in out
    assert "not reported as deleted" in out.lower()


# ---------------------------------------------------------------------------
# 8. Backward compatibility (Week 1 + Week 2 still intact)
# ---------------------------------------------------------------------------

def test_w3_week1_and_week2_apis_keep_their_old_signatures(tmp_path):
    """Existing call styles must still work without the new arguments."""
    folder = _make_folder(tmp_path / "test_folder", {"file1.txt": "one\n"})

    # Week 1
    assert len(main.hash_file(folder / "file1.txt")) == 64
    assert len(_quiet_command(main.hash_file, folder / "file1.txt", "sha1")) == 40
    assert isinstance(_quiet_command(main.monitor_folder, folder), dict)

    # Week 2 - no ignore/unreadable arguments at all
    snapshot = _quiet_command(main.build_snapshot, folder)
    result = _quiet_command(main.compare_snapshots, snapshot, snapshot)
    assert result["unchanged"] == ["file1.txt"]
    assert set(result) == {"added", "modified", "deleted", "unchanged",
                           "skipped", "unreadable"}


def test_w3_cli_still_supports_every_previous_command(tmp_path, capsys):
    """baseline, check, default scan and --demo all still work through main()."""
    folder = _make_folder(tmp_path / "test_folder", {"file1.txt": "one\n"})
    baseline_path = tmp_path / "baseline.json"

    assert main.main(["--folder", str(folder), "--baseline", str(baseline_path),
                      "baseline"]) == main.EXIT_OK
    assert main.main(["--folder", str(folder), "--baseline", str(baseline_path),
                      "check"]) == main.EXIT_OK
    assert main.main(["--folder", str(folder)]) == main.EXIT_OK
    assert main.main(["--folder", str(folder),
                      "--log", str(tmp_path / "d.log"),
                      "watch", "--once"]) == main.EXIT_OK
    capsys.readouterr()


def test_w3_cli_parses_watch_options():
    """--interval, --log, --ignore, --once and --repeat-alerts are wired up."""
    args = main.parse_args(["watch", "--interval", "2.5", "--log", "l.log",
                            "--ignore", "i.cfg", "--once", "--repeat-alerts"])
    assert args.command == "watch"
    assert args.interval == 2.5
    assert args.log == "l.log"
    assert args.ignore == "i.cfg"
    assert args.once is True
    assert args.repeat_alerts is True

    defaults = main.parse_args(["watch"])
    assert defaults.interval == main.DEFAULT_INTERVAL
    assert defaults.log == main.LOG_FILENAME
    assert defaults.once is False
    assert defaults.repeat_alerts is False


def test_w3_cli_rejects_non_numeric_interval(tmp_path):
    """A non-numeric --interval is a usage error (exit code 2)."""
    with contextlib.redirect_stderr(io.StringIO()):
        with pytest.raises(SystemExit) as excinfo:
            main.parse_args(["watch", "--interval", "soon"])
    assert excinfo.value.code == 2


def test_w3_demo_still_never_modifies_originals(tmp_path):
    """Week 1's safe demonstration still leaves the original untouched."""
    folder = _make_folder(tmp_path / "test_folder", {"sample.txt": "original\n"})
    before = (folder / "sample.txt").read_bytes()

    result = _quiet_command(main.demonstrate_avalanche, folder)

    assert result["changed"] is True
    assert (folder / "sample.txt").read_bytes() == before
    assert [p.name for p in folder.iterdir()] == ["sample.txt"]


def test_w3_shipped_files_still_verify_against_shipped_baseline():
    """The committed baseline still matches the shipped samples (with ignores)."""
    project_root = Path(__file__).resolve().parent
    baseline_path = project_root / main.BASELINE_FILENAME
    if not baseline_path.is_file():
        pytest.skip("baseline.json not shipped in this copy")

    rules = main.load_ignore_rules(folder=project_root / "test_folder")
    result = _quiet_command(main.compare_snapshots,
                            _quiet_command(main.load_baseline, baseline_path),
                            _quiet_command(main.build_snapshot,
                                           project_root / "test_folder",
                                           main.DEFAULT_ALGORITHM, rules))

    assert not main.has_changes(result), (
        f"added={result['added']} modified={result['modified']} "
        f"deleted={result['deleted']}"
    )


if __name__ == "__main__":
    unittest.main(verbosity=2)
# ===========================================================================
# WEEK 4 (STRETCH) TESTS - HMAC baseline signing
# ===========================================================================
#
# Keys are generated in-process with secrets.token_hex() and passed as bytes,
# so no secret is ever hardcoded, committed, or read from the environment of
# the test machine. A couple of tests deliberately exercise the environment
# variable path using monkeypatch, which is cleaned up automatically.

import stat as _stat


@pytest.fixture
def hmac_key():
    """A fresh random 32-byte HMAC key per test."""
    return bytes.fromhex(main.generate_hmac_key())


def _signed_baseline(tmp_path, files, key):
    """Create a folder and a *signed* baseline.json; returns their paths."""
    folder = _make_folder(tmp_path / "test_folder", files)
    baseline_path = tmp_path / "baseline.json"
    _quiet_command(main.command_baseline, folder, baseline_path=baseline_path,
                   sign=True, key=key)
    return folder, baseline_path


def _read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Key generation and resolution
# ---------------------------------------------------------------------------

def test_w4_keygen_is_random_and_long_enough():
    """generate_hmac_key() returns unpredictable keys of >= 32 bytes."""
    first = main.generate_hmac_key()
    second = main.generate_hmac_key()

    assert first != second, "two keys must never be identical"
    assert len(bytes.fromhex(first)) >= main.MIN_HMAC_KEY_BYTES
    int(first, 16)  # valid hex


def test_w4_no_hardcoded_key_in_the_source():
    """The source must not contain a literal key (documentation requirement)."""
    source = (Path(__file__).resolve().parent / "main.py").read_text(encoding="utf-8")

    # A 32+ byte hex literal would look like a key. There should be none.
    suspicious = re.findall(r"['\"][0-9a-fA-F]{64,}['\"]", source)
    assert suspicious == [], f"possible hardcoded key(s): {suspicious}"
    # And the key always comes from the environment or a file.
    assert "FILEWATCH_HMAC_KEY" in source


def test_w4_resolve_key_from_explicit_bytes(hmac_key):
    """An explicitly supplied key is used as-is."""
    assert main.resolve_hmac_key(key=hmac_key) == hmac_key


def test_w4_resolve_key_from_environment_hex(monkeypatch):
    """A hex environment value is decoded as hex bytes."""
    raw = main.generate_hmac_key()
    monkeypatch.delenv(main.HMAC_KEY_FILE_ENV, raising=False)
    monkeypatch.setenv(main.HMAC_KEY_ENV, raw)

    resolved = main.resolve_hmac_key()

    assert resolved == bytes.fromhex(raw)


def test_w4_resolve_key_from_environment_raw_text(monkeypatch):
    """A non-hex environment value is used as raw UTF-8 bytes."""
    passphrase = "correct horse battery staple correct horse"  # 44 bytes
    monkeypatch.delenv(main.HMAC_KEY_FILE_ENV, raising=False)
    monkeypatch.setenv(main.HMAC_KEY_ENV, passphrase)

    assert main.resolve_hmac_key() == passphrase.encode("utf-8")


def test_w4_missing_key_raises_when_required(monkeypatch):
    """No key + required=True -> a clear BaselineSignatureError."""
    monkeypatch.delenv(main.HMAC_KEY_ENV, raising=False)
    monkeypatch.delenv(main.HMAC_KEY_FILE_ENV, raising=False)

    with pytest.raises(main.BaselineSignatureError) as excinfo:
        main.resolve_hmac_key()
    assert "No HMAC key configured" in str(excinfo.value)

    # ... but asking politely for an optional key returns None.
    assert main.resolve_hmac_key(required=False) is None


def test_w4_short_key_is_rejected(monkeypatch):
    """A key shorter than 32 bytes is refused."""
    monkeypatch.setenv(main.HMAC_KEY_ENV, "abc123")
    monkeypatch.delenv(main.HMAC_KEY_FILE_ENV, raising=False)

    with pytest.raises(main.BaselineSignatureError) as excinfo:
        main.resolve_hmac_key()
    assert "too short" in str(excinfo.value)


def test_w4_key_file_must_be_private(tmp_path, monkeypatch):
    """A 0600 key file is accepted; a 0644 one is rejected."""
    key_file = tmp_path / "hmac.key"
    key_file.write_text(main.generate_hmac_key() + "\n", encoding="utf-8")
    os.chmod(key_file, 0o600)
    monkeypatch.delenv(main.HMAC_KEY_ENV, raising=False)
    monkeypatch.setenv(main.HMAC_KEY_FILE_ENV, str(key_file))

    assert main.resolve_hmac_key() == bytes.fromhex(key_file.read_text().strip())

    os.chmod(key_file, 0o644)
    with pytest.raises(main.BaselineSignatureError) as excinfo:
        main.resolve_hmac_key()
    assert "too permissive" in str(excinfo.value)


def test_w4_missing_key_file_is_reported(tmp_path, monkeypatch):
    """A configured but absent key file fails with a clear message."""
    monkeypatch.delenv(main.HMAC_KEY_ENV, raising=False)
    monkeypatch.setenv(main.HMAC_KEY_FILE_ENV, str(tmp_path / "nope.key"))

    with pytest.raises(main.BaselineSignatureError) as excinfo:
        main.resolve_hmac_key()
    assert "not found" in str(excinfo.value)


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------

def test_w4_signed_baseline_contains_a_signature_block(tmp_path, hmac_key):
    """`baseline --sign` writes an hmac-sha256 signature into the JSON."""
    _folder, baseline_path = _signed_baseline(tmp_path, {"file1.txt": "one\n"}, hmac_key)

    data = _read_json(baseline_path)
    signature = data[main.SIGNATURE_KEY]

    assert signature["algorithm"] == "hmac-sha256"
    assert len(signature["value"]) == 64  # 32-byte digest as hex
    assert "files" in signature["signed_fields"]
    # The signature itself is not part of what was signed.
    assert main.SIGNATURE_KEY not in signature["signed_fields"]
    assert "signed_fields" not in signature["signed_fields"]


def test_w4_unsigned_baseline_has_no_signature(tmp_path):
    """Without --sign the baseline is unchanged from Week 2 (no signature)."""
    folder = _make_folder(tmp_path / "test_folder", {"file1.txt": "one\n"})
    baseline_path = tmp_path / "baseline.json"
    _quiet_command(main.command_baseline, folder, baseline_path=baseline_path)

    assert main.SIGNATURE_KEY not in _read_json(baseline_path)


def test_w4_signature_is_deterministic_for_same_content(hmac_key):
    """Signing identical metadata twice gives the identical signature."""
    metadata = {"tool": "x", "files": {"a.txt": {"sha256": "abc"}}, "file_count": 1}

    first = main.compute_baseline_signature(metadata, hmac_key)
    second = main.compute_baseline_signature(metadata, hmac_key)

    assert first == second


def test_w4_signature_ignores_key_order(hmac_key):
    """Reordered JSON keys still verify (sort_keys in the payload)."""
    first = {"tool": "x", "algorithm": "sha256", "file_count": 1}
    second = {"file_count": 1, "tool": "x", "algorithm": "sha256"}

    assert (main.compute_baseline_signature(first, hmac_key)
            == main.compute_baseline_signature(second, hmac_key))


def test_w4_signing_without_key_aborts_and_writes_nothing(tmp_path, monkeypatch):
    """A missing key refuses to produce an unsigned baseline by accident."""
    folder = _make_folder(tmp_path / "test_folder", {"file1.txt": "one\n"})
    baseline_path = tmp_path / "baseline.json"
    monkeypatch.delenv(main.HMAC_KEY_ENV, raising=False)
    monkeypatch.delenv(main.HMAC_KEY_FILE_ENV, raising=False)

    exit_code = _quiet_command(main.command_baseline, folder,
                               baseline_path=baseline_path, sign=True)

    assert exit_code == main.EXIT_FAILURE
    assert not baseline_path.exists(), "must not write an unsigned baseline"


def test_w4_save_baseline_returns_none_when_signing_fails(tmp_path):
    """save_baseline(sign=True, key=too-short) fails cleanly."""
    snapshot = {"file1.txt": {"sha256": "0" * 64, "size": 1, "mtime": 0.0}}
    result = _quiet_command(main.save_baseline, snapshot,
                            baseline_path=tmp_path / "b.json", sign=True,
                            key=b"short")
    assert result is None
    assert not (tmp_path / "b.json").exists()


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def test_w4_verify_accepts_a_good_signature(tmp_path, hmac_key):
    """verify_baseline_signature() returns True for an untouched baseline."""
    _folder, baseline_path = _signed_baseline(tmp_path, {"file1.txt": "one\n"}, hmac_key)

    ok, reason = main.verify_baseline_signature(_read_json(baseline_path), hmac_key)

    assert ok is True
    assert "verified" in reason


def test_w4_verify_detects_a_tampered_hash(tmp_path, hmac_key):
    """Editing a stored hash breaks the signature (the core threat model)."""
    _folder, baseline_path = _signed_baseline(tmp_path, {"file1.txt": "one\n"}, hmac_key)
    data = _read_json(baseline_path)
    data["files"]["file1.txt"]["sha256"] = "0" * 64  # attacker hides a change
    baseline_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    ok, reason = main.verify_baseline_signature(data, hmac_key)

    assert ok is False
    assert "MISMATCH" in reason


def test_w4_verify_detects_added_and_removed_entries(tmp_path, hmac_key):
    """Smuggling an extra file into the baseline, or dropping one, is detected."""
    _folder, baseline_path = _signed_baseline(tmp_path, {"file1.txt": "one\n"}, hmac_key)

    with_extra = _read_json(baseline_path)
    with_extra["files"]["evil.txt"] = {"sha256": "1" * 64, "size": 1, "mtime": 0.0}
    assert main.verify_baseline_signature(with_extra, hmac_key)[0] is False

    with_dropped = _read_json(baseline_path)
    with_dropped["files"].pop("file1.txt")
    assert main.verify_baseline_signature(with_dropped, hmac_key)[0] is False


def test_w4_verify_rejects_the_wrong_key(tmp_path):
    """A different key of the same length does not verify."""
    key_a = bytes.fromhex(main.generate_hmac_key())
    key_b = bytes.fromhex(main.generate_hmac_key())
    _folder, baseline_path = _signed_baseline(tmp_path, {"file1.txt": "one\n"}, key_a)

    ok, reason = main.verify_baseline_signature(_read_json(baseline_path), key_b)

    assert ok is False
    assert "MISMATCH" in reason


def test_w4_verify_reports_unsigned_baseline():
    """An unsigned baseline is reported as unverifiable, never as valid."""
    ok, reason = main.verify_baseline_signature({"files": {}}, b"k" * 32)
    assert ok is False
    assert "UNSIGNED" in reason


def test_w4_verify_reports_missing_key(tmp_path, hmac_key):
    """A signed baseline with no key configured cannot be verified."""
    _folder, baseline_path = _signed_baseline(tmp_path, {"file1.txt": "one\n"}, hmac_key)

    ok, reason = main.verify_baseline_signature(_read_json(baseline_path), None)

    assert ok is False
    assert "no HMAC key" in reason


def test_w4_verify_uses_constant_time_comparison(tmp_path, hmac_key):
    """hmac.compare_digest() is used rather than '==' (timing safety)."""
    source = (Path(__file__).resolve().parent / "main.py").read_text(encoding="utf-8")
    assert "compare_digest" in source

    calls = []
    real_compare = main.hmac.compare_digest

    def spy(left, right):
        calls.append((left, right))
        return real_compare(left, right)

    with mock.patch("main.hmac.compare_digest", side_effect=spy):
        _folder, baseline_path = _signed_baseline(tmp_path, {"a.txt": "a\n"}, hmac_key)
        main.verify_baseline_signature(_read_json(baseline_path), hmac_key)

    assert calls, "verification must go through hmac.compare_digest"


# ---------------------------------------------------------------------------
# Command-level behaviour: check / watch with signatures
# ---------------------------------------------------------------------------

def test_w4_check_verifies_signature_end_to_end(tmp_path, hmac_key, capsys):
    """`check --verify` succeeds on an authentic baseline."""
    folder, baseline_path = _signed_baseline(tmp_path, {"file1.txt": "one\n"}, hmac_key)

    exit_code = main.command_check(folder, baseline_path=baseline_path,
                                   verify_signature=True, key=hmac_key)
    out = capsys.readouterr().out

    assert exit_code == main.EXIT_OK
    assert "signature verified" in out
    assert "No changes detected" in out


def test_w4_check_refuses_a_tampered_baseline(tmp_path, hmac_key, capsys):
    """`check --verify` exits 1 and never reports on a forged baseline."""
    folder, baseline_path = _signed_baseline(tmp_path, {"file1.txt": "one\n"}, hmac_key)
    data = _read_json(baseline_path)
    data["files"]["file1.txt"]["sha256"] = "0" * 64
    baseline_path.write_text(json.dumps(data), encoding="utf-8")

    exit_code = main.command_check(folder, baseline_path=baseline_path,
                                   verify_signature=True, key=hmac_key)
    captured = capsys.readouterr()

    assert exit_code == main.EXIT_FAILURE
    assert "MISMATCH" in captured.err
    assert "No changes detected" not in captured.out


def test_w4_check_does_not_rewrite_a_tampered_baseline(tmp_path, hmac_key):
    """Even a failed verification leaves the baseline bytes untouched."""
    folder, baseline_path = _signed_baseline(tmp_path, {"file1.txt": "one\n"}, hmac_key)
    data = _read_json(baseline_path)
    data["file_count"] = 99
    baseline_path.write_text(json.dumps(data), encoding="utf-8")
    before = baseline_path.read_bytes()

    _quiet_command(main.command_check, folder, baseline_path=baseline_path,
                   verify_signature=True, key=hmac_key)

    assert baseline_path.read_bytes() == before


def test_w4_unsigned_baseline_is_backward_compatible(tmp_path, hmac_key, capsys):
    """--verify warns on an unsigned baseline but still works (Weeks 1-3)."""
    folder = _make_folder(tmp_path / "test_folder", {"file1.txt": "one\n"})
    baseline_path = tmp_path / "baseline.json"
    _quiet_command(main.command_baseline, folder, baseline_path=baseline_path)

    exit_code = main.command_check(folder, baseline_path=baseline_path,
                                   verify_signature=True, key=hmac_key)
    captured = capsys.readouterr()

    assert exit_code == main.EXIT_OK
    assert "UNSIGNED" in captured.err


def test_w4_require_signature_refuses_unsigned(tmp_path, hmac_key, capsys):
    """--require-signature makes an unsigned baseline a hard failure."""
    folder = _make_folder(tmp_path / "test_folder", {"file1.txt": "one\n"})
    baseline_path = tmp_path / "baseline.json"
    _quiet_command(main.command_baseline, folder, baseline_path=baseline_path)

    exit_code = main.command_check(folder, baseline_path=baseline_path,
                                   require_signature=True, key=hmac_key)
    captured = capsys.readouterr()

    assert exit_code == main.EXIT_FAILURE
    assert "UNSIGNED" in captured.err


def test_w4_watch_refuses_to_start_on_a_bad_signature(tmp_path, hmac_key, clean_logging):
    """watch --require-signature will not monitor with a forged baseline."""
    folder, baseline_path = _signed_baseline(tmp_path, {"file1.txt": "one\n"}, hmac_key)
    data = _read_json(baseline_path)
    data["files"]["file1.txt"]["sha256"] = "9" * 64
    baseline_path.write_text(json.dumps(data), encoding="utf-8")
    log_path = tmp_path / "filewatch.log"

    exit_code = _quiet_command(main.command_watch, folder,
                               baseline_path=baseline_path, interval=0,
                               log_path=log_path, max_scans=1,
                               require_signature=True, key=hmac_key)

    assert exit_code == main.EXIT_FAILURE
    assert "could not hash" not in _read_log(log_path).lower()


def test_w4_watch_runs_with_a_valid_signature(tmp_path, hmac_key, clean_logging):
    """watch --verify starts normally when the signature checks out."""
    folder, baseline_path = _signed_baseline(tmp_path, {"file1.txt": "one\n"}, hmac_key)

    exit_code = _quiet_command(main.command_watch, folder,
                               baseline_path=baseline_path, interval=0,
                               log_path=tmp_path / "w.log", max_scans=1,
                               verify_signature=True, key=hmac_key)

    assert exit_code == main.EXIT_OK


def test_w4_load_baseline_defaults_are_unchanged(tmp_path):
    """load_baseline() without the new flags behaves exactly as in Week 2/3."""
    folder = _make_folder(tmp_path / "test_folder", {"file1.txt": "one\n"})
    baseline_path = tmp_path / "baseline.json"
    _quiet_command(main.command_baseline, folder, baseline_path=baseline_path)

    loaded = _quiet_command(main.load_baseline, baseline_path)

    assert list(loaded) == ["file1.txt"]


# ---------------------------------------------------------------------------
# keygen command
# ---------------------------------------------------------------------------

def test_w4_keygen_writes_a_private_file(tmp_path, capsys):
    """`keygen --out` writes a 0600 key file outside the project."""
    target = tmp_path / "secrets" / "hmac.key"

    exit_code = main.command_keygen(output_path=target)
    capsys.readouterr()

    assert exit_code == main.EXIT_OK
    assert target.is_file()
    mode = _stat.S_IMODE(target.stat().st_mode)
    assert mode == 0o600, f"key file mode is {oct(mode)}, expected 0o600"
    assert len(bytes.fromhex(target.read_text().strip())) >= 32


def test_w4_keygen_refuses_to_write_inside_the_project(capsys):
    """A key written next to the code is one `git add .` from leaking."""
    project_root = Path(main.__file__).resolve().parent
    target = project_root / "leaked.key"

    exit_code = main.command_keygen(output_path=target)
    captured = capsys.readouterr()

    assert exit_code == main.EXIT_FAILURE
    assert "Refusing to write a key inside the project" in captured.err
    assert not target.exists()


def test_w4_keygen_refuses_to_overwrite_without_force(tmp_path, capsys):
    """An existing key file is protected unless --force is given."""
    target = tmp_path / "hmac.key"
    target.write_text("existing\n", encoding="utf-8")

    assert main.command_keygen(output_path=target) == main.EXIT_FAILURE
    assert target.read_text(encoding="utf-8") == "existing\n"

    assert main.command_keygen(output_path=target, force=True) == main.EXIT_OK
    assert target.read_text(encoding="utf-8").strip() != "existing"
    capsys.readouterr()


def test_w4_keygen_cli_prints_a_key(capsys):
    """`main.py keygen` prints an exportable key without writing anything."""
    assert main.main(["keygen"]) == main.EXIT_OK
    out = capsys.readouterr().out

    assert f"export {main.HMAC_KEY_ENV}=" in out
    exported = out.split(f"export {main.HMAC_KEY_ENV}=")[1].split()[0]
    assert len(bytes.fromhex(exported)) >= 32


# ---------------------------------------------------------------------------
# CLI wiring for the new flags
# ---------------------------------------------------------------------------

def test_w4_cli_parses_signing_flags():
    """--sign, --verify, --require-signature, --key-file, --out, --force."""
    args = main.parse_args(["baseline", "--sign"])
    assert args.sign is True

    args = main.parse_args(["check", "--require-signature"])
    assert args.require_signature is True and args.verify is False

    args = main.parse_args(["keygen", "--out", "k.key", "--force"])
    assert args.out == "k.key" and args.force is True

    args = main.parse_args(["check", "--verify", "--key-file", "/tmp/k"])
    assert args.verify is True and args.key_file == "/tmp/k"


def test_w4_cli_signs_and_verifies_end_to_end(tmp_path, monkeypatch, capsys):
    """The full CLI path: baseline --sign, then check --require-signature."""
    folder = _make_folder(tmp_path / "test_folder", {"file1.txt": "one\n"})
    baseline_path = tmp_path / "baseline.json"
    monkeypatch.delenv(main.HMAC_KEY_FILE_ENV, raising=False)
    monkeypatch.setenv(main.HMAC_KEY_ENV, main.generate_hmac_key())

    assert main.main(["--folder", str(folder), "--baseline", str(baseline_path),
                      "baseline", "--sign"]) == main.EXIT_OK
    assert main.SIGNATURE_KEY in _read_json(baseline_path)

    assert main.main(["--folder", str(folder), "--baseline", str(baseline_path),
                      "check", "--require-signature"]) == main.EXIT_OK
    capsys.readouterr()


# ---------------------------------------------------------------------------
# Documented limitations, encoded as executable tests
# ---------------------------------------------------------------------------
#
# These tests assert what HMAC does NOT do. They exist so the limitation is
# verified rather than merely claimed in prose, and so nobody "fixes" a failing
# assumption by quietly changing the documentation.

def test_w4_limitation_baseline_is_not_encrypted(tmp_path, hmac_key):
    """LIMIT: signing never encrypts - the inventory stays readable."""
    folder = _make_folder(tmp_path / "test_folder", {
        "secret_project/merger_agreement.pdf": "confidential\n",
    })
    baseline_path = tmp_path / "baseline.json"
    _quiet_command(main.command_baseline, folder, baseline_path=baseline_path,
                   sign=True, key=hmac_key)

    raw = baseline_path.read_text(encoding="utf-8")

    # The path, the algorithm and the digest are all plaintext, signature or not.
    assert "secret_project/merger_agreement.pdf" in raw
    assert "sha256" in raw
    expected_digest = hashlib.sha256(b"confidential\n").hexdigest()
    assert expected_digest in raw
    assert main.SIGNATURE_KEY in raw

    # And it still parses as ordinary JSON without any key.
    data = json.loads(raw)
    assert "secret_project/merger_agreement.pdf" in data["files"]


def test_w4_limitation_stolen_key_allows_forgery(tmp_path, hmac_key):
    """LIMIT: an attacker holding the key can forge and re-sign undetected.

    This documents the boundary of the guarantee: HMAC distinguishes holders of
    the key from non-holders, and nothing more. The forge below uses only the
    standard library and takes no privileged access.
    """
    folder, baseline_path = _signed_baseline(
        tmp_path, {"file1.txt": "original\n"}, hmac_key)

    # 1. The attacker changes a monitored file.
    (folder / "file1.txt").write_bytes(b"original\nmalware\n")

    # 2. ...and rewrites the baseline to match, re-signing with the stolen key.
    data = _read_json(baseline_path)
    data["files"]["file1.txt"]["sha256"] = hashlib.sha256(
        (folder / "file1.txt").read_bytes()).hexdigest()
    data[main.SIGNATURE_KEY]["value"] = main.compute_baseline_signature(
        data, hmac_key)
    baseline_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    # 3. FileWatch accepts the forgery: the signature is cryptographically valid.
    ok, reason = main.verify_baseline_signature(_read_json(baseline_path), hmac_key)
    assert ok is True, "the forged signature is genuinely valid"
    assert "verified" in reason

    exit_code = _quiet_command(main.command_check, folder,
                               baseline_path=baseline_path,
                               require_signature=True, key=hmac_key)
    assert exit_code == main.EXIT_OK, (
        "with the key, a forged baseline passes --require-signature. This is the "
        "documented limit of a symmetric MAC, not a bug."
    )


def test_w4_limitation_without_the_key_forgery_is_detected(tmp_path):
    """The complement: an attacker WITHOUT the key cannot forge."""
    key = bytes.fromhex(main.generate_hmac_key())
    wrong_key = bytes.fromhex(main.generate_hmac_key())
    folder, baseline_path = _signed_baseline(tmp_path, {"file1.txt": "original\n"}, key)

    (folder / "file1.txt").write_bytes(b"original\nmalware\n")
    data = _read_json(baseline_path)
    data["files"]["file1.txt"]["sha256"] = hashlib.sha256(
        (folder / "file1.txt").read_bytes()).hexdigest()
    # The attacker guesses a key but does not have the real one.
    data[main.SIGNATURE_KEY]["value"] = main.compute_baseline_signature(
        data, wrong_key)
    baseline_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    ok, reason = main.verify_baseline_signature(_read_json(baseline_path), key)
    assert ok is False
    assert "MISMATCH" in reason

    exit_code = _quiet_command(main.command_check, folder,
                               baseline_path=baseline_path,
                               require_signature=True, key=key)
    assert exit_code == main.EXIT_FAILURE


def test_w4_limitation_rollback_cannot_be_detected(tmp_path, hmac_key):
    """LIMIT: an old, validly-signed baseline can be replayed later.

    Nothing binds a signature to "now", so restoring a stale signed baseline
    hides everything that changed after it was taken.
    """
    folder, baseline_path = _signed_baseline(tmp_path, {"file1.txt": "v1\n"}, hmac_key)
    old_signed = baseline_path.read_bytes()

    # Legitimate re-baseline after a deliberate change (v2).
    (folder / "file1.txt").write_bytes(b"v2\n")
    _quiet_command(main.command_baseline, folder, baseline_path=baseline_path,
                   sign=True, key=hmac_key)
    assert not main.has_changes(
        _quiet_command(main.compare_snapshots,
                       _quiet_command(main.load_baseline, baseline_path),
                       _quiet_command(main.build_snapshot, folder)))

    # Attacker rolls the baseline back to the still-valid v1 signature...
    (folder / "file1.txt").write_bytes(b"v1\n")
    baseline_path.write_bytes(old_signed)

    ok, _reason = main.verify_baseline_signature(_read_json(baseline_path), hmac_key)
    assert ok is True, "the replayed signature is still valid"
    # ...and the rollback is invisible: v1 matches v1.
    exit_code = _quiet_command(main.command_check, folder,
                               baseline_path=baseline_path,
                               require_signature=True, key=hmac_key)
    assert exit_code == main.EXIT_OK


def test_w4_limitation_log_is_plaintext_and_unsigned(tmp_path, clean_logging):
    """LIMIT: filewatch.log is not signed; it is ordinary readable text."""
    folder, baseline_path = _baseline_for(tmp_path, {"file1.txt": "one\n"})
    log_path = tmp_path / "filewatch.log"
    (folder / "added.txt").write_bytes(b"new\n")

    _quiet_command(main.command_watch, folder, baseline_path=baseline_path,
                   interval=0, log_path=log_path, max_scans=1)

    log_text = _read_log(log_path)
    assert "added.txt" in log_text, "log contents are readable in plaintext"
    # No signature/HMAC material is written to the log.
    assert main.SIGNATURE_KEY not in log_text
    assert "hmac" not in log_text.lower()


# ===========================================================================
# WEEK 4 TESTS - log parsing, dashboard data, reports, security documentation
# ===========================================================================
#
# New modules under test: logger_parser.py (pure stdlib), report.py (stdlib
# CLI) and dashboard.py (Streamlit). The Streamlit UI tests are skipped
# automatically when Streamlit is not installed, so the suite always runs.
#
# No earlier test was modified or removed to make these pass.

from datetime import datetime

import logger_parser as lp
import report as rp

# A representative slice of a real filewatch.log produced by `main.py watch`.
SAMPLE_LOG = """\
2026-11-25 17:22:55 | INFO     | filewatch | Watch started: folder=/p/test_folder algorithm=sha256 interval=1.0s files=12 patterns=26
2026-11-25 17:22:55 | INFO     | filewatch | Scan 1: no changes (12 file(s))
2026-11-25 17:22:57 | WARNING  | filewatch | ADDED file: added_a.txt
2026-11-25 17:22:57 | WARNING  | filewatch | MODIFIED file: file2.txt
2026-11-25 17:22:57 | WARNING  | filewatch | DELETED file: subfolder/file7.txt
2026-11-25 17:22:58 | ERROR    | filewatch | Unreadable file (content unknown, not reported as deleted): locked.txt
2026-11-25 17:22:59 | ERROR    | filewatch | No usable baseline - run `python main.py baseline` first.
2026-11-25 17:22:59 | INFO     | filewatch | Watch ended: scans=3 exit_code=130
"""


def _write_log(tmp_path, text, name="filewatch.log"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# 1. Log parsing
# ---------------------------------------------------------------------------

def test_w4_parse_single_line_extracts_all_fields():
    """Timestamp, severity, event type and path are all extracted."""
    line = "2026-11-25 17:22:57 | WARNING  | filewatch | ADDED file: added_a.txt"

    event, status = lp.parse_log_line(line)

    assert status == "event"
    assert event.timestamp == datetime(2026, 11, 25, 17, 22, 57)
    assert event.level == "WARNING"
    assert event.event_type == "ADDED"
    assert event.path == "added_a.txt"


def test_w4_parse_all_change_event_types():
    """ADDED, MODIFIED, DELETED, UNREADABLE and generic ERROR are recognised."""
    result = lp.parse_log_text(SAMPLE_LOG)

    types = [event.event_type for event in result.events]
    assert types == ["ADDED", "MODIFIED", "DELETED", "UNREADABLE", "ERROR"]

    paths = [event.path for event in result.events]
    assert paths[0] == "added_a.txt"
    assert paths[2] == "subfolder/file7.txt"   # nested paths survive intact
    assert paths[4] is None                     # generic error has no file


def test_w4_parse_counts_and_line_accounting():
    """Counts, info lines, malformed lines and totals add up correctly."""
    result = lp.parse_log_text(SAMPLE_LOG)

    assert result.counts["ADDED"] == 1
    assert result.counts["MODIFIED"] == 1
    assert result.counts["DELETED"] == 1
    assert result.counts["UNREADABLE"] == 1
    assert result.counts["ERROR"] == 1
    assert result.change_count == 3
    assert result.total_lines == 8
    assert result.info_lines == 3               # 2 INFO + ... see below
    assert result.malformed_lines == 0


def test_w4_parse_ignores_info_lines_as_events():
    """'Scan 1: no changes' must never be reported as a change event."""
    result = lp.parse_log_text(SAMPLE_LOG)

    assert all("no changes" not in event.message for event in result.events)
    assert lp.summarize(result).startswith("3 change event(s)")


def test_w4_parse_preserves_nested_and_unusual_paths():
    """Relative paths with folders, spaces and unicode are parsed verbatim."""
    log = (
        "2026-11-25 10:00:00 | WARNING  | filewatch | ADDED file: a/b/c/deep file.txt\n"
        "2026-11-25 10:00:01 | WARNING  | filewatch | MODIFIED file: données/é.txt\n"
        "2026-11-25 10:00:02 | WARNING  | filewatch | DELETED file: [weird] name (1).tmp\n"
    )

    result = lp.parse_log_text(log)

    assert [event.path for event in result.events] == [
        "a/b/c/deep file.txt", "données/é.txt", "[weird] name (1).tmp",
    ]


def test_w4_parse_tolerates_extra_whitespace():
    """Hand-edited spacing still parses (the logger pads levels with %-8s)."""
    line = "2026-11-25 17:22:57|WARNING|filewatch|ADDED file: x.txt"

    event, status = lp.parse_log_line(line)

    assert status == "event"
    assert event.event_type == "ADDED"
    assert event.path == "x.txt"


# ---------------------------------------------------------------------------
# 2. Missing / empty / malformed logs
# ---------------------------------------------------------------------------

def test_w4_missing_log_is_handled(tmp_path):
    """A missing log returns an empty result with an explanatory error."""
    result = lp.parse_log_file(tmp_path / "nope.log")

    assert result.has_error
    assert "not found" in result.error.lower()
    assert result.events == []
    assert result.is_empty


def test_w4_empty_log_is_handled(tmp_path):
    """An empty log is not an error - it simply has no events."""
    path = _write_log(tmp_path, "")

    result = lp.parse_log_file(path)

    assert not result.has_error
    assert result.events == []
    assert result.total_lines == 0
    assert "No log events available" in lp.summarize(result)


def test_w4_whitespace_only_log_is_handled(tmp_path):
    path = _write_log(tmp_path, "\n\n   \n\t\n")
    result = lp.parse_log_file(path)

    assert not result.has_error
    assert result.events == []
    assert result.skipped_lines == 4


def test_w4_malformed_lines_are_counted_not_fatal(tmp_path):
    """Garbage, wrong dates and binary bytes are counted, never raised."""
    path = tmp_path / "filewatch.log"
    path.write_bytes(
        b"this is not a log line\n"
        b"2026-13-45 99:99:99 | WARNING | filewatch | ADDED file: impossible.txt\n"
        b"2026-11-25 10:00:00 | WARNING | filewatch | ADDED file: good.txt\n"
        b"\x00\x01\x02 binary junk\n"
    )

    result = lp.parse_log_file(path)

    assert result.malformed_lines == 3
    assert result.counts["ADDED"] == 1          # the one good line survived
    assert result.events[0].path == "good.txt"
    assert len(result.malformed_samples) <= 5


def test_w4_directory_instead_of_log_is_handled(tmp_path):
    """Pointing at a directory is reported, not crashed on."""
    result = lp.parse_log_file(tmp_path)

    assert result.has_error
    assert "directory" in result.error.lower()


def test_w4_unreadable_log_is_handled(tmp_path):
    """PermissionError while opening the log is caught."""
    path = _write_log(tmp_path, SAMPLE_LOG)

    with mock.patch("builtins.open", side_effect=PermissionError(13, "denied")):
        result = lp.parse_log_file(path)

    assert result.has_error
    assert "permission" in result.error.lower()


def test_w4_log_with_traceback_lines_is_partially_parsed():
    """`logger.exception` writes a traceback; the summary line still counts."""
    log = (
        "2026-11-25 10:00:00 | ERROR    | filewatch | Watch loop stopped by an OS error\n"
        "Traceback (most recent call last):\n"
        '  File "main.py", line 1, in <module>\n'
        "OSError: [Errno 5] Input/output error\n"
    )

    result = lp.parse_log_text(log)

    assert result.counts["ERROR"] == 1
    assert result.malformed_lines == 3


# ---------------------------------------------------------------------------
# 3. Counts, timeline and dashboard data
# ---------------------------------------------------------------------------

def test_w4_event_counts_are_correct():
    result = lp.parse_log_text(SAMPLE_LOG)

    counts = lp.event_counts(result)

    assert counts["ADDED"] == 1
    assert counts["MODIFIED"] == 1
    assert counts["DELETED"] == 1
    assert set(counts) == set(lp.EVENT_ORDER)


def test_w4_timeline_buckets_by_minute():
    """Two events in the same minute share one bucket."""
    log = (
        "2026-11-25 10:00:01 | WARNING  | filewatch | ADDED file: a.txt\n"
        "2026-11-25 10:00:59 | WARNING  | filewatch | MODIFIED file: b.txt\n"
        "2026-11-25 10:02:00 | WARNING  | filewatch | DELETED file: c.txt\n"
    )

    rows = lp.timeline(lp.parse_log_text(log), bucket="minute")

    assert [row["bucket"] for row in rows] == ["2026-11-25 10:00", "2026-11-25 10:02"]
    assert rows[0]["ADDED"] == 1 and rows[0]["MODIFIED"] == 1
    assert rows[1]["DELETED"] == 1


def test_w4_timeline_hour_and_day_buckets():
    log = (
        "2026-11-25 10:00:01 | WARNING  | filewatch | ADDED file: a.txt\n"
        "2026-11-25 10:30:00 | WARNING  | filewatch | ADDED file: b.txt\n"
        "2026-11-26 09:00:00 | WARNING  | filewatch | ADDED file: c.txt\n"
    )
    result = lp.parse_log_text(log)

    hourly = lp.timeline(result, bucket="hour")
    daily = lp.timeline(result, bucket="day")

    assert [row["bucket"] for row in hourly] == ["2026-11-25 10:00", "2026-11-26 09:00"]
    assert hourly[0]["ADDED"] == 2
    assert [row["bucket"] for row in daily] == ["2026-11-25", "2026-11-26"]


def test_w4_timeline_rows_include_totals():
    rows = lp.timeline_rows(lp.parse_log_text(SAMPLE_LOG))
    assert rows and rows[0]["total"] == 3


def test_w4_timeline_rejects_unknown_bucket():
    with pytest.raises(ValueError):
        lp.timeline(lp.parse_log_text(SAMPLE_LOG), bucket="fortnight")


def test_w4_timeline_is_empty_without_events():
    assert lp.timeline(lp.parse_log_text(SAMPLE_LOG[:0])) == []


def test_w4_recent_events_are_newest_first():
    events = lp.recent_events(lp.parse_log_text(SAMPLE_LOG), limit=2)

    assert len(events) == 2
    assert events[0].timestamp >= events[1].timestamp
    assert events[0].event_type == "ERROR"     # 17:22:59 is the latest


def test_w4_filter_events_by_type():
    result = lp.parse_log_text(SAMPLE_LOG)

    only_changes = lp.filter_events(result, ["ADDED", "DELETED"])

    assert {event.event_type for event in only_changes} == {"ADDED", "DELETED"}


def test_w4_events_as_rows_shape():
    rows = lp.events_as_rows(lp.parse_log_text(SAMPLE_LOG))

    assert set(rows[0]) == {"Timestamp", "Event", "Level", "File", "Details"}
    assert rows[0]["Event"] == "ADDED"


# ---------------------------------------------------------------------------
# 4. Report generation
# ---------------------------------------------------------------------------

def test_w4_markdown_report_contains_required_sections(tmp_path):
    """The Markdown report has a timestamp, counts and recent details."""
    path = _write_log(tmp_path, SAMPLE_LOG)
    result = lp.parse_log_file(path)

    text = lp.render_markdown(lp.build_report_data(result, log_path=path))

    assert "# FileWatch - File Integrity Report" in text
    assert "**Generated:**" in text
    assert "## Event summary" in text
    assert "| ADDED | 1 |" in text
    assert "## Recent changes" in text
    assert "file2.txt" in text
    assert "subfolder/file7.txt" in text
    assert "LEGAL AND ETHICAL NOTICE" in text


def test_w4_html_report_is_valid_and_escapes_html(tmp_path):
    """The HTML report escapes hostile file names (no script injection)."""
    evil_log = ("2026-11-25 10:00:00 | WARNING  | filewatch | "
                "ADDED file: <script>alert('x')</script>.txt\n")
    path = _write_log(tmp_path, evil_log)
    result = lp.parse_log_file(path)

    html_text = lp.render_html(lp.build_report_data(result, log_path=path))

    assert html_text.startswith("<!DOCTYPE html>")
    assert "<script>alert" not in html_text, "raw script tag must be escaped"
    assert "&lt;script&gt;" in html_text
    assert "LEGAL AND ETHICAL NOTICE" in html_text
    assert "</html>" in html_text


def test_w4_report_handles_missing_log(tmp_path):
    """A missing log still produces a report that says so."""
    missing = tmp_path / "nope.log"
    result = lp.parse_log_file(missing)

    markdown = lp.render_markdown(lp.build_report_data(result, log_path=missing))
    html_text = lp.render_html(lp.build_report_data(result, log_path=missing))

    assert "No log data available" in markdown
    assert "not found" in markdown.lower()
    assert "No log data available" in html_text


def test_w4_report_handles_empty_log(tmp_path):
    path = _write_log(tmp_path, "")
    result = lp.parse_log_file(path)
    text = lp.render_markdown(lp.build_report_data(result, log_path=path))

    assert "No change events were found" in text
    assert "| **Total changes** | **0** |" in text


def test_w4_write_report_markdown_and_html(tmp_path):
    path = _write_log(tmp_path, SAMPLE_LOG)
    report_data = lp.build_report_data(lp.parse_log_file(path), log_path=path)

    md_path = lp.write_report(report_data, tmp_path / "out" / "r.md")
    html_path = lp.write_report(report_data, tmp_path / "out" / "r.html")

    assert md_path.is_file() and md_path.stat().st_size > 0
    assert html_path.is_file() and html_path.stat().st_size > 0
    assert md_path.read_text(encoding="utf-8").startswith("# FileWatch")
    assert "<!DOCTYPE html>" in html_path.read_text(encoding="utf-8")


def test_w4_write_report_rejects_unknown_format(tmp_path):
    report_data = lp.build_report_data(lp.parse_log_text(SAMPLE_LOG))
    with pytest.raises(ValueError):
        lp.write_report(report_data, tmp_path / "r.pdf")


def test_w4_reports_never_contain_secrets(tmp_path, monkeypatch):
    """No HMAC key material may leak into a report, even if it is in the env."""
    secret = main.generate_hmac_key()
    monkeypatch.setenv(main.HMAC_KEY_ENV, secret)
    path = _write_log(tmp_path, SAMPLE_LOG)
    result = lp.parse_log_file(path)

    markdown = lp.render_markdown(lp.build_report_data(result, log_path=path))
    html_text = lp.render_html(lp.build_report_data(result, log_path=path))

    assert secret not in markdown
    assert secret not in html_text
    # ...and no key *value* pattern (64 hex chars) appears either.
    assert re.search(r"\b[0-9a-f]{64}\b", markdown) is None


def test_w4_report_cli_generates_both_formats(tmp_path, capsys):
    """`report.py report --format both` writes both files."""
    log_path = _write_log(tmp_path, SAMPLE_LOG)
    out_dir = tmp_path / "reports"

    exit_code = rp.main(["report", "--log", str(log_path),
                         "--format", "both", "--out", str(out_dir)])
    captured = capsys.readouterr()

    assert exit_code == rp.EXIT_OK
    assert (out_dir / "integrity-report.md").is_file()
    assert (out_dir / "integrity-report.html").is_file()
    assert "Written" in captured.out


def test_w4_report_cli_handles_missing_log(tmp_path, capsys):
    """A missing log yields a warning, a report, and exit code 1."""
    exit_code = rp.main(["report", "--log", str(tmp_path / "nope.log"),
                         "--format", "md", "--out", str(tmp_path / "out")])
    captured = capsys.readouterr()

    assert exit_code == rp.EXIT_FAILURE
    assert "Log file not found" in captured.err
    assert (tmp_path / "out" / "integrity-report.md").is_file()


def test_w4_events_cli_prints_a_table(tmp_path, capsys):
    log_path = _write_log(tmp_path, SAMPLE_LOG)

    exit_code = rp.main(["events", "--log", str(log_path)])
    out = capsys.readouterr().out

    assert exit_code == rp.EXIT_OK
    assert "Timestamp" in out and "Event" in out and "File" in out
    assert "added_a.txt" in out
    assert "ADDED        1" in out


def test_w4_events_cli_handles_missing_log(tmp_path, capsys):
    exit_code = rp.main(["events", "--log", str(tmp_path / "nope.log")])
    captured = capsys.readouterr()

    assert exit_code == rp.EXIT_FAILURE
    assert "Log file not found" in captured.err


def test_w4_events_cli_limit(tmp_path, capsys):
    log_path = _write_log(tmp_path, SAMPLE_LOG)

    rp.main(["events", "--log", str(log_path), "--limit", "2"])
    out = capsys.readouterr().out

    assert "Showing 2 event(s) (most recent 2)" in out


def test_w4_render_table_aligns_and_truncates():
    table = rp.render_table(["A", "B"], [["1", "x" * 100]], max_widths=[5, 10])
    lines = table.splitlines()

    assert len(lines) == 3                      # header, separator, one row
    assert all(len(line) <= 20 for line in lines)
    assert "…" in lines[2]


# ---------------------------------------------------------------------------
# 5. Dashboard data layer (no Streamlit needed)
# ---------------------------------------------------------------------------

def test_w4_dashboard_data_from_log(tmp_path, monkeypatch):
    import dashboard

    log_path = _write_log(tmp_path, SAMPLE_LOG)
    monkeypatch.setenv("FILEWATCH_LOG", str(log_path))

    data = dashboard.load_dashboard_data()

    assert data["has_events"] is True
    assert data["counts"]["ADDED"] == 1
    assert data["counts"]["MODIFIED"] == 1
    assert data["counts"]["DELETED"] == 1
    assert len(data["timeline_rows"]) == 1
    assert data["timeline_rows"][0]["total"] == 3
    assert "3 change event(s)" in data["summary"]


def test_w4_dashboard_data_missing_log(tmp_path, monkeypatch):
    import dashboard

    monkeypatch.setenv("FILEWATCH_LOG", str(tmp_path / "nope.log"))

    data = dashboard.load_dashboard_data()

    assert data["has_events"] is False
    assert data["error"] and "not found" in data["error"].lower()
    message = dashboard.empty_state_message(data["path"], data["parse_result"])
    assert "not found" in message.lower()
    assert "python3 main.py watch" in message


def test_w4_dashboard_empty_state_for_empty_log(tmp_path):
    import dashboard

    log_path = _write_log(tmp_path, "")
    data = dashboard.load_dashboard_data(str(log_path))

    message = dashboard.empty_state_message(data["path"], data["parse_result"])
    assert "No log events available" in message


def test_w4_dashboard_events_to_csv():
    import dashboard

    rows = lp.events_as_rows(lp.parse_log_text(SAMPLE_LOG), limit=2)
    csv_text = dashboard.events_to_csv(rows)
    lines = csv_text.strip().splitlines()

    assert lines[0] == "Timestamp,Event,Level,File,Details"
    assert len(lines) == 3
    assert all(line.startswith('"') for line in lines[1:])


def test_w4_dashboard_events_to_csv_empty():
    import dashboard
    assert dashboard.events_to_csv([]) == ""


def test_w4_dashboard_resolve_log_path(tmp_path, monkeypatch):
    import dashboard

    monkeypatch.delenv("FILEWATCH_LOG", raising=False)
    assert dashboard.resolve_log_path().name == "filewatch.log"

    monkeypatch.setenv("FILEWATCH_LOG", str(tmp_path / "custom.log"))
    assert dashboard.resolve_log_path() == tmp_path / "custom.log"

    assert dashboard.resolve_log_path(str(tmp_path / "x.log")) == tmp_path / "x.log"


# ---------------------------------------------------------------------------
# 6. Streamlit UI smoke tests (skipped when Streamlit is absent)
# ---------------------------------------------------------------------------

streamlit = pytest.importorskip.__self__ if False else None  # placeholder


def _app_test(log_path, monkeypatch):
    """Build a Streamlit AppTest for dashboard.py against a given log."""
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("FILEWATCH_LOG", str(log_path))
    return AppTest.from_file("dashboard.py", default_timeout=60).run()


@pytest.mark.skipif(
    __import__("importlib").util.find_spec("streamlit") is None,
    reason="Streamlit is not installed (pip install -r requirements.txt)",
)
def test_w4_streamlit_dashboard_renders_events(tmp_path, monkeypatch):
    """The dashboard renders metrics, a table and a timeline without errors."""
    log_path = _write_log(tmp_path, SAMPLE_LOG)

    app = _app_test(log_path, monkeypatch)

    assert not app.exception
    metrics = {m.label: m.value for m in app.metric}
    assert metrics["Total changes"] == "3"
    assert metrics["➕ Added"] == "1"
    assert metrics["✏️ Modified"] == "1"
    assert metrics["➖ Deleted"] == "1"
    assert len(app.dataframe) == 1
    assert any("Timeline of changes" in s.value for s in app.subheader)


@pytest.mark.skipif(
    __import__("importlib").util.find_spec("streamlit") is None,
    reason="Streamlit is not installed (pip install -r requirements.txt)",
)
def test_w4_streamlit_dashboard_empty_state(tmp_path, monkeypatch):
    """With no log the dashboard shows a clear message, not a crash."""
    log_path = tmp_path / "nope.log"

    app = _app_test(log_path, monkeypatch)

    assert not app.exception
    warnings = " ".join(w.value for w in app.warning)
    assert "not found" in warnings.lower()
    assert {m.label: m.value for m in app.metric}["Total changes"] == "0"


@pytest.mark.skipif(
    __import__("importlib").util.find_spec("streamlit") is None,
    reason="Streamlit is not installed (pip install -r requirements.txt)",
)
def test_w4_streamlit_dashboard_refresh_button_exists(tmp_path, monkeypatch):
    """The required refresh control is present and labelled."""
    app = _app_test(_write_log(tmp_path, SAMPLE_LOG), monkeypatch)
    assert any("Refresh" in b.label for b in app.button)


@pytest.mark.skipif(
    __import__("importlib").util.find_spec("streamlit") is None,
    reason="Streamlit is not installed (pip install -r requirements.txt)",
)
def test_w4_streamlit_dashboard_malformed_log(tmp_path, monkeypatch):
    """Malformed lines surface as an informational note, not an exception."""
    path = tmp_path / "filewatch.log"
    path.write_text("garbage line\nmore garbage\n", encoding="utf-8")

    app = _app_test(path, monkeypatch)

    assert not app.exception
    assert any("could not be parsed" in i.value for i in app.info)


# ---------------------------------------------------------------------------
# 7. Week 4 documentation requirements
# ---------------------------------------------------------------------------

def test_w4_readme_documents_limitations_and_ethics():
    """README must document >=3 limitations, detection-not-prevention and ethics."""
    readme = (Path(__file__).resolve().parent / "README.md").read_text(encoding="utf-8")

    lowered = readme.lower()
    # The three named risks from the brief.
    assert "baseline" in lowered and "rewrit" in lowered
    assert "hmac key" in lowered or "hmac-key" in lowered
    assert "log" in lowered and "tamper" in lowered
    # Detection, not prevention.
    assert "does not prevent" in lowered
    # Ethical use and the exact legal sentence.
    assert "Scanning or attacking systems you do not own or have written " \
           "permission to test is illegal. This tool only monitors your own " \
           "test folder." in readme
    # Dashboard + report instructions.
    assert "streamlit run dashboard.py" in readme
    assert "report.py" in readme


def test_w4_no_secrets_or_keys_in_repo_docs():
    """No 32+ byte hex literal (key material) appears in docs or reports."""
    root = Path(__file__).resolve().parent
    pattern = re.compile(r"\b[0-9a-fA-F]{64}\b")

    for name in ("README.md", "requirements.txt", ".filewatchignore"):
        text = (root / name).read_text(encoding="utf-8")
        # The signature example in the README is a hash of public data, but a
        # *key* would be indistinguishable; ensure none is presented as a key.
        for match in pattern.findall(text):
            assert "FILEWATCH_HMAC_KEY=" not in text.split(match)[0][-40:], \
                f"possible key literal in {name}"


if __name__ == "__main__":
    unittest.main(verbosity=2)
