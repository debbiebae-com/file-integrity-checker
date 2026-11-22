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


if __name__ == "__main__":
    unittest.main(verbosity=2)
