#!/usr/bin/env python3
"""
FileWatch - File Integrity Monitor
==================================

Week 1 (SHA-256 File Integrity Checker)
---------------------------------------
1. Calculates cryptographic hashes (SHA-256 by default, SHA-1 optional) for
   every regular file inside a local folder called ``test_folder``.
2. Demonstrates the "avalanche effect": changing exactly one character in a
   file produces a completely different hash.

Week 2 (Baseline and change detection)
--------------------------------------
3. ``baseline`` builds a recursive snapshot of the monitored folder and saves
   it to ``baseline.json`` (relative paths -> SHA-256 hash, plus optional size
   and modification-time metadata).
4. ``check`` rebuilds the snapshot and compares it with the saved baseline,
   reporting ADDED, MODIFIED, DELETED and UNCHANGED files.

Scope and safety
----------------
This program ONLY reads files inside the ``test_folder`` directory (or the
folder given with ``--folder``). It does not scan arbitrary system directories,
does not touch the network, never follows symbolic links, and never modifies
the original sample files. The demonstration mode works on a temporary copy
that is deleted automatically. ``check`` never rewrites an existing baseline.

The legal/ethical notice that applies to this project:

    Scanning or attacking systems you do not own or have written permission
    to test is illegal. This tool only monitors your own test folder.

Running the program itself needs only the Python standard library.
``pytest`` is required only to run the optional pytest test suite.
Tested with Python 3.9+ on Linux, macOS and Windows.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import hmac
import json
import logging
import os
import secrets
import shutil
import signal
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

#: Folder that this tool is allowed to look at (next to this script).
DEFAULT_FOLDER = Path("test_folder")

#: Size of the chunks we read at a time: 4096 bytes = 4 KiB.
CHUNK_SIZE = 4096

#: Algorithms this tool accepts. SHA-256 is the default and the recommended one.
SUPPORTED_ALGORITHMS = ("sha256", "sha1")
DEFAULT_ALGORITHM = "sha256"

#: Prefix used for the temporary copy created by the demonstration.
DEMO_PREFIX = "demo_copy_"

#: Default name of the baseline file, stored at the project root.
BASELINE_FILENAME = "baseline.json"

#: Current baseline file format version (bumped if the schema ever changes).
BASELINE_SCHEMA_VERSION = 2

#: Name of the key holding per-file metadata in the baseline JSON.
FILES_KEY = "files"

#: Exit codes used by the command-line interface.
EXIT_OK = 0            # success, integrity verified / baseline written
EXIT_FAILURE = 1       # runtime problem: bad folder, unreadable baseline, ...
EXIT_CHANGES = 2       # `check` found changes (useful in scripts / CI)
EXIT_USAGE = 2         # argparse usage error (same value, by argparse design)
EXIT_INTERRUPTED = 130 # Ctrl+C during `watch` (128 + SIGINT)

# --- WEEK 3: continuous monitoring and alerts -------------------------------

#: Logger name used everywhere in this module.
LOGGER_NAME = "filewatch"

#: Default log file, at the project root (next to main.py).
LOG_FILENAME = "filewatch.log"

#: Default polling interval for `watch`, in seconds.
DEFAULT_INTERVAL = 5.0

#: Lowest accepted interval. 0 is allowed on purpose: it means "start the next
#: scan immediately", which is what the automated tests use to stay fast and
#: deterministic. Negative values are rejected.
MIN_INTERVAL = 0.0

#: Default ignore-configuration file, at the project root.
IGNORE_FILENAME = ".filewatchignore"

# --- WEEK 4 (stretch): HMAC-signed baselines --------------------------------

#: Environment variable that holds the HMAC key (hex or raw text).
HMAC_KEY_ENV = "FILEWATCH_HMAC_KEY"

#: Optional file containing the HMAC key (mode 0600, outside the monitored tree).
HMAC_KEY_FILE_ENV = "FILEWATCH_HMAC_KEY_FILE"

#: JSON key holding the signature, and the fields that are *not* signed.
SIGNATURE_KEY = "signature"
HMAC_ALGORITHM = "sha256"

#: Minimum key length in bytes. RFC 2104 / current guidance: at least the
#: output length of the hash, i.e. 32 bytes for HMAC-SHA256.
MIN_HMAC_KEY_BYTES = 32

#: Refuse to read a key file that is readable by group or others.
KEY_FILE_MAX_MODE = 0o600

# --- WEEK 4 ENHANCED: structured JSONL events ----------------------------------------

#: Default structured event file (one JSON object per line), at the project root.
EVENTS_FILENAME = "events.jsonl"

#: Patterns always ignored, even when no ignore file exists. These cover this
#: tool's own output (its log file and the baseline temp file) plus Python byte
#: caches, so the monitor never alerts about its own artifacts. Anything else -
#: such as ``.git``, ``.venv`` or ``*.tmp`` - belongs in ``.filewatchignore``,
#: which ships with a sensible default list.
DEFAULT_IGNORE_PATTERNS: Tuple[str, ...] = (
    "filewatch.log",
    "baseline.json.tmp",
    "*.json.tmp",
    "__pycache__",
    "*.pyc",
    "*.pyo",
)


# ---------------------------------------------------------------------------
# Core hashing functions
# ---------------------------------------------------------------------------

def hash_file(path, algorithm: str = DEFAULT_ALGORITHM) -> Optional[str]:
    """Return the hexadecimal hash digest of a file, or ``None`` on failure.

    How the reading works
    ---------------------
    Hashing is streamed, not loaded in one go:

        with open(path, "rb") as file_handle:
            while True:
                chunk = file_handle.read(CHUNK_SIZE)   # at most 4096 bytes
                if not chunk:                          # end of file reached
                    break
                hasher.update(chunk)                   # feed the hasher

    Reading in 4096-byte chunks keeps memory usage tiny, so even a multi-
    gigabyte file can be hashed without exhausting RAM.

    Parameters
    ----------
    path:
        Path to the file (``str``, ``os.PathLike`` or ``pathlib.Path``).
    algorithm:
        ``"sha256"`` (default) or ``"sha1"``. Case-insensitive.
        An unsupported value raises :class:`ValueError` - that is a programming
        error, not a runtime file problem, so it is not swallowed.

    Returns
    -------
    str | None
        The hex digest, or ``None`` if the file is missing, unreadable or
        otherwise cannot be hashed. The program never crashes because of a
        single bad file.
    """
    if not isinstance(algorithm, str):
        raise ValueError(f"Unsupported hashing algorithm: {algorithm!r}")

    normalized = algorithm.lower().strip()
    if normalized not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"Unsupported hashing algorithm: {algorithm!r}. "
            f"Supported algorithms: {', '.join(SUPPORTED_ALGORITHMS)}"
        )

    # hashlib.new() lets us pick the algorithm by name at runtime.
    hasher = hashlib.new(normalized)

    try:
        # "rb" = read binary. Required: hashing must see the exact raw bytes,
        # not text that could be re-encoded by the operating system.
        with open(path, "rb") as file_handle:
            while True:
                chunk = file_handle.read(CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
    except FileNotFoundError:
        print(f"  [ERROR] File not found: {path}", file=sys.stderr)
        return None
    except PermissionError:
        print(f"  [ERROR] Permission denied: {path}", file=sys.stderr)
        return None
    except IsADirectoryError:
        print(f"  [ERROR] Expected a file but found a directory: {path}", file=sys.stderr)
        return None
    except OSError as exc:
        # Covers other OS-level problems: I/O errors, name too long,
        # device errors, a file deleted mid-read, and so on.
        print(f"  [ERROR] Could not read {path}: {exc}", file=sys.stderr)
        return None

    return hasher.hexdigest()


def list_regular_files(folder=DEFAULT_FOLDER) -> List[Path]:
    """Return the regular files that live *directly* inside ``folder``.

    Only the one folder is inspected - there is no recursion, so this tool
    cannot walk into ``test_folder/sub/deeper`` or anywhere above its own
    directory.

    Skipped on purpose:
      * directories (including sub-folders of ``test_folder``),
      * symbolic links (their target could live outside the test folder),
      * the temporary copies created by the demonstration mode.

    Returns an empty list if the folder does not exist or cannot be read.
    """
    folder_path = Path(folder)

    try:
        if not folder_path.exists():
            print(f"  [ERROR] Folder not found: {folder_path}", file=sys.stderr)
            return []
        if not folder_path.is_dir():
            print(f"  [ERROR] Not a folder: {folder_path}", file=sys.stderr)
            return []

        entries = list(folder_path.iterdir())
    except (PermissionError, OSError) as exc:
        print(f"  [ERROR] Cannot list folder {folder_path}: {exc}", file=sys.stderr)
        return []

    files: List[Path] = []
    for entry in sorted(entries, key=lambda item: item.name.lower()):
        try:
            # is_symlink() is checked first: a link could point outside the
            # test folder, so we refuse to follow it.
            if entry.is_symlink():
                continue
            if not entry.is_file():
                continue  # directories, sockets, pipes, ...
        except OSError:
            continue  # unreadable metadata - simply skip this entry

        if entry.name.startswith(DEMO_PREFIX):
            continue  # leftover demo copy, never report it as a sample file

        files.append(entry)

    return files


def monitor_folder(folder=DEFAULT_FOLDER, algorithm: str = DEFAULT_ALGORITHM) -> dict:
    """Hash every regular file in ``folder`` and print a readable report.

    Returns a dictionary mapping ``filename -> hex digest`` so the results can
    be reused (for example by the demonstration or by the unit tests).
    Files that cannot be hashed are reported but do not stop the scan.
    """
    folder_path = Path(folder)

    print("=" * 74)
    print("SHA-256 FILE INTEGRITY CHECKER".center(74))
    print("=" * 74)
    print(f"Folder    : {folder_path}")
    print(f"Algorithm : {algorithm.upper().replace('SHA', 'SHA-')}")
    print("-" * 74)

    files = list_regular_files(folder_path)

    if not files:
        print("  No regular files found in this folder.")
        print("  (Empty folder, or every entry was a directory or symbolic link.)")
        print("-" * 74)
        return {}

    results: dict = {}
    for file_path in files:
        digest = hash_file(file_path, algorithm=algorithm)
        if digest is None:
            print(f"  {file_path.name:<16} <unreadable - skipped>")
            continue
        results[file_path.name] = digest
        print(f"  {file_path.name:<16} {digest}")

    print("-" * 74)
    print(f"Files hashed: {len(results)} of {len(files)} found")
    print("=" * 74)
    return results


# ---------------------------------------------------------------------------
# Demonstration mode
# ---------------------------------------------------------------------------

def _change_one_character(text: str) -> str:
    """Return ``text`` with exactly one character altered.

    The first ASCII letter is replaced with a different letter (``a`` becomes
    ``b``, any other letter becomes ``a``). If the text contains no letters at
    all, the first digit is changed, and as a last resort a single character is
    appended. The result always differs from the input by exactly one character.
    """
    for index, char in enumerate(text):
        if char.isalpha():
            replacement = "b" if char.lower() == "a" else "a"
            # Preserve the original case so the change stays realistic.
            if char.isupper():
                replacement = replacement.upper()
            return text[:index] + replacement + text[index + 1:]

    for index, char in enumerate(text):
        if char.isdigit():
            replacement = "8" if char != "8" else "9"
            return text[:index] + replacement + text[index + 1:]

    # Fallback for content made only of symbols/whitespace.
    return text + "X"


def demonstrate_avalanche(folder=DEFAULT_FOLDER, algorithm: str = DEFAULT_ALGORITHM) -> Optional[dict]:
    """Prove that a one-character change produces a completely different hash.

    Steps
    -----
    1. Pick one existing sample file from ``test_folder``.
    2. Hash the original.
    3. Copy it to a temporary file *inside* ``test_folder``.
    4. Change exactly one character in the temporary copy.
    5. Hash the copy and compare both digests.
    6. Delete the copy - in a ``finally`` block, so it happens even on error.

    The original sample file is opened read-only and is never written to.
    """
    label = algorithm.upper().replace("SHA", "SHA-")
    folder_path = Path(folder)

    print()
    print("=" * 74)
    print("DEMONSTRATION: THE AVALANCHE EFFECT".center(74))
    print("=" * 74)

    # Week 2: the folder is now walked recursively, so sample files that live
    # inside sub-folders are found too. Symbolic links and directories are
    # still skipped, and the temporary copy is always written next to the
    # sample it came from (inside the monitored folder).
    sample_files, _skipped = walk_regular_files(folder_path)
    text_samples = [item for item in sample_files
                    if item.suffix.lower() in (".txt", ".md")
                    and not item.name.startswith(DEMO_PREFIX)]

    if not text_samples:
        print("  Demonstration skipped: no sample text file found in", folder_path)
        print("=" * 74)
        return None

    original_path = text_samples[0]
    temp_path = original_path.parent / f"{DEMO_PREFIX}{original_path.stem}_{os.getpid()}.txt"

    try:
        # --- Step 1: read the original (read-only, never modified) ----------
        original_bytes = original_path.read_bytes()
        original_text = original_bytes.decode("utf-8", errors="replace")

        # --- Step 2: hash the original --------------------------------------
        original_hash = hash_file(original_path, algorithm=algorithm)
        if original_hash is None:
            print("  Demonstration aborted: the sample file could not be read.")
            print("=" * 74)
            return None

        print(f"  Sample file      : {original_path.name}")
        print(f"  Original content : {original_text.splitlines()[0][:56]!r}")
        print(f"  Original {label:<7}: {original_hash}")
        print("  " + "-" * 70)

        # --- Step 3: create the temporary copy inside test_folder ----------
        shutil.copy2(original_path, temp_path)

        # --- Step 4: change exactly one character in the copy --------------
        modified_text = _change_one_character(original_text)
        # Write the modified text back as UTF-8 bytes.
        temp_path.write_bytes(modified_text.encode("utf-8"))

        # --- Step 5: hash the modified copy and compare -------------------
        modified_hash = hash_file(temp_path, algorithm=algorithm)
        print(f"  Temporary copy   : {temp_path.name}")
        print(f"  Modified content : {modified_text.splitlines()[0][:56]!r}")
        print(f"  Modified {label:<7}: {modified_hash}")
        print("  " + "-" * 70)

        if modified_hash is None:
            print("  Comparison failed: the temporary copy could not be hashed.")
            print("=" * 74)
            return None

        if original_hash == modified_hash:
            print("  UNEXPECTED: the hashes are identical - please investigate.")
        else:
            differing = sum(
                1 for left, right in zip(original_hash, modified_hash) if left != right
            )
            print("  RESULT: the two hashes are COMPLETELY DIFFERENT.")
            print(f"  Only one character changed in the file, yet {differing} of "
                  f"{len(original_hash)} hex digits differ.")
            print()
            print("  Why? A hash function is designed to avalanche: each output bit")
            print("  depends on every input bit. One changed input character alters")
            print("  the internal state, which scrambles the whole digest. This is")
            print("  exactly why hashes can detect tampered or corrupted files.")
            print()
            print(f"  Original sample file '{original_path.name}' was NOT modified.")
        print("=" * 74)

        return {
            "file": original_path.name,
            "algorithm": algorithm,
            "original_hash": original_hash,
            "modified_hash": modified_hash,
            "changed": original_hash != modified_hash,
        }

    except (OSError, UnicodeError) as exc:
        print(f"  [ERROR] Demonstration failed: {exc}", file=sys.stderr)
        return None
    finally:
        # --- Step 6: always remove the temporary copy ----------------------
        try:
            if temp_path.exists():
                temp_path.unlink()
                print(f"  Cleanup: temporary copy '{temp_path.name}' deleted.")
        except OSError as exc:
            print(f"  [WARNING] Could not delete {temp_path}: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# WEEK 3: structured logging
# ---------------------------------------------------------------------------

def setup_logging(log_path=LOG_FILENAME,
                  verbose: bool = False,
                  console: bool = True) -> logging.Logger:
    """Configure and return the ``filewatch`` logger.

    Structure
    ---------
    * one :class:`logging.FileHandler` writing to ``filewatch.log`` with
      timestamps, level names and module names,
    * optionally one stream handler for warnings and errors on stderr.

    Duplicate-handler safety
    ------------------------
    Calling this function more than once (a watch loop, a test, the CLI) must
    not duplicate log lines. Every handler created here is tagged with
    ``_filewatch_managed = True``; any managed handler already attached is
    closed and removed first. Handlers added by the *application user* (e.g.
    pytest's ``caplog``) are left alone.

    The logger never propagates to the root logger, so importing this module in
    another program cannot pollute that program's logging configuration.
    """
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False

    # Remove only handlers we previously installed - never foreign ones.
    for handler in list(logger.handlers):
        if getattr(handler, "_filewatch_managed", False):
            logger.removeHandler(handler)
            try:
                handler.close()
            except OSError:  # pragma: no cover - closing a dead file
                pass

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    target = Path(log_path)
    try:
        if target.parent and str(target.parent) not in ("", "."):
            target.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(target, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        file_handler.setFormatter(formatter)
        file_handler._filewatch_managed = True  # type: ignore[attr-defined]
        logger.addHandler(file_handler)
    except OSError as exc:
        # Logging must never be the reason the tool fails to start.
        print(f"  [WARNING] Could not open log file {target}: {exc}",
              file=sys.stderr)
        file_handler = None

    if console:
        stream_handler = logging.StreamHandler(stream=sys.stderr)
        stream_handler.setLevel(logging.WARNING)
        stream_handler.setFormatter(formatter)
        stream_handler._filewatch_managed = True  # type: ignore[attr-defined]
        logger.addHandler(stream_handler)

    logger.debug("Logging initialised (log file: %s)", target)
    return logger


def get_logger() -> logging.Logger:
    """Return the shared ``filewatch`` logger without reconfiguring it."""
    return logging.getLogger(LOGGER_NAME)


def reset_logging() -> None:
    """Detach and close every managed handler (used by tests and shutdown)."""
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        if getattr(handler, "_filewatch_managed", False):
            logger.removeHandler(handler)
            try:
                handler.close()
            except OSError:  # pragma: no cover
                pass


# ---------------------------------------------------------------------------
# WEEK 3: terminal alerts (colour where the terminal supports it)
# ---------------------------------------------------------------------------

#: ANSI escape sequences, keyed by meaning. Empty strings when colour is off.
_COLOURS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "grey": "\033[90m",
}

_NO_COLOURS = {key: "" for key in _COLOURS}


def supports_colour(stream=None) -> bool:
    """Best-effort check: is colour output appropriate for this stream?

    Colour is disabled when ``NO_COLOR`` is set (see https://no-color.org),
    when ``TERM`` is ``dumb``, and whenever the stream is not a TTY - which
    also keeps piped output, log redirection and test capture clean.
    """
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("TERM", "") == "dumb":
        return False
    stream = stream if stream is not None else sys.stdout
    return bool(getattr(stream, "isatty", lambda: False)())


def colour_map(enabled: bool) -> Dict[str, str]:
    """Return the ANSI map when ``enabled``, otherwise a map of empty strings."""
    return dict(_COLOURS) if enabled else dict(_NO_COLOURS)


def paint(text: str, colour: str, enabled: bool = True) -> str:
    """Wrap ``text`` in an ANSI colour when ``enabled``; otherwise return it."""
    if not enabled:
        return text
    code = _COLOURS.get(colour, "")
    if not code:
        return text
    return f"{code}{text}{_COLOURS['reset']}"


# ---------------------------------------------------------------------------
# WEEK 3: ignore configuration (.filewatchignore)
# ---------------------------------------------------------------------------

class IgnoreRules:
    """Compiled ignore rules: comments, blank lines and ``fnmatch`` patterns.

    Matching rules
    --------------
    A file is ignored when **any** of these match:

    * ``fnmatch`` against the full relative path (``subfolder/notes.tmp``),
    * ``fnmatch`` against the basename (``notes.tmp``),
    * ``fnmatch`` against any parent directory name (``__pycache__``, ``.git``),
    * equality/prefix match on a directory-style pattern (``.git`` or ``.git/``),
    * the same three checks against each pattern's basename (so ``**/cache``
      also matches ``a/b/cache/file.txt``).

    ``*`` therefore behaves like a git-ignore "single segment" pattern and
    ``**/x`` or a bare directory name matches at any depth, which is what people
    expect from patterns such as ``*.tmp``, ``.git``, ``.venv`` and
    ``__pycache__``.
    """

    def __init__(self, patterns: Optional[Iterable[str]] = None,
                 source: Optional[Path] = None) -> None:
        self.patterns: List[str] = []
        self.source = source
        self._add_patterns(patterns or ())

    # -- construction ------------------------------------------------------
    def _add_patterns(self, patterns: Iterable[str]) -> None:
        for raw in patterns:
            pattern = raw.strip()
            if not pattern or pattern.startswith("#"):
                continue  # blank line or comment
            if pattern.startswith("./"):
                pattern = pattern[2:]
            pattern = pattern.rstrip("/")
            if pattern and pattern not in self.patterns:
                self.patterns.append(pattern)

    @classmethod
    def from_file(cls, path) -> "IgnoreRules":
        """Load a ``.filewatchignore`` file. A missing file means "no rules"."""
        rules = cls()
        rules.source = Path(path)
        try:
            text = Path(path).read_text(encoding="utf-8")
        except (FileNotFoundError, NotADirectoryError):
            return rules
        except (OSError, UnicodeDecodeError) as exc:
            get_logger().warning("Could not read ignore file %s: %s", path, exc)
            return rules
        rules._add_patterns(text.splitlines())
        return rules

    @classmethod
    def default(cls) -> "IgnoreRules":
        """Always-on internal patterns (this tool's own artifacts)."""
        return cls(DEFAULT_IGNORE_PATTERNS)

    # -- matching ----------------------------------------------------------
    @staticmethod
    def _pattern_matches(pattern: str, path: str, name: str,
                         parents: Tuple[str, ...]) -> bool:
        candidates = (path, name) + parents
        pat_name = pattern.rsplit("/", 1)[-1]
        for candidate in candidates:
            if fnmatch.fnmatchcase(candidate, pattern):
                return True
            if pat_name != pattern and fnmatch.fnmatchcase(candidate, pat_name):
                return True
        return False

    def is_ignored_path(self, path_parts: Iterable[str]) -> bool:
        """True if any part of a path matches a pattern (used while walking)."""
        parts = [part for part in path_parts if part not in ("", ".")]
        if not parts:
            return False
        joined = "/".join(parts)
        name = parts[-1]
        parents = tuple(parts[:-1])
        return any(self._pattern_matches(pattern, joined, name, parents)
                   for pattern in self.patterns)

    def is_ignored(self, relative_path: str) -> bool:
        """True if a relative POSIX path (``sub/x.tmp``) is ignored."""
        return self.is_ignored_path(str(relative_path).split("/"))

    def filter_snapshot(self, snapshot: Dict[str, dict]) -> Dict[str, dict]:
        """Return only the snapshot entries that are *not* ignored."""
        return {key: value for key, value in snapshot.items()
                if not self.is_ignored(key)}

    def __len__(self) -> int:
        return len(self.patterns)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"IgnoreRules({self.patterns!r})"


def load_ignore_rules(ignore_path=None, folder=None) -> IgnoreRules:
    """Load the default patterns plus ``.filewatchignore``.

    Lookup order for the ignore file:

    1. an explicit ``ignore_path`` (``--ignore``),
    2. ``<monitored folder>/.filewatchignore``,
    3. ``<project root>/.filewatchignore``.

    The first file found wins; the always-on internal patterns are always
    included, so the tool never alerts about its own log file.
    """
    rules = IgnoreRules.default()

    candidates: List[Path] = []
    if ignore_path:
        candidates.append(Path(ignore_path))
    else:
        if folder is not None:
            candidates.append(Path(folder) / IGNORE_FILENAME)
        candidates.append(Path(__file__).resolve().parent / IGNORE_FILENAME)

    for candidate in candidates:
        if candidate.is_file():
            loaded = IgnoreRules.from_file(candidate)
            rules._add_patterns(loaded.patterns)
            rules.source = candidate
            break

    return rules


# ---------------------------------------------------------------------------
# WEEK 2: snapshot building (recursive, relative paths, no symlinks)
# ---------------------------------------------------------------------------

def _relative_key(file_path: Path, root: Path) -> str:
    """Return a POSIX-style path of ``file_path`` relative to ``root``.

    Relative paths (``"subfolder/file3.txt"``) are used for two reasons:

    * a baseline stays valid if the project folder is moved or copied,
    * no absolute path of your machine ever leaks into a committed file.

    ``as_posix()`` forces forward slashes, so a baseline written on Windows
    still matches the same files on Linux or macOS.
    """
    return file_path.relative_to(root).as_posix()


def walk_regular_files(folder,
                       ignore: Optional["IgnoreRules"] = None
                       ) -> Tuple[List[Path], List[str]]:
    """Recursively collect regular files under ``folder``.

    Returns ``(files, skipped)`` where ``files`` is a list of paths and
    ``skipped`` is a list of human-readable notes about entries that were
    deliberately not hashed (symbolic links, directories, folders we were not
    allowed to read, ignored paths).

    ``ignore`` is optional so Week 1/2 callers keep working unchanged (Week 3
    passes the compiled :class:`IgnoreRules` from ``.filewatchignore``).

    Rules, in order:

    1. ``os.walk(..., followlinks=False)`` never descends into symlinked
       directories, so the walk can never escape the monitored folder.
    2. Symbolic links (files *or* directories) are skipped: their target could
       live outside the folder, and reading it would break the boundary.
    3. Ordinary directories are simply not files, so they are skipped.
    4. Demonstration leftovers (``demo_copy_*``) are ignored so a temporary
       copy can never show up as an "added" file.
    5. Unreadable sub-folders are reported and skipped instead of crashing.
    """
    root = Path(folder)
    files: List[Path] = []
    skipped: List[str] = []

    # os.walk is a generator: an OSError (I/O failure, a directory removed
    # mid-walk, an unreadable mount) is raised while *iterating*, not when the
    # generator is created. Catching it here keeps one bad tree from taking
    # down the whole scan - the requirement is "log the error, keep going".
    try:
        for dir_path, dir_names, file_names in os.walk(root, followlinks=False):
            _collect_from_dir(Path(dir_path), root, dir_names, file_names,
                              ignore, files, skipped)
    except (PermissionError, OSError) as exc:
        message = f"Could not walk {root}: {exc}"
        skipped.append(message)
        get_logger().error("%s - keeping the files collected so far", message)

    files.sort(key=lambda item: _relative_key(item, root).lower())
    return files, skipped


def _collect_from_dir(current_dir: Path, root: Path, dir_names: List[str],
                      file_names: List[str], ignore: Optional["IgnoreRules"],
                      files: List[Path], skipped: List[str]) -> None:
    """Handle one directory yielded by ``os.walk``.

    Prunes symlinked and ignored sub-directories by mutating ``dir_names`` in
    place, so the walk never descends into them, and appends the regular files
    that survive the ignore rules.
    """
    # Prune symlinked *and ignored* directories before os.walk descends into
    # them. Pruning ignored directories early is what keeps scans cheap: an
    # ignored `.git` or `.venv` tree is never entered at all.
    kept_dirs: List[str] = []
    for name in sorted(dir_names):
        candidate = current_dir / name
        relative = _relative_key(candidate, root)
        try:
            is_link = candidate.is_symlink()
        except OSError:
            continue  # metadata unreadable - do not descend
        if is_link:
            skipped.append(f"{relative} (symbolic link to a directory)")
        elif ignore is not None and ignore.is_ignored(relative):
            skipped.append(f"{relative}/ (ignored)")
        else:
            kept_dirs.append(name)
    dir_names[:] = kept_dirs

    for name in sorted(file_names):
        candidate = current_dir / name
        relative = _relative_key(candidate, root)
        if name.startswith(DEMO_PREFIX):
            continue  # temporary demo copy - never part of a baseline
        if ignore is not None and ignore.is_ignored(relative):
            continue  # ignored by .filewatchignore - never reported or alerted
        try:
            if candidate.is_symlink():
                skipped.append(f"{relative} (symbolic link)")
                continue
            if not candidate.is_file():
                continue  # sockets, pipes, devices ...
        except OSError as exc:
            skipped.append(f"{relative} (metadata unreadable: {exc})")
            continue
        files.append(candidate)


def build_snapshot(folder, algorithm: str = DEFAULT_ALGORITHM,
                   ignore: Optional["IgnoreRules"] = None,
                   unreadable: Optional[Set[str]] = None,
                   report_skipped: bool = True) -> Dict[str, dict]:
    """Build a snapshot of every regular file under ``folder``.

    Walks the folder **recursively** (sub-folders included), hashes each regular
    file with ``hash_file()`` and returns a dictionary keyed by *relative* path:

        {
            "file1.txt":            {"sha256": "ae51...", "size": 155, "mtime": ...},
            "subfolder/file3.txt":  {"sha256": "a9c0...", "size": 154, "mtime": ...},
        }

    Each value also carries the stretch-goal metadata (``size`` in bytes and
    ``mtime``, the last-modified time). The hash is the authoritative signal:
    metadata is informational only and never decides whether a file changed.

    Files that cannot be read (permissions, I/O errors) are reported and
    omitted from the snapshot rather than aborting the whole run.

    ``ignore`` (optional) drops paths matching ``.filewatchignore``.
    ``unreadable`` (optional) is a set the caller provides; the relative paths
    of files that could not be hashed are added to it so callers can tell
    "missing" apart from "unreadable".

    ``report_skipped`` controls the ``[SKIPPED]`` console notes. ``watch`` sets
    it to ``False`` because the same notes would otherwise repeat on every
    scan; they still go to the log file at DEBUG level.
    """
    root = Path(folder)
    files, skipped = walk_regular_files(root, ignore=ignore)
    snapshot: Dict[str, dict] = {}

    for file_path in files:
        digest = hash_file(file_path, algorithm=algorithm)
        if digest is None:
            # hash_file() already printed a specific [ERROR] line.
            if unreadable is not None:
                # Week 3: tell the caller *which* files failed, so `watch` can
                # avoid reporting them as deleted.
                unreadable.add(_relative_key(file_path, root))
            get_logger().error("Could not read/hash %s - skipped in this scan",
                               _relative_key(file_path, root))
            continue

        entry = {algorithm: digest}
        try:
            stat_result = file_path.stat()
            entry["size"] = stat_result.st_size
            entry["mtime"] = stat_result.st_mtime
        except OSError as exc:
            print(f"  [WARNING] Could not read metadata for {file_path}: {exc}",
                  file=sys.stderr)

        snapshot[_relative_key(file_path, root)] = entry

    if skipped:
        logger = get_logger()
        for note in skipped:
            logger.debug("Skipped entry: %s", note)
            if report_skipped:
                print(f"  [SKIPPED] {note}", file=sys.stderr)

    return snapshot


# ---------------------------------------------------------------------------
# WEEK 2: comparing a baseline with a fresh snapshot
# ---------------------------------------------------------------------------

def get_hash(entry: dict, algorithm: str = DEFAULT_ALGORITHM) -> Optional[str]:
    """Read the digest for ``algorithm`` out of a snapshot entry.

    Tolerates a plain-string entry (``{"file1.txt": "abc..."}``), which keeps
    very simple hand-written baselines usable.
    """
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        return entry.get(algorithm)
    return None


def compare_snapshots(baseline: Dict[str, dict],
                      current: Dict[str, dict],
                      algorithm: str = DEFAULT_ALGORITHM,
                      unreadable: Optional[Iterable[str]] = None,
                      root: Optional[Path] = None) -> Dict[str, list]:
    """Compare two snapshots and classify every difference.

    Pure dictionary/set arithmetic - no I/O - which makes it trivial to test:

        added     = current keys - baseline keys
        deleted   = baseline keys - current keys
        common    = current keys & baseline keys
        modified  = common keys whose digest differs
        unchanged = common keys whose digest is identical

    Returns a dictionary with the six lists (sorted for stable output):
    ``added``, ``modified``, ``deleted``, ``unchanged``, ``skipped`` (files in
    both but lacking a digest for the chosen algorithm) and ``unreadable``.

    A file is MODIFIED only when its content hash changed. A new timestamp or
    size with an identical hash is *not* a modification.

    Week 3 - no false deletions
    ---------------------------
    ``unreadable`` lists relative paths that are present on disk but could not
    be hashed (permissions, I/O errors). Such a file must never be reported as
    DELETED just because it is missing from ``current``: the tool cannot prove
    it is gone. Those paths land in the ``unreadable`` bucket instead, and -
    when ``root`` is given - a final ``os.path.lexists()`` check decides:

    * the path really is gone            -> genuine DELETED,
    * the path is still there            -> kept in ``unreadable`` (no alert).

    With ``unreadable=None`` (the Week 1/2 call signature) the behaviour is
    byte-for-byte what it was before.
    """
    baseline_keys = set(baseline)
    current_keys = set(current)
    unreadable_set = set(unreadable or ())

    added_files = current_keys - baseline_keys

    # Candidates for "deleted": absent from the snapshot ...
    deleted_candidates = baseline_keys - current_keys
    # ... but only report the ones we never failed to read.
    deleted_files = deleted_candidates - unreadable_set
    protected_files = deleted_candidates & unreadable_set

    common_files = current_keys & baseline_keys

    modified_files: List[str] = []
    unchanged_files: List[str] = []
    skipped_files: List[str] = []

    for name in sorted(common_files):
        old_hash = get_hash(baseline[name], algorithm)
        new_hash = get_hash(current[name], algorithm)

        if old_hash is None or new_hash is None:
            # e.g. baseline was recorded with SHA-256 but we are checking SHA-1.
            skipped_files.append(name)
        elif old_hash != new_hash:
            modified_files.append(name)
        else:
            unchanged_files.append(name)

    # Second safety net: an unreadable path is only a genuine deletion if it is
    # definitely not on disk any more. `lexists` is True for broken symlinks
    # too, which is what we want here: "something is still there".
    still_unreadable: List[str] = []
    if root is not None:
        root_path = Path(root)
        for name in sorted(protected_files):
            try:
                exists = os.path.lexists(root_path / name)
            except OSError:  # pragma: no cover - defensive
                exists = True
            if exists:
                still_unreadable.append(name)
            else:
                deleted_files.add(name)
    else:
        still_unreadable = sorted(protected_files)

    return {
        "added": sorted(added_files),
        "modified": modified_files,
        "deleted": sorted(deleted_files),
        "unchanged": unchanged_files,
        "skipped": sorted(skipped_files),
        "unreadable": sorted(still_unreadable),
    }


def has_changes(result: Dict[str, list]) -> bool:
    """True if the comparison found any added, modified or deleted file."""
    return bool(result["added"] or result["modified"] or result["deleted"])


# ---------------------------------------------------------------------------
# WEEK 4 (stretch): HMAC baseline signing
# ---------------------------------------------------------------------------
#
# Why: a hash baseline proves *file* integrity, but it is itself just a file.
# Anyone who can edit a monitored file can also edit baseline.json to match.
# An HMAC signature binds the baseline to a secret key, so tampering with the
# baseline is detectable without the key.
#
# What it does NOT do: it does not protect against an attacker who already has
# the key or who can run code as your user (they can just re-sign). It also
# does not stop deletions inside the monitored folder. It closes exactly one
# gap: "someone quietly rewrote the baseline".
#
# Key handling rules enforced here (see README section on key management):
#   * the key is NEVER hardcoded and never written into the project folder,
#   * it comes from the environment or a 0600 file outside the project,
#   * it must be >= 32 bytes for HMAC-SHA256,
#   * comparisons use hmac.compare_digest() (constant time),
#   * failures are reported as "cannot verify", never ignored silently.

class BaselineSignatureError(Exception):
    """Raised when a baseline cannot be signed or verified safely."""


def _looks_like_hex(text: str) -> bool:
    """True for an even-length, non-empty string of hex digits."""
    if not text or len(text) % 2 != 0:
        return False
    return all(char in "0123456789abcdefABCDEF" for char in text)


def resolve_hmac_key(required: bool = True,
                     key: Optional[bytes] = None,
                     key_file=None) -> Optional[bytes]:
    """Load the HMAC key from (1) an explicit value, (2) an explicit file,
    (3) ``$FILEWATCH_HMAC_KEY_FILE``, (4) ``$FILEWATCH_HMAC_KEY``.

    Encoding of the environment variable
    ------------------------------------
    * an even-length hex string is decoded as hex
      (``export FILEWATCH_HMAC_KEY=$(openssl rand -hex 32)``),
    * anything else is used as raw UTF-8 bytes.

    A key file must not be group/world readable (mode ``0600`` expected);
    otherwise the key is treated as compromised and rejected.

    Returns ``None`` when no key is configured and ``required`` is False.
    Raises :class:`BaselineSignatureError` when a key is needed but missing or
    too short - signing must never silently fall back to "unsigned".
    """
    if key is not None:
        material = key
    else:
        # An explicit path wins over the environment variable.
        path = key_file or os.environ.get(HMAC_KEY_FILE_ENV)
        if path:
            candidate = Path(path)
            try:
                # A key stored inside the project is one `git add .` away from
                # being published. Warn loudly; do not refuse, since a private
                # repo may be an acceptable trade-off for the user.
                project_root = Path(__file__).resolve().parent
                if candidate.resolve().parent == project_root or \
                        project_root in candidate.resolve().parents:
                    print(f"  [WARNING] Key file {candidate} lives inside the "
                          f"project folder - keep it outside and out of Git.",
                          file=sys.stderr)
            except OSError:
                pass
            try:
                # Refuse a key file that other users can read.
                mode = stat.S_IMODE(candidate.stat().st_mode)
                if mode & 0o077:
                    raise BaselineSignatureError(
                        f"Key file {candidate} is too permissive "
                        f"(mode {oct(mode)}); run: chmod 600 {candidate}"
                    )
                text = candidate.read_text(encoding="utf-8").strip()
                # A key file written by `keygen` holds hex; accept raw bytes too.
                material = (bytes.fromhex(text) if _looks_like_hex(text)
                            else text.encode("utf-8"))
            except FileNotFoundError:
                raise BaselineSignatureError(f"Key file not found: {candidate}")
            except PermissionError:
                raise BaselineSignatureError(f"Cannot read key file: {candidate}")
            except OSError as exc:
                raise BaselineSignatureError(f"Cannot read key file {candidate}: {exc}")
        else:
            env_value = os.environ.get(HMAC_KEY_ENV)
            if not env_value:
                if not required:
                    return None
                raise BaselineSignatureError(
                    f"No HMAC key configured. Set {HMAC_KEY_ENV} "
                    f"(e.g. export {HMAC_KEY_ENV}=$(python -c "
                    f"'import secrets;print(secrets.token_hex(32))')) "
                    f"or point {HMAC_KEY_FILE_ENV} at a 0600 key file."
                )
            material = (bytes.fromhex(env_value)
                        if _looks_like_hex(env_value) else env_value.encode("utf-8"))

    if len(material) < MIN_HMAC_KEY_BYTES:
        raise BaselineSignatureError(
            f"HMAC key is too short ({len(material)} bytes). "
            f"Use at least {MIN_HMAC_KEY_BYTES} random bytes."
        )
    return material


def generate_hmac_key(num_bytes: int = MIN_HMAC_KEY_BYTES) -> str:
    """Return a fresh cryptographically random hex key (``secrets`` module)."""
    return secrets.token_hex(max(num_bytes, MIN_HMAC_KEY_BYTES))


def baseline_signing_payload(metadata: Dict[str, object]) -> bytes:
    """Serialise the signed part of a baseline deterministically.

    ``signature`` is excluded (obviously) and ``signed_fields`` is excluded too
    - it only records *which* fields were covered, so it cannot include itself.

    ``sort_keys=True`` and fixed separators make the byte sequence independent
    of dictionary ordering, so a pretty-printed, reordered or reformatted JSON
    file still verifies as long as the *values* are unchanged.
    """
    signed = {key: value for key, value in metadata.items()
              if key not in (SIGNATURE_KEY, "signed_fields")}
    return json.dumps(signed, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def compute_baseline_signature(metadata: Dict[str, object], key: bytes) -> str:
    """Return the hex HMAC-SHA256 of the baseline metadata."""
    if not key:
        raise BaselineSignatureError("Refusing to sign without a key.")
    return hmac.new(key, baseline_signing_payload(metadata),
                    getattr(hashlib, HMAC_ALGORITHM)).hexdigest()


def sign_baseline_payload(payload: Dict[str, object], key: bytes) -> Dict[str, object]:
    """Return ``payload`` with a ``signature`` block added (copy, not in place)."""
    signed = dict(payload)
    signature = compute_baseline_signature(signed, key)
    signed[SIGNATURE_KEY] = {
        "algorithm": f"hmac-{HMAC_ALGORITHM}",
        "value": signature,
        "signed_fields": sorted(k for k in signed
                                if k not in (SIGNATURE_KEY, "signed_fields")),
    }
    return signed


def verify_baseline_signature(metadata: Dict[str, object],
                              key: Optional[bytes]) -> Tuple[bool, str]:
    """Check a baseline's signature. Returns ``(ok, human_readable_reason)``.

    Outcomes:

    * ``(False, "... unsigned ...")``      - baseline carries no signature,
    * ``(False, "... no key ...")``        - signed, but we have no key,
    * ``(False, "... MISMATCH ...")``      - tampered or wrong key,
    * ``(True,  "... verified ...")``      - signature matches.

    Never raises: callers decide whether a failure is fatal.
    """
    signature_block = metadata.get(SIGNATURE_KEY)

    if not signature_block:
        return False, ("baseline is UNSIGNED - its authenticity cannot be "
                       "verified (re-sign it with `baseline --sign`)")
    if not isinstance(signature_block, dict) or "value" not in signature_block:
        return False, "baseline signature block is malformed"
    if key is None:
        return False, ("baseline is signed but no HMAC key is configured - "
                       "set FILEWATCH_HMAC_KEY to verify it")

    expected = str(signature_block.get("value", ""))
    try:
        actual = compute_baseline_signature(metadata, key)
    except BaselineSignatureError as exc:  # pragma: no cover - defensive
        return False, str(exc)

    # Constant-time comparison: never leak how much of the digest matched.
    if hmac.compare_digest(expected, actual):
        return True, f"signature verified (hmac-{HMAC_ALGORITHM})"
    return False, ("signature MISMATCH - the baseline was modified after it was "
                   "signed, or the wrong key is being used")

# ---------------------------------------------------------------------------
# WEEK 2: baseline file I/O (JSON)
# ---------------------------------------------------------------------------

def _human_size(num_bytes: Optional[int]) -> str:
    """Format a byte count as e.g. ``155 B`` or ``12.4 KiB``."""
    if not isinstance(num_bytes, int):
        return "unknown size"
    if num_bytes < 1024:
        return f"{num_bytes} B"
    for unit in ("KiB", "MiB", "GiB"):
        num_bytes /= 1024.0
        if num_bytes < 1024 or unit == "GiB":
            return f"{num_bytes:.1f} {unit}"
    return f"{num_bytes:.1f} GiB"


def _format_mtime(timestamp) -> str:
    """Format a POSIX timestamp as readable local time (``YYYY-MM-DD HH:MM:SS``)."""
    if not isinstance(timestamp, (int, float)):
        return "unknown mtime"
    try:
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return "invalid mtime"


def _resolve_baseline_path(baseline_path) -> Path:
    """Resolve a baseline path; relative paths become project-root relative."""
    candidate = Path(baseline_path)
    if not candidate.is_absolute():
        candidate = Path(__file__).resolve().parent / candidate
    return candidate


def save_baseline(snapshot: Dict[str, dict],
                  baseline_path=BASELINE_FILENAME,
                  folder=DEFAULT_FOLDER,
                  algorithm: str = DEFAULT_ALGORITHM,
                  sign: bool = False,
                  key: Optional[bytes] = None) -> Optional[Path]:
    """Write ``snapshot`` to ``baseline.json`` as readable, indented JSON.

    The file is written by ``json.dump(..., indent=2)`` so it diffs cleanly in
    Git. A small header records the schema version, algorithm, monitored folder
    and creation time - handy when a baseline is read months later.

    Week 4 (optional): with ``sign=True`` an ``hmac-sha256`` signature over the
    whole metadata block is added. ``key`` may be supplied directly (used by the
    tests); otherwise it is resolved from the environment / key file. Signing
    fails loudly rather than writing an unsigned baseline by accident.

    Returns the path written, or ``None`` if it could not be written.
    """
    target = _resolve_baseline_path(baseline_path)

    payload = {
        "tool": "FileWatch - File Integrity Monitor",
        "schema_version": BASELINE_SCHEMA_VERSION,
        "algorithm": algorithm,
        "folder": Path(folder).name or str(folder),
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "file_count": len(snapshot),
        FILES_KEY: dict(sorted(snapshot.items())),
    }

    if sign:
        try:
            signing_key = resolve_hmac_key(required=True, key=key)
            payload = sign_baseline_payload(payload, signing_key)
        except BaselineSignatureError as exc:
            print(f"  [ERROR] Could not sign the baseline: {exc}", file=sys.stderr)
            print("  The baseline was NOT written (refusing to save it unsigned).",
                  file=sys.stderr)
            return None
        print(f"  Signature : hmac-{HMAC_ALGORITHM} "
              f"({payload[SIGNATURE_KEY]['value'][:16]}...)")

    try:
        # Write to a temporary file first, then atomically replace the target.
        # If the write fails halfway, the previous good baseline survives.
        temp_target = target.with_name(target.name + ".tmp")
        with open(temp_target, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        os.replace(temp_target, target)
    except (OSError, TypeError, ValueError) as exc:
        print(f"  [ERROR] Could not write baseline file {target}: {exc}",
              file=sys.stderr)
        try:
            if temp_target.exists():
                temp_target.unlink()
        except OSError:
            pass
        return None

    return target


def load_baseline(baseline_path=BASELINE_FILENAME,
                  verify: bool = False,
                  key: Optional[bytes] = None,
                  require_signature: Optional[bool] = None,
                  allow_unsigned: bool = True) -> Optional[Dict[str, dict]]:
    """Load a baseline file and return its ``files`` mapping.

    Handles the realistic failure modes without crashing:

    * file missing            -> message + ``None``
    * permission / I/O error  -> message + ``None``
    * invalid JSON            -> message + ``None``
    * wrong overall structure -> message + ``None``
    * legacy flat baselines   -> accepted (``{"file1.txt": "abc..."}``)

    Week 4 (optional) - signature verification
    ------------------------------------------
    With ``verify=True`` the HMAC signature is checked before the baseline is
    trusted. Behaviour:

    * valid signature                  -> loaded,
    * signature mismatch (tampered)    -> refused, ``None``  (always fatal),
    * signed but no key configured     -> refused, ``None``,
    * unsigned baseline                -> loaded with a warning when
      ``allow_unsigned`` is True (default, so existing users keep working),
      refused when False.

    ``require_signature=True`` is shorthand for ``verify=True,
    allow_unsigned=False``. Defaults leave Week 1-3 behaviour untouched.
    """
    if require_signature is not None:
        verify = require_signature
        allow_unsigned = not require_signature

    target = _resolve_baseline_path(baseline_path)

    try:
        with open(target, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        print(f"  [ERROR] No baseline found at {target}", file=sys.stderr)
        print("  Run `python main.py baseline` first to create one.", file=sys.stderr)
        return None
    except PermissionError:
        print(f"  [ERROR] Permission denied while reading {target}", file=sys.stderr)
        return None
    except json.JSONDecodeError as exc:
        print(f"  [ERROR] Baseline file is not valid JSON: {target}", file=sys.stderr)
        print(f"          {exc}", file=sys.stderr)
        print("  The file was left untouched. Delete it or regenerate it with "
              "`python main.py baseline`.", file=sys.stderr)
        return None
    except OSError as exc:
        print(f"  [ERROR] Could not read {target}: {exc}", file=sys.stderr)
        return None
    except UnicodeDecodeError:
        print(f"  [ERROR] Baseline file is not UTF-8 text: {target}", file=sys.stderr)
        return None

    if not isinstance(data, dict):
        print(f"  [ERROR] Baseline has an unexpected structure: {target}", file=sys.stderr)
        print("  Expected a JSON object at the top level.", file=sys.stderr)
        return None

    if verify:
        try:
            verification_key = resolve_hmac_key(required=False, key=key) \
                if data.get(SIGNATURE_KEY) else key
        except BaselineSignatureError as exc:
            print(f"  [ERROR] {exc}", file=sys.stderr)
            return None

        ok, reason = verify_baseline_signature(data, verification_key)

        if ok:
            print(f"  Signature : {reason}")
        elif not data.get(SIGNATURE_KEY) and allow_unsigned:
            print(f"  [WARNING] {reason}", file=sys.stderr)
        else:
            print(f"  [ERROR] Baseline signature check failed: {reason}",
                  file=sys.stderr)
            print("  Refusing to trust this baseline. Do not regenerate it "
                  "until you understand why it changed.", file=sys.stderr)
            return None

    files = data.get(FILES_KEY)
    if files is None:
        # Legacy/plain format: the whole object is the mapping, or it holds
        # only string values.
        files = {key: value for key, value in data.items()
                 if not key.startswith("_")}

    if not isinstance(files, dict):
        print(f"  [ERROR] Baseline 'files' section is not an object: {target}",
              file=sys.stderr)
        return None

    valid_entries = {}
    for key, value in files.items():
        if isinstance(value, (str, dict)):
            valid_entries[key] = value
    return valid_entries


def baseline_metadata(baseline_path=BASELINE_FILENAME) -> Dict[str, object]:
    """Return the informational header of a baseline file (may be empty)."""
    target = _resolve_baseline_path(baseline_path)
    try:
        with open(target, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {key: value for key, value in data.items() if key != FILES_KEY}


# ---------------------------------------------------------------------------
# WEEK 2: the two new commands
# ---------------------------------------------------------------------------

def command_keygen(output_path=None, force: bool = False) -> int:
    """``python main.py keygen`` - create a random HMAC key, safely.

    Prints the key to stdout (so it can go into a secrets manager) and, with
    ``--out PATH``, also writes it to a file with mode ``0600``.

    Refuses to overwrite an existing file unless ``--force`` is given, and
    refuses outright to write the key inside the project folder: a key that
    sits next to the code is one `git add .` away from being published.
    """
    new_key = generate_hmac_key()

    print("=" * 74)
    print("FILEWATCH - GENERATING AN HMAC KEY".center(74))
    print("=" * 74)
    print("Store this key OUTSIDE the project (secrets manager, password")
    print("manager, or a 0600 file). Never commit it and never share it.")
    print("-" * 74)

    if output_path:
        target = Path(output_path).expanduser()
        project_root = Path(__file__).resolve().parent
        try:
            resolved = target.resolve()
            if resolved.parent == project_root or project_root in resolved.parents:
                print(f"  [ERROR] Refusing to write a key inside the project "
                      f"folder: {target}", file=sys.stderr)
                print("  Choose a path outside the repository, e.g. "
                      "~/.config/filewatch/hmac.key", file=sys.stderr)
                return EXIT_FAILURE
        except OSError:
            pass

        if target.exists() and not force:
            print(f"  [ERROR] {target} already exists. Use --force to overwrite.",
                  file=sys.stderr)
            return EXIT_FAILURE

        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            # os.open with mode 0600 so the key is never world-readable,
            # not even for a moment.
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(new_key + "\n")
            os.chmod(target, 0o600)
        except OSError as exc:
            print(f"  [ERROR] Could not write key file {target}: {exc}",
                  file=sys.stderr)
            return EXIT_FAILURE

        print(f"  Key file written: {target} (mode 0600)")
        print(f"  Use it with: export {HMAC_KEY_FILE_ENV}={target}")
    else:
        print(f"  export {HMAC_KEY_ENV}={new_key}")

    print("-" * 74)
    print("Then sign your baseline:  python main.py baseline --sign")
    print("=" * 74)
    return EXIT_OK


def command_baseline(folder=DEFAULT_FOLDER,
                     baseline_path=BASELINE_FILENAME,
                     algorithm: str = DEFAULT_ALGORITHM,
                     ignore_path=None,
                     sign: bool = False,
                     key: Optional[bytes] = None) -> int:
    """``python main.py baseline`` - create or update baseline.json.

    Week 3: the same ``.filewatchignore`` rules used by ``watch`` are applied
    here too, so an ignored file is never recorded in the baseline in the first
    place (and therefore can never raise an alert later).

    Returns an exit code: ``EXIT_OK`` on success, ``EXIT_FAILURE`` if the folder
    is unusable or the file could not be written.
    """
    folder_path = Path(folder)

    print("=" * 74)
    print("FILEWATCH - CREATING BASELINE".center(74))
    print("=" * 74)
    print(f"Folder    : {folder_path}")
    print(f"Algorithm : {algorithm.upper().replace('SHA', 'SHA-')}")
    print(f"Baseline  : {_resolve_baseline_path(baseline_path)}")
    print("-" * 74)

    if not folder_path.exists():
        print(f"  [ERROR] Folder not found: {folder_path}", file=sys.stderr)
        return EXIT_FAILURE
    if not folder_path.is_dir():
        print(f"  [ERROR] Not a folder: {folder_path}", file=sys.stderr)
        return EXIT_FAILURE

    existing = _resolve_baseline_path(baseline_path).exists()
    ignore_rules = load_ignore_rules(ignore_path, folder=folder_path)
    print(f"Ignore    : {len(ignore_rules)} pattern(s)"
          + (f" from {ignore_rules.source}" if ignore_rules.source else " (built-in only)"))

    snapshot = build_snapshot(folder_path, algorithm=algorithm, ignore=ignore_rules)

    if not snapshot:
        print("  Warning: no readable regular files were found.")
        print("  Writing an empty baseline anyway (delete it if that was a mistake).")

    written = save_baseline(snapshot, baseline_path=baseline_path,
                            folder=folder_path, algorithm=algorithm,
                            sign=sign, key=key)
    if written is None:
        return EXIT_FAILURE

    for name, entry in sorted(snapshot.items()):
        digest = get_hash(entry, algorithm) or "?"
        print(f"  {name:<28} {digest}  ({_human_size(entry.get('size'))})")

    print("-" * 74)
    verb = "updated" if existing else "created"
    print(f"Baseline {verb}: {len(snapshot)} file(s) -> {written}")
    print("=" * 74)
    return EXIT_OK


def command_check(folder=DEFAULT_FOLDER,
                  baseline_path=BASELINE_FILENAME,
                  algorithm: str = DEFAULT_ALGORITHM,
                  ignore_path=None,
                  verify_signature: bool = False,
                  require_signature: bool = False,
                  key: Optional[bytes] = None) -> int:
    """``python main.py check`` - compare the folder against baseline.json.

    Returns ``EXIT_OK`` (no changes), ``EXIT_CHANGES`` (changes found) or
    ``EXIT_FAILURE`` (missing/invalid baseline or unusable folder).

    This function never writes to the baseline file.
    """
    folder_path = Path(folder)
    baseline_target = _resolve_baseline_path(baseline_path)

    print("=" * 74)
    print("FILEWATCH - CHECKING FOR CHANGES".center(74))
    print("=" * 74)
    print(f"Folder    : {folder_path}")
    print(f"Baseline  : {baseline_target}")
    print(f"Algorithm : {algorithm.upper().replace('SHA', 'SHA-')}")
    print("-" * 74)

    if not folder_path.exists() or not folder_path.is_dir():
        print(f"  [ERROR] Monitored folder is missing or not a folder: {folder_path}",
              file=sys.stderr)
        return EXIT_FAILURE

    baseline = load_baseline(baseline_path, verify=verify_signature,
                             require_signature=True if require_signature else None,
                             key=key)
    if baseline is None:
        return EXIT_FAILURE  # never replace the baseline during a check

    meta = baseline_metadata(baseline_path)
    if meta.get("created_utc"):
        print(f"Baseline created: {meta['created_utc']} "
              f"({meta.get('file_count', '?')} files, "
              f"{str(meta.get('algorithm', '?')).upper().replace('SHA', 'SHA-')})")
    if meta.get("algorithm") and meta.get("algorithm") != algorithm:
        print(f"  [WARNING] Baseline was recorded with {meta['algorithm']}. "
              f"You are comparing with {algorithm}; hashes are not comparable.")
    print("-" * 74)

    # Week 3: identical ignore rules to `watch`/`baseline`, and the unreadable
    # set so a file we could not read is never labelled "deleted".
    ignore_rules = load_ignore_rules(ignore_path, folder=folder_path)
    unreadable: Set[str] = set()
    current = build_snapshot(folder_path, algorithm=algorithm,
                             ignore=ignore_rules, unreadable=unreadable)
    result = compare_snapshots(baseline, current, algorithm=algorithm,
                               unreadable=unreadable, root=folder_path)

    def section(title: str, names: Iterable[str], marker: str) -> None:
        names = list(names)
        print()
        print(f"  {marker} {title} ({len(names)})")
        print("  " + "-" * 70)
        if not names:
            print("    (none)")
            return
        for name in names:
            if title.startswith("ADDED"):
                entry = current.get(name, {})
                print(f"    + {name}")
                print(f"        size : {_human_size(entry.get('size'))}")
                print(f"        mtime: {_format_mtime(entry.get('mtime'))}")
                print(f"        hash : {get_hash(entry, algorithm)}")
            elif title.startswith("MODIFIED"):
                old_entry = baseline.get(name, {})
                new_entry = current.get(name, {})
                print(f"    ~ {name}")
                print(f"        old hash: {get_hash(old_entry, algorithm)}")
                print(f"        new hash: {get_hash(new_entry, algorithm)}")
                print(f"        size    : {_human_size(old_entry.get('size'))} "
                      f"-> {_human_size(new_entry.get('size'))}")
                print(f"        mtime   : {_format_mtime(old_entry.get('mtime'))} "
                      f"-> {_format_mtime(new_entry.get('mtime'))}")
            elif title.startswith("DELETED"):
                old_entry = baseline.get(name, {})
                print(f"    - {name}")
                print(f"        last known hash : {get_hash(old_entry, algorithm)}")
                print(f"        last known size : {_human_size(old_entry.get('size'))}")
            else:
                print(f"    = {name}")

    print()
    print("=" * 74)
    print("RESULTS".center(74))
    print("=" * 74)

    section("ADDED files", result["added"], "[+]")
    section("MODIFIED files", result["modified"], "[~]")
    section("DELETED files", result["deleted"], "[-]")
    section("UNCHANGED files", result["unchanged"], "[=]")
    if result["skipped"]:
        section("SKIPPED files (no comparable hash)", result["skipped"], "[?]")
    if result.get("unreadable"):
        section("UNREADABLE files (content unknown - NOT reported as deleted)",
                result["unreadable"], "[!]")

    print()
    print("=" * 74)
    if has_changes(result):
        total = len(result["added"]) + len(result["modified"]) + len(result["deleted"])
        print(f"CHANGES DETECTED: {total} change(s) - "
              f"{len(result['added'])} added, {len(result['modified'])} modified, "
              f"{len(result['deleted'])} deleted.")
        print(f"Unchanged files: {len(result['unchanged'])}")
        print("=" * 74)
        return EXIT_CHANGES

    print("No changes detected. Folder integrity verified.")
    print(f"All {len(result['unchanged'])} file(s) match the baseline.")
    print("=" * 74)
    return EXIT_OK


# ---------------------------------------------------------------------------
# WEEK 3: alerts, single scan step and the continuous monitoring loop
# ---------------------------------------------------------------------------

#: Human-readable headers for each change category.
ALERT_TITLES = {
    "added": "ADDED",
    "modified": "MODIFIED",
    "deleted": "DELETED",
}

#: Colour and symbol for each change category.
ALERT_STYLE = {
    "added": ("green", "+"),
    "modified": ("yellow", "~"),
    "deleted": ("red", "-"),
}


def format_alerts(result: Dict[str, list],
                  current: Optional[Dict[str, dict]] = None,
                  baseline: Optional[Dict[str, dict]] = None,
                  algorithm: str = DEFAULT_ALGORITHM,
                  use_colour: bool = False) -> List[str]:
    """Build the coloured terminal alert lines for one scan.

    Returns a list of printable lines (no trailing newlines). Each changed file
    appears on its own line with its **relative path**, so alerts are unambiguous
    when several subfolders are monitored.

    ``current``/``baseline`` are optional; when given, size and hash details are
    appended for added and modified files.
    """
    lines: List[str] = []

    for category in ("added", "modified", "deleted"):
        names = list(result.get(category, []))
        if not names:
            continue

        colour_name, symbol = ALERT_STYLE[category]
        heading = f"[{symbol}] {ALERT_TITLES[category]} ({len(names)})"
        lines.append("")
        lines.append("  " + paint(heading, colour_name, use_colour))

        for name in names:
            alert = f"    {symbol} {name}"
            lines.append("  " + paint(alert, colour_name, use_colour))

            if category == "added" and current is not None:
                entry = current.get(name, {})
                lines.append("      " + paint(
                    f"size: {_human_size(entry.get('size'))}  "
                    f"mtime: {_format_mtime(entry.get('mtime'))}",
                    "grey", use_colour))
            elif category == "modified" and current is not None:
                entry = current.get(name, {})
                lines.append("      " + paint(
                    f"sha256: {get_hash(entry, algorithm)}", "grey", use_colour))
            elif category == "deleted" and baseline is not None:
                entry = baseline.get(name, {})
                lines.append("      " + paint(
                    f"last known sha256: {get_hash(entry, algorithm)}",
                    "grey", use_colour))

    unreadable = result.get("unreadable") or []
    if unreadable:
        lines.append("")
        lines.append("  " + paint(
            f"[!] UNREADABLE ({len(unreadable)}) - not reported as deleted",
            "magenta", use_colour))
        for name in unreadable:
            lines.append("  " + paint(f"    ! {name}", "magenta", use_colour))

    return lines


def print_alerts(result: Dict[str, list],
                 current: Optional[Dict[str, dict]] = None,
                 baseline: Optional[Dict[str, dict]] = None,
                 algorithm: str = DEFAULT_ALGORITHM,
                 use_colour: Optional[bool] = None) -> bool:
    """Print the alerts for one scan. Returns True if anything was reported."""
    if use_colour is None:
        use_colour = supports_colour()

    lines = format_alerts(result, current=current, baseline=baseline,
                          algorithm=algorithm, use_colour=use_colour)
    if not lines:
        return False

    header = paint("FILEWATCH ALERT", "bold", use_colour)
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n{header}  {paint(stamp, 'grey', use_colour)}")
    for line in lines:
        print(line)
    print()
    return True


def log_result(result: Dict[str, list], logger: Optional[logging.Logger] = None) -> None:
    """Write every detected change and every scan problem to the log file."""
    logger = logger or get_logger()

    for category in ("added", "modified", "deleted"):
        for name in result.get(category, []):
            logger.warning("%s file: %s", category.upper(), name)

    for name in result.get("unreadable", []):
        logger.error("Unreadable file (content unknown, not reported as deleted): %s", name)

    for name in result.get("skipped", []):
        logger.debug("No comparable hash for %s (algorithm mismatch?)", name)


def emit_structured_events(result: Dict[str, list],
                           current: Optional[Dict[str, dict]] = None,
                           baseline: Optional[Dict[str, dict]] = None,
                           algorithm: str = DEFAULT_ALGORITHM,
                           source: str = "watch",
                           events_path=None,
                           logger: Optional[logging.Logger] = None) -> int:
    """Write detected changes to ``events.jsonl`` and return how many were written.

    Week 4 enhancement. This runs *in addition to* the unchanged human-readable
    ``filewatch.log``; it never replaces or alters that file.

    Failure policy: **never fatal.** If the JSONL file cannot be written (full
    disk, read-only folder, bad permissions), the problem is logged as a warning
    and monitoring continues. The terminal alerts and ``filewatch.log`` still
    record the change, so an unwritable event file degrades the tool rather
    than breaking it - and the missed records can be recovered from
    ``filewatch.log``.
    """
    if events_path is None:
        return 0

    try:
        # Imported lazily so Week 1-4 commands keep working even if this
        # optional module is missing from someone's checkout.
        import event_logger
    except ImportError as exc:  # pragma: no cover - defensive
        (logger or get_logger()).warning(
            "Structured event logging unavailable (%s); continuing with "
            "filewatch.log only.", exc)
        return 0

    try:
        records = event_logger.events_from_result(
            result, current=current, baseline=baseline,
            algorithm=algorithm, source=source,
        )
    except (ValueError, TypeError) as exc:  # pragma: no cover - defensive
        (logger or get_logger()).warning("Could not build structured events: %s", exc)
        return 0

    if not records:
        return 0

    written, error = event_logger.append_events(records, events_path)
    log = logger or get_logger()
    if error:
        log.warning("Structured event log not updated: %s", error)
    else:
        log.debug("Wrote %d structured event(s) to %s", written, events_path)
    return written


def scan_once(folder,
              baseline: Dict[str, dict],
              algorithm: str = DEFAULT_ALGORITHM,
              ignore: Optional[IgnoreRules] = None,
              root: Optional[Path] = None) -> Tuple[Dict[str, dict], Dict[str, list]]:
    """One monitoring cycle: snapshot the folder and compare it to ``baseline``.

    Returns ``(current_snapshot, comparison_result)``. Errors while reading are
    logged and never raised, so the watch loop can always continue.
    """
    folder_path = Path(folder)
    root = root or folder_path
    unreadable: Set[str] = set()

    try:
        current = build_snapshot(folder_path, algorithm=algorithm,
                                 ignore=ignore, unreadable=unreadable,
                                 report_skipped=False)
    except (OSError, PermissionError) as exc:  # pragma: no cover - defensive
        get_logger().error("Scan failed for %s: %s", folder_path, exc)
        return {}, {"added": [], "modified": [], "deleted": [], "unchanged": [],
                    "skipped": [], "unreadable": []}

    result = compare_snapshots(baseline, current, algorithm=algorithm,
                               unreadable=unreadable, root=root)
    return current, result


def advance_reference(reference: Dict[str, dict],
                      current: Dict[str, dict],
                      result: Dict[str, list]) -> Dict[str, dict]:
    """Move an in-memory reference forward after changes have been alerted.

    This is what stops a watch loop from repeating the *same* alert on every
    cycle. Only the in-memory dictionary is updated - ``baseline.json`` on disk
    is never written by ``watch``, so the approved "never silently replace a
    baseline" rule still holds.

    * ADDED files      -> added to the reference with their current entry,
    * MODIFIED files   -> reference entry replaced by the current one,
    * DELETED files    -> entry removed from the reference,
    * UNREADABLE files -> left untouched (their state is still unknown).

    Returns a new dictionary (the input is not mutated).
    """
    updated = dict(reference)

    for name in result.get("added", []):
        if name in current:
            updated[name] = current[name]
    for name in result.get("modified", []):
        if name in current:
            updated[name] = current[name]
    for name in result.get("deleted", []):
        updated.pop(name, None)

    return updated


def command_watch(folder=DEFAULT_FOLDER,
                  baseline_path=BASELINE_FILENAME,
                  algorithm: str = DEFAULT_ALGORITHM,
                  interval: float = DEFAULT_INTERVAL,
                  log_path=LOG_FILENAME,
                  ignore_path=None,
                  verbose: bool = False,
                  max_scans: Optional[int] = None,
                  iterations: Optional[int] = None,
                  use_colour: Optional[bool] = None,
                  logger: Optional[logging.Logger] = None,
                  alert_once: bool = True,
                  verify_signature: bool = False,
                  require_signature: bool = False,
                  key: Optional[bytes] = None,
                  events_path: Optional[str] = None) -> int:
    """``python main.py watch`` - continuous monitoring until interrupted.

    Behaviour
    ---------
    * loads ``baseline.json`` once and re-scans the folder every ``interval``
      seconds,
    * alerts (coloured) and logs when files are added, modified or deleted,
    * logs scan errors, keeps running, and never reports an unreadable file as
      deleted (the comparison protects those paths),
    * handles ``Ctrl+C`` / ``SIGTERM`` cleanly: no traceback, exit code 130,
    * accepts a ``stop_event``-like hook so tests can run it deterministically.

    Parameters
    ----------
    interval:
        Seconds between scans (must be >= ``MIN_INTERVAL``).
    max_scans / iterations:
        Test hooks - stop after N scans. ``max_scans`` is the current name;
        ``iterations`` is kept as an alias for backward compatibility.
    events_path:
        Week 4 enhanced: where to append structured JSONL events. ``None`` (default for
        library callers) disables it and gives exact Week 1-4 behaviour; the
        ``watch`` command passes ``events.jsonl`` so the CLI gets the feature
        without changing what ``import main`` does. The human-readable
        ``filewatch.log`` is always written, unchanged.
    alert_once:
        ``True`` (default) alerts each change once, then advances an in-memory
        reference so the next scan does not repeat it. ``baseline.json`` is
        never modified. ``False`` keeps comparing with the original baseline
        and re-alerts for as long as the difference exists.
    use_colour:
        ``None`` = auto-detect from the terminal.

    Returns
    -------
    int
        ``EXIT_OK`` when the requested number of scans completed,
        ``EXIT_FAILURE`` for a startup problem, ``EXIT_INTERRUPTED`` after Ctrl+C.
    """
    logger = logger or setup_logging(log_path, verbose=verbose)
    folder_path = Path(folder)
    baseline_target = _resolve_baseline_path(baseline_path)
    limit = max_scans if max_scans is not None else iterations
    if use_colour is None:
        use_colour = supports_colour()

    print("=" * 74)
    print(paint("FILEWATCH - CONTINUOUS MONITORING", "bold", use_colour).center(74))
    print("=" * 74)
    print(f"Folder    : {folder_path}")
    print(f"Baseline  : {baseline_target}")
    print(f"Algorithm : {algorithm.upper().replace('SHA', 'SHA-')}")
    print(f"Interval  : {interval:g} second(s)")
    print(f"Log file  : {log_path}")
    if events_path:
        print(f"Events    : {events_path} (structured JSONL)")

    if interval < MIN_INTERVAL:
        message = (f"Interval must be >= {MIN_INTERVAL:g} seconds (got {interval:g}). "
                   f"Use e.g. --interval 5 for one scan every five seconds.")
        print(f"  [ERROR] {message}", file=sys.stderr)
        logger.error(message)
        return EXIT_FAILURE

    if not folder_path.exists() or not folder_path.is_dir():
        message = f"Monitored folder is missing or not a folder: {folder_path}"
        print(f"  [ERROR] {message}", file=sys.stderr)
        logger.error(message)
        return EXIT_FAILURE

    baseline = load_baseline(baseline_path, verify=verify_signature,
                             require_signature=True if require_signature else None,
                             key=key)
    if baseline is None:
        message = ("No usable baseline - run `python main.py baseline` first. "
                   "Monitoring will not start.")
        print(f"  [ERROR] {message}", file=sys.stderr)
        logger.error(message)
        return EXIT_FAILURE

    ignore_rules = load_ignore_rules(ignore_path, folder=folder_path)
    print(f"Ignore    : {len(ignore_rules)} pattern(s)"
          + (f" from {ignore_rules.source}" if ignore_rules.source else " (built-in only)"))
    print("-" * 74)
    print("Press Ctrl+C to stop.")
    print(f"Baseline loaded: {len(baseline)} file(s).")
    print("=" * 74)
    logger.info(
        "Watch started: folder=%s algorithm=%s interval=%ss files=%d patterns=%d",
        folder_path, algorithm, interval, len(baseline), len(ignore_rules),
    )

    # The in-memory comparison reference. It starts as the loaded baseline and
    # may move forward (see alert_once) without ever touching baseline.json.
    reference: Dict[str, dict] = dict(baseline)

    scans = 0
    exit_code = EXIT_OK
    quiet_rounds = 0

    try:
        while True:
            scans += 1
            current, result = scan_once(folder_path, reference, algorithm=algorithm,
                                        ignore=ignore_rules, root=folder_path)

            stamp = datetime.now().strftime("%H:%M:%S")
            if has_changes(result) or result.get("unreadable"):
                log_result(result, logger)
                print_alerts(result, current=current, baseline=baseline,
                             algorithm=algorithm, use_colour=use_colour)
                # Week 4 enhanced: mirror the same changes into events.jsonl. The
                # ORIGINAL baseline supplies old_hash (the true previous
                # state), not the moving in-memory reference.
                emit_structured_events(result, current=current, baseline=baseline,
                                       algorithm=algorithm, source="watch",
                                       events_path=events_path, logger=logger)
                if alert_once:
                    # Keep the original baseline for reporting "last known"
                    # hashes, but move the comparison reference forward so the
                    # same change is not reported again next cycle.
                    reference = advance_reference(reference, current, result)
            else:
                quiet_rounds += 1
                logger.info("Scan %d: no changes (%d file(s))", scans, len(current))
                print(paint(f"[{stamp}] scan {scans}: no changes "
                            f"({len(current)} file(s) monitored)", "grey", use_colour))

            if limit is not None and scans >= limit:
                logger.info("Stopping after %d requested scan(s).", scans)
                break

            time.sleep(interval)

    except KeyboardInterrupt:
        # Ctrl+C: clean shutdown, no traceback.
        logger.info("Watch interrupted by user after %d scan(s).", scans)
        print(f"\n{paint('[stopped]', 'yellow', use_colour)} "
              f"Monitoring stopped by user after {scans} scan(s).")
        print(f"Log written to {log_path}.")
        exit_code = EXIT_INTERRUPTED
    except (OSError, PermissionError) as exc:
        logger.exception("Watch loop stopped by an OS error")
        print(f"  [ERROR] Monitoring stopped: {exc}", file=sys.stderr)
        exit_code = EXIT_FAILURE
    finally:
        logger.info("Watch ended: scans=%d exit_code=%d", scans, exit_code)

    return exit_code


# ---------------------------------------------------------------------------
# Command-line interface
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Build and parse the command-line arguments.

    Two styles are supported:

    * Week 1 style (no command):
          python main.py
          python main.py --demo
          python main.py --algorithm sha1
    * Week 2 commands:
          python main.py baseline
          python main.py check

    ``argparse`` handles ``--help``, unknown options and missing values. Only
    the algorithm needs extra validation, because argparse cannot express
    "these two lowercase strings only" cleanly with a helpful message.
    """
    parser = argparse.ArgumentParser(
        prog="main.py",
        description=(
            "FileWatch - a local file integrity monitor. Hash the files in "
            "test_folder (SHA-256 by default), save a baseline and detect "
            "added, modified and deleted files."
        ),
        epilog=(
            "Examples:\n"
            "  python main.py                     Week 1: hash every file now\n"
            "  python main.py --demo              Week 1: avalanche demonstration\n"
            "  python main.py --algorithm sha1    Week 1: use SHA-1 instead\n"
            "  python main.py baseline            Week 2: save baseline.json\n"
            "  python main.py check               Week 2: compare with baseline.json\n"
            "  python main.py watch               Week 3: monitor continuously\n"
            "  python main.py watch --interval 5  Week 3: scan every 5 seconds\n"
            "  python main.py watch --once        Week 3: one scan, then exit\n"
            "  python main.py check --algorithm sha1\n"
            "\n"
            "Exit codes: 0 = OK / no changes, 1 = error, 2 = changes found or "
            "bad arguments."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # --- Week 2 commands (optional, so plain `python main.py` still works) ---
    parser.add_argument(
        "command",
        nargs="?",
        choices=["baseline", "check", "watch", "keygen",
                 "import-events", "query-events"],
        default=None,
        help=("'baseline' saves a hash snapshot, 'check' compares against it, "
              "'watch' monitors continuously until interrupted, "
              "'import-events' loads events.jsonl into SQLite, "
              "'query-events' filters stored events"),
    )

    parser.add_argument(
        "--demo",
        action="store_true",
        help="also run the safe one-character-change demonstration",
    )
    parser.add_argument(
        "--algorithm",
        default=DEFAULT_ALGORITHM,
        type=str.lower,  # accepts SHA256, Sha256, sha256 ...
        metavar="NAME",
        help="hashing algorithm: sha256 (default) or sha1",
    )
    parser.add_argument(
        "--folder",
        default=str(DEFAULT_FOLDER),
        metavar="PATH",
        help="folder to monitor (default: test_folder next to main.py)",
    )
    parser.add_argument(
        "--baseline",
        default=BASELINE_FILENAME,
        metavar="PATH",
        help=f"baseline file to write/read (default: {BASELINE_FILENAME} at the project root)",
    )

    # --- Week 3: continuous monitoring options -----------------------------
    parser.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_INTERVAL,
        metavar="SECONDS",
        help=f"seconds between scans for 'watch' (default: {DEFAULT_INTERVAL:g})",
    )
    parser.add_argument(
        "--log",
        default=LOG_FILENAME,
        metavar="PATH",
        help=f"log file for 'watch' (default: {LOG_FILENAME} at the project root)",
    )
    parser.add_argument(
        "--ignore",
        default=None,
        metavar="PATH",
        help=f"ignore file with patterns (default: {IGNORE_FILENAME})",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="'watch': perform a single scan then exit (useful for cron/CI)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="write DEBUG-level detail to the log file",
    )
    # --- Week 4 (stretch): HMAC baseline signing ---------------------------
    parser.add_argument(
        "--sign",
        action="store_true",
        help="'baseline': sign the baseline with HMAC-SHA256",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="'check'/'watch': verify the baseline signature before using it",
    )
    parser.add_argument(
        "--require-signature",
        action="store_true",
        help="'check'/'watch': refuse an unsigned baseline (implies --verify)",
    )
    parser.add_argument(
        "--key-file",
        default=None,
        metavar="PATH",
        help=f"HMAC key file, mode 0600 (default: ${HMAC_KEY_FILE_ENV})",
    )
    parser.add_argument(
        "--out",
        default=None,
        metavar="PATH",
        help="'keygen': also write the new key to this file (mode 0600)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="'keygen': overwrite an existing key file",
    )
    # --- Week 4 enhanced: structured events + SQLite --------------------------------
    parser.add_argument(
        "--events",
        default=None,
        metavar="PATH",
        help=(f"'watch': structured JSONL event file "
              f"(default: {EVENTS_FILENAME} next to the log file)"),
    )
    parser.add_argument(
        "--db",
        default="filewatch.db",
        metavar="PATH",
        help="'import-events'/'query-events': SQLite database (default: filewatch.db)",
    )
    parser.add_argument(
        "--start",
        default=None,
        metavar="DATE",
        help="'query-events': inclusive start date/time, e.g. 2026-11-01",
    )
    parser.add_argument(
        "--end",
        default=None,
        metavar="DATE",
        help="'query-events': inclusive end date/time, e.g. 2026-11-30",
    )
    parser.add_argument(
        "--type",
        dest="event_type",
        default=None,
        choices=["ADDED", "MODIFIED", "DELETED"],
        help="'query-events': only this event type",
    )
    parser.add_argument(
        "--path",
        default=None,
        metavar="TEXT",
        help="'query-events': only paths containing this text",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        metavar="N",
        help="'query-events': maximum rows to show (default: 20)",
    )
    parser.add_argument(
        "--repeat-alerts",
        action="store_true",
        help="'watch': re-alert every cycle while a change persists "
             "(default: alert each change once)",
    )

    args = parser.parse_args(argv)

    # An explicit --key-file is exported so resolve_hmac_key() uses it without
    # threading another parameter through every command.
    if getattr(args, "key_file", None):
        os.environ[HMAC_KEY_FILE_ENV] = str(args.key_file)

    if args.algorithm not in SUPPORTED_ALGORITHMS:
        parser.error(
            f"unsupported algorithm '{args.algorithm}'. "
            f"Choose one of: {', '.join(SUPPORTED_ALGORITHMS)}"
        )

    return args


def main(argv: Optional[List[str]] = None) -> int:
    """Program entry point. Dispatches to the right command, returns an exit code."""
    args = parse_args(argv)

    # Resolve the folder relative to this script, not the current directory,
    # so `python /some/path/main.py` behaves the same from anywhere.
    folder = Path(args.folder)
    if not folder.is_absolute():
        folder = Path(__file__).resolve().parent / folder

    # --- Week 2 commands ---------------------------------------------------
    if args.command == "keygen":
        return command_keygen(output_path=args.out, force=args.force)
    if args.command == "baseline":
        return command_baseline(folder, baseline_path=args.baseline,
                                algorithm=args.algorithm, ignore_path=args.ignore,
                                sign=args.sign)
    if args.command == "check":
        return command_check(folder, baseline_path=args.baseline,
                             algorithm=args.algorithm, ignore_path=args.ignore,
                             verify_signature=args.verify or args.require_signature,
                             require_signature=args.require_signature)
    if args.command == "import-events":
        return command_import_events(events_path=resolve_events_path(args.events, args.log),
                                     db_path=args.db)
    if args.command == "query-events":
        return command_query_events(db_path=args.db, start=args.start,
                                    end=args.end, event_type=args.event_type,
                                    path=args.path, limit=args.limit)
    if args.command == "watch":
        return command_watch(folder, baseline_path=args.baseline,
                             algorithm=args.algorithm, interval=args.interval,
                             log_path=args.log, ignore_path=args.ignore,
                             verbose=args.verbose,
                             max_scans=1 if args.once else None,
                             alert_once=not args.repeat_alerts,
                             verify_signature=args.verify or args.require_signature,
                             require_signature=args.require_signature,
                             events_path=resolve_events_path(args.events, args.log))

    # --- Week 1 behaviour: hash everything now, optionally demonstrate ------
    results = monitor_folder(folder, algorithm=args.algorithm)

    if args.demo:
        demonstrate_avalanche(folder, algorithm=args.algorithm)

    print()
    if results:
        print(f"Done. {len(results)} file(s) hashed with "
              f"{args.algorithm.upper().replace('SHA', 'SHA-')}.")
    else:
        print("Done. Nothing to hash.")
    print("Tip: `python main.py baseline` saves a snapshot, "
          "`python main.py check` compares against it.")
    return EXIT_OK


# ---------------------------------------------------------------------------
# WEEK 4 ENHANCED: SQLite commands
# ---------------------------------------------------------------------------

def resolve_events_path(events_path: Optional[str] = None,
                       log_path: Optional[str] = None) -> str:
    """Work out where the structured event file lives.

    Priority: an explicit ``--events`` value, otherwise ``events.jsonl`` in the
    same directory as the log file (so ``--log /tmp/x/fw.log`` puts the events
    beside it instead of surprising the caller). Default CLI use lands both at
    the project root, which is what the README documents.
    """
    if events_path:
        return str(events_path)
    if log_path:
        parent = Path(log_path).parent
        if str(parent) not in ("", "."):
            return str(parent / EVENTS_FILENAME)
    return EVENTS_FILENAME


def command_import_events(events_path: Optional[str] = None,
                          db_path: Optional[str] = None) -> int:
    """``python main.py import-events`` - load events.jsonl into SQLite.

    Safe to run repeatedly and safe to run against a file that does not exist
    yet: duplicates are skipped, missing/empty input is reported, and existing
    rows are never deleted.
    """
    events_file = Path(events_path) if events_path else Path(EVENTS_FILENAME)
    db_file = Path(db_path) if db_path else Path("filewatch.db")

    try:
        import database
    except ImportError as exc:
        print(f"Error: SQLite support unavailable ({exc}).")
        return EXIT_FAILURE

    try:
        summary = database.import_jsonl(events_file, db_file)
    except (OSError, ValueError) as exc:
        print(f"Error: could not import events: {exc}")
        return EXIT_FAILURE

    print(f"Events file: {summary['source']}")
    print(f"Database   : {summary['database']}")
    if summary["missing"]:
        print("Events file not found - nothing to import. "
              "Run `python main.py watch` first to generate it.")
        return EXIT_OK

    print(f"Imported   : {summary['inserted']} new event(s)")
    print(f"Duplicates : {summary['duplicates']} already present (skipped)")
    if summary["rejected"]:
        print(f"Rejected   : {summary['rejected']} invalid record(s)")
    if summary["malformed_lines"]:
        print(f"Malformed  : {summary['malformed_lines']} line(s) could not be parsed")
        for problem in summary["parse_errors"][:5]:  # type: ignore[index]
            print(f"  - {problem}")
        if len(summary["parse_errors"]) > 5:  # type: ignore[arg-type]
            print(f"  ... and {len(summary['parse_errors']) - 5} more")

    status = database.database_status(db_file)
    if status.get("error"):
        print(f"Warning: {status['error']}")
        return EXIT_FAILURE
    print(f"Total in DB: {status['events']} event(s)")
    if status["first"]:
        print(f"Range      : {status['first']} .. {status['last']}")
    return EXIT_OK


def command_query_events(db_path: Optional[str] = None,
                         start: Optional[str] = None,
                         end: Optional[str] = None,
                         event_type: Optional[str] = None,
                         path: Optional[str] = None,
                         source: Optional[str] = None,
                         limit: int = 20) -> int:
    """``python main.py query-events`` - filter stored events.

    Filters combine with AND. Dates are inclusive and interpreted as UTC days
    when only a date is given.
    """
    db_file = Path(db_path) if db_path else Path("filewatch.db")
    try:
        import database
    except ImportError as exc:
        print(f"Error: SQLite support unavailable ({exc}).")
        return EXIT_FAILURE

    if not db_file.exists():
        print(f"No database at {db_file}.")
        print("Create it with: python main.py import-events")
        return EXIT_OK

    try:
        rows = database.query_events(
            db_file, start_date=start, end_date=end, event_type=event_type,
            path=path, source=source, limit=limit,
        )
        counts = database.count_by_type(
            db_file, start_date=start, end_date=end,
            event_type=event_type, path=path, source=source,
        )
    except ValueError as exc:
        print(f"Error: {exc}")
        return EXIT_FAILURE
    except Exception as exc:  # noqa: BLE001 - sqlite3.Error and friends
        print(f"Error: could not query database: {exc}")
        return EXIT_FAILURE

    print(f"Database: {db_file}")
    active = [f"{name}={value}" for name, value in
              (("start", start), ("end", end), ("type", event_type),
               ("path", path), ("source", source)) if value]
    print(f"Filters : {', '.join(active) if active else 'none'}")
    print(f"Matches : {len(rows)} shown (limit {limit}) | "
          f"ADDED {counts['ADDED']}, MODIFIED {counts['MODIFIED']}, "
          f"DELETED {counts['DELETED']}")

    if not rows:
        print("No matching events.")
        return EXIT_OK

    header = f"{'Timestamp':<21}{'Event':<10}{'Path':<34}{'Source':<8}"
    print()
    print(header)
    print("-" * len(header))
    for row in rows:
        path_text = str(row["path"])
        if len(path_text) > 32:
            path_text = "..." + path_text[-29:]
        print(f"{row['timestamp']:<21}{row['event_type']:<10}"
              f"{path_text:<34}{row['source']:<8}")
    return EXIT_OK


def _install_sigterm_handler() -> None:
    """Treat SIGTERM like Ctrl+C so `kill` also shuts down cleanly.

    Only SIGTERM is touched (SIGINT already raises KeyboardInterrupt), and only
    on platforms that provide it. Terminals do not allow signal handlers from
    non-main threads, so failure to install is ignored.
    """
    term_signal = getattr(signal, "SIGTERM", None)
    if term_signal is None:
        return
    try:
        def _raise_interrupt(signum, frame):  # noqa: ANN001 - signal signature
            raise KeyboardInterrupt

        signal.signal(term_signal, _raise_interrupt)
    except (ValueError, OSError, AttributeError):  # pragma: no cover
        pass


if __name__ == "__main__":
    _install_sigterm_handler()
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        # Clean exit: no traceback for a normal interruption.
        print("\nInterrupted by user.", file=sys.stderr)
        sys.exit(EXIT_INTERRUPTED)
