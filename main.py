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
import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

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


def walk_regular_files(folder) -> Tuple[List[Path], List[str]]:
    """Recursively collect regular files under ``folder``.

    Returns ``(files, skipped)`` where ``files`` is a list of paths and
    ``skipped`` is a list of human-readable notes about entries that were
    deliberately not hashed (symbolic links, directories, folders we were not
    allowed to read).

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

    for dir_path, dir_names, file_names in os.walk(root, followlinks=False):
        current_dir = Path(dir_path)

        # Prune symlinked directories *before* os.walk descends into them.
        # (os.walk with followlinks=False already refuses to follow them; this
        # keeps the reported "skipped" list accurate and the intent explicit.)
        kept_dirs: List[str] = []
        for name in sorted(dir_names):
            candidate = current_dir / name
            if candidate.is_symlink():
                skipped.append(f"{_relative_key(candidate, root)} (symbolic link to a directory)")
            else:
                kept_dirs.append(name)
        dir_names[:] = kept_dirs

        for name in sorted(file_names):
            candidate = current_dir / name
            if name.startswith(DEMO_PREFIX):
                continue  # temporary demo copy - never part of a baseline
            if candidate.is_symlink():
                skipped.append(f"{_relative_key(candidate, root)} (symbolic link)")
                continue
            if not candidate.is_file():
                continue  # sockets, pipes, devices ...
            files.append(candidate)

    files.sort(key=lambda item: _relative_key(item, root).lower())
    return files, skipped


def build_snapshot(folder, algorithm: str = DEFAULT_ALGORITHM) -> Dict[str, dict]:
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
    """
    root = Path(folder)
    files, skipped = walk_regular_files(root)
    snapshot: Dict[str, dict] = {}

    for file_path in files:
        digest = hash_file(file_path, algorithm=algorithm)
        if digest is None:
            # hash_file() already printed a specific [ERROR] line.
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
        for note in skipped:
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
                      algorithm: str = DEFAULT_ALGORITHM) -> Dict[str, list]:
    """Compare two snapshots and classify every difference.

    Pure dictionary/set arithmetic - no I/O - which makes it trivial to test:

        added     = current keys - baseline keys
        deleted   = baseline keys - current keys
        common    = current keys & baseline keys
        modified  = common keys whose digest differs
        unchanged = common keys whose digest is identical

    Returns a dictionary with the five lists (sorted for stable output):
    ``added``, ``modified``, ``deleted``, ``unchanged`` and ``skipped``
    (files present in both but lacking a digest for the chosen algorithm).

    A file is MODIFIED only when its content hash changed. A new timestamp or
    size with an identical hash is *not* a modification.
    """
    baseline_keys = set(baseline)
    current_keys = set(current)

    added_files = current_keys - baseline_keys
    deleted_files = baseline_keys - current_keys
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

    return {
        "added": sorted(added_files),
        "modified": modified_files,
        "deleted": sorted(deleted_files),
        "unchanged": unchanged_files,
        "skipped": sorted(skipped_files),
    }


def has_changes(result: Dict[str, list]) -> bool:
    """True if the comparison found any added, modified or deleted file."""
    return bool(result["added"] or result["modified"] or result["deleted"])


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
                  algorithm: str = DEFAULT_ALGORITHM) -> Optional[Path]:
    """Write ``snapshot`` to ``baseline.json`` as readable, indented JSON.

    The file is written by ``json.dump(..., indent=2)`` so it diffs cleanly in
    Git. A small header records the schema version, algorithm, monitored folder
    and creation time - handy when a baseline is read months later.

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


def load_baseline(baseline_path=BASELINE_FILENAME) -> Optional[Dict[str, dict]]:
    """Load a baseline file and return its ``files`` mapping.

    Handles the realistic failure modes without crashing:

    * file missing            -> message + ``None``
    * permission / I/O error  -> message + ``None``
    * invalid JSON            -> message + ``None``
    * wrong overall structure -> message + ``None``
    * legacy flat baselines   -> accepted (``{"file1.txt": "abc..."}``)
    """
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

def command_baseline(folder=DEFAULT_FOLDER,
                     baseline_path=BASELINE_FILENAME,
                     algorithm: str = DEFAULT_ALGORITHM) -> int:
    """``python main.py baseline`` - create or update baseline.json.

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
    snapshot = build_snapshot(folder_path, algorithm=algorithm)

    if not snapshot:
        print("  Warning: no readable regular files were found.")
        print("  Writing an empty baseline anyway (delete it if that was a mistake).")

    written = save_baseline(snapshot, baseline_path=baseline_path,
                            folder=folder_path, algorithm=algorithm)
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
                  algorithm: str = DEFAULT_ALGORITHM) -> int:
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

    baseline = load_baseline(baseline_path)
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

    current = build_snapshot(folder_path, algorithm=algorithm)
    result = compare_snapshots(baseline, current, algorithm=algorithm)

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
        choices=["baseline", "check"],
        default=None,
        help="'baseline' saves a hash snapshot, 'check' compares against it",
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

    args = parser.parse_args(argv)

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
    if args.command == "baseline":
        return command_baseline(folder, baseline_path=args.baseline,
                                algorithm=args.algorithm)
    if args.command == "check":
        return command_check(folder, baseline_path=args.baseline,
                             algorithm=args.algorithm)

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


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.", file=sys.stderr)
        sys.exit(130)
