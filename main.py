#!/usr/bin/env python3
"""
SHA-256 File Integrity Checker
==============================

A small, beginner-friendly educational tool that:

1. Calculates cryptographic hashes (SHA-256 by default, SHA-1 optional)
   for every regular file inside a single local folder called ``test_folder``.
2. Demonstrates the "avalanche effect": changing exactly one character in a
   file produces a completely different hash.

Scope and safety
----------------
This program ONLY reads files inside the ``test_folder`` directory that sits
next to this script. It does not scan other directories, does not touch the
network, and never modifies the original sample files. The demonstration mode
works on a temporary copy that is deleted automatically.

The legal/ethical notice that applies to this project:

    Scanning or attacking systems you do not own or have written permission
    to test is illegal. This tool only monitors your own test folder.

Standard library only - no third-party dependencies.
Tested with Python 3.9+ on Linux, macOS and Windows.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sys
from pathlib import Path
from typing import List, Optional

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

    sample_files = list_regular_files(folder_path)
    text_samples = [item for item in sample_files if item.suffix.lower() in (".txt", ".md")]

    if not text_samples:
        print("  Demonstration skipped: no sample text file found in", folder_path)
        print("=" * 74)
        return None

    original_path = text_samples[0]
    temp_path = folder_path / f"{DEMO_PREFIX}{original_path.stem}_{os.getpid()}.txt"

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
# Command-line interface
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Build and parse the command-line arguments.

    ``argparse`` handles ``--help``, unknown options and missing values. Only
    the algorithm needs extra validation, because argparse cannot express
    "these two lowercase strings only" cleanly with a helpful message.
    """
    parser = argparse.ArgumentParser(
        prog="main.py",
        description=(
            "Calculate SHA-256 (or SHA-1) hashes for the files in test_folder "
            "and optionally demonstrate the avalanche effect."
        ),
        epilog=(
            "Examples:\n"
            "  python main.py\n"
            "  python main.py --demo\n"
            "  python main.py --algorithm sha1\n"
            "  python main.py --algorithm sha256 --demo"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
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

    args = parser.parse_args(argv)

    if args.algorithm not in SUPPORTED_ALGORITHMS:
        parser.error(
            f"unsupported algorithm '{args.algorithm}'. "
            f"Choose one of: {', '.join(SUPPORTED_ALGORITHMS)}"
        )

    return args


def main(argv: Optional[List[str]] = None) -> int:
    """Program entry point. Returns a process exit code (0 = success)."""
    args = parse_args(argv)

    # Resolve the folder relative to this script, not the current directory,
    # so `python /some/path/main.py` behaves the same from anywhere.
    folder = Path(args.folder)
    if not folder.is_absolute():
        folder = Path(__file__).resolve().parent / folder

    results = monitor_folder(folder, algorithm=args.algorithm)

    if args.demo:
        demonstrate_avalanche(folder, algorithm=args.algorithm)

    print()
    if results:
        print(f"Done. {len(results)} file(s) hashed with "
              f"{args.algorithm.upper().replace('SHA', 'SHA-')}.")
    else:
        print("Done. Nothing to hash.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.", file=sys.stderr)
        sys.exit(130)
