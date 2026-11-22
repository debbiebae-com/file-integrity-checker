# SHA-256 File Integrity Checker

A small, beginner-friendly Python project that shows how **cryptographic hashing**
detects changes to files. It hashes every file inside a local `test_folder` with
SHA-256 (SHA-1 optional) and demonstrates the **avalanche effect**: change one
character and the entire hash changes.

> ### 📌 LEGAL AND ETHICAL NOTICE
>
> Scanning or attacking systems you do not own or have written permission to test is illegal. This tool only monitors your own test folder.
>
> This project is an **educational local file integrity demonstration**. It is **not** a
> network scanner, port scanner, vulnerability scanner, or penetration-testing tool.
> It never opens a socket, never touches the network, and never reads anything
> outside its own `test_folder` directory.

---

## Table of Contents

1. [Project overview](#1-project-overview)
2. [Objectives](#2-objectives)
3. [Features](#3-features)
4. [Technologies used](#4-technologies-used)
5. [Requirements](#5-requirements)
6. [Project directory structure](#6-project-directory-structure)
7. [Installation](#7-installation)
8. [Usage — step by step](#8-usage--step-by-step)
9. [Command-line examples](#9-command-line-examples)
10. [How SHA-256 works](#10-how-sha-256-works)
11. [SHA-1 and why SHA-256 is preferred](#11-sha-1-and-why-sha-256-is-preferred)
12. [The avalanche effect](#12-the-avalanche-effect)
13. [Why one changed character changes the whole hash](#13-why-one-changed-character-changes-the-whole-hash)
14. [How 4096-byte chunked reading works](#14-how-4096-byte-chunked-reading-works)
15. [Error handling](#15-error-handling)
16. [Running the automated tests](#16-running-the-automated-tests)
17. [Manual hash verification](#17-manual-hash-verification)
18. [Troubleshooting](#18-troubleshooting)
19. [License and responsible use](#19-license-and-responsible-use)

---

## 1. Project overview

A **hash** is a fixed-length fingerprint of data. Feed any file to a hash
function and you get back a short string, for example:

```
file1.txt   ae510d7cd737086c15f672c3e47d6d801d7de14a4b6767307229ce674d039026
file2.txt   9205ab020474954eff2177c6c6b7f114c6e1aca87cf690fe4496486b9b5b3df3
```

Hashing is the foundation of **file integrity monitoring (FIM)**. You record a
file's hash when you know the file is trustworthy (a *baseline*). Later you hash
the file again and compare. Same hash → same bytes → nothing changed. Different
hash → the file was modified, corrupted, or replaced.

This project turns that idea into a working command-line tool you can read,
run, and test in a few minutes.

## 2. Objectives

By reading and running this project you should be able to:

* Explain what a cryptographic hash function is and what makes it useful.
* Compute SHA-256 and SHA-1 digests in Python with `hashlib`.
* Hash large files safely by reading them in 4096-byte chunks.
* Recognise why a one-character file change produces a completely different hash.
* Build a baseline-and-compare workflow for detecting file tampering.
* Write and run automated tests (`unittest`) including mocks and temporary folders.
* Understand why SHA-1 is deprecated and SHA-256 is preferred.

## 3. Features

| Feature | Description |
|---|---|
| SHA-256 hashing | Default algorithm, 64-hex-character digests |
| SHA-1 hashing | Optional, `--algorithm sha1`, shown for comparison |
| Folder monitoring | Hashes every regular file directly inside `test_folder` |
| Directory skipping | Sub-folders are never entered (no recursion) |
| Symbolic link skipping | Links are skipped so the tool cannot follow paths outside the folder |
| Chunked reading | 4096 bytes per read, so memory use stays flat on huge files |
| Safe demonstration | `--demo` copies a file, changes one character, compares hashes, deletes the copy |
| Bulletproof error handling | Missing, unreadable, or broken files are reported, never fatal |
| Argument validation | Clear `argparse` errors for unsupported algorithms |
| 36 automated tests | Correctness, safety, cleanup, boundary and CLI behaviour |
| Zero dependencies | Python standard library only |

## 4. Technologies used

* **Python 3.9+** (tested on Python 3.13)
* **`hashlib`** — SHA-256 / SHA-1 digests
* **`pathlib`** — safe, cross-platform path handling
* **`argparse`** — command-line interface
* **`shutil`, `os`** — copying and cleaning up the temporary file
* **`unittest` + `unittest.mock`** — automated testing
* **`tempfile`** — isolated temporary folders for the tests

No third-party packages. Nothing to `pip install`.

## 5. Requirements

* Python **3.9 or newer** (`python3 --version`)
* Any operating system: Linux, macOS, or Windows
* Write permission inside the project folder (only needed for `--demo`)

## 6. Project directory structure

```
file-integrity-checker/
│
├── main.py               # The hashing tool and CLI
├── README.md             # This file
├── test_main.py          # 36 automated tests (unittest)
├── .gitignore            # Keeps caches and OS junk out of Git
│
└── test_folder/          # The only folder this tool ever reads
    ├── file1.txt
    ├── file2.txt
    ├── file3.txt
    ├── file4.txt
    ├── file5.txt
    ├── file6.txt
    ├── file7.txt
    └── file8.txt
```

## 7. Installation

The project has no dependencies; "installation" is just unpacking it.

```bash
# 1. Unzip the archive
unzip file-integrity-checker.zip

# 2. Enter the project folder
cd file-integrity-checker

# 3. Check your Python version (3.9+ required)
python3 --version
```

On Windows, use `python` instead of `python3`:

```cmd
python --version
```

Nothing else is required — no virtual environment, no `requirements.txt`,
no `pip install`.

## 8. Usage — step by step

1. **Unzip** the archive and `cd file-integrity-checker`.
2. **Run the basic scan**: `python3 main.py`.
   You will see the eight sample files with their SHA-256 digests.
3. **Run the demonstration**: `python3 main.py --demo`.
   The tool hashes `file1.txt`, creates a temporary copy inside `test_folder`,
   changes exactly one character (`Alpha` → `Blpha`), hashes the copy, prints the
   comparison, and deletes the copy. `file1.txt` itself is never written to.
4. **Try SHA-1**: `python3 main.py --algorithm sha1`.
   Note that digests are now 40 characters instead of 64.
5. **Run the tests**: `python3 -m unittest -v` (or `python3 test_main.py`).
6. **Experiment**: edit a file in `test_folder`, run `python3 main.py` again, and
   watch the hash for that file change while the others stay the same.
7. **Make your own baseline**: save the output and compare it later:

   ```bash
   python3 main.py > baseline.txt
   # ...do something that might change your files...
   python3 main.py > current.txt
   diff baseline.txt current.txt
   ```

## 9. Command-line examples

```bash
# Normal SHA-256 folder scan (default)
python3 main.py

# Scan + the safe one-character-change demonstration
python3 main.py --demo

# Use SHA-1 instead of SHA-256
python3 main.py --algorithm sha1

# Explicitly select SHA-256 (the default)
python3 main.py --algorithm sha256

# Combine options
python3 main.py --algorithm sha1 --demo

# Monitor a different folder (still limited to a single folder)
python3 main.py --folder test_folder

# Show help
python3 main.py --help

# Unsupported algorithm -> helpful error, exit code 2
python3 main.py --algorithm md5
# usage: main.py [-h] [--demo] [--algorithm NAME] [--folder PATH]
# main.py: error: unsupported algorithm 'md5'. Choose one of: sha256, sha1
```

Windows equivalents:

```cmd
python main.py
python main.py --demo
python main.py --algorithm sha1
```

### Example output

```
==========================================================================
                      SHA-256 FILE INTEGRITY CHECKER
==========================================================================
Folder    : /home/user/file-integrity-checker/test_folder
Algorithm : SHA-256
--------------------------------------------------------------------------
  file1.txt        ae510d7cd737086c15f672c3e47d6d801d7de14a4b6767307229ce674d039026
  file2.txt        9205ab020474954eff2177c6c6b7f114c6e1aca87cf690fe4496486b9b5b3df3
  ...
--------------------------------------------------------------------------
Files hashed: 8 of 8 found
==========================================================================
```

## 10. How SHA-256 works

**SHA-256** (Secure Hash Algorithm, 256-bit) belongs to the **SHA-2 family**,
published by NIST in 2001. It takes an input of any length and returns a
**256-bit** digest — 32 bytes, written as **64 hexadecimal characters**.

The process, in outline:

1. **Padding.** The message is padded so its length is a multiple of 512 bits.
   The padding encodes the original message length, so different messages cannot
   pad into one another.
2. **Block processing.** The padded message is split into 512-bit blocks. Each
   block is expanded into a schedule of 64 32-bit words.
3. **Compression.** Every block is fed through 64 rounds of bitwise operations
   (AND, OR, XOR, NOT, rotations, additions modulo 2³²) that mix the block with
   the running state. Each round uses a distinct constant.
4. **Chaining.** The 256-bit result of one block becomes the starting state for
   the next block. The final state is the digest.

Properties that matter in practice:

| Property | Meaning | Why you care |
|---|---|---|
| **Deterministic** | The same input always gives the same digest | You can compare digests reliably |
| **Fixed size** | 1 byte or 100 GB → always 64 hex characters | Easy to store and compare |
| **One-way (preimage resistant)** | You cannot rebuild the file from the digest | The digest leaks nothing useful |
| **Avalanche effect** | A tiny input change alters ~half the output bits | Tampering cannot hide |
| **Collision resistant** | Finding two files with one digest is infeasible | Two different files can't pass as the same |

## 11. SHA-1 and why SHA-256 is preferred

**SHA-1** produces a **160-bit** digest (40 hex characters). It was designed by
the NSA and published in 1995 and was once ubiquitous in certificates and
version control.

SHA-1 is **no longer safe**, because it is vulnerable to **collisions**: two
different inputs that produce the same digest. The published attacks progressed
from theoretical (2005) to practical *chosen-prefix collisions* (SHAttered, 2017),
which let attackers craft two different files sharing one SHA-1 digest. Broken
hash functions destroy the guarantee an integrity checker depends on. SHA-1 is
still included in this project only so you can compare it side by side.

**SHA-256 is preferred** because:

* It belongs to the **SHA-2 family**, which has no practical collisions.
* Its **256-bit digest** makes brute-force and collision attacks far harder
  (a generic collision search would need roughly 2¹²⁸ operations).
* It is the algorithm behind TLS certificates, code signing, Git, package
  managers, and file-integrity tools today.
* It is a drop-in replacement in practice: `hashlib.sha256()` instead of
  `hashlib.sha1()`.

**Rule of thumb:** use SHA-256 (or SHA-3) for integrity. Use SHA-1 only to
verify an existing legacy system, never for new security work.

## 12. The avalanche effect

The **avalanche effect** is the property that a minimal change in the input
produces a large, unpredictable change in the output. In an ideal hash function,
every output bit depends on every input bit, so flipping one input bit flips each
output bit with roughly 50% probability.

In practice a SHA-256 comparison looks like this:

```
One changed character:  'A'  ->  'B'

Original:  ae510d7c d737086c 15f672c3 e47d6d80 1d7de14a 4b676730 7229ce67 4d039026
Modified:  4b141f0b 1911d7e9 94cbe398 a80b6035 756e41a8 c5c8f152 4a09ed7c 9ae5c163
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
           61 of 64 hex digits differ — there is no visible pattern or "small change"
```

You cannot tell from the two digests *where* the file changed, or how much. That
is precisely what makes hashing useful: any change, however small and however
carefully hidden, is fully visible as a mismatched digest.

## 13. Why one changed character changes the whole hash

The digest is not a stored summary of the input — it is the **final state of a
long chain of bit mixing**.

1. The changed character sits in one 512-bit block. Because that block's bytes
   feed the 64-round compression function, *every* bit of that block influences
   *every* bit of the block's output state.
2. That 256-bit output state is the **starting state of the next block**. So one
   altered character randomises the hashing of all subsequent blocks too — a
   single-bit change propagates through the whole file's processing.
3. The finalisation step mixes the last state once more, so the tail of the digest
   is as scrambled as the head.

There is no "undo" and no locality: nothing in the algorithm lets a small input
difference stay a small output difference. That is a deliberate design goal
(called diffusion), and it is why integrity checks catch even a single flipped
character — a replaced `A` with `B`, a changed digit, an extra trailing space, a
line ending switched from `\n` to `\r\n`.

> A single changed character also changes the file **length** metadata, so
> hash-based detection is unaffected by whether the byte count happens to stay
> the same.

## 14. How 4096-byte chunked reading works

A naive implementation would read an entire file into memory:

```python
data = open(path, "rb").read()      # loads the whole file — bad for big files
hashlib.sha256(data).hexdigest()
```

For a 5 GB file that is 5 GB of RAM. This project streams instead:

```python
hasher = hashlib.new("sha256")
with open(path, "rb") as file_handle:
    while True:
        chunk = file_handle.read(CHUNK_SIZE)   # CHUNK_SIZE = 4096
        if not chunk:                          # b"" means end of file
            break
        hasher.update(chunk)                   # feed 4 KiB, then loop
digest = hasher.hexdigest()
```

What happens, step by step:

1. `open(path, "rb")` opens the file in **binary** mode. Text mode would let the
   OS translate line endings and decode bytes, changing the data before it is
   hashed. Binary mode gives the exact raw bytes.
2. `read(4096)` returns at most 4096 bytes (the final chunk may be shorter).
3. `hasher.update(chunk)` folds that chunk into the running state. `hashlib` is
   incremental: feeding a file in pieces gives exactly the same digest as feeding
   it all at once.
4. The loop stops when `read()` returns `b""`, the end-of-file marker.
5. `hexdigest()` returns the final digest as lowercase hex.

**Why 4096 bytes?** It is a classic block/buffer size (one memory page on many
systems). It is small enough that memory use is negligible and large enough that
system calls are not dominated by overhead. Any power of two would work; 4096 is
a sensible, readable default and is exposed as `CHUNK_SIZE` in `main.py` so you
can experiment.

## 15. Error handling

Integrity checks run against real disks, where files disappear, permissions get
revoked, and drives fail. The tool is built so that **one bad file never stops
the scan**.

`hash_file()` catches and reports:

| Exception | Typical cause | Handling |
|---|---|---|
| `FileNotFoundError` | File deleted or path typo | Prints `[ERROR] File not found`, returns `None` |
| `PermissionError` | No read permission on the file | Prints `[ERROR] Permission denied`, returns `None` |
| `IsADirectoryError` | A directory was passed by mistake | Prints a clear message, returns `None` |
| other `OSError` | I/O error, file vanished mid-read, name too long, device error | Prints `[ERROR] Could not read ...`, returns `None` |
| `ValueError` | Unsupported algorithm name (e.g. `md5`) | **Not** swallowed — it is a programming/usage error and is reported to the caller |

`monitor_folder()` additionally handles a missing folder, an unreadable folder,
and per-entry metadata errors, and it prints `<unreadable - skipped>` for a file
it could not hash while continuing with the rest. The demonstration wraps its
work in `try/except/finally`; the `finally` block deletes the temporary copy even
if hashing or writing failed.

On the command line, an unsupported algorithm exits with argparse's status `2`
and a helpful message instead of a stack trace.

## 16. Running the automated tests

`test_main.py` uses the standard-library `unittest` framework and runs entirely in
throw-away temporary directories, so your real `test_folder` is never touched.

```bash
# From inside the project folder
python3 -m unittest -v

# Or run the file directly
python3 test_main.py

# Or use unittest discovery
python3 -m unittest discover -v
```

Expected result: **36 tests, all OK**. Example tail of the output:

```
----------------------------------------------------------------------
Ran 36 tests in 0.015s

OK
```

Coverage map (test numbers match the project specification):

| # | Test | What it proves |
|---|---|---|
| 1 | `test_01_sha256_hashing_is_correct` | SHA-256 digests match an independent `hashlib` computation |
| 2 | `test_02_sha1_hashing_is_correct` | SHA-1 digests match, and are 40 hex characters |
| 3 | `test_03_identical_files_produce_identical_hashes` | Deterministic hashing |
| 4 | `test_04_one_character_change_changes_the_hash` | Avalanche effect on real files |
| 5 | `test_05_empty_file_hashing` | Empty file → the known `e3b0c442...b855` digest |
| 6 | `test_06_large_file_is_read_in_chunks` | 512 KiB file read only in 4096-byte calls (verified with a read spy) |
| 7 | `test_07_missing_file_returns_none` | `FileNotFoundError` handled |
| 8 | `test_08_unreadable_file_returns_none` (+`08b`–`08d`) | `PermissionError` and `OSError` handled, via mocking |
| 9 | `test_09_empty_folder_is_handled` (+`09b`) | Empty and missing folders handled gracefully |
| 10 | `test_10_directories_are_skipped` | Sub-folders, and files inside them, are ignored |
| 11 | `test_11_symbolic_links_are_skipped` (+`11b`) | Symlinks — even ones pointing outside — are skipped |
| 12 | `test_12_monitoring_stays_inside_the_folder` (+`12b`,`12c`) | Files outside the folder are never hashed |
| 13 | `test_13_demo_changes_only_the_temporary_copy` (+`13b`,`13c`) | The original file's bytes and hash are unchanged |
| 14 | `test_14_temporary_files_are_cleaned_up_after_success` (+`14b`,`14c`) | Cleanup on both success and error paths |
| 15 | `test_15_unsupported_algorithm_raises_value_error` (+`15b`,`15c`) | `md5`, `sha512`, empty names rejected; valid ones normalised |
| — | `TestCommandLine`, `TestShippedSampleFolder` | CLI defaults/errors and the eight real sample files |

## 17. Manual hash verification

You can verify any digest printed by this tool with a system utility. If the two
values match, the file is byte-for-byte identical.

### Linux

```bash
sha256sum test_folder/file1.txt
```

### macOS

```bash
shasum -a 256 test_folder/file1.txt
```

### Windows (Command Prompt or PowerShell)

```cmd
certutil -hashfile test_folder\file1.txt SHA256
```

SHA-1 variants:

```bash
sha1sum test_folder/file1.txt          # Linux
shasum -a 1 test_folder/file1.txt      # macOS
certutil -hashfile test_folder\file1.txt SHA1   # Windows
```

### Python one-liner (any OS)

```bash
python3 -c "import hashlib;print(hashlib.sha256(open('test_folder/file1.txt','rb').read()).hexdigest())"
```

### Whole-folder checksum file

Generate a checksum file, then verify it later (Linux):

```bash
cd file-integrity-checker
sha256sum test_folder/*.txt > checksums.sha256   # create the baseline
sha256sum -c checksums.sha256                    # verify: prints "OK" per file
```

If you edit a file after creating the baseline, verification prints `FAILED` for
that file and the tool tells you which one changed. (`checksums.sha256` is a
generated artifact and is already listed in `.gitignore`.)

## 18. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `python: command not found` | Windows-style name on Linux/macOS | Use `python3` |
| `ModuleNotFoundError: No module named 'main'` when testing | Wrong working directory | `cd file-integrity-checker` first |
| `No regular files found in this folder.` | Folder is empty, or holds only sub-folders/symlinks | Add a file, or check `--folder` |
| All files show `<unreadable - skipped>` | Permission problem | Check file permissions (`ls -l`) |
| `error: unsupported algorithm 'md5'` | Only `sha256` and `sha1` are supported | Use `--algorithm sha256` |
| Demonstration says "skipped" | No `.txt`/`.md` file in the folder | Put a text file in `test_folder` |
| Windows symlink tests skipped | Creating symlinks needs admin/developer mode | Expected; they skip cleanly and the suite still passes |

## 19. License and responsible use

This project is provided for **education and self-study**. Use it freely, modify
it, and learn from it.

> **LEGAL AND ETHICAL NOTICE:** Scanning or attacking systems you do not own or have written permission to test is illegal. This tool only monitors your own test folder.

This tool reads only the files in its own `test_folder`. It performs no network
access, no port scanning, no exploitation, and no collection of data about other
systems. Do not extend it into something that inspects machines or data you do
not own or have explicit written authorisation to test.
