# FileWatch — File Integrity Monitor

**Week 1:** SHA-256 File Integrity Checker (hashing + avalanche demonstration)
**Week 2:** Baseline snapshots and change detection (added / modified / deleted / unchanged)

A beginner-friendly, standard-library-only Python tool that shows how cryptographic
hashing is used to detect changes to files. It hashes the files in a local
`test_folder`, saves a **baseline** of those hashes to JSON, and later compares the
folder against that baseline to tell you exactly what changed.

> ### 📌 LEGAL AND ETHICAL NOTICE
>
> **Scanning or attacking systems you do not own or have written permission to test is illegal. This tool only monitors your own test folder.**
>
> This program is intended for **educational local file integrity monitoring only**.
> It is **not** a network scanner, port scanner, vulnerability scanner, or
> penetration-testing tool. It never opens a socket, never touches the network, and
> never reads anything outside the folder you point it at.
> **LEGAL AND ETHICAL NOTICE:** Scanning or attacking systems you do not own or have written permission to test is illegal. This tool only monitors your own test folder.

---

## Table of Contents

**Week 1 — hashing basics**
1. [Project overview](#1-project-overview)
2. [Week 1 functionality](#2-week-1-functionality)
3. [How SHA-256 works](#3-how-sha-256-works)
4. [SHA-1 and why SHA-256 is preferred](#4-sha-1-and-why-sha-256-is-preferred)
5. [The avalanche effect](#5-the-avalanche-effect)
6. [How 4096-byte chunked reading works](#6-how-4096-byte-chunked-reading-works)

**Week 2 — baseline and change detection**
7. [Week 2 functionality](#7-week-2-functionality)
8. [How to generate a baseline](#8-how-to-generate-a-baseline)
9. [How to check for changes](#9-how-to-check-for-changes)
10. [How added files are detected](#10-how-added-files-are-detected)
11. [How modified files are detected](#11-how-modified-files-are-detected)
12. [How deleted files are detected](#12-how-deleted-files-are-detected)
13. [How subfolders are monitored](#13-how-subfolders-are-monitored)
14. [How UNIX-style symlinks and boundaries are handled](#14-how-symlinks-and-boundaries-are-handled)
15. [Explanation of JSON storage](#15-explanation-of-json-storage)
16. [Explanation of relative paths](#16-explanation-of-relative-paths)
17. [File size and modification time (stretch goal)](#17-file-size-and-modification-time-stretch-goal)
18. [Exit codes](#18-exit-codes)

**Using and testing the project**
19. [Technologies used](#19-technologies-used)
20. [Installation requirements](#20-installation-requirements)
21. [Project structure](#21-project-structure)
22. [Step-by-step usage](#22-step-by-step-usage)
23. [Command-line reference](#23-command-line-reference)
24. [Example terminal output](#24-example-terminal-output)
25. [Error handling](#25-error-handling)
26. [Automated testing instructions](#26-automated-testing-instructions)
27. [Manual hash verification](#27-manual-hash-verification)
28. [Troubleshooting](#28-troubleshooting)
29. [Roadmap and responsible use](#29-roadmap-and-responsible-use)

---

## 1. Project overview

A **hash** is a fixed-length fingerprint of data. Feed any file to a hash function
and you get back a short string:

```
file1.txt   ae510d7cd737086c15f672c3e47d6d801d7de14a4b6767307229ce674d039026
file2.txt   9205ab020474954eff2177c6c6b7f114c6e1aca87cf690fe4496486b9b5b3df3
```

Hashing is the foundation of **file integrity monitoring (FIM)**. You record a
file's hash when you trust it (the *baseline*), then re-hash it later. Same hash →
same bytes → nothing changed. Different hash → the file was modified, corrupted,
or replaced.

**Week 1** proved the idea on one folder and one moment in time.
**Week 2** turns it into an actual monitor: it *remembers* the hashes and tells you
what changed since — including files added, deleted, or edited inside subfolders.

## 2. Week 1 functionality

Everything from Week 1 is still present and still works; nothing was removed.

| Week 1 feature | Status | Where |
|---|---|---|
| `hash_file(path, algorithm="sha256")` | Preserved, unchanged signature | `main.py` |
| SHA-256 default, SHA-1 optional | Preserved | `SUPPORTED_ALGORITHMS` |
| Binary read mode (`"rb"`) | Preserved | `hash_file()` |
| 4096-byte chunked reading | Preserved (`CHUNK_SIZE = 4096`) | `hash_file()` |
| Error handling (missing / permission / OSError) | Preserved and reused by Week 2 | `hash_file()` |
| Safe avalanche demonstration (`--demo`) | Preserved, now finds files in subfolders too | `demonstrate_avalanche()` |
| Eight original sample files | Preserved, byte-for-byte identical | `test_folder/file1..8.txt` |
| Week 1 `unittest` tests (36) | Preserved and still passing | `test_main.py` |
| Plain `python main.py` scan | Preserved | `main()` |

The only Week 1 behaviour that changed is intentional and additive: the
demonstration now also locates sample text files inside subfolders, and writes its
temporary copy **next to** the sample it copies (still inside the monitored
folder). With the original flat `test_folder`, the behaviour is identical to
Week 1.

## 3. How SHA-256 works

**SHA-256** (Secure Hash Algorithm, 256-bit) belongs to the **SHA-2 family**,
published by NIST in 2001. It takes an input of any length and returns a
**256-bit** digest — 32 bytes, written as **64 hexadecimal characters**.

The process, in outline:

1. **Padding.** The message is padded so its length is a multiple of 512 bits. The
   padding encodes the original length, so different messages cannot pad into one
   another.
2. **Block processing.** The padded message is split into 512-bit blocks; each is
   expanded into 64 32-bit words.
3. **Compression.** Each block goes through 64 rounds of bitwise mixing — AND, OR,
   XOR, NOT, rotations, additions modulo 2³² — combined with the running state.
4. **Chaining.** The 256-bit result of one block becomes the starting state for the
   next block. The final state is the digest.

| Property | Meaning | Why you care |
|---|---|---|
| **Deterministic** | Same input → same digest, always | Comparisons are reliable |
| **Fixed size** | 1 byte or 100 GB → 64 hex chars | Easy to store and compare |
| **One-way** | You cannot rebuild the file from the digest | The digest leaks nothing |
| **Avalanche effect** | A tiny input change alters ~half the output bits | Tampering cannot hide |
| **Collision resistant** | Two files sharing one digest is infeasible | Files can't impersonate each other |

## 4. SHA-1 and why SHA-256 is preferred

**SHA-1** produces a **160-bit** digest (40 hex characters). It was published in
1995 and was once ubiquitous.

SHA-1 is **no longer safe** because it is vulnerable to **collisions**: two
different inputs with the same digest. Attacks progressed from theoretical (2005) to
practical *chosen-prefix collisions* (SHAttered, 2017), which let attackers craft
two different files sharing one SHA-1 digest. A broken hash destroys exactly the
guarantee an integrity monitor depends on.

**SHA-256 is preferred** because:

* It belongs to the **SHA-2 family**, which has no practical collisions.
* Its **256-bit digest** makes collision search infeasible (~2¹²⁸ operations).
* It is the algorithm behind TLS certificates, code signing, Git, and package
  managers today.
* It is a drop-in replacement: `hashlib.sha256()` instead of `hashlib.sha1()`.

SHA-1 remains available here (`--algorithm sha1`) only so you can compare the two
side by side. Never use it for new security work. Baselines record which algorithm
produced them, and `check` warns you if you compare with a different one.

## 5. The avalanche effect

The **avalanche effect** is the property that a minimal input change produces a
large, unpredictable output change. In an ideal hash, every output bit depends on
every input bit, so flipping one input bit flips each output bit with ~50%
probability.

```
One changed character:  'A'  ->  'B'

Original:  ae510d7c d737086c 15f672c3 e47d6d80 1d7de14a 4b676730 7229ce67 4d039026
Modified:  4b141f0b 1911d7e9 94cbe398 a80b6035 756e41a8 c5c8f152 4a09ed7c 9ae5c163
           61 of 64 hex digits differ — no visible pattern, no "small change"
```

You cannot tell from two digests *where* or *how much* a file changed. That is
exactly what makes hashing useful: any change, however small and however carefully
hidden, shows up as a mismatched digest.

**Why one character changes everything:** the digest is not a summary of the input,
it is the final state of a long chain of bit mixing. The changed character sits in
one 512-bit block, and every bit of that block influences every bit of the block's
output. That output is the *starting state* of the next block, so the disturbance
propagates through the rest of the file. Finalisation mixes the state once more.
Nothing in the algorithm lets a small input difference stay a small output
difference — this is deliberate diffusion, and it is why integrity checks catch a
single flipped character.

Try it yourself:

```bash
python main.py --demo
```

The demonstration copies a sample file, changes exactly one character in the copy,
hashes both, prints the comparison, and deletes the copy in a `finally` block. The
original sample file is opened read-only and is never modified.

## 6. How 4096-byte chunked reading works

A naive implementation loads the whole file into memory:

```python
data = open(path, "rb").read()      # bad for large files
hashlib.sha256(data).hexdigest()
```

For a 5 GB file that is 5 GB of RAM. FileWatch streams instead:

```python
hasher = hashlib.new("sha256")
with open(path, "rb") as file_handle:
    while True:
        chunk = file_handle.read(CHUNK_SIZE)   # CHUNK_SIZE = 4096
        if not chunk:                          # b"" means end of file
            break
        hasher.update(chunk)
digest = hasher.hexdigest()
```

1. `open(path, "rb")` opens the file in **binary** mode. Text mode would translate
   line endings and decode bytes, changing the data before it is hashed.
2. `read(4096)` returns at most 4096 bytes; the last chunk may be shorter.
3. `hasher.update(chunk)` folds that chunk into the running state. `hashlib` is
   incremental, so feeding a file in pieces gives exactly the same digest as
   feeding it all at once.
4. The loop stops when `read()` returns `b""`.
5. `hexdigest()` returns the final digest as lowercase hex.

**Why 4096?** It is a classic buffer size (one memory page on many systems): small
enough that memory use is negligible, large enough that system-call overhead
doesn't dominate. It is exposed as `CHUNK_SIZE` so you can experiment.

## 7. Week 2 functionality

Week 2 adds a persistent baseline and a comparison command.

| Feature | Description |
|---|---|
| `build_snapshot(folder)` | Recursively walks the folder and returns `{relative_path: {hash, size, mtime}}` |
| `baseline` command | Writes that snapshot to `baseline.json` as indented JSON |
| `check` command | Rebuilds the snapshot and compares it with the saved baseline |
| ADDED detection | Files present now but not in the baseline |
| MODIFIED detection | Files in both whose SHA-256 digest differs |
| DELETED detection | Files in the baseline but no longer on disk |
| UNCHANGED reporting | Files in both with identical digests |
| Recursive coverage | Files inside subfolders (any depth) are included, keyed by relative path |
| Metadata (stretch) | Size in bytes and last-modified time stored and displayed |
| Safe failures | Missing / invalid / malformed baselines are reported, never overwritten |

## 8. How to generate a baseline

```bash
cd file-integrity-checker
python main.py baseline
```

This walks `test_folder` recursively, hashes every regular file with SHA-256, and
writes `baseline.json` at the project root (override with `--baseline PATH`).

```
==========================================================================
                      FILEWATCH - CREATING BASELINE
==========================================================================
Folder    : /home/user/file-integrity-checker/test_folder
Algorithm : SHA-256
Baseline  : /home/user/file-integrity-checker/baseline.json
--------------------------------------------------------------------------
  documents/nested/deep.txt    12e627982f32b3827aaeefe165128bbf16b1b1208e75c266fab21332f91ce826  (160 B)
  file1.txt                    ae510d7cd737086c15f672c3e47d6d801d7de14a4b6767307229ce674d039026  (155 B)
  subfolder/file9.txt          7d51b0eef6045d86114ca515c88202d7c5f21e15d81ecaef1598340570787708  (183 B)
  ...
--------------------------------------------------------------------------
Baseline created: 12 file(s) -> /home/user/file-integrity-checker/baseline.json
==========================================================================
```

Running it a second time **updates** the baseline (the message changes to
"Baseline updated"). Do this only when you have reviewed the current state and
decided it is the new "known good" state.

The write is atomic: the file is written as `baseline.json.tmp` and then renamed,
so an interrupted run cannot leave a half-written baseline behind. If the folder
does not exist, the command fails with exit code 1 and writes nothing.

## 9. How to check for changes

```bash
python main.py check
```

Steps performed:

1. Load `baseline.json` (missing or invalid → clear error, exit 1, nothing written).
2. Build a fresh snapshot of the current `test_folder`.
3. Compare the two with dictionary and set operations.
4. Print ADDED, MODIFIED, DELETED and UNCHANGED sections.
5. Finish with either the changes summary or the exact sentence
   `No changes detected. Folder integrity verified.`

`check` is **read-only with respect to the baseline**: it never creates, updates or
repairs `baseline.json`. That is deliberate — a monitor that silently rewrote its
own reference point would hide exactly the changes it exists to report.

Useful options:

```bash
python main.py check --algorithm sha1      # compare SHA-1 baselines
python main.py check --baseline other.json # use a different baseline file
python main.py check --folder /path/to/dir # monitor a different folder
```

## 10. How added files are detected

Set difference on the keys:

```python
added_files = set(current_snapshot) - set(baseline)
```

Any relative path that exists now but is absent from the baseline is **ADDED**.
The report shows its size, modification time and current hash so you can see what
appeared:

```
  [+] ADDED files (2)
  ----------------------------------------------------------------------
    + added_new.txt
        size : 11 B
        mtime: 2026-11-24 16:25:18
        hash : f25c4f863aefe36e14fa0a313c6d26f98e93c2f65e119eba0f87d0f767432546
    + subfolder/file11.txt
        size : 11 B
        mtime: 2026-11-24 16:25:18
        hash : 8f8f4a014c523bb3739fbffa2b102e8e5ea9188a8c7633a28b239b2f9f9f979f
```

## 11. How modified files are detected

For files in **both** snapshots, the digests are compared:

```python
common = set(current_snapshot) & set(baseline)
for name in common:
    if current[name]["sha256"] != baseline[name]["sha256"]:
        modified.append(name)
```

A file is MODIFIED **only when its content hash changed**. Both hashes are printed
so the difference is visible and verifiable:

```
  [~] MODIFIED files (1)
  ----------------------------------------------------------------------
    ~ file1.txt
        old hash: ae510d7cd737086c15f672c3e47d6d801d7de14a4b6767307229ce674d039026
        new hash: 28d7ee908b2ef37d72d0ebaf04dc3dfb7613c58c086ee5e986f81ecbff495312
        size    : 155 B -> 166 B
        mtime   : 2026-11-24 16:25:18 -> 2026-11-24 16:25:19
```

Note the deliberate rule: **a changed timestamp or size alone is never enough**.
If you `touch` a file (or a backup tool rewrites identical bytes), the hash is
unchanged and the file is reported as UNCHANGED. Size and mtime are shown for
context; SHA-256 decides. See [section 17](#17-file-size-and-modification-time-stretch-goal).

## 12. How deleted files are detected

The opposite set difference:

```python
deleted_files = set(baseline) - set(current_snapshot)
```

Paths in the baseline that are no longer on disk are **DELETED**. The report shows
the last known hash and size so you can identify a file that vanished:

```
  [-] DELETED files (1)
  ----------------------------------------------------------------------
    - file5.txt
        last known hash : de354fc1340c6f1e2fe404def8ef10913a1f5a5f3d471a264e0618d56f95883a
        last known size : 123 B
```

## 13. How subfolders are monitored

`build_snapshot()` uses `os.walk(root, followlinks=False)`, which visits the folder
**and every subfolder, at any depth**. Directories themselves are never hashed —
only regular files.

```
test_folder/
├── file1.txt                     ->  "file1.txt"
├── subfolder/
│   ├── file9.txt                 ->  "subfolder/file9.txt"
│   └── file10.txt                ->  "subfolder/file10.txt"
└── documents/
    ├── notes.txt                 ->  "documents/notes.txt"
    └── nested/
        └── deep.txt              ->  "documents/nested/deep.txt"
```

Because keys are *relative*, moving the whole project folder does not invalidate
the baseline, and a file moved from `subfolder/file9.txt` to `file9.txt` is
correctly reported as one DELETED plus one ADDED (which is what a monitor should
tell you: the path changed).

Empty subfolders contain no files, so they produce no entries; deleting an empty
folder therefore does not count as a change to file content.

## 14. How symlinks and boundaries are handled

The monitor stays strictly inside the folder you give it:

* **Symbolic links to files** are skipped completely — their contents are never
  read, because the link target may live outside the monitored folder.
* **Symbolic links to directories** are pruned before the walk descends, and
  `followlinks=False` guarantees the walk cannot climb out of the tree.
* **Directories, sockets, pipes and devices** are skipped (`is_file()` filter).
* **`demo_copy_*` files** (temporary copies made by `--demo`) are excluded, so a
  leftover copy can never appear as an "added" file.
* **No system directories are scanned.** The default target is `test_folder` next
  to `main.py`, and paths are resolved relative to the script, not the shell's
  working directory.

## 15. Explanation of JSON storage

The baseline is a JSON object written with `json.dump(..., indent=2)`:

```json
{
  "tool": "FileWatch - File Integrity Monitor",
  "schema_version": 2,
  "algorithm": "sha256",
  "folder": "test_folder",
  "created_utc": "2026-11-24T16:25:10Z",
  "file_count": 12,
  "files": {
    "file1.txt": {
      "sha256": "ae510d7cd737086c15f672c3e47d6d801d7de14a4b6767307229ce674d039026",
      "size": 155,
      "mtime": 1795537435.4133298
    },
    "subfolder/file9.txt": {
      "sha256": "7d51b0eef6045d86114ca515c88202d7c5f21e15d81ecaef1598340570787708",
      "size": 183,
      "mtime": 1795537507.94
    }
  }
}
```

Why JSON:

* **Built in** — `import json`, no dependencies.
* **Human readable and diff-friendly** — indentation means a changed hash shows up
  as a one-line Git diff, so a baseline change is reviewable like any other code.
* **Portable** — no pickle (unsafe on untrusted input), no database, no binary
  format. It can be inspected on any machine.
* **Structured metadata** — the header records schema version, algorithm, folder
  name and creation time, which makes stale baselines obvious.
* **Backwards compatible** — `load_baseline()` also accepts a *legacy flat* file
  (`{"file1.txt": "abc123..."}`) in case you hand-write a tiny baseline.

`mtime` is stored as a POSIX timestamp (float seconds since the epoch) because it
is unambiguous across time zones; the CLI converts it to local time for display.

## 16. Explanation of relative paths

Keys are produced with:

```python
file_path.relative_to(root).as_posix()   # e.g. "subfolder/file3.txt"
```

Two reasons:

1. **Privacy and portability.** An absolute path like
   `/home/alice/projects/filewatch/test_folder/file1.txt` would leak your machine's
   layout into a file you commit to Git, and would break for anyone else. A
   relative key works on any machine, in any checkout location.
2. **Stability.** Move or rename the project folder and the baseline still matches.
   Only changes to *files* — not to where the project lives — are reported.

`as_posix()` forces forward slashes, so a baseline created on Windows
(`subfolder\file3.txt`) and one created on Linux produce identical keys. A test
covers this by moving a folder and asserting the baseline still verifies.

## 17. File size and modification time (stretch goal)

Each baseline entry records, in addition to the hash:

* **`size`** — file size in bytes at the time of hashing,
* **`mtime`** — last-modified time (POSIX timestamp).

These are displayed for ADDED files (current values) and MODIFIED files (old → new),
and they are helpful for triage: a 4 KB config file that is suddenly 2 MB is worth a
look.

**However, SHA-256 remains the only authority on content changes.** The comparison
logic is:

```python
if old_hash != new_hash:      # content changed  -> MODIFIED
    ...
else:                          # identical bytes  -> UNCHANGED
    ...                        # even if mtime/size moved
```

Consequences:

* `touch file1.txt` → **UNCHANGED** (timestamp moved, content did not).
* Restoring a file from a backup with identical bytes → **UNCHANGED**.
* Editing then reverting a file exactly → **UNCHANGED** (correct: nothing changed).
* Adding a trailing newline → **MODIFIED** (content really did change).

A test (`test_pytest_timestamp_change_alone_is_not_a_modification`) asserts the
mtime really did change while the file is still reported as unchanged.

## 18. Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. For `check`: no changes — integrity verified |
| `1` | Runtime error: missing folder, missing/invalid baseline, write failure |
| `2` | `check` found changes, **or** argparse usage error (bad command/algorithm) |

The `2` on changes makes the tool scriptable:

```bash
python main.py check || echo "ALERT: files changed!"
```

A monitor that finds a problem should not report "success", so this is intentional.
(`argparse` also uses `2` for usage errors; the printed message makes clear which
case occurred.)

## 19. Technologies used

* **Python 3.9+** (developed and tested on Python 3.13)
* **`hashlib`** — SHA-256 / SHA-1 digests
* **`pathlib`** — safe, cross-platform path handling
* **`json`** — baseline storage
* **`os` / `os.walk`** — recursive traversal without following symlinks
* **`argparse`** — CLI with commands and validated options
* **`datetime`** — human-readable metadata timestamps
* **`shutil`, `tempfile`** — safe copies and isolated tests
* **`unittest` + `unittest.mock`** — Week 1 test suite
* **`pytest`** — Week 2 test suite (`tmp_path` fixture)

The **program itself uses only the standard library**. `pytest` is needed only to
run the tests.

## 20. Installation requirements

**To run the tool:**

* Python **3.9 or newer** (`python3 --version`)
* Linux, macOS or Windows
* Write permission in the project folder (only needed for `baseline` and `--demo`)

No `pip install` is required.

**To run the automated tests:**

* `pytest` — install it in your environment:

  ```bash
  python3 -m pip install pytest
  # or, isolated:
  python3 -m venv .venv && . .venv/bin/activate && pip install pytest
  ```

  On Debian/Ubuntu, `sudo apt install python3-pytest` also works, and some systems
  provide `python3 -m pytest` already.

  The Week 1 tests need nothing extra: `python3 -m unittest -v` works with a bare
  Python install. If `pytest` is missing, `test_main.py` still runs under
  `unittest` **only if** the pytest import succeeds — so install pytest (or skip the
  file) when running the Week 2 tests.

## 21. Project structure

```
file-integrity-checker/
│
├── main.py                 # FileWatch: hashing, snapshot, baseline, check, demo
├── baseline.json           # Saved SHA-256 baseline (sample, committed)
├── README.md               # This document
├── test_main.py            # Week 1 unittest suite + Week 2 pytest suite
├── .gitignore              # Keeps caches, demo leftovers and secrets out of Git
│
└── test_folder/            # The only folder this tool ever monitors
    ├── file1.txt
    ├── file2.txt
    ├── file3.txt
    ├── file4.txt
    ├── file5.txt
    ├── file6.txt
    ├── file7.txt
    ├── file8.txt
    ├── subfolder/          # Week 2: proves recursive monitoring
    │   ├── file9.txt
    │   └── file10.txt
    └── documents/
        ├── notes.txt
        └── nested/
            └── deep.txt
```

## 22. Step-by-step usage

1. **Unzip and enter the project**

   ```bash
   unzip filewatch-week2.zip
   cd file-integrity-checker
   python3 --version        # must be 3.9+
   ```

2. **Run the Week 1 scan** (hash everything now, no baseline involved)

   ```bash
   python3 main.py
   ```

3. **Run the Week 1 avalanche demonstration**

   ```bash
   python3 main.py --demo
   ```

4. **Create the baseline**

   ```bash
   python3 main.py baseline
   ```

5. **Verify the folder is unchanged**

   ```bash
   python3 main.py check
   # -> No changes detected. Folder integrity verified.
   ```

6. **Make a change and detect it**

   ```bash
   echo "tampered" >> test_folder/file1.txt      # modify
   echo "new file" > test_folder/new.txt         # add
   rm test_folder/file5.txt                      # delete
   python3 main.py check
   ```

   You will see one MODIFIED, one ADDED and one DELETED file, and the exit code
   will be `2`.

7. **Restore the samples** (if you edited the real folder)

   ```bash
   git checkout -- test_folder/        # if you keep this in Git
   # or simply re-download the ZIP
   ```

8. **Run the tests**

   ```bash
   python3 -m pytest -v          # Week 2 (recommended)
   python3 -m unittest -v        # Week 1 (built in)
   ```

9. **Use another folder or baseline**

   ```bash
   python3 main.py baseline --folder /path/to/my_folder --baseline my.json
   python3 main.py check    --folder /path/to/my_folder --baseline my.json
   ```

> Tip: practise steps 4–6 in a **copy** of the project so the shipped sample files
> stay clean.

## 23. Command-line reference

```bash
# --- Week 1 ---
python3 main.py                        # hash every file in test_folder
python3 main.py --demo                 # + avalanche demonstration
python3 main.py --algorithm sha1       # use SHA-1 instead of SHA-256
python3 main.py --algorithm sha256     # explicit default

# --- Week 2 ---
python3 main.py baseline               # create or update baseline.json
python3 main.py check                  # compare against baseline.json
python3 main.py check --algorithm sha1 # compare SHA-1 baselines
python3 main.py baseline --baseline other.json
python3 main.py --folder /path/to/dir check

# --- Help ---
python3 main.py --help
```

Windows equivalents use `python` instead of `python3`.

## 24. Example terminal output

### Unchanged folder

```
$ python3 main.py check
==========================================================================
                     FILEWATCH - CHECKING FOR CHANGES
==========================================================================
Folder    : /home/user/file-integrity-checker/test_folder
Baseline  : /home/user/file-integrity-checker/baseline.json
Algorithm : SHA-256
--------------------------------------------------------------------------
Baseline created: 2026-11-24T16:25:10Z (12 files, SHA-256)
--------------------------------------------------------------------------

==========================================================================
                                 RESULTS
==========================================================================

  [+] ADDED files (0)
  ----------------------------------------------------------------------
    (none)

  [~] MODIFIED files (0)
  ----------------------------------------------------------------------
    (none)

  [-] DELETED files (0)
  ----------------------------------------------------------------------
    (none)

  [=] UNCHANGED files (12)
  ----------------------------------------------------------------------
    = documents/nested/deep.txt
    = documents/notes.txt
    = file1.txt
    ...
    = subfolder/file9.txt

==========================================================================
No changes detected. Folder integrity verified.
All 12 file(s) match the baseline.
==========================================================================
```

### After adding, modifying and deleting files

```
$ python3 main.py check ; echo "exit=$?"
...
  [+] ADDED files (2)
    + added_new.txt
        size : 11 B
        mtime: 2026-11-24 16:25:18
        hash : f25c4f863aefe36e14fa0a313c6d26f98e93c2f65e119eba0f87d0f767432546
    + subfolder/file11.txt
        size : 11 B
        mtime: 2026-11-24 16:25:18
        hash : 8f8f4a014c523bb3739fbffa2b102e8e5ea9188a8c7633a28b239b2f9f9f979f

  [~] MODIFIED files (1)
    ~ file1.txt
        old hash: ae510d7cd737086c15f672c3e47d6d801d7de14a4b6767307229ce674d039026
        new hash: 28d7ee908b2ef37d72d0ebaf04dc3dfb7613c58c086ee5e986f81ecbff495312
        size    : 155 B -> 166 B
        mtime   : 2026-11-24 16:25:18 -> 2026-11-24 16:25:18

  [-] DELETED files (1)
    - file5.txt
        last known hash : de354fc1340c6f1e2fe404def8ef10913a1f5a5f3d471a264e0618d56f95883a
        last known size : 123 B

  [=] UNCHANGED files (10)
    = documents/nested/deep.txt
    ...
==========================================================================
CHANGES DETECTED: 4 change(s) - 2 added, 1 modified, 1 deleted.
Unchanged files: 10
==========================================================================
exit=2
```

### Errors

```
$ python3 main.py check
  [ERROR] No baseline found at /path/baseline.json
  Run `python main.py baseline` first to create one.

$ python3 main.py check --baseline broken.json
  [ERROR] Baseline file is not valid JSON: /path/broken.json
          Expecting property name enclosed in double quotes: line 1 column 14 (char 13)
  The file was left untouched. Delete it or regenerate it with `python main.py baseline`.

$ python3 main.py --algorithm md5
usage: main.py [-h] [--demo] [--algorithm NAME] [--folder PATH] [--baseline PATH] [baseline|check]
main.py: error: unsupported algorithm 'md5'. Choose one of: sha256, sha1
```

## 25. Error handling

Integrity checks run against real disks, where files disappear, permissions get
revoked, and drives fail. **One bad file never stops a scan, and a failure never
silently destroys your baseline.**

| Situation | Behaviour |
|---|---|
| File missing while hashing | `[ERROR] File not found`, file skipped, scan continues |
| `PermissionError` on a file | `[ERROR] Permission denied`, file skipped |
| Other `OSError` / I/O failure | `[ERROR] Could not read ...`, file skipped |
| Unreadable subfolder | Reported and skipped by `os.walk`'s error handling |
| Folder does not exist | `[ERROR] Folder not found`, exit 1 |
| Baseline missing | `[ERROR] No baseline found ... Run 'baseline' first`, exit 1 |
| Baseline is invalid JSON | Error with the exact decoder message, **file untouched**, exit 1 |
| Baseline has the wrong shape | `[ERROR] Baseline has an unexpected structure`, exit 1 |
| Baseline is non-UTF-8 | Reported, exit 1 |
| Can't write the baseline | Error printed, temp file cleaned up, exit 1 |
| Baseline written with other algorithm | Warning printed; affected files listed as SKIPPED |
| Unsupported algorithm name | `ValueError` from `hash_file()`, argparse error with exit 2 |
| `Ctrl+C` | `Interrupted by user.`, exit 130 |

Notes:

* `hash_file()` **returns `None`** instead of raising for file problems, so callers
  can skip and continue.
* `ValueError` for an unknown *algorithm* is **not** swallowed: that is a bug or a
  bad flag, and it must be visible.
* The baseline is written atomically (`baseline.json.tmp` → `os.replace`), so a
  crash mid-write cannot corrupt an existing good baseline.
* `check` never writes anything, by design.

## 26. Automated testing instructions

Both suites live in `test_main.py` and neither touches the real sample files —
everything runs in temporary directories (`tempfile.TemporaryDirectory` for the
`unittest` classes, pytest's `tmp_path` for the Week 2 functions).

```bash
# Week 2 suite (pytest) - also runs the Week 1 tests, since they are collected too
python3 -m pytest -v

# Week 1 suite only (standard library, no install needed)
python3 -m unittest -v

# Run the file directly
python3 test_main.py
```

Expected result:

```
63 passed, 6 subtests passed
```

Coverage map — Week 2 specification:

| # | Requirement | Test |
|---|---|---|
| 1 | Creating a baseline | `test_pytest_create_baseline_writes_readable_json`, `test_pytest_build_snapshot_returns_hashes_keyed_by_relative_path` |
| 2 | Detecting added files | `test_pytest_detects_added_file` |
| 3 | Detecting modified files | `test_pytest_detects_modified_file` |
| 4 | Detecting deleted files | `test_pytest_detects_deleted_file` |
| 5 | No changes reported | `test_pytest_reports_no_changes_when_folder_unchanged`, `test_pytest_no_changes_detected_by_comparison` |
| 6 | Files inside subfolders | `test_pytest_detects_files_inside_subfolders`, `test_pytest_detects_changes_inside_subfolders` |
| 7 | Missing baseline | `test_pytest_missing_baseline_is_handled`, `test_pytest_baseline_command_rejects_missing_folder` |
| 8 | Invalid JSON | `test_pytest_invalid_json_is_handled_and_not_overwritten`, `test_pytest_wrong_baseline_structure_is_handled` |
| 9 | Relative path storage | `test_pytest_baseline_stores_relative_paths_only`, `test_pytest_relative_keys_survive_folder_move` |
| 10 | Size / mtime metadata | `test_pytest_metadata_records_size_and_mtime`, `test_pytest_timestamp_change_alone_is_not_a_modification`, `test_pytest_metadata_helpers_format_output` |

Extra safety tests: symlinks not followed, demo copies excluded, unreadable files
survive, CLI wiring, SHA-1 end to end, and a check that the **shipped**
`baseline.json` still matches the **shipped** `test_folder` (so a stale committed
baseline fails the suite).

Week 1 coverage (hashing correctness, SHA-1, identical files, one-character change,
empty file, chunked large file, missing/unreadable files, empty folder, directory
skipping, symlink skipping, folder boundaries, demo safety, temp cleanup, algorithm
validation) is unchanged and still passing — 36 `unittest` tests.

## 27. Manual hash verification

Verify any digest yourself. If the values match, the file is byte-for-byte
identical.

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
sha1sum test_folder/file1.txt                   # Linux
shasum -a 1 test_folder/file1.txt               # macOS
certutil -hashfile test_folder\file1.txt SHA1   # Windows
```

### Python one-liner (any OS)

```bash
python3 -c "import hashlib;print(hashlib.sha256(open('test_folder/file1.txt','rb').read()).hexdigest())"
```

### Whole-folder checksum file (Linux)

```bash
sha256sum test_folder/*.txt test_folder/*/*.txt > checksums.sha256
sha256sum -c checksums.sha256          # prints "OK" / "FAILED" per file
```

`checksums.sha256` is a generated artifact and is already listed in `.gitignore`.
FileWatch's `baseline.json` is the JSON equivalent, with metadata and without
needing shell tools.

## 28. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `python: command not found` | Windows-style name on Linux/macOS | Use `python3` |
| `ModuleNotFoundError: No module named 'main'` | Wrong working directory | `cd file-integrity-checker` |
| `ModuleNotFoundError: No module named 'pytest'` | pytest not installed | `python3 -m pip install pytest` |
| `No baseline found` | `baseline` never run, or wrong `--baseline` | `python3 main.py baseline` |
| `Baseline file is not valid JSON` | File truncated or hand-edited | Delete it or regenerate with `baseline` |
| `check` exits with `2` | Changes were found (or a usage error) | Read the ADDED/MODIFIED/DELETED sections |
| Everything shows as SKIPPED | Baseline used a different algorithm | Use the same `--algorithm` as the baseline |
| A file shows MODIFIED but looks the same | Bytes differ (line endings, trailing newline, encoding) | Compare with `sha256sum` / `git diff --binary` |
| Touched file still shows UNCHANGED | Correct! Only content changes count | Nothing to fix |
| `No regular files found` | Folder empty or only subfolders/symlinks | Add a file or check `--folder` |
| Windows symlink tests skipped | Creating symlinks needs admin/developer mode | Expected; the suite still passes |
| `baseline.json` shows as modified in Git after `check` | Should not happen — `check` never writes | Confirm you ran `baseline`, not `check` |

## 29. Roadmap and responsible use

Possible next steps for a Week 3:

* `--report json` so results can be consumed by other tools.
* Watch mode (`--watch`) that polls the folder every N seconds.
* Multiple baselines / snapshots over time, with history.
* HMAC-signed baselines, so the baseline itself cannot be edited undetected.

**Responsible use.** This is an educational tool for monitoring files on your own
machine.

> **LEGAL AND ETHICAL NOTICE:** Scanning or attacking systems you do not own or have written permission to test is illegal. This tool only monitors your own test folder.

It reads only the folder you point at, follows no symbolic links, opens no network
connections, and collects no data about other systems. Do not modify it to inspect
machines or data you do not own or have explicit written authorisation to test.
