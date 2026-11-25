# FileWatch — File Integrity Monitor

**Week 1:** SHA-256 File Integrity Checker (hashing + avalanche demonstration)
**Week 2:** Baseline snapshots and change detection (added / modified / deleted / unchanged)
**Week 3:** Continuous monitoring, structured logging, ignore rules and terminal alerts
**Week 4 (stretch):** HMAC-SHA256 signed baselines — tamper-evident reference data
**Week 4:** Integrity reports and dashboard — log parsing, Streamlit dashboard, Markdown/HTML reports

A beginner-friendly, standard-library-only Python tool that shows how cryptographic
hashing is used to detect changes to files. It hashes the files in a local
`test_folder`, saves a **baseline** of those hashes to JSON, compares the folder
against that baseline to report exactly what changed, and can now **watch the folder
continuously**, logging and alerting on every change until you stop it.

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

**Week 3 — continuous monitoring and alerts**
19. [Week 3 functionality](#19-week-3-functionality)
20. [Continuous monitoring (`watch`)](#20-continuous-monitoring-watch)
21. [Watch interval](#21-watch-interval)
22. [Ignore configuration (`.filewatchignore`)](#22-ignore-configuration-filewatchignore)
23. [Structured logging](#23-structured-logging)
24. [Terminal alerts](#24-terminal-alerts)
25. [No false deletions: unreadable vs deleted](#25-no-false-deletions-unreadable-vs-deleted)
26. [Clean shutdown (Ctrl+C / SIGTERM)](#26-clean-shutdown-ctrlc--sigterm)
27. [What changed in Week 3 (and why)](#27-what-changed-in-week-3-and-why)
28. [HMAC baseline signing (stretch goal — implemented)](#28-hmac-baseline-signing-stretch-goal--implemented)

**Week 4 — reports and dashboard**
40. [Week 4 functionality](#40-week-4-functionality)
41. [Installing the Week 4 dependencies](#41-installing-the-week-4-dependencies)
42. [Parsing the monitoring log](#42-parsing-the-monitoring-log)
43. [Running the dashboard](#43-running-the-dashboard)
44. [Generating reports](#44-generating-reports)
45. [Security limitations and mitigations](#45-security-limitations-and-mitigations)
46. [Detection is not prevention](#46-detection-is-not-prevention)
47. [Screenshots and demo instructions](#47-screenshots-and-demo-instructions)
48. [Ethical use](#48-ethical-use)

**Using and testing the project**
29. [Technologies used](#29-technologies-used)
30. [Installation requirements](#30-installation-requirements)
31. [Project structure](#31-project-structure)
32. [Step-by-step usage](#32-step-by-step-usage)
33. [Command-line reference](#33-command-line-reference)
34. [Example terminal output](#34-example-terminal-output)
35. [Error handling](#35-error-handling)
36. [Automated testing instructions](#36-automated-testing-instructions)
37. [Manual hash verification](#37-manual-hash-verification)
38. [Troubleshooting](#38-troubleshooting)
39. [Roadmap and responsible use](#39-roadmap-and-responsible-use)

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

## 19. Week 3 functionality

Week 3 turns the one-shot checker into a **monitor**. Everything from Weeks 1
and 2 still works exactly as before; Week 3 adds four capabilities on top.

| Feature | Description |
|---|---|
| `watch` command | Scans the folder continuously until interrupted, reusing `build_snapshot()` and `compare_snapshots()` |
| `--interval SECONDS` | How long to wait between scans (default `5`, `0` = back-to-back, negatives rejected) |
| Structured logging | `logging` module, `filewatch.log`, timestamped lines, one handler per run |
| `.filewatchignore` | `fnmatch` patterns (`*.tmp`, `.git`, `.venv`, `__pycache__`, ...) applied to `baseline`, `check` **and** `watch` |
| Terminal alerts | Coloured, labelled ADDED / MODIFIED / DELETED blocks with relative paths |
| Robust errors | `PermissionError`, `OSError`, and files vanishing mid-scan are logged, never fatal |
| No false deletions | An unreadable file is **never** reported as deleted unless it is provably gone |
| Clean shutdown | `Ctrl+C` and `SIGTERM` exit with code 130, no traceback |

## 20. Continuous monitoring (`watch`)

```bash
python3 main.py watch                  # monitor every 5 seconds
python3 main.py watch --interval 2     # monitor every 2 seconds
python3 main.py watch --once           # a single scan, then exit (cron/CI)
```

What happens:

1. `filewatch.log` is opened and structured logging starts.
2. `baseline.json` is loaded **once** (a missing baseline aborts with a clear
   message and exit code 1 — `watch` will not invent one).
3. `.filewatchignore` is loaded and compiled.
4. A loop: `scan_once()` → snapshot the folder → compare with the reference →
   alert + log any changes → sleep `interval` → repeat.
5. `Ctrl+C` logs "interrupted by user", prints a friendly line, exits `130`.

```
==========================================================================
                    FILEWATCH - CONTINUOUS MONITORING
==========================================================================
Folder    : /home/user/file-integrity-checker/test_folder
Baseline  : /home/user/file-integrity-checker/baseline.json
Algorithm : SHA-256
Interval  : 2 second(s)
Log file  : filewatch.log
Ignore    : 26 pattern(s) from /home/user/file-integrity-checker/.filewatchignore
--------------------------------------------------------------------------
Press Ctrl+C to stop.
Baseline loaded: 12 file(s).
==========================================================================
[16:25:07] scan 1: no changes (12 file(s) monitored)
[16:25:09] scan 2: no changes (12 file(s) monitored)

FILEWATCH ALERT  2026-11-24 16:25:11

  [+] ADDED (1)
      + added.txt
      size: 18 B  mtime: 2026-11-24 16:25:10

  [~] MODIFIED (1)
      ~ subfolder/file9.txt
      sha256: 79d63b7f0d03ce2c958bc4cb89baad3c11746e2a55ed86d4549e9b7e09227d6a

  [-] DELETED (1)
      - file6.txt
      last known sha256: 6c646211e6da710b673b02a0eff9360460ce9d35ce41e2671a390c4b7211dcb5

[16:25:13] scan 4: no changes (12 file(s) monitored)
^C
[stopped] Monitoring stopped by user after 4 scan(s).
Log written to filewatch.log.
```

### Alert each change once (default)

`watch` keeps an **in-memory reference** that advances after a change has been
alerted, so a file that stays modified does not re-alert on every scan. The
reference lives in RAM only: **`baseline.json` on disk is never written by
`watch`**, which preserves the approved Week 2 rule that a monitor must never
silently move its own reference point.

To keep re-alerting for as long as a difference exists (closer to a "current
state" view), pass `--repeat-alerts`.

## 21. Watch interval

| Value | Meaning |
|---|---|
| `--interval 5` | one scan every 5 seconds (default) |
| `--interval 0.5` | twice a second |
| `--interval 0` | scan back-to-back with no sleep (used by the tests; CPU-heavy) |
| `--interval -1` | rejected with exit code 1 |

The interval is a *polling* interval, not a filesystem-notification interval:
each scan re-reads and re-hashes every monitored file. That is simple, portable
and needs no extra dependencies. For very large folders, prefer a longer interval
(30–300 s) — the cost of a scan grows with total folder size, not with the number
of changes.

## 22. Ignore configuration (`.filewatchignore`)

A plain-text file at the project root (next to `main.py`) lists patterns that
must never be reported. One pattern per line; `#` starts a comment.

```
# .filewatchignore (shipped excerpt)
*.tmp
__pycache__
.venv
.git
*.log
```

### Matching rules

Patterns are matched with `fnmatch` against:

* the **full relative path** — `subfolder/notes.tmp`
* the **file name** — `notes.tmp`
* **every parent folder name** — `__pycache__`, `.git`, `.venv`

So `*.tmp` matches at any depth, and a bare folder name such as `.venv` matches
`a/b/.venv/lib/python3/site.py`. Matching is **case-sensitive** on all platforms
for predictable behaviour. Negation patterns (`!keep.txt`) are **not**
supported — that would need a full `.gitignore` engine.

### Where the rules apply

| Command | Ignore rules applied? |
|---|---|
| `baseline` | Yes — ignored files never enter `baseline.json` |
| `check` | Yes — consistent with `baseline` |
| `watch` | Yes — ignored files never alert |

This consistency matters: if `baseline` recorded a file that `watch` ignores (or
vice versa) the tool would report phantom changes forever.

### Built-in patterns

A few patterns are **always** active, even without a config file, so the tool
never alerts about its own output: `filewatch.log`, `baseline.json.tmp`,
`*.json.tmp`, `__pycache__`, `*.pyc`, `*.pyo`.

### Ignored directories are pruned

Ignored directories are removed from the walk *before* `os.walk` descends into
them, so an ignored `.git` or `.venv` is never entered at all. That keeps scans
fast and prevents a huge dependency tree from dominating the runtime.

Custom file: `python3 main.py check --ignore my-rules.txt`

## 23. Structured logging

`watch` writes to `filewatch.log` (override with `--log PATH`) using Python's
standard `logging` module:

```
2026-11-24 16:25:07 | INFO     | filewatch | Watch started: folder=/.../test_folder algorithm=sha256 interval=2.0s files=12 patterns=26
2026-11-24 16:25:11 | WARNING  | filewatch | ADDED file: added.txt
2026-11-24 16:25:11 | WARNING  | filewatch | MODIFIED file: subfolder/file9.txt
2026-11-24 16:25:11 | WARNING  | filewatch | DELETED file: file6.txt
2026-11-24 16:25:11 | ERROR    | filewatch | Unreadable file (content unknown, not reported as deleted): locked.txt
2026-11-24 16:25:11 | INFO     | filewatch | Scan 4: no changes (12 file(s))
2026-11-24 16:25:19 | INFO     | filewatch | Watch interrupted by user after 4 scan(s).
2026-11-24 16:25:19 | INFO     | filewatch | Watch ended: scans=4 exit_code=130
```

Format: `timestamp | level | logger name | message`.

| Level | Used for |
|---|---|
| `INFO` | start/stop, scan counters, the end-of-run summary |
| `WARNING` | every detected ADDED / MODIFIED / DELETED change |
| `ERROR` | files that could not be read or hashed, startup failures |
| `DEBUG` | per-skip detail (ignored/symlinked entries); enable with `--verbose` |

### No duplicate handlers

`setup_logging()` tags the handlers it creates with `_filewatch_managed = True`
and removes any previously tagged handler before adding a new one. Calling it
repeatedly (a watch loop, a test, an embedded use) therefore cannot duplicate
log lines. Tagged-handler removal deliberately leaves **foreign** handlers alone,
so pytest's `caplog` and your own handlers keep working. The logger also sets
`propagate = False`, so embedding FileWatch cannot pollute the root logger.

If the log file cannot be opened (read-only volume, bad path), a warning is
printed and monitoring continues with console alerts only — logging is never the
reason the tool fails.

## 24. Terminal alerts

Each change category gets its own labelled block, and every entry shows the
**relative path** so alerts are unambiguous across subfolders:

```
FILEWATCH ALERT  2026-11-24 16:25:11

  [+] ADDED (2)
      + added.txt
      size: 18 B  mtime: 2026-11-24 16:25:10
      + subfolder/new_file.txt
      size: 6 B  mtime: 2026-11-24 16:25:10

  [~] MODIFIED (1)
      ~ file1.txt
      sha256: 28d7ee908b2ef37d72d0ebaf04dc3dfb7613c58c086ee5e986f81ecbff495312

  [-] DELETED (1)
      - file6.txt
      last known sha256: 6c646211e6da710b673b02a0eff9360460ce9d35ce41e2671a390c4b7211dcb5
```

Colours: green `+` for added, yellow `~` for modified, red `-` for deleted,
magenta `!` for unreadable. Colour is **auto-detected** and automatically
disabled when:

* the output is not a TTY (piped to a file, captured by a test),
* the `NO_COLOR` environment variable is set (<https://no-color.org>),
* `TERM=dumb`.

No dependency such as `colorama` is needed; ANSI codes are plain strings and the
Windows 10+ console understands them.

## 25. No false deletions: unreadable vs deleted

This is the subtlest Week 3 requirement, and the easiest to get wrong.

**The problem.** Suppose `secret.txt` is in the baseline, and during a scan the
tool cannot read it (permission revoked, ACL changed, file locked on Windows). A
naive comparison sees "in baseline, not in the new snapshot" and shouts
**DELETED** — a false alarm that could send you chasing an incident that never
happened.

**What FileWatch does.**

1. `build_snapshot(..., unreadable=set())` records the relative path of every
   file it could not hash in that set. Unreadable is *not* the same as missing.
2. `compare_snapshots(baseline, current, unreadable=..., root=...)` computes
   `deleted = (baseline − current) − unreadable`, so a file we failed to read
   never enters the deleted bucket.
3. Those paths are reported in a separate **UNREADABLE** bucket instead:

   ```
     [!] UNREADABLE (1) - not reported as deleted
       ! locked.txt
   ```
4. As a second safety net the tool asks the filesystem directly with
   `os.path.lexists()`. Only if the path is **provably gone** does it become a
   genuine deletion; if it still exists in any form, it stays unreadable.
5. Every unreadable file is logged at `ERROR` level, so nothing is hidden.

`has_changes()` ignores the unreadable bucket, so an unreadable file alone does
not make `check` exit with code 2 or `watch` claim a change. It is surfaced, but
not misreported.

## 26. Clean shutdown (Ctrl+C / SIGTERM)

```bash
python3 main.py watch
# ...
^C
[stopped] Monitoring stopped by user after 4 scan(s).
Log written to filewatch.log.
```

* `KeyboardInterrupt` is caught inside the loop: no traceback, exit code **130**
  (128 + `SIGINT`, the conventional code).
* The shutdown is logged (`Watch interrupted by user after N scan(s)`), and a
  `finally` block always writes the end-of-run summary.
* `SIGTERM` (plain `kill`, most service managers) is translated into the same
  clean path by a small handler installed in `__main__`. Only `SIGTERM` is
  touched; `SIGINT` already raises `KeyboardInterrupt`.
* `os._exit()` is never used, so buffered log lines are flushed and handlers
  closed normally.

## 27. What changed in Week 3 (and why)

Incremental, backward-compatible changes only — every Week 1/2 signature still
works, and all 36 original `unittest` tests pass unmodified.

| File | Change | Why |
|---|---|---|
| `main.py` | **New** Week 3 sections: `setup_logging`, `IgnoreRules`, `scan_once`, `advance_reference`, `format_alerts`, `command_watch` | The four new capabilities |
| `main.py` | `walk_regular_files(folder, ignore=None)` | Ignore rules must be applied during the walk (and prune ignored directories) — added as an **optional** argument so old calls are untouched |
| `main.py` | `build_snapshot(..., ignore=None, unreadable=None, report_skipped=True)` | Same reason; `unreadable` lets callers distinguish "missing" from "unreadable" |
| `main.py` | `compare_snapshots(..., unreadable=None, root=None)` + new `unreadable` result key | Prevents false DELETED reports (section 25). Old calls behave identically |
| `main.py` | `walk` now catches `OSError`/`PermissionError` from `os.walk` and per-entry `stat` calls | A failing tree must not abort a scan (found by a test) |
| `main.py` | `command_baseline` / `command_check` accept `ignore_path` and apply the same rules as `watch` | Consistency across commands; without it, ignored files could still trigger alerts |
| `main.py` | CLI: `watch` command, `--interval`, `--log`, `--ignore`, `--once`, `--verbose`, `--repeat-alerts` | New options, all optional |
| `main.py` | `__main__` block installs a `SIGTERM` handler | Clean shutdown under `kill`/systemd |
| `.filewatchignore` | **New file** | Default ignore patterns (`*.tmp`, `.git`, `.venv`, `__pycache__`, logs, editor/O​S noise) |
| `test_main.py` | **40 new tests** (Week 3), existing 63 untouched | Monitoring, ignore rules, errors, logging, alerts, shutdown |
| `.gitignore` | Ignores `filewatch.log`, `*.log`, alternate baselines | Runtime output stays out of Git |
| `README.md` | Week 3 sections 19–28 added, later sections renumbered | Documentation |
| `baseline.json` | Regenerated with ignore rules active | Same 12 sample files, no behaviour change |

Nothing was removed, renamed or rewritten for its own sake: Week 1's `hash_file`,
`monitor_folder` and demonstration, and Week 2's `build_snapshot` (without new
arguments) and `compare_snapshots` (without new arguments) behave exactly as
approved.

## 28. HMAC baseline signing (stretch goal — implemented)

**Status: implemented and tested** (36 dedicated tests). It was built only after
all Week 3 core requirements were complete and green.

> ### Read this first - two limits that define what HMAC does
>
> **1. HMAC does not encrypt anything.** `baseline.json` stays plaintext JSON.
> Every monitored path, every SHA-256 digest, every file size, every timestamp,
> and the folder name are readable by anyone who can open the file. HMAC proves
> *who wrote it*; it hides *nothing*.
>
> **2. HMAC does not help once the key is stolen.** The signature proves the
> baseline was signed by a holder of the key - and an attacker holding the key
> **is** a valid holder. They can edit a file, rewrite the baseline, compute a
> fresh signature, and FileWatch will report `signature verified` with no
> changes detected. This was demonstrated here, not assumed (see
> [the two hard limits](#the-two-hard-limits-honestly)).
>
> If either limit matters for your threat model, HMAC alone is not enough: see
> [What would actually be needed](#what-would-actually-be-needed).

### The gap this closes

FileWatch verifies *files* against `baseline.json`. But `baseline.json` is itself
just a file. An attacker who can edit a monitored file can edit the baseline to
match it, and `check` will happily say "no changes":

```bash
echo "malware" >> test_folder/app.py       # 1. change the file
# 2. ...and rewrite baseline.json so the hash matches again
python3 main.py check                      # "No changes detected" — undetected!
```

An **HMAC signature** binds the baseline to a secret key. Without the key the
baseline cannot be quietly rewritten; changing any byte invalidates the
signature, and `check --verify` refuses to trust it.

### What it does and does not protect

| Protects against | Does **not** protect against |
|---|---|
| Silent edits to `baseline.json` (any field, any entry) | An attacker who already has the key |
| A forged baseline copied in from elsewhere | An attacker running code as your user (they can re-sign) |
| Accidental hand-editing / truncation of the baseline | Deletions inside the monitored folder (different problem) |
| An unsigned baseline being passed off as trustworthy | A compromised machine or logging system |

Signing authenticates the **baseline**, not your whole system. It is one layer,
not a solution.

### The signature format

`baseline --sign` adds one block to the JSON:

```json
{
  "tool": "FileWatch - File Integrity Monitor",
  "schema_version": 2,
  "algorithm": "sha256",
  "folder": "test_folder",
  "created_utc": "2026-11-25T09:04:20Z",
  "file_count": 12,
  "files": { "file1.txt": { "sha256": "ae51...", "size": 155, "mtime": 1795... } },
  "signature": {
    "algorithm": "hmac-sha256",
    "value": "1e030c06886653abf6be9c7f49023ed0dfae54509369310b897cae89fd850ffb",
    "signed_fields": ["algorithm", "created_utc", "file_count", "files",
                      "folder", "schema_version", "tool"]
  }
}
```

How it is computed:

```python
payload = json.dumps(signed_part, sort_keys=True, separators=(",", ":"))
value   = hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
```

* everything except `signature` and `signed_fields` is signed — including every
  per-file hash, the algorithm, and the file count;
* `sort_keys=True` + fixed separators make the payload **deterministic**, so
  re-indenting or reordering the JSON does not break verification, while any
  change of *value* does;
* verification uses `hmac.compare_digest()` — constant time, so a timing side
  channel cannot leak how much of the digest matched.

### Using it

```bash
# 1. Generate a key (never hardcoded, never inside the project)
python3 main.py keygen
#   export FILEWATCH_HMAC_KEY=85f9c59192f963d8...
# or write it to a 0600 file outside the repo:
python3 main.py keygen --out ~/.config/filewatch/hmac.key

# 2. Load the key
export FILEWATCH_HMAC_KEY=85f9c59192f963d8...        # from a secrets manager
# or
export FILEWATCH_HMAC_KEY_FILE=~/.config/filewatch/hmac.key

# 3. Sign the baseline
python3 main.py baseline --sign
#   Signature : hmac-sha256 (1e030c06886653ab...)

# 4. Verify on every check
python3 main.py check --verify
#   Signature : signature verified (hmac-sha256)
#   No changes detected. Folder integrity verified.
```

| Flag | Applies to | Meaning |
|---|---|---|
| `--sign` | `baseline` | Sign the baseline with HMAC-SHA256 |
| `--verify` | `check`, `watch` | Check the signature; warn (not fail) if unsigned |
| `--require-signature` | `check`, `watch` | Refuse an unsigned baseline (implies `--verify`) |
| `--key-file PATH` | all | Load the key from this 0600 file |
| `keygen [--out PATH] [--force]` | command | Generate a random key; optionally write it 0600 |

### Refusal behaviour (fail closed)

Nothing about signing is "best effort" — if it cannot be done safely, it is not
done at all:

| Situation | Result |
|---|---|
| `baseline --sign` with no key configured | Exit 1, **baseline not written** |
| `baseline --sign` with a key shorter than 32 bytes | Exit 1, baseline not written, previous baseline preserved |
| Signature mismatch (baseline edited) | Exit 1, baseline **not** loaded, `check`/`watch` stop |
| Signed baseline, no key to verify with | Exit 1, clear message |
| Unsigned baseline + `--verify` | Warning, then continues (backward compatible) |
| Unsigned baseline + `--require-signature` | Exit 1 |
| Key file readable by group/others (`0644`) | Exit 1, "too permissive; run chmod 600" |
| `keygen --out` inside the project folder | Exit 1, nothing written |
| `keygen --out` over an existing key | Exit 1 unless `--force` |

A failed verification never rewrites or repairs the baseline — same principle as
Week 2's "a check must never move its own reference point".

### Safe key management (the rules this implementation enforces)

1. **Never hardcode a key.** There is no default key and no key in the source;
   a test (`test_w4_no_hardcoded_key_in_the_source`) asserts no 64+ hex literal
   exists in `main.py`.
2. **Key from the environment or a private file**, resolved in this order:
   explicit argument → `--key-file` → `$FILEWATCH_HMAC_KEY_FILE` →
   `$FILEWATCH_HMAC_KEY`. `FILEWATCH_HMAC_KEY` accepts hex (recommended) or a
   raw passphrase; hex is decoded as bytes.
3. **At least 32 bytes of entropy** (the HMAC-SHA256 output length). Shorter
   keys are rejected. `keygen` uses `secrets.token_hex(32)`.
4. **Key file mode 0600.** Anything group/world readable is refused, because a
   leaked baseline signature key defeats the whole mechanism.
5. **Keep the key outside the repository.** `keygen --out` refuses to write
   inside the project, and `.gitignore` already ignores `*.key`, `*.hmac`,
   `hmac.key`, `.env`.
6. **Constant-time comparison** via `hmac.compare_digest()`, never `==`.
7. **Fail closed.** A missing key never silently downgrades to "unsigned".
8. **Rotate on suspicion.** Re-run `keygen` and `baseline --sign`; a new key
   invalidates signatures made with the old one.

> If the key leaks, the signature guarantees nothing. Treat it like a password:
> store it in a password manager or secrets manager, not in a shell history you
> share, and not in the repo.

### The two hard limits, honestly

#### Limit 1 - no confidentiality

`baseline.json` is ordinary JSON. There is no encryption anywhere in FileWatch
(`grep -cE "AES|Fernet|cipher|encrypt" main.py` returns `0`). Opening the file
reveals:

```json
{
  "folder": "test_folder",
  "created_utc": "2026-11-25T09:05:17Z",
  "files": {
    "documents/nested/deep.txt": { "sha256": "12e62798...", "size": 160, "mtime": 1795... },
    "file1.txt":                 { "sha256": "ae510d7c...", "size": 155, "mtime": 1795... }
  }
}
```

That is a **file inventory**: names, directory layout, sizes, modification times
and content fingerprints. For a personal project that is harmless; in an
organisation it can leak that a folder contains `merger_agreement_2026.pdf` or
`incident_report_final.docx`, when it was last touched and how big it is -
regardless of what the file contains.

A signature makes that content **tamper-evident**, not **secret**. Confidentiality
and authenticity are independent properties; HMAC provides only the second.

#### Limit 2 - a stolen key ends the guarantee

The forgery is trivial, and was verified in this project's sandbox:

```console
$ echo "malware" >> test_folder/file1.txt          # 1. change the file
$ python3 forge.py                                 # 2. rewrite + re-sign
attacker rewrote + re-signed the baseline with the stolen key

$ python3 main.py check --require-signature
  Signature : signature verified (hmac-sha256)
No changes detected. Folder integrity verified.      <- the forgery is accepted
```

where `forge.py` is four lines of standard library - recompute the file's hash,
drop it into `files`, recompute the HMAC over the same canonical payload, write
it back:

```python
import json, hmac, hashlib, os
d = json.load(open("baseline.json"))
d["files"]["file1.txt"]["sha256"] = hashlib.sha256(
    open("test_folder/file1.txt", "rb").read()).hexdigest()
payload = json.dumps({k: v for k, v in d.items()
                      if k not in ("signature", "signed_fields")},
                     sort_keys=True, separators=(",", ":")).encode()
d["signature"]["value"] = hmac.new(
    bytes.fromhex(os.environ["FILEWATCH_HMAC_KEY"]), payload,
    hashlib.sha256).hexdigest()
json.dump(d, open("baseline.json", "w"), indent=2)
```

`--require-signature` did exactly what it promises: it verified a signature that
really was produced with the right key. There is **no cryptographic flaw** here -
the **key model itself is the limit**. A symmetric MAC can only distinguish
"someone with the key" from "someone without it"; it cannot tell *which* key
holder, and it cannot help if the holder is the attacker.

Consequences worth stating plainly:

* The attacker needs no exploit, no privilege escalation and no FileWatch bug -
  only the key material.
* The forgery happens **entirely off-line**. FileWatch never runs during it, so
  nothing is logged, alerted or timestamped.
* It is **not detectable after the fact** by FileWatch: the forged baseline is
  indistinguishable, byte for byte, from a legitimate one.
* A file deleted from the monitored folder can likewise be removed from a forged
  baseline, hiding the deletion.

#### Further limits

* **Rollback / replay.** A previously valid, validly-signed baseline can be put
  back later; nothing binds a signature to "now".
* **The log is not protected.** `filewatch.log` is plaintext and unsigned; an
  attacker who can edit files can edit it too.
* **No key-id or rotation scheme.** Re-signing with a new key invalidates old
  signatures, with no way to tell "rotated" from "forged".
* **Anyone who can run code as you wins.** They can read the key from your
  environment, or simply re-sign. HMAC cannot defend an already-compromised host.

### What would actually be needed

Neither limit is fixable by "more HMAC". Each needs a different mechanism:

| Goal | Mechanism | Trade-off |
|---|---|---|
| **Confidentiality** - hide the inventory | Encrypt `baseline.json` (AES-GCM or `cryptography.fernet`) with a *separate* key | Becomes unreadable to humans; needs a third-party dependency; still fails once that key leaks |
| **Authenticity against key theft** | Asymmetric signature - sign with an Ed25519 **private** key, verify with a **public** key held elsewhere | The verifier only needs the public key, so stealing the verifier cannot forge; more moving parts and key distribution |
| **Tamper evidence you cannot forge locally** | Append signatures to a system you do not control (remote log, SIEM, WORM storage, RFC 3161 timestamp authority) | Needs infrastructure and network; contradicts this project's local-only scope |
| **Anti-rollback** | Anchor each signature in an external monotonic record or trusted timestamp | Same infrastructure requirement |

Two of these are within reach as future work. Both would break the current
"standard library only, local only" constraint, so they are documented rather
than implemented:

* **Encrypt the baseline** with `cryptography`'s `Fernet`/AES-GCM, key from a
  secrets manager, decrypted in memory only.
* **Switch to Ed25519 signatures**: `baseline --sign` uses the private key,
  `check --verify` uses a public key that can be distributed openly. This removes
  the "stolen key = game over" property - the single most valuable upgrade for a
  real deployment.

**Mitigations available today, with the current code:**

1. Keep the key **out of the monitored folder and out of the repo** (enforced).
2. Store it in a secrets manager / OS keyring, not shell history or a committed
   `.env`.
3. Rotate the key on any suspicion, then `baseline --sign` again.
4. Treat `baseline.json` as **public information**: if the file *names* are
   sensitive, do not put them in a monitored folder.
5. Keep an **offline copy** of the baseline (or its signature) somewhere the
   attacker cannot write, and compare occasionally - this catches forgeries that
   would otherwise look legitimate.

## 40. Week 4 functionality

Week 4 adds a **reporting and visualisation layer** on top of the monitoring
engine. Nothing from Weeks 1-3 changed: `main.py` is untouched by this work, and
the new code lives in three new files.

| File | Purpose | Dependencies |
|---|---|---|
| `logger_parser.py` | Parses `filewatch.log` into events; builds report data; renders Markdown and HTML | **stdlib only** |
| `report.py` | CLI: `events` table and `report` generation | **stdlib only** |
| `dashboard.py` | Streamlit dashboard: metrics, timeline, event table, refresh | Streamlit (+ pandas) |
| `requirements.txt` | The optional dashboard/test dependencies | — |

Because the parsing and reporting modules use only the standard library,
`python3 report.py report --format both` works on a machine where **nothing**
has been pip-installed. Only the dashboard needs Streamlit.

Recognised log events:

| Event | Log line written by `watch` |
|---|---|
| `ADDED` | `WARNING \| filewatch \| ADDED file: <path>` |
| `MODIFIED` | `WARNING \| filewatch \| MODIFIED file: <path>` |
| `DELETED` | `WARNING \| filewatch \| DELETED file: <path>` |
| `UNREADABLE` | `ERROR \| filewatch \| Unreadable file (...): <path>` |
| `ERROR` | any other `ERROR`/`CRITICAL` line |

`INFO`/`DEBUG` lines ("Scan 1: no changes", "Watch started") are counted as
monitoring activity but are **never** shown as change events.

## 41. Installing the Week 4 dependencies

The monitor, the parser and the report generator need **nothing** beyond Python
3.9+. Only the dashboard (and the dashboard tests) need extra packages.

```bash
cd file-integrity-checker

# Recommended: an isolated environment
python3 -m venv .venv
. .venv/bin/activate            # Linux / macOS
# .venv\Scripts\activate         # Windows

python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

`requirements.txt` contains exactly three packages:

```
streamlit>=1.30,<2.0      # dashboard
plotly>=5.18,<7.0         # stacked timeline chart (optional, graceful fallback)
pytest>=7.0               # test suite
```

If you install nothing, these still work:

```bash
python3 main.py                 # Weeks 1-3 unchanged
python3 report.py events        # parsed event table
python3 report.py report --format both
```

## 42. Parsing the monitoring log

```bash
python3 report.py events
```

```
============================================================================================
                               FILEWATCH - PARSED LOG EVENTS
============================================================================================
Log file   : filewatch.log
Lines read : 8  (recognised 8, malformed 0)
Summary    : 3 change event(s): 1 added, 1 modified, 1 deleted
--------------------------------------------------------------------------------------------
Event counts:
  ADDED        1
  MODIFIED     1
  DELETED      1
  UNREADABLE   0
  ERROR        0
--------------------------------------------------------------------------------------------
Timestamp            Event     Level    File
-------------------  --------  -------  -----------
2026-11-25 17:22:57  ADDED     WARNING  added_a.txt
2026-11-25 17:22:57  MODIFIED  WARNING  file2.txt
2026-11-25 17:22:57  DELETED   WARNING  file7.txt
--------------------------------------------------------------------------------------------
Showing 3 event(s)
```

Options:

| Option | Meaning |
|---|---|
| `--log PATH` | Parse a different log file (default `filewatch.log`) |
| `--limit N` | Show only the N most recent events |

From Python:

```python
import logger_parser as lp

result = lp.parse_log_file("filewatch.log")
print(lp.summarize(result))          # "3 change event(s): ..."
for event in lp.recent_events(result, limit=5):
    print(event.timestamp, event.event_type, event.path)
print(lp.timeline(result, bucket="hour"))
```

**Robustness.** The parser tolerates a missing file, an empty file, a directory
path, a permission error, binary bytes, impossible timestamps, traceback
continuation lines and hand-edited spacing. Nothing raises: unreadable lines are
counted in `malformed_lines` and the good lines are still returned. Malformed
lines are surfaced deliberately, because a burst of them can mean a crash, two
writers, or someone editing the log.

## 43. Running the dashboard

```bash
python3 -m streamlit run dashboard.py
```

Then open <http://localhost:8501>. To use a different log:

```bash
FILEWATCH_LOG=/path/to/other.log python3 -m streamlit run dashboard.py
# or type the filename in the sidebar "Log file (optional)" box
```

What it shows:

| Area | Content |
|---|---|
| **Metrics** | Total changes, plus separate ADDED / MODIFIED / DELETED counts |
| **Timeline** | Stacked bar chart of changes over time (minute / hour / day buckets) |
| **Recent events** | Table of the latest events with timestamp, type, level and relative path |
| **Filters** | Event-type filter and row-count slider |
| **Refresh** | A **🔄 Refresh** button, plus an optional auto-refresh interval |
| **Downloads** | CSV of the visible events; Markdown and HTML reports, generated in memory |
| **Empty state** | An explicit message when the log is missing, empty, or has no events |

Useful options for a headless machine:

```bash
python3 -m streamlit run dashboard.py \
    --server.address 0.0.0.0 --server.port 8501 \
    --server.headless true --browser.gatherUsageStats false
```

The dashboard is **read-only** with respect to your data: it never writes to the
log, the baseline or the monitored folder, and it never reads or displays HMAC
keys.

## 44. Generating reports

```bash
# Markdown (default)
python3 report.py report --format md

# HTML
python3 report.py report --format html

# Both at once
python3 report.py report --format both

# Choose the output directory / add more recent changes
python3 report.py report --format both --out reports --recent 50
```

Default output is `reports/integrity-report.md` and
`reports/integrity-report.html`.

Each report contains:

* generation timestamp and the log file analysed,
* event summary table (ADDED / MODIFIED / DELETED / UNREADABLE / ERROR + total),
* log-health block (lines read, recognised, informational, malformed),
* first and last event timestamps,
* a table of recent changes with relative paths,
* the most frequently changed files,
* the limitations section and the legal/ethical notice.

A report generated when the log is missing is still written - it states clearly
that no log data was available and how to create some, which is more useful than
an empty file. The CLI exits `1` in that case so scripts can detect it.

From Python:

```python
import logger_parser as lp

result = lp.parse_log_file("filewatch.log")
data   = lp.build_report_data(result, recent_limit=25)
print(lp.render_markdown(data))          # str
print(lp.render_html(data))              # str
lp.write_report(data, "reports/r.md")    # writes the file
```

HTML safety: every dynamic value (including file names) is escaped with
`html.escape()` and inline CSS is used, so a file called
`<script>alert(1)</script>.txt` appears as text. Reports contain **no secrets** -
a test asserts that no HMAC key material can leak into a report.

## 45. Security limitations and mitigations

FileWatch is a learning project, and it is honest about what it cannot do. These
are not theoretical: each one is demonstrated in the Week 4 test suite or the
notes below.

### Limitation 1 — an attacker can modify the baseline

`baseline.json` is an ordinary file. Anyone who can write to the project folder
can edit a stored hash (or delete an entry) so that a tampered file looks
normal. The monitor then reports "no changes" while the change is real.

**Mitigations**

1. **Sign the baseline** and always verify it:
   ```bash
   export FILEWATCH_HMAC_KEY=<key from a secrets manager>
   python3 main.py baseline --sign
   python3 main.py check --require-signature
   python3 main.py watch --require-signature
   ```
   Any edit to `baseline.json` now produces `signature MISMATCH` and the check
   refuses to run.
2. **Restrict permissions** on the project folder: `chmod 750`, owned by the
   monitoring account, not writable by others.
3. **Keep a copy off-box** (`rsync`, a git commit of `baseline.json`, object
   storage) and compare occasionally. A locally forged baseline cannot match an
   externally stored copy.
4. **Watch the baseline itself** with a second baseline in a different folder,
   or simply record its hash somewhere else you trust.

**Residual risk:** with the HMAC key in hand the forgery is undetectable by
FileWatch (see limitation 2). Mitigation 3 is the only one that survives that.

### Limitation 2 — an attacker can compromise the HMAC key

If the key leaks, the signature stops meaning anything: the attacker edits a
file, rewrites the baseline and re-signs it. FileWatch reports
`signature verified` and sees no changes. There is no cryptographic bug here -
a symmetric MAC can only distinguish *has the key* from *does not have the key*.

**Mitigations**

1. **Never hardcode the key.** It comes from `$FILEWATCH_HMAC_KEY` or a `0600`
   key file; a test asserts no 64-character hex literal exists in the source.
2. **Keep it outside the repository and outside the monitored folder**, in a
   secrets manager or OS keyring. `.gitignore` already excludes `*.key`.
3. **Enforce file mode `0600`** - FileWatch refuses a group/world-readable key
   file outright.
4. **Rotate on any suspicion:** generate a new key and re-run
   `baseline --sign`. Old signatures become invalid, which is the point.
5. **Move to asymmetric signing (Ed25519)** for real deployments: `check` would
   hold only a *public* key, so stealing the verifier's key no longer permits
   forgery. Documented in section 28, not implemented (needs the
   `cryptography` package and breaks the stdlib-only design).
6. **Limit blast radius:** run the monitor as a dedicated low-privilege user
   whose environment holds nothing else worth stealing.

**Residual risk:** if the key is stolen *and* the attacker can write to the
baseline, detection is impossible locally. External anchoring is required.

### Limitation 3 — the local log can be tampered with (or lost)

`filewatch.log` is a plain text file on the same disk as the thing it monitors.
An attacker who can write to the folder can delete their own `ADDED` lines,
forge `INFO` lines, truncate the file, or replace it with binary junk. It can
also simply be lost to disk-full or log rotation. **The dashboard and the
reports inherit whatever the log says** - they visualise evidence, they do not
create it.

**Mitigations**

1. **Ship copies off-box in real time:** use `rsyslog`/`systemd-journal-upload`,
   a `tail -F filewatch.log | logger` pipe, or an append-only remote bucket.
2. **Make the log append-only locally:** `chattr +a filewatch.log` (Linux,
   ext4/xfs) stops rewriting and truncation. Combine with file permissions.
3. **Detect log tampering with FileWatch itself:** put `filewatch.log` inside a
   *second* monitored folder, or add it to a baseline in another location, so
   deletions and truncations become `MODIFIED`/`DELETED` events.
4. **Watch `malformed_lines`.** A sudden burst of unparsable lines - shown in the
   dashboard as an info banner and counted in every report - often means the log
   was appended to, interleaved by a second process, or replaced.
5. **Prefer WORM / append-only storage** for anything you may need as evidence.
6. **Note the clock.** Timestamps come from the local machine; a host with a
   wrong (or attacker-set) clock produces misleading timelines. Keep NTP
   healthy, or timestamp at the log shipper instead.

**Residual risk:** with only local storage, a determined attacker can always
cover their tracks. Only off-host, append-only storage changes that.

### Limitation 4 — scope: one folder, polling, no prevention

FileWatch only looks at the folder you point it at (default `test_folder`),
only by polling every `--interval` seconds, and it only ever **reads**. It does
not use inotify, so a file created and deleted within one interval is missed
entirely; and it does not block anything (see section 46).

**Mitigations:** use a short interval on small folders, add the folders you care
about explicitly, and pair FileWatch with prevention controls (file permissions,
SELinux/AppArmor, immutable attributes, backups) rather than relying on
detection alone.

### Summary table

| Risk | Detected by FileWatch alone? | Primary mitigation |
|---|---|---|
| Baseline edited | No (looks normal) | `baseline --sign` + `--require-signature` |
| HMAC key stolen | **No** | Off-box copy of baseline; rotate; move to Ed25519 |
| Log edited / truncated | Partly (`malformed_lines`, second monitor) | Ship logs off-box; `chattr +a`; second baseline |
| Change missed between polls | No | Shorter `--interval`; add more folders |
| Attack prevented | **Never** | File permissions, MAC, backups, patching |

## 46. Detection is not prevention

**FileWatch detects changes; it does not prevent attacks.**

Every event in the log describes something that **already happened**. By the
time `ADDED file: shell.php` appears in the dashboard, the file is on disk and
whatever it does has already begun. FileWatch has no ability to:

* block a write, delete or rename,
* stop a process from running,
* quarantine or restore a file,
* prevent privilege escalation, ransomware encryption or data exfiltration.

Concretely:

* an attacker who adds a webshell and deletes nothing will appear as one `ADDED`
  event - after the shell is already reachable;
* ransomware that encrypts 10 000 files shows as 10 000 `MODIFIED` events *while*
  they are being encrypted;
* if the attacker also edits the baseline and holds the key, there may be **no
  event at all**.

That is why integrity monitoring is one layer of defence in depth, never the
whole defence. It answers "did this change?" and "when?" - not "is this safe?"
and never "stop that". Pair it with controls that actually enforce something:
least-privilege file permissions, mandatory access control (SELinux/AppArmor),
read-only or immutable mounts, tested offline backups, and timely patching.

Its real value is **detection and evidence**: noticing an unexpected change
quickly, and being able to say precisely what changed and when.

## 47. Screenshots and demo instructions

A five-minute demonstration that produces everything the dashboard and reports
need. Run it in a **copy** of the project so the shipped samples stay pristine.

```bash
# 1. One-time setup (dashboard only; reports need nothing)
python3 -m venv .venv && . .venv/bin/activate
python3 -m pip install -r requirements.txt

# 2. Baseline, then start the monitor in this terminal
python3 main.py baseline
python3 main.py watch --interval 3

# 3. In a SECOND terminal, generate some events
echo "new file"        > test_folder/demo_added.txt
echo "tampered line"  >> test_folder/file1.txt
rm                     test_folder/file5.txt
echo "ignored"         > test_folder/scratch.tmp     # ignored by .filewatchignore

# 4. Stop the monitor with Ctrl+C, then view the events
python3 report.py events

# 5. Generate the reports
python3 report.py report --format both

# 6. Start the dashboard and open http://localhost:8501
python3 -m streamlit run dashboard.py
```

**Screenshots worth capturing** (each demonstrates a requirement):

1. **`python3 report.py events`** - the parsed event table with counts
   (requirement 1).
2. **Dashboard overview** - the four metric cards (total / added / modified /
   deleted) and the red "Deleted" tile (requirement 2).
3. **Dashboard timeline** - the stacked bar chart after two or three rounds of
   changes, with the bucket selector set to `minute`.
4. **Dashboard with no log** - the empty-state message, proving graceful
   handling of a missing log.
5. **Reports in an editor** - `reports/integrity-report.md` open beside
   `reports/integrity-report.html` in a browser (requirement 3).
6. **Test run** - `python3 -m pytest -q` showing the full green summary.
7. *(Optional)* `ls -l` on the project showing `filewatch.log` and the
   `reports/` directory.

**Before you publish any screenshot:** check that no HMAC key, `.env` content or
absolute `/home/<you>/...` path is visible. FileWatch never prints keys - but
your terminal scrollback might.

## 48. Ethical use

FileWatch is a **defensive, educational** tool for monitoring files on a machine
you own or are explicitly authorised to monitor.

> **LEGAL AND ETHICAL NOTICE:** Scanning or attacking systems you do not own or have written permission to test is illegal. This tool only monitors your own test folder.

* Only point `--folder` at directories you own or have **written permission** to
  monitor. On a work or school machine, get that permission before you start.
* Do not use it to watch another person's files, to build a profile of their
  activity, or to monitor a shared machine without disclosing it. Doing so may
  breach computer-misuse law, privacy law (e.g. GDPR) and your organisation's
  policy.
* FileWatch is **not** a network scanner, port scanner, vulnerability scanner or
  penetration-testing tool. It opens no sockets, sends no traffic and scans
  nothing outside the folder you give it.
* Do not extend it to inspect machines or data you do not own. "It only reads
  files" is not a legal defence if the files are not yours.
* If you find a real security incident, do not investigate it yourself -
  report it through your organisation's incident process.

## 29. Technologies used

* **Python 3.9+** (developed and tested on Python 3.13)
* **`hashlib`** — SHA-256 / SHA-1 digests
* **`pathlib`** — safe, cross-platform path handling
* **`json`** — baseline storage
* **`os` / `os.walk`** — recursive traversal without following symlinks
* **`argparse`** — CLI with commands and validated options
* **`datetime`** — human-readable metadata timestamps
* **`shutil`, `tempfile`** — safe copies and isolated tests
* **`logging`** — structured logging to `filewatch.log` (Week 3)
* **`fnmatch`** — ignore-pattern matching (Week 3)
* **`time`** — polling interval in the watch loop (Week 3)
* **`signal`** — clean `SIGTERM` shutdown (Week 3)
* **`hmac`** — HMAC-SHA256 baseline signatures (Week 4)
* **`secrets`** — cryptographically secure key generation (Week 4)
* **`stat`** — enforcing `0600` on key files (Week 4)
* **`dataclasses`** — typed `LogEvent` / `ParseResult` records (Week 4)
* **`html`** — escaping dynamic values in HTML reports (Week 4)
* **Streamlit** — dashboard UI (Week 4, optional dependency)
* **Plotly / pandas** — timeline chart and event table (Week 4, optional)
* **`unittest` + `unittest.mock`** — Week 1 test suite
* **`pytest`** — Week 2/3 test suites (`tmp_path` fixture)

The **program itself uses only the standard library**. `pytest` is needed only to
run the tests.

## 30. Installation requirements

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

## 31. Project structure

```
file-integrity-checker/
│
├── main.py                 # FileWatch: hashing, snapshot, baseline, check, watch, demo
├── baseline.json           # Saved SHA-256 baseline (sample, committed)
├── .filewatchignore        # Week 3: ignore patterns for scan/check/watch
├── filewatch.log           # Week 3: created at runtime by `watch` (git-ignored)
├── logger_parser.py        # Week 4: log parsing + Markdown/HTML report rendering (stdlib)
├── report.py               # Week 4: reporting CLI (events table, reports) (stdlib)
├── dashboard.py            # Week 4: Streamlit dashboard (metrics, timeline, refresh)
├── requirements.txt        # Week 4: optional dashboard/test dependencies
├── reports/                # Week 4: generated reports (git-ignored)
├── README.md               # This document
├── test_main.py            # Week 1 unittest + Week 2/3 pytest suites (103 tests)
├── .gitignore              # Keeps caches, logs, demo leftovers and secrets out of Git
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

## 32. Step-by-step usage

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

8. **Start continuous monitoring (Week 3)**

   ```bash
   python3 main.py watch             # every 5 seconds
   python3 main.py watch --interval 2
   ```

   In a second terminal, change a file and watch the alert appear:

   ```bash
   echo "hello" > test_folder/new.txt
   echo "edit" >> test_folder/file1.txt
   rm test_folder/file5.txt
   ```

   Stop with `Ctrl+C`. Inspect `filewatch.log` afterwards for the full history.

9. **Try the ignore rules**

   ```bash
   echo noise > test_folder/scratch.tmp     # ignored: *.tmp
   mkdir -p test_folder/.git                # ignored: .git
   python3 main.py check                    # still "No changes detected"
   ```

10. **Parse the log and generate reports (Week 4)**

    ```bash
    python3 report.py events                  # structured event table
    python3 report.py report --format md      # -> reports/integrity-report.md
    python3 report.py report --format html    # -> reports/integrity-report.html
    ```

11. **Open the dashboard (Week 4)**

    ```bash
    python3 -m pip install -r requirements.txt
    python3 -m streamlit run dashboard.py     # http://localhost:8501
    ```

12. **Run the tests**

    ```bash
    python3 -m pytest -v          # Week 1-4 (recommended)
    python3 -m unittest -v        # Week 1 (built in)
    ```

9. **Use another folder or baseline**

   ```bash
   python3 main.py baseline --folder /path/to/my_folder --baseline my.json
   python3 main.py check    --folder /path/to/my_folder --baseline my.json
   ```

> Tip: practise steps 4–6 in a **copy** of the project so the shipped sample files
> stay clean.

## 33. Command-line reference

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

# --- Week 3: continuous monitoring ---
python3 main.py watch                       # monitor every 5 seconds
python3 main.py watch --interval 2          # every 2 seconds
python3 main.py watch --interval 0          # scan back-to-back (test/CPU stress)
python3 main.py watch --once                # one scan then exit (cron/CI)
python3 main.py watch --log my.log          # different log file
python3 main.py watch --ignore rules.txt    # different ignore file
python3 main.py watch --verbose             # DEBUG detail in the log
python3 main.py watch --repeat-alerts       # re-alert while a change persists

# --- Week 4 (stretch): HMAC-signed baselines ---
python3 main.py keygen                              # print a new random key
python3 main.py keygen --out ~/.config/fw/hmac.key  # write a 0600 key file
python3 main.py baseline --sign                     # sign the baseline
python3 main.py check --verify                      # verify, warn if unsigned
python3 main.py check --require-signature           # refuse unsigned baselines
python3 main.py watch --require-signature           # monitor only a signed baseline
python3 main.py check --key-file ~/.config/fw/hmac.key

# --- Week 4: reports and dashboard ---
python3 report.py events                          # parsed events as a table
python3 report.py events --limit 10               # only the 10 most recent
python3 report.py report --format md              # Markdown report
python3 report.py report --format html            # HTML report
python3 report.py report --format both            # both formats
python3 report.py report --out reports --recent 50
python3 report.py events --log /path/to/other.log
python3 -m streamlit run dashboard.py             # dashboard on :8501

# --- Help ---
python3 main.py --help
python3 report.py --help
```

Windows equivalents use `python` instead of `python3`.

## 34. Example terminal output

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

## 35. Error handling

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
| `Ctrl+C` / `SIGTERM` | `[stopped] Monitoring stopped by user...`, exit 130, no traceback |
| Unreadable file during `watch` | Logged at `ERROR`, listed under UNREADABLE, **not** reported as deleted, loop continues |
| File vanishes mid-scan | Logged, treated as unreadable rather than a false deletion |
| `os.walk` raises `OSError` | Logged, scan returns what it collected so far, monitoring continues |
| Ignored directory unreadable | Pruned before descent, so it is never a problem |
| Log file cannot be opened | Warning printed, monitoring continues with console alerts |
| `watch` without a baseline | Clear error, exit 1, **no** baseline created |
| `--interval` negative | Clear error, exit 1 |
| `.filewatchignore` unreadable | Warning logged, built-in patterns still apply |
| `--sign` with no key / short key | Exit 1, baseline **not** written (never silently unsigned) |
| Baseline signature mismatch | Exit 1, baseline rejected, `check`/`watch` stop |
| Signed baseline, no key configured | Exit 1, tells you to set `FILEWATCH_HMAC_KEY` |
| Unsigned baseline with `--verify` | Warning only (Weeks 1–3 keep working) |
| Unsigned baseline with `--require-signature` | Exit 1 |
| Key file mode `0644` | Exit 1, "too permissive; run chmod 600" |
| `keygen --out` inside the project | Exit 1, nothing written |
| `report.py` with a missing log | Warning + a report that says "no data", exit 1 |
| `filewatch.log` malformed | Bad lines counted and shown; good lines still parsed |
| `filewatch.log` larger than 256 MiB | Only the most recent portion is read (reported) |
| Dashboard with no log | Clear empty-state message with the commands to fix it |

Notes:

* `hash_file()` **returns `None`** instead of raising for file problems, so callers
  can skip and continue.
* `ValueError` for an unknown *algorithm* is **not** swallowed: that is a bug or a
  bad flag, and it must be visible.
* The baseline is written atomically (`baseline.json.tmp` → `os.replace`), so a
  crash mid-write cannot corrupt an existing good baseline.
* `check` never writes anything, by design.

## 36. Automated testing instructions

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
191 passed, 6 subtests passed
```

(63 Week 1/2 + 40 Week 3 + 36 HMAC + 5 HMAC-limitation + 47 Week 4 reporting
tests.) The four Streamlit UI tests are skipped automatically when Streamlit is
not installed; the rest of the suite always runs.

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

### Week 3 test coverage

| Area | Representative tests |
|---|---|
| Monitoring loop | `test_w3_watch_alerts_added_modified_deleted`, `test_w3_scan_once_returns_snapshot_and_result`, `test_w3_watch_returns_ok_after_requested_scans` |
| Changed files | `test_w3_watch_logs_every_change_and_scan`, `test_w3_watch_repeats_alerts_or_not` |
| Ignore rules | `test_w3_ignore_rules_match_globs_and_folder_names`, `test_w3_ignored_files_never_enter_a_baseline`, `test_w3_ignored_files_never_trigger_alerts`, `test_w3_watch_reports_no_change_for_ignored_files`, `test_w3_ignore_rules_prune_ignored_directories_early`, `test_w3_shipped_filewatchignore_covers_required_patterns` |
| Permission errors | `test_w3_permission_error_is_logged_and_monitoring_continues`, `test_w3_unreadable_file_is_not_reported_as_deleted`, `test_w3_unreadable_file_that_really_vanishes_is_deleted` |
| Disappearing files | `test_w3_file_disappearing_between_walk_and_read`, `test_w3_oserror_in_walk_does_not_stop_the_scan` |
| Clean shutdown | `test_w3_ctrl_c_exits_cleanly_without_traceback`, `test_w3_sigterm_is_translated_to_clean_exit` |
| Logging hygiene | `test_w3_setup_logging_does_not_duplicate_handlers`, `test_w3_logger_does_not_propagate_to_root`, `test_w3_reset_logging_removes_managed_handlers`, `test_w3_log_has_timestamp_level_and_message` |
| Alerts & colour | `test_w3_format_alerts_lists_relative_paths`, `test_w3_colour_autodetection_respects_no_color`, `test_w3_unreadable_files_are_shown_in_alerts` |
| HMAC limitations (Week 4) | `test_w4_limitation_baseline_is_not_encrypted`, `test_w4_limitation_stolen_key_allows_forgery`, `test_w4_limitation_without_the_key_forgery_is_detected`, `test_w4_limitation_rollback_cannot_be_detected`, `test_w4_limitation_log_is_plaintext_and_unsigned` |
| Backward compatibility | `test_w3_week1_and_week2_apis_keep_their_old_signatures`, `test_w3_cli_still_supports_every_previous_command`, `test_w3_cli_parses_watch_options`, `test_w3_demo_still_never_modifies_originals`, `test_w3_shipped_files_still_verify_against_shipped_baseline` |

The five `test_w4_limitation_*` tests assert what HMAC does **not** do - the
baseline stays plaintext, a stolen key permits forgery, a keyless attacker is
still blocked, signed baselines can be replayed, and the log is unsigned. They
are executable documentation: if someone later overstates the guarantee, these
tests show the real boundary.

### Week 4 test coverage

| Area | Representative tests |
|---|---|
| Log parsing | `test_w4_parse_single_line_extracts_all_fields`, `test_w4_parse_all_change_event_types`, `test_w4_parse_preserves_nested_and_unusual_paths`, `test_w4_parse_tolerates_extra_whitespace` |
| Counts | `test_w4_parse_counts_and_line_accounting`, `test_w4_event_counts_are_correct`, `test_w4_parse_ignores_info_lines_as_events` |
| Missing / empty / malformed logs | `test_w4_missing_log_is_handled`, `test_w4_empty_log_is_handled`, `test_w4_malformed_lines_are_counted_not_fatal`, `test_w4_unreadable_log_is_handled`, `test_w4_log_with_traceback_lines_is_partially_parsed` |
| Timeline | `test_w4_timeline_buckets_by_minute`, `test_w4_timeline_hour_and_day_buckets`, `test_w4_timeline_rejects_unknown_bucket` |
| Report generation | `test_w4_markdown_report_contains_required_sections`, `test_w4_html_report_is_valid_and_escapes_html`, `test_w4_write_report_markdown_and_html`, `test_w4_report_handles_missing_log` |
| Secrets hygiene | `test_w4_reports_never_contain_secrets`, `test_w4_no_secrets_or_keys_in_repo_docs` |
| Report CLI | `test_w4_report_cli_generates_both_formats`, `test_w4_report_cli_handles_missing_log`, `test_w4_events_cli_prints_a_table` |
| Dashboard data layer | `test_w4_dashboard_data_from_log`, `test_w4_dashboard_data_missing_log`, `test_w4_dashboard_events_to_csv` |
| Dashboard UI (Streamlit) | `test_w4_streamlit_dashboard_renders_events`, `test_w4_streamlit_dashboard_empty_state`, `test_w4_streamlit_dashboard_refresh_button_exists`, `test_w4_streamlit_dashboard_malformed_log` |
| Documentation | `test_w4_readme_documents_limitations_and_ethics` |

`test_w4_readme_documents_limitations_and_ethics` fails the build if the README
stops documenting the three risks, "does not prevent", or the exact legal
notice - so the documentation cannot silently rot.

**Determinism.** No test sleeps: the watch loop is called with `interval=0` and
`max_scans=N`, which exits after N scans. Clean shutdown is tested by making the
scan raise `KeyboardInterrupt` (exactly what the signal handler does), so the
suite finishes in well under a second and is safe in CI.

## 37. Manual hash verification

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

## 38. Troubleshooting

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
| `watch` re-alerts the same file | Change still differs from the reference | Default alerts once; use `--repeat-alerts` to change that deliberately |
| Alerts have no colour | Output is piped, not a TTY, or `NO_COLOR` is set | Expected; disable-safe by design |
| `filewatch.log` missing | `watch` was never run (only `watch` logs) | Run `python3 main.py watch --once` |
| Log lines duplicated | A foreign handler was added by your own code | FileWatch only manages its own handlers; check yours |
| `watch` exits immediately with code 1 | No baseline, or the folder is missing | Run `python3 main.py baseline` first |
| Ignored file still alerts | Pattern does not match (matching is case-sensitive) | Test with `--verbose` and check the log's `Skipped entry` lines |
| Huge folder, high CPU | Polling re-hashes everything each scan | Increase `--interval`, or add caches to `.filewatchignore` |
| `No HMAC key configured` | Signing/verifying without a key | `python3 main.py keygen` then export the key |
| `key is too short` | Fewer than 32 bytes | Use `keygen` (32 random bytes) |
| `Key file ... too permissive` | Mode is not `0600` | `chmod 600 <file>` |
| `signature MISMATCH` after re-baselining | New baseline data, old signature | Re-sign: `baseline --sign` |
| Signature mismatch but you did not edit it | Wrong key, or the baseline really was changed | Investigate **before** re-signing |
| `ModuleNotFoundError: No module named 'streamlit'` | Dashboard deps not installed | `python3 -m pip install -r requirements.txt` |
| Dashboard shows "Log file not found" | `watch` has never run | `python3 main.py watch --once`, then Refresh |
| Dashboard shows zero events but the log is full | Log has only INFO lines, or the path is wrong | Check `python3 report.py events --log <path>` |
| `report.py` prints "no events" | No changes have been detected yet | Change a file while `watch` is running |
| Port 8501 already in use | Another Streamlit app is running | `--server.port 8502` |

## 39. Roadmap and responsible use

Completed in Week 3: continuous watch mode with a configurable interval,
structured logging, `.filewatchignore` rules, coloured alerts, robust error
handling and clean shutdown.

Completed in Week 4 (stretch): HMAC-SHA256 signed baselines with safe key
management (`keygen`, `--sign`, `--verify`, `--require-signature`) — section 28.

Possible next steps:

* `--report json` so results can be consumed by other tools.
* Multiple baselines / snapshots over time, with history.
* Inotify/ReadDirectoryChangesW notifications instead of polling.
* Key rotation with a key-id field, so old and new signatures can coexist.
* Anti-rollback: anchor the baseline signature in an external trusted store.
* Ship logs to a remote append-only store (syslog/S3 Object Lock) to defeat the
  log-tampering limitation in section 45.
* Replace polling with inotify/ReadDirectoryChangesW for real-time detection.

**Responsible use.** This is an educational tool for monitoring files on your own
machine.

> **LEGAL AND ETHICAL NOTICE:** Scanning or attacking systems you do not own or have written permission to test is illegal. This tool only monitors your own test folder.

It reads only the folder you point at, follows no symbolic links, opens no network
connections, and collects no data about other systems. Do not modify it to inspect
machines or data you do not own or have explicit written authorisation to test.

---

## 49. Enhanced edition: structured events and a SQLite store

This is the **enhanced Week 4 edition** (`filewatch-week4-enhanced.zip`). It keeps
every Week 1-4 command, file format and test exactly as it was and adds two things
on top:

1. **`events.jsonl`** - a machine-readable, append-only event log written
   alongside (never instead of) `filewatch.log`.
2. **`filewatch.db`** - a SQLite database that stores the same events so they
   can be filtered, charted and reported on efficiently.

Neither is mandatory. If you delete `events.jsonl` and `filewatch.db`, the tool
behaves exactly as it did in Week 4: `baseline`, `check`, `watch`, `keygen`,
`report.py` and `dashboard.py` all still work from `filewatch.log` alone.

### How the pieces fit together

```
                    +---------------------+
 monitored folder -> | scan + SHA-256 hash | -> changes detected
                    +---------------------+
                              |
              +---------------+----------------+
              |                                |
       filewatch.log                    events.jsonl
   (human-readable, Week 3)        (one JSON object per line)
              |                                |
       logger_parser.py                  import-events
              |                                |
     report.py / dashboard.py          filewatch.db (SQLite)
              |                                |
              +------------> report.py / dashboard.py <----------+
                                 (--source log | --source db)
```

* `watch` writes **both** files at the same moment, from the same detection.
* `filewatch.log` is unchanged: same format string, same parser, same reports.
* Importing is **idempotent** - run it as often as you like.

## 50. `events.jsonl` format

UTF-8, one compact JSON object per line, append-only, timestamps in **UTC**.
Field order is fixed so diffs and `tail -f` stay readable:

| Field | Type | Meaning |
| --- | --- | --- |
| `timestamp` | string | ISO 8601 UTC, `YYYY-MM-DDTHH:MM:SSZ` |
| `event_type` | string | `ADDED`, `MODIFIED` or `DELETED` |
| `path` | string | path relative to the monitored folder, POSIX separators |
| `algorithm` | string or null | `sha256` / `sha1`, null when unknown |
| `old_hash` | string or null | previous digest (null for `ADDED`) |
| `new_hash` | string or null | current digest (null for `DELETED`) |
| `source` | string | `watch` (from the monitor) or `import` |

Real lines from a test run (hashes truncated here for width only - the file
contains full 64-character digests):

```json
{"timestamp":"2026-11-25T18:50:11Z","event_type":"ADDED","path":"d.txt","algorithm":"sha256","old_hash":null,"new_hash":"0f15384d18...","source":"watch"}
{"timestamp":"2026-11-25T18:50:11Z","event_type":"MODIFIED","path":"a.txt","algorithm":"sha256","old_hash":"b6a98d9ce9...","new_hash":"f05f6f5ba8...","source":"watch"}
{"timestamp":"2026-11-25T18:50:11Z","event_type":"DELETED","path":"b.txt","algorithm":"sha256","old_hash":"f2c82decdd...","new_hash":null,"source":"watch"}
```

Nothing is written when a scan finds no changes.

**Robustness rules**

* A malformed line, a missing field or an unparsable timestamp is **skipped and
  reported**, never silently dropped and never fatal - see `read_events()`.
* A file that cannot be read is logged as `UNREADABLE` in `filewatch.log` but is
  **not** written to `events.jsonl`. An unknown file has no trustworthy hash, so
  the tool refuses to guess.
* No secrets are ever written: the HMAC key is never touched by this module.
* If `events.jsonl` cannot be written (read-only folder, full disk), a warning is
  logged and monitoring continues on `filewatch.log` as before.

## 51. SQLite database: schema and setup

Created automatically on first import; nothing to install (SQLite ships with
Python).

```sql
CREATE TABLE events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id    TEXT NOT NULL UNIQUE,   -- de-duplication key
    timestamp   TEXT NOT NULL,          -- ISO 8601 UTC, sortable as text
    event_type  TEXT NOT NULL,
    path        TEXT NOT NULL,
    algorithm   TEXT,
    old_hash    TEXT,
    new_hash    TEXT,
    source      TEXT NOT NULL,
    imported_at TEXT NOT NULL           -- when this row entered the DB
);
CREATE INDEX idx_events_timestamp ON events(timestamp);
CREATE INDEX idx_events_type      ON events(event_type);
CREATE INDEX idx_events_path      ON events(path);
```

* **Parameterised SQL only** - every user value is a bound parameter. There is no
  string-built SQL anywhere in `database.py`.
* **Transactions** - a whole import is one transaction; it either lands or rolls
  back, so a crash cannot leave half a batch behind.
* **Never destructive** - no `DELETE`, no `DROP`, no "reset on startup". Your
  history is never thrown away by the tool.
* `PRAGMA journal_mode=WAL` and `PRAGMA user_version=1` are set on connect.

**Uniqueness strategy (why re-importing cannot duplicate rows).** Each row gets

```
event_id = sha256(timestamp ␟ event_type ␟ path ␟ algorithm ␟ old_hash ␟ new_hash)
```

The column is `UNIQUE` and rows are inserted with `INSERT OR IGNORE`, so the
database treats an event as "the same event" if and only if all its identifying
content matches. Import the same file ten times: rows 2-10 change nothing.
`import-events` reports the split as `Imported` / `Duplicates`.

**Timezone handling.** Everything is stored in UTC, so comparing the ISO strings
gives chronological order. A bare `--start 2026-11-01` means
`2026-11-01T00:00:00Z` and a bare `--end 2026-11-30` means
`2026-11-30T23:59:59Z` - **both ends are inclusive of the whole day**. An
explicit offset such as `2026-11-25T12:00:00+02:00` is converted to UTC
(`10:00:00Z`) before comparing.

## 52. Monitor -> database workflow

```bash
# 1. start the monitor (writes filewatch.log AND events.jsonl)
python3 main.py baseline
python3 main.py watch --interval 5

# 2. load the events into SQLite (safe to repeat)
python3 main.py import-events
```

`import-events` prints what it did:

```
Events file: events.jsonl
Database   : filewatch.db
Imported   : 3 new event(s)
Duplicates : 0 already present (skipped)
Total in DB: 3 event(s)
Range      : 2026-11-25T18:50:11Z .. 2026-11-25T18:50:11Z
```

**Retry and recovery.** Import is pure "read the file, insert what is missing",
which makes failure easy to recover from:

| Situation | What to do |
| --- | --- |
| Import crashed halfway | Run `import-events` again. Loaded rows are skipped as duplicates. |
| Database deleted or corrupted | Point `--db` at a new file and re-import the whole JSONL. JSONL is the source of truth. |
| Events missed while the DB was down | They are still in `events.jsonl`; the next import picks them up. |
| A line was hand-edited into nonsense | It is counted as malformed and listed; fix or delete that line, re-import. |

SQLite is **never** required for Weeks 1-3 behaviour - the monitor does not
depend on it and will not fail if it is absent or locked.

## 53. Querying events

```bash
python3 main.py query-events                                  # newest 20
python3 main.py query-events --limit 100                      # more rows
python3 main.py query-events --type MODIFIED                  # one type
python3 main.py query-events --start 2026-11-01 --end 2026-11-30
python3 main.py query-events --path documents/                # contains
python3 main.py query-events --start 2026-11-01 --end 2026-11-30 \
                             --type DELETED --path documents/ # combined
python3 main.py query-events --db /path/to/other.db           # other database
```

Every filter combines with AND. `--path` is a substring match and is escaped, so
a literal `%` or `_` in a filename is matched literally rather than acting as a
wildcard. An unparsable date gives a clear error and exit code 1.

## 54. Reports from SQLite

`report.py` gains `--source db` (default stays `log`, so Week 4 behaviour is
byte-for-byte unchanged):

```bash
python3 report.py report --source db --format md
python3 report.py report --source db --format both --out reports
python3 report.py report --source db --start 2026-11-01 --end 2026-11-30
python3 report.py report --source db --type MODIFIED --format html
python3 report.py events --source db --limit 50
```

DB reports are written as `reports/integrity-report-db.md` and
`.html`, carry a **Data source: SQLite database** line plus the active filters,
and are rendered by the same escaping-aware functions used in Week 4 (HTML
special characters in paths are escaped). An empty or missing database still
produces a report that states the problem - never a crash.

## 55. Dashboard with date and type filters

```bash
python3 -m pip install -r requirements.txt
python3 -m streamlit run dashboard.py
```

In the sidebar choose **Data source -> SQLite database** to get:

* total matching changes and ADDED / MODIFIED / DELETED counts,
* an inclusive **start date** / **end date** filter (`YYYY-MM-DD`),
* an **event type** filter (leave all selected for every type),
* an optional "path contains" filter and an hour/day timeline bucket,
* the most recent events table with CSV download, plus Markdown/HTML report
  downloads built from exactly what is on screen,
* a **Refresh** button and an auto-refresh toggle.

The dashboard reads the database in bounded queries (`MAX_ROWS = 5000`) and
counts, timeline bucketing and filtering all happen inside SQLite, so it never
pulls the whole table into memory. A missing database, an empty database, a
corrupt file, a locked file or a bad date each produce a clear on-screen message
instead of a traceback. Switch back to **Text log** at any time for the Week 4
view.

Useful environment variables: `FILEWATCH_LOG` (log path) and `FILEWATCH_DB`
(database path), both overridable by the text boxes in the sidebar.

## 56. Repository layout (enhanced edition)

```
main.py            engine, watch loop, CLI (incl. import-events / query-events)
event_logger.py    NEW - events.jsonl writer/reader and schema validation
database.py        NEW - SQLite schema, import, filtering, aggregation
logger_parser.py   filewatch.log parser + Markdown/HTML renderers (now also
                   renders DB rows via result_from_events())
report.py          report CLI (--source log|db)
dashboard.py       Streamlit dashboard (log or SQLite source)
test_main.py       Weeks 1-4 suite (unchanged)
test_enhanced.py      NEW - enhanced-edition suite (62 tests)
requirements.txt   streamlit, plotly, pytest (all optional except for the dashboard)
```

## 57. Testing the enhanced edition

```bash
python3 -m pytest -q                 # everything: 253 passed
python3 -m pytest test_enhanced.py -q   # enhanced suite only: 62 passed
python3 -m unittest test_enhanced -v    # same 62 tests, stdlib runner
python3 -m unittest test_main -v     # 36 TestCase classes from Weeks 1-4
```

Coverage includes: database creation and schema, insertion, persistence across
connections, duplicate prevention, inclusive date filtering, type filtering,
combined filters, empty database, corrupt database, malformed JSONL, missing
fields, invalid timestamps, DB-sourced Markdown/HTML reports, empty-data
reports, dashboard date/type filtering, and guards that Week 1-4 commands and
the sample folder are untouched. Every test uses a temporary directory - the
real `baseline.json`, `filewatch.log`, `events.jsonl` and `filewatch.db` are
never touched.

## 58. Limitations of the enhanced edition

The five core limitations from section 45 still apply unchanged. The enhanced
edition adds storage, so the honest position on the new files is:

1. **`events.jsonl` and `filewatch.db` are ordinary local files.** Neither is
   tamper-proof. Anyone who can write to the project directory - especially
   root, or malware running as your user - can edit, truncate or delete them,
   and the tool cannot tell. *Mitigation:* treat them as convenience stores for
   analysis, not as evidence; ship events to a remote append-only store
   (syslog, S3 Object Lock) if you need an audit trail you can defend, and keep
   filesystem permissions tight (`chmod 600`, directory `700`).
2. **A privileged attacker can also edit rows directly in SQLite.** The
   `event_id` uniqueness column prevents accidental duplicates, not deliberate
   forgery. *Mitigation:* the same remote-logging answer, plus cross-checking the
   database against `filewatch.log` (both are written from the same detection,
   so a mismatch is itself a signal).
3. **Import is one-way and lossy about what it could not read.** Malformed lines
   are reported and skipped. If you lose `events.jsonl` before importing, the
   history exists only in `filewatch.log` in human-readable form. *Mitigation:*
   import on a schedule (cron), keep a `.jsonl` copy outside the project.
4. **Polling still may miss a create-and-delete between two scans,** so no event
   is recorded at all - a database cannot fix that. *Mitigation:* shorter
   `--interval`, and inotify-based monitoring as future work.
5. **Timestamps come from the local clock.** A wrong clock puts events in the
   wrong date bucket. *Mitigation:* keep NTP enabled; UTC storage at least
   removes DST/year-boundary ambiguity.
6. **Date filters are whole-day and UTC-based.** `--start 2026-11-25` means
   00:00Z-23:59Z, which is not midnight-to-midnight in Accra or Lagos
   (UTC+0 is forgiving, UTC+2 is not). *Mitigation:* pass full ISO timestamps
   with an offset when you need exact boundaries.
7. **Detection is still not prevention.** FileWatch detects and reports changes
   to files you own; it does not block, quarantine or reverse them.

> **LEGAL AND ETHICAL NOTICE:** Scanning or attacking systems you do not own or have written permission to test is illegal. This tool only monitors your own test folder.
