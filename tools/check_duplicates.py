#!/usr/bin/env python3
"""
check_duplicates.py — Verify that intentionally duplicated skill scripts are
still byte-identical across the repository.

============================================================================
WHY THIS EXISTS
============================================================================
Several scripts are deliberately shipped in two places so that each skill
stays self-contained and installable on its own:

    skills/virustotal/scripts/vt_lookup.py
    skills/ioc-orchestrator/scripts/vt_lookup.py          (same file)

That duplication is a feature — a user can install just the `virustotal`
skill without pulling in the orchestrator. The risk is that someone edits
one copy and forgets the other, leaving the two silently out of sync.

This script is the guard: it hashes every duplicated filename and fails if
any pair has drifted. Run it before committing, or wire it into CI.

============================================================================
INPUT
============================================================================
    (none)                Scans the repository this script lives in.
    --root DIR            Scan a different directory instead.
    --fix                 Copy the NEWEST version of each drifted file over
                          the older ones. Use only after checking the diff —
                          this overwrites files.

============================================================================
OUTPUT
============================================================================
Human-readable report on stdout, one block per duplicated filename:

    OK    vt_lookup.py           2 copies in sync (sha 136329be)
    DRIFT ioc_extractor.py       2 copies differ:
            f2dd5899  skills/ioc-extractor/scripts/ioc_extractor.py
            a91b0c33  skills/email-triage-pipeline/scripts/ioc_extractor.py

============================================================================
EXIT CODES
============================================================================
    0  every duplicate set is in sync (or --fix resolved them)
    1  at least one set has drifted
    2  usage / filesystem error
============================================================================
"""

import argparse
import hashlib
import os
import shutil
import sys
from collections import defaultdict

# Filenames that are intentionally duplicated across skills. Anything not on
# this list is expected to be unique; if a NEW duplicate appears it is
# reported too, so the list stays honest.
KNOWN_DUPLICATES = {
    "ioc_extractor.py",
    "vt_lookup.py",
    "abuseipdb_lookup.py",
    "otx_lookup.py",
    "ha_lookup.py",
    "urlscan_lookup.py",
}


def sha(path):
    """Return the SHA-256 hex digest of a file (streamed, memory-safe)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def collect(root):
    """Map every *.py basename under skills/ to the list of paths using it.

    Input : root — repository root directory
    Output: {basename: [relative paths...]} containing only names that occur
            more than once.
    """
    by_name = defaultdict(list)
    skills_dir = os.path.join(root, "skills")
    for dirpath, _dirnames, filenames in os.walk(skills_dir):
        for fn in filenames:
            if fn.endswith(".py"):
                full = os.path.join(dirpath, fn)
                by_name[fn].append(os.path.relpath(full, root))
    return {k: v for k, v in by_name.items() if len(v) > 1}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Check that duplicated skill scripts stay in sync.")
    ap.add_argument("--root", default=os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))),
        help="repository root (default: parent of this script's directory)")
    ap.add_argument("--fix", action="store_true",
                    help="overwrite older copies with the newest one")
    args = ap.parse_args(argv)

    if not os.path.isdir(os.path.join(args.root, "skills")):
        print(f"error: no skills/ directory under {args.root}",
              file=sys.stderr)
        return 2

    dupes = collect(args.root)
    if not dupes:
        print("No duplicated scripts found.")
        return 0

    drifted = 0
    for name in sorted(dupes):
        paths = sorted(dupes[name])
        hashes = {p: sha(os.path.join(args.root, p)) for p in paths}
        unique = set(hashes.values())

        if name not in KNOWN_DUPLICATES:
            print(f"NEW   {name:<24} {len(paths)} copies found — add it to "
                  "KNOWN_DUPLICATES or de-duplicate it")

        if len(unique) == 1:
            print(f"OK    {name:<24} {len(paths)} copies in sync "
                  f"(sha {list(unique)[0][:8]})")
            continue

        drifted += 1
        print(f"DRIFT {name:<24} {len(paths)} copies differ:")
        for p in paths:
            mtime = os.path.getmtime(os.path.join(args.root, p))
            print(f"        {hashes[p][:8]}  {p}")
        if args.fix:
            # Newest wins — the assumption is that the most recent edit is
            # the intended one. Always eyeball a diff before trusting this.
            newest = max(paths, key=lambda p: os.path.getmtime(
                os.path.join(args.root, p)))
            for p in paths:
                if p != newest:
                    shutil.copy2(os.path.join(args.root, newest),
                                 os.path.join(args.root, p))
                    print(f"        fixed: {p}  <-  {newest}")
            drifted -= 1

    if drifted:
        print(f"\n{drifted} duplicate set(s) out of sync. "
              "Re-run with --fix after reviewing the differences.")
        return 1
    print("\nAll duplicate sets are in sync.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
