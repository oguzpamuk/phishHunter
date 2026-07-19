#!/usr/bin/env python3
"""
ioc_orchestrator.py - Multi-source IOC triage orchestrator.

Purpose:
    SOC / email-security "one command" triage. Takes one or more IOCs,
    auto-detects each IOC's type (IP, domain, URL, file hash, or a local
    file path), then queries every applicable threat-intel source IN
    PARALLEL by invoking the individual skill CLI scripts as subprocesses:

        VirusTotal       -> vt_lookup.py         (env: VT_API_KEY)
        AbuseIPDB        -> abuseipdb_lookup.py  (env: ABUSEIPDB_API_KEY)
        urlscan.io       -> urlscan_lookup.py    (env: URLSCAN_API_KEY)
        AlienVault OTX   -> otx_lookup.py        (env: OTX_API_KEY)
        Hybrid Analysis  -> ha_lookup.py         (env: HYBRID_ANALYSIS_API_KEY)

    Results are merged into one aggregated JSON report with an overall
    verdict per IOC and for the whole run. Sources with a missing API key
    are skipped gracefully (never a fatal error).

Inputs (positional):
    ioc [ioc ...]        One or more IOCs. Type detection order:
                           1. existing local file path -> "file"
                              (SHA256 computed locally; queried as hash
                               unless --upload is given)
                           2. valid IPv4/IPv6 address  -> "ip"
                           3. MD5/SHA1/SHA256 hex      -> "hash"
                           4. has http(s):// scheme    -> "url"
                           5. otherwise                -> "domain"

Options:
    --sources LIST       Comma-separated source ids to use; subset of
                         "vt,abuseipdb,urlscan,otx,ha". Default: all.
    --timeout N          Per-source subprocess timeout in seconds
                         (default 420 - sandbox/URL scans poll for a while).
    --workers N          Max parallel worker threads (default 8).
    --upload             For local files: upload to VT + Hybrid Analysis
                         sandboxes instead of only hash lookups.
                         WARNING: uploads are shared with those communities.
    --raw                Keep each source's full JSON output in the report
                         (default keeps the condensed summaries only).
    --scripts-dir PATH   Directory containing the five source scripts.
                         Default: the directory this script lives in.

Output (stdout):
    Single JSON document:
        {
          "results": [
            {
              "ioc": "...",
              "detected_type": "ip|domain|url|hash|file",
              "sha256": "...",                     # only for local files
              "overall_verdict": "malicious|suspicious|clean|unknown",
              "verdict_breakdown": {"<source>": "<verdict>", ...},
              "sources": {"<source>": {<summary JSON from that tool>}},
              "skipped": {"<source>": "<reason>"},
              "errors":  {"<source>": "<error text>"}
            }, ...
          ],
          "overall_verdict": "<worst verdict across all IOCs>"
        }

Exit codes:
    0 = run completed, nothing malicious
    1 = fatal orchestrator error (bad args, scripts missing)
    2 = run completed and at least one IOC verdict is MALICIOUS
"""

import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys

# ---------------------------------------------------------------------------
# Source registry: one entry per threat-intel source.
#   script   : filename of the CLI tool (expected in --scripts-dir)
#   env      : API key environment variable required for that source
#   commands : maps IOC type -> list of CLI args to run for that type.
#              "{ioc}" is replaced with the IOC value at run time.
#              IOC types absent from the map mean "source not applicable".
# ---------------------------------------------------------------------------
SOURCES = {
    "virustotal": {
        "id": "vt",
        "script": "vt_lookup.py",
        "env": "VT_API_KEY",
        "commands": {
            "ip":     ["ip", "{ioc}"],
            "domain": ["domain", "{ioc}"],
            "url":    ["url", "{ioc}"],
            "hash":   ["hash", "{ioc}"],
            "upload": ["upload", "{ioc}"],   # used only with --upload
        },
    },
    "abuseipdb": {
        "id": "abuseipdb",
        "script": "abuseipdb_lookup.py",
        "env": "ABUSEIPDB_API_KEY",
        "commands": {
            "ip": ["check", "{ioc}"],        # AbuseIPDB is IP-only
        },
    },
    "urlscan": {
        "id": "urlscan",
        "script": "urlscan_lookup.py",
        "env": "URLSCAN_API_KEY",
        "commands": {
            "ip":     ["search-ip", "{ioc}"],
            "domain": ["search-domain", "{ioc}"],
            "url":    ["scan", "{ioc}"],     # live scan for URLs
            "hash":   ["search-hash", "{ioc}"],
        },
    },
    "alienvault-otx": {
        "id": "otx",
        "script": "otx_lookup.py",
        "env": "OTX_API_KEY",
        "commands": {
            "ip":     ["ip", "{ioc}"],
            "domain": ["domain", "{ioc}"],
            "url":    ["url", "{ioc}"],
            "hash":   ["hash", "{ioc}"],
        },
    },
    "hybrid-analysis": {
        "id": "ha",
        "script": "ha_lookup.py",
        "env": "HYBRID_ANALYSIS_API_KEY",
        "commands": {
            "hash":   ["hash", "{ioc}"],
            "upload": ["upload", "{ioc}"],   # used only with --upload
        },
    },
}

# Verdict severity ranking used for aggregation (higher = worse).
VERDICT_RANK = {"unknown": 0, "clean": 1, "suspicious": 2, "malicious": 3}


def detect_type(ioc: str) -> str:
    """
    Auto-detect the IOC type from its syntax.

    Input:  raw IOC string (or local path).
    Output: "file" | "ip" | "hash" | "url" | "domain"
    Detection order matters: a 64-char hex filename on disk should be
    treated as a file, so the file check runs first.
    """
    if os.path.isfile(ioc):
        return "file"
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError:
        pass
    if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", ioc):
        return "hash"
    if re.match(r"^https?://", ioc, re.IGNORECASE):
        return "url"
    # Fallback: anything else is treated as a domain/hostname.
    return "domain"


def sha256_of_file(path: str) -> str:
    """
    Compute the SHA256 of a local file without loading it fully into RAM.

    Input:  file path.
    Output: lowercase hex SHA256 digest string.
    """
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run_source(source_name: str, script_path: str, cli_args, timeout: int):
    """
    Execute one source CLI script as a subprocess and parse its JSON output.

    Input:
        source_name : registry key, e.g. "virustotal" (for error messages)
        script_path : absolute path to the tool script
        cli_args    : list of arguments after the script path
        timeout     : max seconds to wait before killing the subprocess
    Output:
        (summary_dict_or_None, error_string_or_None)
        Note: the tools exit with code 2 for "malicious" - that is a
        SUCCESS from the orchestrator's point of view, so only stderr with
        unparseable stdout counts as an error.
    """
    cmd = [sys.executable, script_path] + cli_args
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, f"timeout after {timeout}s"
    except OSError as exc:
        return None, f"failed to execute: {exc}"

    stdout = (proc.stdout or "").strip()
    if stdout:
        try:
            return json.loads(stdout), None
        except json.JSONDecodeError:
            return None, f"non-JSON output: {stdout[:300]}"
    # No stdout at all -> report whatever the tool wrote to stderr.
    return None, (proc.stderr or "no output").strip()[:300]


def triage_ioc(ioc: str, args, scripts_dir: str, executor) -> dict:
    """
    Fan out one IOC to all applicable+enabled sources in parallel.

    Input:
        ioc         : the IOC string
        args        : parsed argparse namespace (sources filter, upload, ...)
        scripts_dir : directory containing the tool scripts
        executor    : shared ThreadPoolExecutor for parallelism
    Output:
        Per-IOC result dict (see module docstring "results" schema).
    """
    ioc_type = detect_type(ioc)
    result = {"ioc": ioc, "detected_type": ioc_type,
              "sources": {}, "skipped": {}, "errors": {},
              "verdict_breakdown": {}}

    # Local files: either upload to sandboxes, or hash-lookup everywhere.
    # In hash mode we rewrite the IOC to its SHA256 and treat it as "hash".
    effective_ioc, effective_type = ioc, ioc_type
    if ioc_type == "file" and not args.upload:
        result["sha256"] = sha256_of_file(ioc)
        effective_ioc, effective_type = result["sha256"], "hash"
    elif ioc_type == "file" and args.upload:
        effective_type = "upload"

    # Build the list of (source_name, future) jobs to run in parallel.
    futures = {}
    enabled = {s.strip() for s in args.sources.split(",")} if args.sources else None
    for name, cfg in SOURCES.items():
        if enabled and cfg["id"] not in enabled:
            continue  # user restricted the source list with --sources
        template = cfg["commands"].get(effective_type)
        if template is None:
            continue  # this source does not support this IOC type
        if not os.environ.get(cfg["env"], "").strip():
            result["skipped"][name] = f"{cfg['env']} not set"
            continue
        script_path = os.path.join(scripts_dir, cfg["script"])
        if not os.path.isfile(script_path):
            result["errors"][name] = f"script not found: {script_path}"
            continue
        cli_args = [a.replace("{ioc}", effective_ioc) for a in template]
        if args.raw:
            # Forward --raw so each tool emits its full raw API JSON
            # instead of the condensed summary.
            cli_args.append("--raw")
        futures[name] = executor.submit(run_source, name, script_path,
                                        cli_args, args.timeout)

    # Collect results as the parallel jobs finish.
    for name, fut in futures.items():
        summary, err = fut.result()
        if err:
            result["errors"][name] = err
            continue
        verdict = summary.get("verdict", "unknown")
        result["verdict_breakdown"][name] = verdict
        result["sources"][name] = summary

    # Aggregate: overall verdict for this IOC = worst source verdict.
    verdicts = list(result["verdict_breakdown"].values()) or ["unknown"]
    result["overall_verdict"] = max(verdicts, key=lambda v: VERDICT_RANK.get(v, 0))
    return result


def main():
    """CLI entry point: parse args, run all IOCs, print aggregated JSON."""
    parser = argparse.ArgumentParser(
        description="Parallel multi-source IOC triage orchestrator")
    parser.add_argument("iocs", nargs="+",
                        help="IOC(s): IP, domain, URL, hash, or local file path")
    parser.add_argument("--sources", default=None,
                        help="Comma-separated source ids: vt,abuseipdb,urlscan,otx,ha")
    parser.add_argument("--timeout", type=int, default=420,
                        help="Per-source timeout in seconds (default 420)")
    parser.add_argument("--workers", type=int, default=8,
                        help="Max parallel workers (default 8)")
    parser.add_argument("--upload", action="store_true",
                        help="Upload local files to VT/HA sandboxes "
                             "(shared with their communities!)")
    parser.add_argument("--raw", action="store_true",
                        help="Include full per-source JSON in the report")
    parser.add_argument("--scripts-dir",
                        default=os.path.dirname(os.path.abspath(__file__)),
                        help="Directory containing the five tool scripts")
    args = parser.parse_args()

    # Sanity check: at least one API key must be set, otherwise every
    # source would be skipped and the run would be pointless.
    if not any(os.environ.get(cfg["env"], "").strip() for cfg in SOURCES.values()):
        sys.stderr.write("ERROR: no API keys set. Export at least one of: "
                         + ", ".join(c["env"] for c in SOURCES.values()) + "\n")
        sys.exit(1)

    # One shared thread pool: parallelism spans BOTH sources and IOCs.
    # Threads (not processes) are the right choice - the work is pure
    # network I/O inside the child subprocesses.
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = [triage_ioc(ioc, args, args.scripts_dir, pool)
                   for ioc in args.iocs]

    overall = max((r["overall_verdict"] for r in results),
                  key=lambda v: VERDICT_RANK.get(v, 0))
    print(json.dumps({"results": results, "overall_verdict": overall},
                     indent=2, ensure_ascii=False))
    sys.exit(2 if overall == "malicious" else 0)


if __name__ == "__main__":
    main()
