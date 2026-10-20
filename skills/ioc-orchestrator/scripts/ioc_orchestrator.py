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
    --workers N          Max parallel worker threads (default 0 = one per
                         (IOC, source) job, capped at 32). All IOCs and
                         sources run concurrently.
    --upload             For local files: upload to VT + Hybrid Analysis
                         sandboxes instead of only hash lookups.
                         WARNING: uploads are shared with those communities.
    --share-urls         Share URLs with the communities: submit them to
                         VirusTotal (POST) and make urlscan scans public.
                         Default (privacy): VT only reads an existing
                         report, urlscan scans privately.
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
              "skipped":  {"<source>": "<reason>"},
              "errors":   {"<source>": "<error text>"},
              "rejected": {"<source>": "<API 400/422 message>"}
            }, ...
          ],
          "overall_verdict": "<worst verdict across all IOCs>",
          "coverage": {
            "jobs_ok": N,        # source queries that returned data
            "jobs_error": N,     # failed (bad key, network, rate limit) or
                                 # incomplete (scan did not finish in time)
            "jobs_rejected": N,  # source refused the indicator (HTTP 400/
                                 # 422: invalid, reserved, unresolvable)
            "jobs_skipped": N,   # not run (API key not set)
            "jobs_no_verdict": N,# answered, but source has no record
            "sources_ok": [...], "sources_error": [...],
            "sources_rejected": [...], "sources_skipped": [...]
          }
        }

    IMPORTANT: "overall_verdict": "unknown" with jobs_ok == 0 means NOTHING
    was actually checked - it does NOT mean the IOC is clean. Callers must
    read "coverage" before trusting a verdict.

Exit codes:
    0 = run completed, nothing malicious
    1 = fatal orchestrator error (bad args, scripts missing, no API keys)
    2 = run completed and at least one IOC verdict is MALICIOUS
    3 = every source query that was attempted FAILED (invalid key, network
        down, rate limit...) - no reputation data at all was obtained
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


API_ERROR_RE = re.compile(r"^ERROR: (?P<api>.+? API) (?P<code>\d{3}): (?P<body>.*)$")


def api_error_message(body: str) -> str:
    """
    Pull the human-readable message out of an API error body.

    Input:  the text after "ERROR: <X> API <code>: " - usually a JSON
            document, often TRUNCATED by the tool scripts (500 chars), so
            json.loads() alone is not enough.
    Output: the message string ("Invalid domain (x)", "DNS Error - Could not
            resolve domain", ...) or the raw body when nothing matches.
    """
    # Field-level validation errors (Hybrid Analysis style) name exactly
    # which request parameter was rejected - surface them first. Works on
    # truncated bodies too, so it runs before json.loads().
    v = re.findall(r'"field"\s*:\s*"([^"]+)"\s*,\s*"errors"\s*:\s*\[\s*"([^"]+)"',
                   body or "")
    if v:
        return "validation failed: " + "; ".join(f"{f}: {e}" for f, e in v)
    try:
        obj = json.loads(body)
        if isinstance(obj, dict):
            inner = obj.get("error", obj)
            if isinstance(inner, dict):
                obj = inner
            for key in ("message", "detail", "description", "error"):
                if isinstance(obj.get(key), str) and obj[key].strip():
                    return obj[key].strip()
    except (ValueError, TypeError):
        pass
    # Truncated JSON: grab the first "message"/"detail"/"description" value.
    m = re.search(r'"(?:message|detail|description)"\s*:\s*"((?:[^"\\]|\\.)*)',
                  body)
    return m.group(1) if m else body


def short_error(text: str, limit: int = 300) -> str:
    """
    Reduce a child process's stderr to its most informative single line.

    Input:  raw stderr text (may be a multi-line Python traceback).
    Output: one line, truncated to `limit` chars:
              * "ERROR: <X> API <code>: <message>" - the API's own message
                extracted from its JSON body (see api_error_message)
              * otherwise the last "ERROR:" line, or the last line (the
                exception) of a traceback.
            Tracebacks otherwise hide the real cause (e.g. "VT API 401:
            Wrong API key") below pages of frames.
    """
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    if not lines:
        return "no output"
    # Prefer an explicit "ERROR:" line written by the tool scripts. Some
    # APIs (urlscan) return pretty-printed multi-line JSON, so the lines
    # after the last "ERROR:" line are joined back onto it.
    for i in range(len(lines) - 1, -1, -1):
        if lines[i].startswith("ERROR:"):
            ln = " ".join(lines[i:])
            m = API_ERROR_RE.match(ln)
            if m:
                ln = (f"ERROR: {m.group('api')} {m.group('code')}: "
                      f"{api_error_message(m.group('body'))}")
            return ln[:limit]
    return lines[-1][:limit]


# HTTP codes a source uses to refuse a request it understood.
REJECT_CODES = {"400", "422"}
# A 400/422 counts as "the source refused THIS INDICATOR" only when the
# message says so. Anything else (e.g. Hybrid Analysis "hash: This value
# should not be blank") means OUR request was malformed - a real failure
# that must stay visible, not be hidden as a rejection.
REJECT_HINTS = ("invalid domain", "invalid url", "invalid ip",
                "not a valid", "unable to parse", "could not resolve",
                "dns error", "not resolvable", "unresolvable",
                "blacklist", "blocklist", "prevented", "not allowed to scan",
                "reserved", "private ip", "malformed")


def is_rejection(err: str) -> bool:
    """
    Input:  error string produced by short_error().
    Output: True when a source rejected the indicator itself (HTTP 400/422
            AND a message naming the indicator as invalid / reserved /
            unresolvable / blocked). False for real failures: 401/403 key,
            429 rate limit, 5xx, network errors, timeouts, and 400s caused
            by a malformed request (validation errors on our parameters).
    """
    m = re.match(r"^ERROR: .+? API (\d{3}):(.*)$", err or "", re.S)
    if not (m and m.group(1) in REJECT_CODES):
        return False
    msg = m.group(2).lower()
    return any(h in msg for h in REJECT_HINTS)


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
            return None, f"non-JSON output: {short_error(stdout)}"
    # No stdout at all -> report whatever the tool wrote to stderr.
    return None, short_error(proc.stderr)


def incomplete_reason(summary: dict):
    """
    Detect a source answer that ran but produced no usable result.

    Input:  summary dict printed by a source script.
    Output: reason string when the answer is incomplete, else None.
            Covers urlscan's "Scan did not finish in time" and any job that
            only queued work ("status": "queued", e.g. --no-wait runs).
            Such answers must not count as coverage: no verdict was obtained.
    """
    if not isinstance(summary, dict):
        return "malformed summary"
    note = str(summary.get("note") or "").lower()
    if "did not finish" in note or "timed out" in note:
        return summary.get("note")
    if summary.get("status") == "queued" and "verdict" not in summary:
        return "analysis queued, no result yet"
    return None


def submit_ioc(ioc: str, args, scripts_dir: str, executor):
    """
    Plan and SUBMIT every applicable source job for one IOC (non-blocking).

    Input:
        ioc         : the IOC string
        args        : parsed argparse namespace (sources filter, upload, ...)
        scripts_dir : directory containing the tool scripts
        executor    : shared ThreadPoolExecutor
    Output:
        (result_dict, {source_name: future}) - result_dict already holds
        "skipped"/"errors" decided before running; futures are collected
        later by collect_ioc(). Submitting all IOCs before collecting any
        is what makes parallelism span IOCs as well as sources.
    """
    ioc_type = detect_type(ioc)
    result = {"ioc": ioc, "detected_type": ioc_type,
              "sources": {}, "skipped": {}, "errors": {}, "rejected": {},
              "verdict_breakdown": {}}

    # Local files: either upload to sandboxes, or hash-lookup everywhere.
    # In hash mode we rewrite the IOC to its SHA256 and treat it as "hash".
    effective_ioc, effective_type = ioc, ioc_type
    if ioc_type == "file" and not args.upload:
        result["sha256"] = sha256_of_file(ioc)
        effective_ioc, effective_type = result["sha256"], "hash"
    elif ioc_type == "file" and args.upload:
        effective_type = "upload"

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
        # Privacy: by default URLs are only LOOKED UP on VirusTotal and
        # scanned PRIVATELY on urlscan (the tools' own defaults). Only
        # --share-urls submits them to VT and makes urlscan scans public.
        if effective_type == "url" and getattr(args, "share_urls", False):
            if name == "virustotal":
                cli_args.append("--submit")
            elif name == "urlscan":
                cli_args += ["--visibility", "public"]
        if args.raw:
            # Forward --raw so each tool emits its full raw API JSON
            # instead of the condensed summary.
            cli_args.append("--raw")
        futures[name] = executor.submit(run_source, name, script_path,
                                        cli_args, args.timeout)
    return result, futures


def collect_ioc(result: dict, futures: dict) -> dict:
    """
    Wait for one IOC's source jobs and aggregate them.

    Input:  result dict + futures from submit_ioc().
    Output: completed per-IOC result (see module docstring schema).
            Answers that ran but returned nothing usable (incomplete_reason)
            are recorded under "errors", not "sources". HTTP 400/422 answers
            (the source refused this indicator) go to "rejected".
    """
    for name, fut in futures.items():
        summary, err = fut.result()
        if err and is_rejection(err):
            result["rejected"][name] = err
            continue
        if err:
            result["errors"][name] = err
            continue
        why = incomplete_reason(summary)
        if why:
            result["errors"][name] = f"incomplete: {why}"
            continue
        verdict = summary.get("verdict", "unknown")
        result["verdict_breakdown"][name] = verdict
        result["sources"][name] = summary

    # Aggregate: overall verdict for this IOC = worst source verdict.
    verdicts = list(result["verdict_breakdown"].values()) or ["unknown"]
    result["overall_verdict"] = max(verdicts, key=lambda v: VERDICT_RANK.get(v, 0))
    return result


def triage_ioc(ioc: str, args, scripts_dir: str, executor) -> dict:
    """
    Convenience wrapper: submit + collect a single IOC (blocking).

    Input/Output: as submit_ioc() / collect_ioc(). Kept for callers that
    import this module; main() uses submit-all-then-collect instead.
    """
    result, futures = submit_ioc(ioc, args, scripts_dir, executor)
    return collect_ioc(result, futures)


def build_coverage(results) -> dict:
    """
    Summarise which source queries really returned data.

    Input:  list of per-IOC result dicts from collect_ioc().
    Output: {"jobs_ok", "jobs_error", "jobs_rejected", "jobs_skipped",
             "jobs_no_verdict",
             "sources_ok", "sources_error", "sources_rejected",
             "sources_skipped"}
            Counts are per (IOC, source) pair; source lists are unique names.
    """
    buckets = (("sources", "ok"), ("errors", "error"),
               ("rejected", "rejected"), ("skipped", "skipped"))
    cov = {f"jobs_{b}": 0 for _, b in buckets}
    names = {b: set() for _, b in buckets}
    for r in results:
        for key, bucket in buckets:
            for src in r.get(key, {}):
                cov[f"jobs_{bucket}"] += 1
                names[bucket].add(src)
    for _, bucket in buckets:
        cov[f"sources_{bucket}"] = sorted(names[bucket])
    # Answers with no verdict (e.g. "not found in VirusTotal") are valid
    # coverage, but worth surfacing: "unknown" here means "source has no
    # record", not "source failed".
    cov["jobs_no_verdict"] = sum(
        1 for r in results for v in r.get("verdict_breakdown", {}).values()
        if v not in ("malicious", "suspicious", "clean"))
    return cov


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
    parser.add_argument("--workers", type=int, default=0,
                        help="Max parallel workers (default 0 = one per "
                             "job, capped at 32)")
    parser.add_argument("--upload", action="store_true",
                        help="Upload local files to VT/HA sandboxes "
                             "(shared with their communities!)")
    parser.add_argument("--raw", action="store_true",
                        help="Include full per-source JSON in the report")
    parser.add_argument("--share-urls", action="store_true",
                        help="SUBMIT URLs to VirusTotal and run PUBLIC "
                             "urlscan scans. Default: VT report lookup only "
                             "+ private urlscan scans (nothing shared). URLs "
                             "in phishing mail often identify the victim.")
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
    # Size the pool so every (IOC, source) job can run at once: total wall
    # time is then ~one per-source timeout, which is what callers budget
    # for (the triage pipeline passes --timeout below its own limit).
    workers = args.workers or min(32, max(4, len(args.iocs) * len(SOURCES)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        # Submit EVERY IOC first, then collect - otherwise each IOC would
        # wait for its slowest source before the next IOC even started.
        planned = [submit_ioc(ioc, args, args.scripts_dir, pool)
                   for ioc in args.iocs]
        results = [collect_ioc(res, futs) for res, futs in planned]

    overall = max((r["overall_verdict"] for r in results),
                  key=lambda v: VERDICT_RANK.get(v, 0))
    coverage = build_coverage(results)
    print(json.dumps({"results": results, "overall_verdict": overall,
                      "coverage": coverage}, indent=2, ensure_ascii=False))
    if coverage["jobs_ok"] == 0 and coverage["jobs_error"] > 0:
        sys.stderr.write("WARNING: every attempted source query failed - "
                         "no reputation data was obtained (see 'errors').\n")
        sys.exit(3)
    sys.exit(2 if overall == "malicious" else 0)


if __name__ == "__main__":
    main()
