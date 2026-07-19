#!/usr/bin/env python3
"""
ha_lookup.py - Hybrid Analysis (Falcon Sandbox) API v2 command-line tool.

Purpose:
    SOC / email-security helper for file-based threats. Looks up file hashes
    against existing Falcon Sandbox reports and submits files (e.g. email
    attachments) for full dynamic (behavioral) sandbox analysis.

Authentication:
    Reads the API key from the environment variable HYBRID_ANALYSIS_API_KEY.
    Example: export HYBRID_ANALYSIS_API_KEY="xxxxxxxx"

Subcommands / Inputs:
    hash <file_hash>       MD5 (32), SHA1 (40) or SHA256 (64) hex string.
                           Searches existing sandbox reports for that hash.
    upload <file_path>     Local file path to submit for dynamic analysis.
        --env N            Sandbox environment ID (default 160):
                             160 = Windows 10 64-bit
                             140 = Windows 11 64-bit
                             120 = Windows 7 64-bit
                             310 = Linux (Ubuntu 20.04, 64-bit)
                             200 = Android Static Analysis
                             400 = macOS Catalina
        --no-wait          Return the job ID immediately without polling.
    report <id>            Job ID (from upload) or SHA256 - fetches the
                           current state/summary of that analysis.

Global options:
    --raw                  Print the raw API JSON instead of the summary.

Output (stdout):
    JSON summary:
        {
          "indicator": "...",
          "type": "hash|file",
          "verdict": "malicious|suspicious|clean|unknown",
          "threat_score": 0-100,
          "av_detect_percent": 0-100,
          "malware_family": "...",
          "file_type": "...",
          "environment": "...",
          "tags": [...],
          "link": "https://www.hybrid-analysis.com/sample/<sha256>"
        }

Exit codes:
    0 = success (clean/suspicious/unknown)
    1 = error (missing key, bad input, API failure)
    2 = success and verdict is MALICIOUS
"""

import argparse
import json
import os
import re
import sys
import time

try:
    import requests
except ImportError:
    sys.stderr.write("ERROR: 'requests' library not installed. Run: pip install requests\n")
    sys.exit(1)

API_BASE = "https://www.hybrid-analysis.com/api/v2"

# Dynamic sandbox runs take minutes; poll every 30s for up to 15 minutes.
POLL_INTERVAL = 30
POLL_TIMEOUT = 900


def get_api_key() -> str:
    """Read HYBRID_ANALYSIS_API_KEY from env; exit(1) if missing."""
    key = os.environ.get("HYBRID_ANALYSIS_API_KEY", "").strip()
    if not key:
        sys.stderr.write("ERROR: HYBRID_ANALYSIS_API_KEY environment variable is not set.\n")
        sys.exit(1)
    return key


def api_call(method: str, path: str, **kwargs):
    """
    Authenticated request to the Hybrid Analysis API.

    Input:
        method : "GET" or "POST"
        path   : API path, e.g. "/search/hash"
        kwargs : data= / files= forwarded to requests
    Output:
        Parsed JSON (dict or list). Exits(1) on HTTP errors.
    Note:
        The API requires a browser-like User-Agent header, otherwise it
        rejects requests with 403.
    """
    headers = {"api-key": get_api_key(),
               "User-Agent": "Falcon Sandbox",
               "accept": "application/json"}
    resp = requests.request(method, API_BASE + path, headers=headers,
                            timeout=120, **kwargs)
    if not resp.ok:
        sys.stderr.write(f"ERROR: Hybrid Analysis API {resp.status_code}: "
                         f"{resp.text[:500]}\n")
        sys.exit(1)
    return resp.json()


def verdict_map(ha_verdict: str, threat_score) -> str:
    """
    Normalize the Hybrid Analysis verdict string into our common scheme.

    Input:  ha_verdict ("malicious", "suspicious", "no specific threat",
            "whitelisted", None), threat_score (0-100 or None)
    Output: "malicious" | "suspicious" | "clean" | "unknown"
    """
    v = (ha_verdict or "").lower()
    if v == "malicious":
        return "malicious"
    if v == "suspicious":
        return "suspicious"
    if v in ("no specific threat", "whitelisted", "no verdict"):
        return "clean"
    # Fall back to the numeric threat score when no textual verdict exists.
    if isinstance(threat_score, (int, float)):
        if threat_score >= 70:
            return "malicious"
        if threat_score >= 30:
            return "suspicious"
        return "clean"
    return "unknown"


def summarize_report(indicator: str, ind_type: str, rep: dict) -> dict:
    """
    Build the condensed summary from a single sandbox report object.

    Input:  indicator (hash/path), ind_type label, rep = one report dict
            as returned by /search/hash or /report/<id>/summary.
    Output: summary dict (see module docstring).
    """
    sha256 = rep.get("sha256")
    return {
        "indicator": indicator,
        "type": ind_type,
        "verdict": verdict_map(rep.get("verdict"), rep.get("threat_score")),
        "threat_score": rep.get("threat_score"),
        "av_detect_percent": rep.get("av_detect"),
        "malware_family": rep.get("vx_family"),
        "file_type": rep.get("type_short") or rep.get("type"),
        "file_name": rep.get("submit_name"),
        "environment": rep.get("environment_description"),
        "tags": rep.get("classification_tags") or rep.get("tags") or [],
        "analysis_date": rep.get("analysis_start_time"),
        "sha256": sha256,
        "link": f"https://www.hybrid-analysis.com/sample/{sha256}" if sha256 else None,
    }


def cmd_hash(args):
    """
    Handle 'hash': search existing reports for a hash.

    Input:  args.indicator (MD5/SHA1/SHA256)
    Output: (summary, raw). If multiple reports exist, the one with the
            highest threat score is summarized and the rest are counted.
    """
    h = args.indicator.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", h):
        sys.stderr.write("ERROR: hash must be a valid MD5/SHA1/SHA256 hex string.\n")
        sys.exit(1)
    raw = api_call("POST", "/search/hash", data={"hash": h})
    reports = raw if isinstance(raw, list) else raw.get("result", [])
    if not reports:
        return {"indicator": h, "type": "hash", "verdict": "unknown",
                "note": "No sandbox reports found for this hash."}, raw
    # Pick the report with the highest threat score as the representative.
    best = max(reports, key=lambda r: (r.get("threat_score") or 0))
    summary = summarize_report(h, "hash", best)
    summary["total_reports"] = len(reports)
    return summary, raw


def cmd_upload(args):
    """
    Handle 'upload': submit a file for dynamic analysis.

    Input:  args.indicator (file path), args.env (environment ID),
            args.no_wait (bool)
    Output: (summary, raw). Polls /report/<job_id>/summary until the state
            becomes SUCCESS (or timeout), then summarizes it.
    """
    path = args.indicator
    if not os.path.isfile(path):
        sys.stderr.write(f"ERROR: file not found: {path}\n")
        sys.exit(1)

    with open(path, "rb") as fh:
        submit = api_call("POST", "/submit/file",
                          data={"environment_id": str(args.env)},
                          files={"file": (os.path.basename(path), fh)})
    job_id = submit.get("job_id")
    sha256 = submit.get("sha256")
    if args.no_wait:
        return {"indicator": path, "type": "file", "status": "queued",
                "job_id": job_id, "sha256": sha256,
                "link": f"https://www.hybrid-analysis.com/sample/{sha256}"}, submit

    # Poll the summary endpoint until the sandbox finishes the run.
    deadline = time.time() + POLL_TIMEOUT
    rep = {}
    while time.time() < deadline:
        time.sleep(POLL_INTERVAL)
        rep = api_call("GET", f"/report/{job_id}/summary")
        if (rep.get("state") or "").upper() in ("SUCCESS", "ERROR"):
            break
    if (rep.get("state") or "").upper() != "SUCCESS":
        return {"indicator": path, "type": "file", "verdict": "unknown",
                "job_id": job_id, "sha256": sha256,
                "note": "Analysis not finished yet - check later with "
                        f"'report {job_id}'."}, rep or submit
    return summarize_report(path, "file", rep), rep


def cmd_report(args):
    """
    Handle 'report': fetch an analysis by job ID or SHA256.

    Input:  args.indicator (job ID like '5f1a...:160', or a SHA256 hash)
    Output: (summary, raw)
    """
    ident = args.indicator.strip()
    if re.fullmatch(r"[0-9a-fA-F]{64}", ident):
        # Bare SHA256 -> reuse the hash-search path for convenience.
        args.indicator = ident
        return cmd_hash(args)
    rep = api_call("GET", f"/report/{ident}/summary")
    return summarize_report(ident, "file", rep), rep


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Hybrid Analysis lookup tool")
    parser.add_argument("command", choices=["hash", "upload", "report"],
                        help="Operation to perform")
    parser.add_argument("indicator", help="Hash, file path, or job ID")
    parser.add_argument("--env", type=int, default=160,
                        help="Sandbox environment ID for upload (default 160 = Win10 x64)")
    parser.add_argument("--no-wait", action="store_true",
                        help="upload: return job ID without polling")
    parser.add_argument("--raw", action="store_true", help="Print raw API JSON")
    args = parser.parse_args()

    handlers = {"hash": cmd_hash, "upload": cmd_upload, "report": cmd_report}
    summary, raw = handlers[args.command](args)

    print(json.dumps(raw if args.raw else summary, indent=2, ensure_ascii=False))
    sys.exit(2 if summary.get("verdict") == "malicious" else 0)


if __name__ == "__main__":
    main()
