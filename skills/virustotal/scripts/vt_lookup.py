#!/usr/bin/env python3
"""
vt_lookup.py - VirusTotal API v3 command-line lookup tool.

Purpose:
    SOC / email-security triage helper. Queries VirusTotal for the reputation
    of IPs, domains, URLs and file hashes, and can upload suspicious files
    (e.g. email attachments) for scanning.

Authentication:
    Reads the API key from the environment variable VT_API_KEY.
    Example: export VT_API_KEY="xxxxxxxx"

Subcommands / Inputs:
    ip <ip_address>        IPv4/IPv6 address, e.g. 8.8.8.8
    domain <domain>        Domain name, e.g. example.com
    url <url>              Full URL, e.g. http://evil.example/login
    hash <file_hash>       MD5 (32 hex), SHA1 (40 hex) or SHA256 (64 hex)
    upload <file_path>     Local file path (email attachment, sample, etc.)

Global options:
    --raw                  Print the full raw API JSON response instead of
                           the condensed verdict summary.
    --no-wait              For 'url' and 'upload': return the analysis ID
                           immediately instead of polling for completion.

Output (stdout):
    JSON object. By default a condensed summary:
        {
          "indicator": "<what was queried>",
          "type": "ip|domain|url|hash|file",
          "verdict": "malicious|suspicious|clean|unknown",
          "stats": {"malicious": N, "suspicious": N, "harmless": N, "undetected": N},
          ... type-specific enrichment fields ...
          "link": "https://www.virustotal.com/gui/..."
        }
    With --raw, the untouched VirusTotal API JSON is printed.

Exit codes:
    0 = success, verdict is clean/suspicious/unknown
    1 = error (bad input, missing API key, network/API failure)
    2 = success, verdict is MALICIOUS (handy for shell scripting / pipelines)
"""

import argparse
import base64
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

# Base URL for the VirusTotal REST API (version 3).
API_BASE = "https://www.virustotal.com/api/v3"

# How long (seconds) and how often to poll pending analyses (url/upload).
POLL_INTERVAL = 15
POLL_TIMEOUT = 300


def get_api_key() -> str:
    """
    Fetch the VirusTotal API key from the environment.

    Input:  none (reads env var VT_API_KEY)
    Output: API key string
    Raises: SystemExit(1) if the variable is missing/empty.
    """
    key = os.environ.get("VT_API_KEY", "").strip()
    if not key:
        sys.stderr.write("ERROR: VT_API_KEY environment variable is not set.\n")
        sys.exit(1)
    return key


def vt_request(method: str, path: str, **kwargs) -> dict:
    """
    Perform an authenticated HTTP request against the VirusTotal API.

    Input:
        method : "GET" or "POST"
        path   : API path beginning with "/", e.g. "/ip_addresses/8.8.8.8"
        kwargs : extra arguments forwarded to requests (data=, files=, ...)
    Output:
        Parsed JSON response body as a Python dict.
    Errors:
        Exits with code 1 and prints the API error message on HTTP errors
        (401 invalid key, 404 not found, 429 rate limited, etc.).
    """
    headers = {"x-apikey": get_api_key()}
    resp = requests.request(method, API_BASE + path, headers=headers, timeout=60, **kwargs)
    if resp.status_code == 404:
        # 404 means VirusTotal has never seen this indicator -> "unknown".
        return {"_not_found": True}
    if not resp.ok:
        sys.stderr.write(f"ERROR: VT API {resp.status_code}: {resp.text[:500]}\n")
        sys.exit(1)
    return resp.json()


def classify(stats: dict) -> str:
    """
    Convert last_analysis_stats into a single human verdict.

    Input:  stats dict, e.g. {"malicious": 3, "suspicious": 1, "harmless": 60, ...}
    Output: "malicious" | "suspicious" | "clean"
    """
    if stats.get("malicious", 0) > 0:
        return "malicious"
    if stats.get("suspicious", 0) > 0:
        return "suspicious"
    return "clean"


def summarize_object(indicator: str, obj_type: str, data: dict, gui_path: str) -> dict:
    """
    Build the condensed summary JSON from a VT 'object' response.

    Input:
        indicator : the original query string (ip/domain/hash/url)
        obj_type  : label used in the output ("ip", "domain", "hash", "url")
        data      : the raw VT API JSON (already parsed)
        gui_path  : path fragment for the VirusTotal web GUI link
    Output:
        Summary dict (see module docstring for the schema).
    """
    if data.get("_not_found"):
        return {"indicator": indicator, "type": obj_type, "verdict": "unknown",
                "note": "Indicator not found in VirusTotal."}

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {}) or attrs.get("stats", {})
    summary = {
        "indicator": indicator,
        "type": obj_type,
        "verdict": classify(stats),
        "stats": {k: stats.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected")},
        "link": f"https://www.virustotal.com/gui/{gui_path}",
    }

    # Type-specific enrichment fields useful for SOC analysts.
    if obj_type == "ip":
        summary["reputation"] = attrs.get("reputation")
        summary["country"] = attrs.get("country")
        summary["as_owner"] = attrs.get("as_owner")
    elif obj_type == "domain":
        summary["reputation"] = attrs.get("reputation")
        summary["registrar"] = attrs.get("registrar")
        summary["creation_date"] = attrs.get("creation_date")  # unix epoch
        summary["categories"] = attrs.get("categories")
    elif obj_type in ("hash", "file"):
        summary["sha256"] = attrs.get("sha256")
        summary["md5"] = attrs.get("md5")
        summary["file_type"] = attrs.get("type_description")
        summary["names"] = (attrs.get("names") or [])[:5]
        summary["popular_threat_label"] = (
            attrs.get("popular_threat_classification", {}) or {}
        ).get("suggested_threat_label")
    return summary


def wait_for_analysis(analysis_id: str) -> dict:
    """
    Poll /analyses/<id> until status == "completed" or timeout.

    Input:  analysis_id string returned by URL submit or file upload.
    Output: final analysis JSON (raw dict). If timeout, last response seen.
    """
    deadline = time.time() + POLL_TIMEOUT
    data = {}
    while time.time() < deadline:
        data = vt_request("GET", f"/analyses/{analysis_id}")
        status = data.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            return data
        time.sleep(POLL_INTERVAL)
    return data


# ---------------------------------------------------------------------------
# Subcommand handlers. Each takes argparse args and returns (summary, raw).
# ---------------------------------------------------------------------------

def cmd_ip(args):
    """Input: args.indicator (IP). Output: (summary, raw) for /ip_addresses."""
    raw = vt_request("GET", f"/ip_addresses/{args.indicator}")
    return summarize_object(args.indicator, "ip", raw, f"ip-address/{args.indicator}"), raw


def cmd_domain(args):
    """Input: args.indicator (domain). Output: (summary, raw) for /domains."""
    raw = vt_request("GET", f"/domains/{args.indicator}")
    return summarize_object(args.indicator, "domain", raw, f"domain/{args.indicator}"), raw


def cmd_hash(args):
    """Input: args.indicator (MD5/SHA1/SHA256). Output: (summary, raw) for /files."""
    h = args.indicator.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", h):
        sys.stderr.write("ERROR: hash must be a valid MD5/SHA1/SHA256 hex string.\n")
        sys.exit(1)
    raw = vt_request("GET", f"/files/{h}")
    return summarize_object(h, "hash", raw, f"file/{h}"), raw


def cmd_url(args):
    """
    Input:  args.indicator (full URL), args.no_wait flag.
    Output: (summary, raw). Submits the URL for analysis, then (unless
            --no-wait) polls and finally fetches the /urls/<id> report.
    """
    submit = vt_request("POST", "/urls", data={"url": args.indicator})
    analysis_id = submit.get("data", {}).get("id", "")
    if args.no_wait:
        return {"indicator": args.indicator, "type": "url",
                "analysis_id": analysis_id, "status": "queued"}, submit
    wait_for_analysis(analysis_id)
    # VT identifies URL reports by url-safe base64(url) without padding.
    url_id = base64.urlsafe_b64encode(args.indicator.encode()).decode().rstrip("=")
    raw = vt_request("GET", f"/urls/{url_id}")
    return summarize_object(args.indicator, "url", raw, f"url/{url_id}"), raw


def cmd_upload(args):
    """
    Upload a local file (e.g. an email attachment) for scanning.

    Input:  args.indicator (file path), args.no_wait flag.
            Files <= 32MB use /files; larger files use /files/upload_url.
    Output: (summary, raw). Polls the analysis, then fetches the /files
            report by SHA256 for full details.
    WARNING: uploaded files are shared with the VirusTotal community.
    """
    path = args.indicator
    if not os.path.isfile(path):
        sys.stderr.write(f"ERROR: file not found: {path}\n")
        sys.exit(1)

    size = os.path.getsize(path)
    upload_endpoint = "/files"
    if size > 32 * 1024 * 1024:
        # Large files need a special one-time upload URL from the API.
        big = vt_request("GET", "/files/upload_url")
        upload_url = big.get("data")
        with open(path, "rb") as fh:
            resp = requests.post(upload_url, headers={"x-apikey": get_api_key()},
                                 files={"file": (os.path.basename(path), fh)}, timeout=600)
        submit = resp.json()
    else:
        with open(path, "rb") as fh:
            submit = vt_request("POST", upload_endpoint,
                                files={"file": (os.path.basename(path), fh)})

    analysis_id = submit.get("data", {}).get("id", "")
    if args.no_wait:
        return {"indicator": path, "type": "file",
                "analysis_id": analysis_id, "status": "queued"}, submit

    done = wait_for_analysis(analysis_id)
    sha256 = done.get("meta", {}).get("file_info", {}).get("sha256")
    if sha256:
        raw = vt_request("GET", f"/files/{sha256}")
        return summarize_object(path, "file", raw, f"file/{sha256}"), raw
    return {"indicator": path, "type": "file", "verdict": "unknown",
            "note": "Analysis did not complete in time.", "analysis_id": analysis_id}, done


def main():
    """CLI entry point: parse args, dispatch, print JSON, set exit code."""
    parser = argparse.ArgumentParser(description="VirusTotal API v3 lookup tool")
    parser.add_argument("command", choices=["ip", "domain", "url", "hash", "upload"],
                        help="Type of lookup to perform")
    parser.add_argument("indicator", help="IP, domain, URL, hash, or file path")
    parser.add_argument("--raw", action="store_true",
                        help="Print full raw API JSON instead of the summary")
    parser.add_argument("--no-wait", action="store_true",
                        help="url/upload: do not poll, return analysis ID only")
    args = parser.parse_args()

    handlers = {"ip": cmd_ip, "domain": cmd_domain, "url": cmd_url,
                "hash": cmd_hash, "upload": cmd_upload}
    summary, raw = handlers[args.command](args)

    print(json.dumps(raw if args.raw else summary, indent=2, ensure_ascii=False))
    # Exit 2 when malicious so shell pipelines can branch on the verdict.
    sys.exit(2 if summary.get("verdict") == "malicious" else 0)


if __name__ == "__main__":
    main()
