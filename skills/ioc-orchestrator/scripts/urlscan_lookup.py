#!/usr/bin/env python3
"""
urlscan_lookup.py - urlscan.io API command-line tool.

Purpose:
    SOC / email-security helper for suspicious link analysis. Submits URLs to
    urlscan.io for a live scan (screenshot, DOM, network behavior, verdicts)
    and searches the historical scan database by domain, IP or file hash.

Authentication:
    Reads the API key from the environment variable URLSCAN_API_KEY.
    Example: export URLSCAN_API_KEY="xxxxxxxx"

Subcommands / Inputs:
    scan <url>               Full URL to scan (include http:// or https://).
        --visibility V       "public" (default), "unlisted", or "private".
                             Use private/unlisted if the URL might contain
                             tokens or personal data.
        --no-wait            Return scan UUID immediately; don't poll.
    search-domain <domain>   Search past scans where this domain appeared.
    search-ip <ip>           Search past scans that contacted this IP.
    search-hash <sha256>     Search past scans that involved this file hash.
    result <uuid>            Fetch the full result of a finished scan.

Global options:
    --raw                    Print the raw API JSON instead of the summary.
    --limit N                search-* only: max results (default 10).

Output (stdout):
    JSON. For 'scan'/'result': a condensed verdict summary with score,
    categories, impersonated brands, page IP/country, screenshot and report
    links. For 'search-*': {"query": ..., "total": N, "results": [...]} where
    each result has scan date, URL, page IP and the report link.

Exit codes:
    0 = success
    1 = error (missing key, invalid input, API/network failure)
    2 = success and scan verdict is MALICIOUS
"""

import argparse
import json
import os
import sys
import time

try:
    import requests
except ImportError:
    sys.stderr.write("ERROR: 'requests' library not installed. Run: pip install requests\n")
    sys.exit(1)

API_BASE = "https://urlscan.io/api/v1"

# Scans typically finish in 10-30s; poll every 5s up to 2 minutes.
POLL_INTERVAL = 5
POLL_TIMEOUT = 120


def get_api_key() -> str:
    """Read URLSCAN_API_KEY from env; exit(1) if missing."""
    key = os.environ.get("URLSCAN_API_KEY", "").strip()
    if not key:
        sys.stderr.write("ERROR: URLSCAN_API_KEY environment variable is not set.\n")
        sys.exit(1)
    return key


def api_call(method: str, path: str, **kwargs):
    """
    Authenticated request to urlscan.io.

    Input:
        method : "GET" or "POST"
        path   : API path, e.g. "/scan/" or "/search/"
        kwargs : json=/params= forwarded to requests
    Output:
        (status_code, parsed JSON dict). 404 is returned to the caller
        (used while polling for a not-yet-finished result); other HTTP
        errors terminate the program with exit code 1.
    """
    headers = {"API-Key": get_api_key(), "Content-Type": "application/json"}
    resp = requests.request(method, API_BASE + path, headers=headers,
                            timeout=60, **kwargs)
    if resp.status_code == 404:
        return 404, {}
    if not resp.ok:
        sys.stderr.write(f"ERROR: urlscan API {resp.status_code}: {resp.text[:500]}\n")
        sys.exit(1)
    return resp.status_code, resp.json()


def summarize_result(indicator: str, raw: dict) -> dict:
    """
    Build the condensed verdict summary from a full scan result JSON.

    Input:  indicator (original URL/UUID), raw result dict from /result/<uuid>
    Output: summary dict with verdict, score, categories, brands, page info,
            screenshot and report links.
    """
    verdicts = raw.get("verdicts", {}).get("overall", {})
    page = raw.get("page", {})
    task = raw.get("task", {})
    score = verdicts.get("score", 0)
    malicious = verdicts.get("malicious", False)
    return {
        "indicator": indicator,
        "type": "url",
        "verdict": "malicious" if malicious else ("suspicious" if score > 0 else "clean"),
        "score": score,
        "categories": verdicts.get("categories", []),
        # Brands the page appears to impersonate (phishing kit detection).
        "brands": [b.get("name", b) if isinstance(b, dict) else b
                   for b in verdicts.get("brands", [])],
        "final_url": page.get("url"),
        "page_domain": page.get("domain"),
        "page_ip": page.get("ip"),
        "page_country": page.get("country"),
        "server": page.get("server"),
        "screenshot": task.get("screenshotURL"),
        "report": task.get("reportURL"),
    }


def cmd_scan(args):
    """
    Submit a URL for scanning and (unless --no-wait) poll for the result.

    Input:  args.indicator (URL), args.visibility, args.no_wait
    Output: (summary, raw)
    """
    payload = {"url": args.indicator, "visibility": args.visibility}
    _, submit = api_call("POST", "/scan/", json=payload)
    uuid = submit.get("uuid")
    if args.no_wait:
        return {"indicator": args.indicator, "type": "url", "status": "queued",
                "uuid": uuid, "report": submit.get("result")}, submit

    # Poll /result/<uuid> until it stops returning 404 (scan finished).
    deadline = time.time() + POLL_TIMEOUT
    raw = {}
    while time.time() < deadline:
        time.sleep(POLL_INTERVAL)
        status, raw = api_call("GET", f"/result/{uuid}/")
        if status != 404:
            break
    if not raw:
        return {"indicator": args.indicator, "type": "url", "uuid": uuid,
                "verdict": "unknown", "note": "Scan did not finish in time."}, submit
    return summarize_result(args.indicator, raw), raw


def cmd_result(args):
    """Fetch a finished scan by UUID. Input: args.indicator (uuid)."""
    status, raw = api_call("GET", f"/result/{args.indicator}/")
    if status == 404:
        sys.stderr.write("ERROR: result not found (scan may still be running).\n")
        sys.exit(1)
    return summarize_result(args.indicator, raw), raw


def do_search(query: str, limit: int):
    """
    Run an Elasticsearch-syntax search against /search/.

    Input:  query string (e.g. 'domain:example.com'), limit (max results)
    Output: (summary dict with results list, raw API dict)
    """
    _, raw = api_call("GET", "/search/", params={"q": query, "size": limit})
    results = []
    for r in raw.get("results", []):
        page, task = r.get("page", {}), r.get("task", {})
        results.append({
            "date": task.get("time"),
            "url": page.get("url") or task.get("url"),
            "domain": page.get("domain"),
            "ip": page.get("ip"),
            "country": page.get("country"),
            "report": r.get("result"),
        })
    return {"query": query, "total": raw.get("total", 0), "results": results}, raw


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="urlscan.io lookup tool")
    parser.add_argument("command",
                        choices=["scan", "search-domain", "search-ip",
                                 "search-hash", "result"],
                        help="Operation to perform")
    parser.add_argument("indicator", help="URL, domain, IP, hash, or scan UUID")
    parser.add_argument("--visibility", default="public",
                        choices=["public", "unlisted", "private"],
                        help="Scan visibility (default public)")
    parser.add_argument("--no-wait", action="store_true",
                        help="scan: return UUID without polling for result")
    parser.add_argument("--limit", type=int, default=10,
                        help="search-*: max results (default 10)")
    parser.add_argument("--raw", action="store_true", help="Print raw API JSON")
    args = parser.parse_args()

    if args.command == "scan":
        summary, raw = cmd_scan(args)
    elif args.command == "result":
        summary, raw = cmd_result(args)
    else:
        # Map the CLI command to the urlscan search-query field syntax.
        field = {"search-domain": "domain", "search-ip": "ip",
                 "search-hash": "hash"}[args.command]
        summary, raw = do_search(f"{field}:{args.indicator}", args.limit)

    print(json.dumps(raw if args.raw else summary, indent=2, ensure_ascii=False))
    sys.exit(2 if summary.get("verdict") == "malicious" else 0)


if __name__ == "__main__":
    main()
