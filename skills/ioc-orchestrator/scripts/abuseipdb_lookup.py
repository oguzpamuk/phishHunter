#!/usr/bin/env python3
"""
abuseipdb_lookup.py - AbuseIPDB API v2 command-line tool.

Purpose:
    SOC / email-security helper for IP reputation. Checks the abuse history
    of an IP address (confidence score, report counts, ISP, usage type) and
    can optionally submit an abuse report.

Authentication:
    Reads the API key from the environment variable ABUSEIPDB_API_KEY.
    Example: export ABUSEIPDB_API_KEY="xxxxxxxx"

Subcommands / Inputs:
    check <ip>             IPv4 or IPv6 address to look up.
        --days N           Lookback window in days for reports (default 90).
        --verbose          Also request the individual report entries.
    report <ip>            IP address to report as abusive.
        --categories LIST  REQUIRED. Comma-separated AbuseIPDB category IDs,
                           e.g. "11,7" (11=EmailSpam, 7=Phishing,
                           18=BruteForce, 22=SSH, 14=PortScan).
        --comment TEXT     Optional free-text evidence description.
                           NEVER include personal data (PII) in comments.

Global options:
    --raw                  Print the raw API JSON instead of the summary.

Output (stdout):
    JSON summary object:
        {
          "indicator": "<ip>",
          "type": "ip",
          "verdict": "malicious|suspicious|clean",
          "abuse_confidence_score": 0-100,
          "total_reports": N,
          "distinct_reporters": N,
          "country": "..", "isp": "..", "usage_type": "..",
          "is_tor": bool, "last_reported_at": "...",
          "link": "https://www.abuseipdb.com/check/<ip>"
        }
    For 'report', a small confirmation object with the new score is printed.

Exit codes:
    0 = success (clean/suspicious)
    1 = error (missing key, bad input, API failure)
    2 = success and verdict is MALICIOUS (score >= 75)
"""

import argparse
import ipaddress
import json
import os
import sys

try:
    import requests
except ImportError:
    sys.stderr.write("ERROR: 'requests' library not installed. Run: pip install requests\n")
    sys.exit(1)

API_BASE = "https://api.abuseipdb.com/api/v2"


def get_api_key() -> str:
    """
    Read the AbuseIPDB API key from the environment.

    Input:  none (env var ABUSEIPDB_API_KEY)
    Output: key string; exits with code 1 if not set.
    """
    key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    if not key:
        sys.stderr.write("ERROR: ABUSEIPDB_API_KEY environment variable is not set.\n")
        sys.exit(1)
    return key


def validate_ip(value: str) -> str:
    """
    Validate that the input string is a syntactically valid IP address.

    Input:  candidate IP string
    Output: the same string if valid; exits with code 1 otherwise.
    """
    try:
        ipaddress.ip_address(value)
    except ValueError:
        sys.stderr.write(f"ERROR: '{value}' is not a valid IP address.\n")
        sys.exit(1)
    return value


def api_call(method: str, endpoint: str, **kwargs) -> dict:
    """
    Perform an authenticated request to AbuseIPDB.

    Input:
        method   : "GET" or "POST"
        endpoint : path like "/check" or "/report"
        kwargs   : params= / data= forwarded to requests
    Output:
        Parsed JSON dict. Exits(1) on HTTP or API-level errors.
    """
    headers = {"Key": get_api_key(), "Accept": "application/json"}
    resp = requests.request(method, API_BASE + endpoint, headers=headers,
                            timeout=60, **kwargs)
    if not resp.ok:
        sys.stderr.write(f"ERROR: AbuseIPDB API {resp.status_code}: {resp.text[:500]}\n")
        sys.exit(1)
    return resp.json()


def verdict_from_score(score: int) -> str:
    """
    Map abuseConfidenceScore (0-100) to a simple verdict.

    Input:  integer score
    Output: "malicious" (>=75) | "suspicious" (25-74) | "clean" (<25)
    """
    if score >= 75:
        return "malicious"
    if score >= 25:
        return "suspicious"
    return "clean"


def cmd_check(args) -> dict:
    """
    Handle the 'check' subcommand.

    Input:  args.ip (validated IP), args.days (lookback), args.verbose (bool)
    Output: (summary dict, raw API dict)
    """
    params = {"ipAddress": args.ip, "maxAgeInDays": args.days}
    if args.verbose:
        # verbose=true makes the API include the individual report entries.
        params["verbose"] = "true"
    raw = api_call("GET", "/check", params=params)

    d = raw.get("data", {})
    score = d.get("abuseConfidenceScore", 0)
    summary = {
        "indicator": args.ip,
        "type": "ip",
        "verdict": verdict_from_score(score),
        "abuse_confidence_score": score,
        "total_reports": d.get("totalReports"),
        "distinct_reporters": d.get("numDistinctUsers"),
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "domain": d.get("domain"),
        "usage_type": d.get("usageType"),
        "is_tor": d.get("isTor"),
        "is_whitelisted": d.get("isWhitelisted"),
        "last_reported_at": d.get("lastReportedAt"),
        "link": f"https://www.abuseipdb.com/check/{args.ip}",
    }
    if args.verbose:
        # Include at most 10 recent reports to keep output readable.
        summary["recent_reports"] = [
            {"reported_at": r.get("reportedAt"),
             "categories": r.get("categories"),
             "comment": (r.get("comment") or "")[:200]}
            for r in (d.get("reports") or [])[:10]
        ]
    return summary, raw


def cmd_report(args) -> dict:
    """
    Handle the 'report' subcommand (submits an abuse report).

    Input:  args.ip, args.categories (comma-separated IDs), args.comment
    Output: (confirmation dict, raw API dict)
    """
    if not args.categories:
        sys.stderr.write("ERROR: --categories is required for 'report'.\n")
        sys.exit(1)
    data = {"ip": args.ip, "categories": args.categories}
    if args.comment:
        data["comment"] = args.comment
    raw = api_call("POST", "/report", data=data)
    d = raw.get("data", {})
    summary = {
        "indicator": args.ip,
        "action": "reported",
        "abuse_confidence_score_after": d.get("abuseConfidenceScore"),
        "link": f"https://www.abuseipdb.com/check/{args.ip}",
    }
    return summary, raw


def main():
    """CLI entry point: parse args, dispatch subcommand, print JSON."""
    parser = argparse.ArgumentParser(description="AbuseIPDB API v2 lookup tool")
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="Check an IP's abuse reputation")
    p_check.add_argument("ip", type=validate_ip, help="IPv4/IPv6 address")
    p_check.add_argument("--days", type=int, default=90,
                         help="Report lookback window in days (default 90)")
    p_check.add_argument("--verbose", action="store_true",
                         help="Include individual report entries")
    p_check.add_argument("--raw", action="store_true", help="Print raw API JSON")

    p_report = sub.add_parser("report", help="Report an abusive IP")
    p_report.add_argument("ip", type=validate_ip, help="IPv4/IPv6 address")
    p_report.add_argument("--categories", help="Comma-separated category IDs, e.g. 11,7")
    p_report.add_argument("--comment", help="Evidence description (no PII!)")
    p_report.add_argument("--raw", action="store_true", help="Print raw API JSON")

    args = parser.parse_args()
    summary, raw = (cmd_check if args.command == "check" else cmd_report)(args)

    print(json.dumps(raw if args.raw else summary, indent=2, ensure_ascii=False))
    sys.exit(2 if summary.get("verdict") == "malicious" else 0)


if __name__ == "__main__":
    main()
