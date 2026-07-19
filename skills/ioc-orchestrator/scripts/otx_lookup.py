#!/usr/bin/env python3
"""
otx_lookup.py - AlienVault OTX (Open Threat Exchange) API command-line tool.

Purpose:
    SOC / email-security helper for threat-intelligence context. Looks up
    IPs, domains, URLs and file hashes in OTX to see which community
    "pulses" (threat reports / campaigns) reference them and which malware
    families they are associated with. Optionally fetches passive DNS.

Authentication:
    Reads the API key from the environment variable OTX_API_KEY.
    Example: export OTX_API_KEY="xxxxxxxx"

Subcommands / Inputs:
    ip <ip_address>       IPv4 or IPv6 address.
    domain <domain>       Domain or hostname.
    url <url>             Full URL.
    hash <file_hash>      MD5 (32), SHA1 (40) or SHA256 (64) hex string.

Global options:
    --raw                 Print the raw API JSON (general section).
    --pdns                ip/domain only: also fetch passive DNS records.

Output (stdout):
    JSON summary:
        {
          "indicator": "...",
          "type": "ip|domain|url|hash",
          "verdict": "malicious|suspicious|clean",
          "pulse_count": N,
          "pulses": [{"name": ..., "created": ..., "tags": [...]}, ...],  # top 10
          "malware_families": [...],
          ... type-specific enrichment (country/asn for IP, etc.) ...
          "passive_dns": [...],   # only when --pdns is used
          "link": "https://otx.alienvault.com/indicator/<type>/<indicator>"
        }

Exit codes:
    0 = success (clean/suspicious)
    1 = error (missing key, invalid input, API failure)
    2 = success and verdict is MALICIOUS
"""

import argparse
import json
import os
import re
import sys
import urllib.parse

try:
    import requests
except ImportError:
    sys.stderr.write("ERROR: 'requests' library not installed. Run: pip install requests\n")
    sys.exit(1)

API_BASE = "https://otx.alienvault.com/api/v1"

# Number of pulses at/over which we call the indicator outright malicious.
MALICIOUS_PULSE_THRESHOLD = 5


def get_api_key() -> str:
    """Read OTX_API_KEY from env; exit(1) if missing."""
    key = os.environ.get("OTX_API_KEY", "").strip()
    if not key:
        sys.stderr.write("ERROR: OTX_API_KEY environment variable is not set.\n")
        sys.exit(1)
    return key


def api_call(path: str) -> dict:
    """
    Authenticated GET request to the OTX API.

    Input:  path beginning with "/", e.g. "/indicators/IPv4/1.2.3.4/general"
    Output: parsed JSON dict; {"_not_found": True} on 404; exit(1) otherwise.
    """
    headers = {"X-OTX-API-KEY": get_api_key()}
    resp = requests.get(API_BASE + path, headers=headers, timeout=60)
    if resp.status_code == 404:
        return {"_not_found": True}
    if not resp.ok:
        sys.stderr.write(f"ERROR: OTX API {resp.status_code}: {resp.text[:500]}\n")
        sys.exit(1)
    return resp.json()


def detect_hash_type(h: str) -> str:
    """
    Determine the OTX indicator section for a hash by its hex length.

    Input:  hash string
    Output: "file" (OTX uses /indicators/file/<hash>/...)
    Raises: SystemExit(1) if the string is not a valid MD5/SHA1/SHA256.
    """
    if not re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", h):
        sys.stderr.write("ERROR: hash must be a valid MD5/SHA1/SHA256 hex string.\n")
        sys.exit(1)
    return "file"


def build_summary(indicator: str, ind_type: str, general: dict) -> dict:
    """
    Build the condensed summary from the /general section of an indicator.

    Input:
        indicator : queried value
        ind_type  : "ip" | "domain" | "url" | "hash"
        general   : raw JSON of the general endpoint
    Output:
        summary dict (see module docstring).
    """
    if general.get("_not_found"):
        return {"indicator": indicator, "type": ind_type, "verdict": "unknown",
                "note": "Indicator not found in OTX."}

    pulse_info = general.get("pulse_info", {}) or {}
    pulses_raw = pulse_info.get("pulses", []) or []
    pulse_count = pulse_info.get("count", len(pulses_raw))

    # Collect malware family names referenced by the pulses.
    families = set()
    for p in pulses_raw:
        for fam in (p.get("malware_families") or []):
            name = fam.get("display_name") if isinstance(fam, dict) else fam
            if name:
                families.add(str(name).lower())

    # Verdict heuristic based on community pulse volume + malware links.
    if pulse_count >= MALICIOUS_PULSE_THRESHOLD or families:
        verdict = "malicious"
    elif pulse_count > 0:
        verdict = "suspicious"
    else:
        verdict = "clean"

    otx_section = {"ip": "ip", "domain": "domain", "url": "url", "hash": "file"}[ind_type]
    summary = {
        "indicator": indicator,
        "type": ind_type,
        "verdict": verdict,
        "pulse_count": pulse_count,
        # Include only the 10 most recent pulses to keep output compact.
        "pulses": [{"name": p.get("name"),
                    "created": (p.get("created") or "")[:10],
                    "tags": (p.get("tags") or [])[:8]}
                   for p in pulses_raw[:10]],
        "malware_families": sorted(families),
        "link": f"https://otx.alienvault.com/indicator/{otx_section}/"
                f"{urllib.parse.quote(indicator, safe='')}",
    }
    # Type-specific enrichment available in the general section.
    if ind_type == "ip":
        summary["country"] = general.get("country_name")
        summary["asn"] = general.get("asn")
        summary["reputation"] = general.get("reputation")
    return summary


def main():
    """CLI entry point: parse args, query OTX, print JSON summary."""
    parser = argparse.ArgumentParser(description="AlienVault OTX lookup tool")
    parser.add_argument("command", choices=["ip", "domain", "url", "hash"],
                        help="Indicator type")
    parser.add_argument("indicator", help="IP, domain, URL or file hash")
    parser.add_argument("--raw", action="store_true", help="Print raw API JSON")
    parser.add_argument("--pdns", action="store_true",
                        help="ip/domain: also fetch passive DNS records")
    args = parser.parse_args()

    ind = args.indicator.strip()

    # Map the CLI command to the OTX REST path segment for that indicator.
    if args.command == "ip":
        # OTX distinguishes IPv4/IPv6 endpoints; pick by presence of ':'.
        section = "IPv6" if ":" in ind else "IPv4"
        path = f"/indicators/{section}/{ind}"
    elif args.command == "domain":
        path = f"/indicators/domain/{ind}"
    elif args.command == "url":
        path = f"/indicators/url/{urllib.parse.quote(ind, safe='')}"
    else:  # hash
        detect_hash_type(ind)
        path = f"/indicators/file/{ind.lower()}"

    general = api_call(f"{path}/general")
    summary = build_summary(ind, args.command, general)

    # Optional passive DNS enrichment (IP and domain indicators only).
    if args.pdns and args.command in ("ip", "domain") and not general.get("_not_found"):
        pdns = api_call(f"{path}/passive_dns")
        summary["passive_dns"] = [
            {"hostname": r.get("hostname"), "address": r.get("address"),
             "first": (r.get("first") or "")[:10], "last": (r.get("last") or "")[:10]}
            for r in (pdns.get("passive_dns") or [])[:20]  # cap at 20 records
        ]

    print(json.dumps(general if args.raw else summary, indent=2, ensure_ascii=False))
    sys.exit(2 if summary.get("verdict") == "malicious" else 0)


if __name__ == "__main__":
    main()
