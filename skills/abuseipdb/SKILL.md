---
name: abuseipdb
description: Query AbuseIPDB for IP address reputation and abuse history (abuse confidence score, report count, ISP, usage type), and optionally report abusive IPs. Use this skill whenever the user wants to check if an IP is abusive/blacklisted, mentions "AbuseIPDB", asks for an IP's abuse confidence score, or is doing email security / SOC triage on sender IPs, brute-force sources, or spam origins.
---

# AbuseIPDB Lookup Skill

Query the AbuseIPDB API v2 from the command line: IP reputation checks (abuse
confidence score, total reports, ISP/usage type) and optional abuse reporting.
AbuseIPDB is IP-only — for domains/hashes use the virustotal, urlscan or
alienvault-otx skills.

## Requirements

- Python 3.8+ with `requests` (`pip install requests`)
- Environment variable `ABUSEIPDB_API_KEY` (free tier: 1,000 checks/day)

```bash
export ABUSEIPDB_API_KEY="your_api_key_here"
```

## Usage (CLI)

```bash
# 1) Check an IP's reputation (default lookback: 90 days)
python scripts/abuseipdb_lookup.py check 118.25.6.39

# 2) Check with custom lookback window and include individual reports
python scripts/abuseipdb_lookup.py check 118.25.6.39 --days 30 --verbose

# 3) Report an abusive IP (categories are AbuseIPDB numeric category IDs,
#    e.g. 18=BruteForce, 22=SSH, 11=EmailSpam, 7=Phishing)
python scripts/abuseipdb_lookup.py report 118.25.6.39 --categories 11,7 \
    --comment "Phishing email source observed at 2026-07-18 09:00 UTC"

# Options:
#   --raw    Print full raw API JSON instead of the summary
```

## Output

Condensed JSON summary on stdout:

```json
{
  "indicator": "118.25.6.39",
  "type": "ip",
  "verdict": "malicious",
  "abuse_confidence_score": 100,
  "total_reports": 512,
  "distinct_reporters": 84,
  "country": "CN",
  "isp": "Tencent Cloud Computing",
  "usage_type": "Data Center/Web Hosting/Transit",
  "is_tor": false,
  "last_reported_at": "2026-07-17T22:10:11+00:00",
  "link": "https://www.abuseipdb.com/check/118.25.6.39"
}
```

Verdict mapping from abuseConfidenceScore: >=75 malicious, 25–74 suspicious,
<25 clean. Exit codes: 0 success, 1 error, 2 malicious verdict.

## Workflow guidance for Claude

1. Use `check` for sender IPs extracted from email headers (Received chain, SPF results).
2. Combine with VirusTotal for a second opinion; AbuseIPDB is community-report based, so a high score with many distinct reporters is a strong signal.
3. Only use `report` when the user explicitly asks to report an IP, and confirm the categories/comment with them first.
