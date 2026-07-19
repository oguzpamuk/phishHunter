---
name: urlscan
description: Submit URLs to urlscan.io for live scanning (screenshot, page behavior, verdicts) and search historical scans by domain, IP, or hash. Use this skill whenever the user wants to analyze a suspicious link from an email, see what a URL actually loads/redirects to, check phishing pages, mentions "urlscan" or "urlscan.io", or needs historical scan data for a domain or IP during email security / SOC triage.
---

# urlscan.io Skill

Submit URLs for scanning and search urlscan.io's historical scan database from
the command line. Ideal for analyzing suspicious links found in phishing
emails without visiting them yourself.

## Requirements

- Python 3.8+ with `requests` (`pip install requests`)
- Environment variable `URLSCAN_API_KEY`

```bash
export URLSCAN_API_KEY="your_api_key_here"
```

## Usage (CLI)

```bash
# 1) Scan a URL (submits, waits for the result, prints verdict summary)
python scripts/urlscan_lookup.py scan "http://suspicious.example/login"

# Private scan (not listed publicly - use for potentially sensitive URLs)
python scripts/urlscan_lookup.py scan "http://suspicious.example/login" --visibility private

# 2) Search historical scans by domain
python scripts/urlscan_lookup.py search-domain example.com

# 3) Search historical scans by IP
python scripts/urlscan_lookup.py search-ip 1.2.3.4

# 4) Search scans that involved a file hash (e.g. a downloaded payload)
python scripts/urlscan_lookup.py search-hash <sha256>

# 5) Fetch the full result of a previous scan by its UUID
python scripts/urlscan_lookup.py result <scan_uuid>

# Options:
#   --raw        Print full raw API JSON
#   --no-wait    (scan only) Return scan UUID immediately without polling
#   --limit N    (search-* only) Max results, default 10
```

## Output

Condensed JSON on stdout. For `scan`:

```json
{
  "indicator": "http://suspicious.example/login",
  "type": "url",
  "verdict": "malicious",
  "score": 100,
  "categories": ["phishing"],
  "brands": ["Microsoft"],
  "page_domain": "suspicious.example",
  "page_ip": "1.2.3.4",
  "page_country": "NL",
  "screenshot": "https://urlscan.io/screenshots/<uuid>.png",
  "report": "https://urlscan.io/result/<uuid>/"
}
```

For `search-*`: a list of recent scans with dates, URLs and verdicts.
Exit codes: 0 success, 1 error, 2 malicious verdict.

## Workflow guidance for Claude

1. Extract link URLs from the email the user is triaging; scan each with `scan`. Prefer `--visibility private` if the URL may contain tokens/PII (public scans are visible to everyone).
2. Use `search-domain` / `search-ip` first to see if the community already scanned the infrastructure — saves quota and is instant.
3. Summarize for the user: verdict, detected brand (phishing kits impersonate brands), screenshot and report links.
