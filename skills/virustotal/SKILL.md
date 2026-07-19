---
name: virustotal
description: Query VirusTotal (VT API v3) for IP address reputation, domain reputation, URL analysis, file hash (MD5/SHA1/SHA256) lookups, and upload suspicious files/email attachments for scanning. Use this skill whenever the user wants to check if an IP, domain, URL, hash, or file/attachment is malicious, wants a VT verdict, mentions "VirusTotal", "VT", vendor detections, or is doing email security / phishing / SOC triage that requires reputation checks against VirusTotal.
---

# VirusTotal Lookup Skill

Query VirusTotal API v3 from the command line for SOC / email-security triage:
IP reputation, domain reputation, URL analysis, file hash lookup, and file (attachment) upload.

## Requirements

- Python 3.8+ with the `requests` library (`pip install requests`)
- Environment variable `VT_API_KEY` must contain a valid VirusTotal API key.
  - Free/public keys are rate-limited to 4 requests/minute, 500/day.

```bash
export VT_API_KEY="your_api_key_here"
```

## Usage (CLI)

All commands are subcommands of `scripts/vt_lookup.py` and print JSON to stdout.

```bash
# 1) IP address reputation
python scripts/vt_lookup.py ip 8.8.8.8

# 2) Domain reputation
python scripts/vt_lookup.py domain example.com

# 3) URL analysis (submits URL, then fetches the report)
python scripts/vt_lookup.py url "http://suspicious.example/login"

# 4) File hash lookup (MD5, SHA1, or SHA256)
python scripts/vt_lookup.py hash 44d88612fea8a8f36de82e1278abb02f

# 5) Upload a file / email attachment for scanning (waits for the analysis)
python scripts/vt_lookup.py upload /path/to/attachment.docx

# Options:
#   --raw       Print full raw API JSON instead of the summarized verdict
#   --no-wait   (upload/url only) Do not poll for the analysis result, just return the analysis ID
```

## Output

Default output is a summarized JSON verdict, for example:

```json
{
  "indicator": "8.8.8.8",
  "type": "ip",
  "verdict": "clean",
  "stats": {"malicious": 0, "suspicious": 0, "harmless": 62, "undetected": 30},
  "reputation": 448,
  "country": "US",
  "as_owner": "GOOGLE",
  "link": "https://www.virustotal.com/gui/ip-address/8.8.8.8"
}
```

Verdict logic: `malicious` if any engine flags malicious, `suspicious` if only
suspicious flags exist, otherwise `clean`. Exit code is `0` on success, `1` on
API/input errors, `2` when the verdict is malicious (useful for shell pipelines).

## Workflow guidance for Claude

1. Detect the indicator type automatically when possible (IP vs domain vs hash vs URL) and pick the matching subcommand.
2. For email triage: check sender IP with `ip`, sender domain and any link domains with `domain`, link URLs with `url`, and attachments with `hash` first (fast, no upload); only `upload` the file if the hash is unknown to VT and the user consents (uploads are shared with the VT community — warn about confidential files).
3. Summarize results for the user: verdict, malicious/suspicious engine counts, and the GUI link.
