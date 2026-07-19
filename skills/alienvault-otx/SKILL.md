---
name: alienvault-otx
description: Query AlienVault OTX (Open Threat Exchange) for threat intelligence on IPs, domains, URLs, and file hashes - pulse (threat report) counts, malware associations, and passive DNS. Use this skill whenever the user wants threat intel context for an indicator, mentions "OTX", "AlienVault", "pulses", or is doing email security / SOC triage and needs to know if an IOC appears in known threat campaigns.
---

# AlienVault OTX Skill

Query the AlienVault OTX API from the command line. OTX tells you whether an
indicator appears in community "pulses" (threat reports/campaigns), which
malware families it is associated with, and its passive DNS history.

## Requirements

- Python 3.8+ with `requests` (`pip install requests`)
- Environment variable `OTX_API_KEY` (free at https://otx.alienvault.com)

```bash
export OTX_API_KEY="your_api_key_here"
```

## Usage (CLI)

```bash
# 1) IP address threat intel
python scripts/otx_lookup.py ip 1.2.3.4

# 2) Domain threat intel
python scripts/otx_lookup.py domain example.com

# 3) URL threat intel
python scripts/otx_lookup.py url "http://evil.example/payload.exe"

# 4) File hash threat intel (MD5/SHA1/SHA256)
python scripts/otx_lookup.py hash <sha256>

# Options:
#   --raw       Print full raw API JSON
#   --pdns      (ip/domain only) Also fetch passive DNS records
```

## Output

Condensed JSON on stdout:

```json
{
  "indicator": "1.2.3.4",
  "type": "ip",
  "verdict": "suspicious",
  "pulse_count": 7,
  "pulses": [
    {"name": "Emotet C2 infrastructure July 2026", "created": "2026-07-01", "tags": ["emotet", "c2"]}
  ],
  "malware_families": ["emotet"],
  "country": "RU",
  "asn": "AS12345 EvilHost",
  "link": "https://otx.alienvault.com/indicator/ip/1.2.3.4"
}
```

Verdict: `malicious` if >=5 pulses or malware families found, `suspicious` if
1–4 pulses, otherwise `clean`. Exit codes: 0 success, 1 error, 2 malicious.

## Workflow guidance for Claude

1. Use OTX as *context* alongside VirusTotal/AbuseIPDB: pulses tell you WHICH campaign an IOC belongs to (e.g. "Emotet C2"), which is valuable for incident reports.
2. Pulse counts can include stale data — check pulse creation dates before declaring an indicator active.
3. Use `--pdns` on domains to find sibling hostnames on the same infrastructure during phishing investigations.
