---
name: ioc-orchestrator
description: Automatically detect the type of a given IOC (IP, domain, URL, file hash, or local file/attachment) and query ALL relevant threat-intel sources in PARALLEL - VirusTotal, AbuseIPDB, urlscan.io, AlienVault OTX, and Hybrid Analysis - then aggregate the results into a single combined verdict. Use this skill whenever the user gives one or more IOCs and wants a full reputation check, multi-source triage, "check this IOC everywhere", email security / phishing / SOC investigation of senders, links, or attachments, or asks to run the reputation skills together.
---

# IOC Orchestrator Skill

Give it an IOC — it detects the type, fans out to every applicable source in
parallel, and merges everything into one JSON report with an overall verdict.

| IOC type | Sources queried in parallel |
|---|---|
| IP | VirusTotal, AbuseIPDB, AlienVault OTX, urlscan.io (search) |
| Domain | VirusTotal, AlienVault OTX, urlscan.io (search) |
| URL | VirusTotal, AlienVault OTX, urlscan.io (live scan) |
| Hash | VirusTotal, AlienVault OTX, Hybrid Analysis, urlscan.io (search) |
| Local file | SHA256 computed locally, then queried as hash (or uploaded with `--upload`) |

Sources whose API key environment variable is missing are automatically
skipped and listed under `"skipped"` — the orchestrator never fails just
because one key is absent.

## Requirements

- Python 3.8+ with `requests` (`pip install requests`)
- The five source scripts bundled in `scripts/` next to the orchestrator
  (`vt_lookup.py`, `abuseipdb_lookup.py`, `urlscan_lookup.py`,
  `otx_lookup.py`, `ha_lookup.py`)
- Set the API keys for the sources you want used (any subset works):

```bash
export VT_API_KEY="..."
export ABUSEIPDB_API_KEY="..."
export URLSCAN_API_KEY="..."
export OTX_API_KEY="..."
export HYBRID_ANALYSIS_API_KEY="..."
```

## Usage (CLI)

```bash
# Single IOC - type is auto-detected
python scripts/ioc_orchestrator.py 8.8.8.8
python scripts/ioc_orchestrator.py evil-domain.example
python scripts/ioc_orchestrator.py "http://evil.example/login"
python scripts/ioc_orchestrator.py 44d88612fea8a8f36de82e1278abb02f

# Multiple IOCs in one run (each fanned out in parallel)
python scripts/ioc_orchestrator.py 1.2.3.4 evil.example <sha256>

# Local file / email attachment: hash is computed and looked up (no upload)
python scripts/ioc_orchestrator.py /path/to/attachment.docx

# Actually UPLOAD the file to VirusTotal + Hybrid Analysis sandboxes
# (WARNING: uploads are shared with those communities)
python scripts/ioc_orchestrator.py /path/to/attachment.docx --upload

# Options:
#   --sources vt,abuseipdb,otx   Restrict to specific sources
#                                (ids: vt, abuseipdb, urlscan, otx, ha)
#   --timeout N                  Per-source timeout in seconds (default 420)
#   --workers N                  Max parallel workers (default 8)
#   --upload                     Upload local files instead of hash lookup
#   --raw                        Include each source's full JSON output
```

## Output

One JSON object per run on stdout:

```json
{
  "results": [
    {
      "ioc": "1.2.3.4",
      "detected_type": "ip",
      "overall_verdict": "malicious",
      "verdict_breakdown": {"virustotal": "malicious", "abuseipdb": "malicious",
                             "alienvault-otx": "suspicious", "urlscan": "clean"},
      "sources": { "virustotal": { ...summary... }, ... },
      "skipped": {"urlscan": "URLSCAN_API_KEY not set"},
      "errors": {}
    }
  ],
  "overall_verdict": "malicious"
}
```

Overall verdict = worst verdict across sources
(malicious > suspicious > clean > unknown).
Exit codes: 0 = clean/suspicious/unknown, 1 = fatal error, 2 = any IOC malicious.

## Workflow guidance for Claude

1. Paste raw IOCs straight in — detection order is: existing file path → IP → hash → URL (has scheme) → domain.
2. For email triage, run one command with the sender IP, sender domain, every link URL, and each attachment path together.
3. In the summary to the user, lead with `overall_verdict`, then note per-source disagreements (e.g. clean on VT but 100 score on AbuseIPDB usually means fresh infrastructure).
4. Ask before using `--upload` and warn that uploaded files become visible to the VT/HA communities.
