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
because one key is absent. Sources that were queried but failed (invalid
key, network error, rate limit) are listed under `"errors"` with the final
error line only (not the full traceback). Answers that ran but produced no
result (urlscan "Scan did not finish in time", queued-only jobs) are also
recorded under `"errors"` as `incomplete: ...`, never as coverage.
When a source answers HTTP 400/422 AND its message names the indicator as
invalid, reserved, unresolvable or blocked (e.g. `Invalid domain`, urlscan
`DNS Error - Could not resolve domain`), it has refused the indicator itself.
Those go under `"rejected"`, not `"errors"`: they are not key/network
failures. A 400 that reports a malformed request (e.g. Hybrid Analysis
`validation failed: hash: This value should not be blank.`) stays in
`"errors"`, because it points at a client-side bug. Error texts carry the API's
own message extracted from its (possibly truncated, multi-line) JSON body.

**Read `coverage` before trusting a verdict.** `overall_verdict: "unknown"`
with `coverage.jobs_ok == 0` means *nothing was checked* — it is not "clean".

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
#   --workers N                  Max parallel workers (default 0 = one per
#                                (IOC, source) job, capped at 32). Every IOC
#                                and source runs concurrently, so total time
#                                is ~one per-source timeout.
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
  "overall_verdict": "malicious",
  "coverage": {"jobs_ok": 7, "jobs_error": 1, "jobs_rejected": 1,
               "jobs_skipped": 3, "jobs_no_verdict": 2,
               "sources_ok": ["virustotal", "abuseipdb"],
               "sources_error": ["urlscan"], "sources_rejected": ["alienvault-otx"],
               "sources_skipped": ["hybrid-analysis"]}
}
```

Overall verdict = worst verdict across sources
(malicious > suspicious > clean > unknown).
Exit codes: 0 = clean/suspicious/unknown, 1 = fatal error (incl. no API keys),
2 = any IOC malicious, 3 = every attempted source query failed (no data).

## Workflow guidance for Claude

1. Paste raw IOCs straight in — detection order is: existing file path → IP → hash → URL (has scheme) → domain.
2. For email triage, run one command with the sender IP, sender domain, every link URL, and each attachment path together.
3. In the summary to the user, lead with `overall_verdict`, then note per-source disagreements (e.g. clean on VT but 100 score on AbuseIPDB usually means fresh infrastructure).
4. Ask before using `--upload` and warn that uploaded files become visible to the VT/HA communities.
