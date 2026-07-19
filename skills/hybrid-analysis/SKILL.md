---
name: hybrid-analysis
description: Query Hybrid Analysis (Falcon Sandbox) for file hash reputation and submit files/email attachments for dynamic sandbox analysis (behavior, threat score, malware family). Use this skill whenever the user wants to sandbox or detonate a suspicious file/attachment, look up an MD5/SHA1/SHA256 in Hybrid Analysis, mentions "Hybrid Analysis", "Falcon Sandbox", or needs behavioral analysis of email attachments during SOC / email security triage.
---

# Hybrid Analysis (Falcon Sandbox) Skill

Query Hybrid Analysis from the command line: hash lookups against past sandbox
reports, and uploading files (e.g. suspicious email attachments) for full
dynamic analysis in the Falcon Sandbox.

## Requirements

- Python 3.8+ with `requests` (`pip install requests`)
- Environment variable `HYBRID_ANALYSIS_API_KEY` (free key from https://www.hybrid-analysis.com after registration)

```bash
export HYBRID_ANALYSIS_API_KEY="your_api_key_here"
```

## Usage (CLI)

```bash
# 1) Look up a file hash (MD5/SHA1/SHA256) in existing sandbox reports
python scripts/ha_lookup.py hash <sha256>

# 2) Submit a file / attachment for dynamic analysis
#    Default environment: 160 = Windows 10 64-bit
python scripts/ha_lookup.py upload /path/to/attachment.doc

# Choose another sandbox environment:
#   160 = Windows 10 64-bit (default)   140 = Windows 11 64-bit
#   120 = Windows 7 64-bit              310 = Linux (Ubuntu 20.04, 64-bit)
#   200 = Android Static Analysis       400 = macOS Catalina
python scripts/ha_lookup.py upload sample.elf --env 310

# 3) Check the status/result of a submitted job
python scripts/ha_lookup.py report <job_id_or_sha256>

# Options:
#   --raw       Print full raw API JSON
#   --no-wait   (upload only) Return job ID immediately, don't poll
```

## Output

Condensed JSON on stdout:

```json
{
  "indicator": "<sha256>",
  "type": "hash",
  "verdict": "malicious",
  "threat_score": 100,
  "av_detect_percent": 87,
  "malware_family": "AgentTesla",
  "file_type": "Office Open XML Document",
  "environment": "Windows 10 64 bit",
  "tags": ["stealer", "keylogger"],
  "link": "https://www.hybrid-analysis.com/sample/<sha256>"
}
```

Verdict comes from the sandbox itself (`malicious` / `suspicious` /
`no specific threat` -> clean). Exit codes: 0 success, 1 error, 2 malicious.

## Workflow guidance for Claude

1. Always try `hash` first (compute the SHA256 locally with `sha256sum file`) — if a report exists you get results instantly without burning upload quota.
2. Sandbox analysis takes several minutes; `upload` polls automatically, but for large queues use `--no-wait` and check later with `report`.
3. Pick the sandbox environment matching the attachment type: Office docs/PE files -> Windows (160), ELF -> Linux (310), APK -> Android (200).
4. Warn the user before uploading confidential files — submissions may be visible to other Hybrid Analysis users unless their account has private submission rights.
