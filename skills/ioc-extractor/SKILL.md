---
name: ioc-extractor
description: Extract all Indicators of Compromise (IOCs) — IP addresses, domains, URLs, file hashes (MD5/SHA1/SHA256), email addresses, and attachment hashes — from a parsed email JSON (email-parser output) or from raw text, including defanged indicators like hxxp:// and evil[.]com. Use this skill whenever the user wants to pull IOCs out of an email or text, asks "what IOCs are in this email", needs input for the ioc-orchestrator / VirusTotal / whois lookups, mentions "IOC extraction", "indicator listesi", "zararlı linkleri çıkar", or as the extraction step of any email security / phishing / SOC triage pipeline.
compatibility: Python 3.8+, standard library only (no pip installs, fully offline).
---

# IOC Extractor

Pulls every actionable indicator out of an email (or any text) and emits a
clean, deduplicated JSON list ready to be fed into the `ioc-orchestrator`,
`virustotal`, and `whois-lookup` skills.

Pipeline position: **email-parser → ioc-extractor → ioc-orchestrator / whois-lookup**

## What it extracts

| Type | Notes |
|---|---|
| IPv4 / IPv6 | Private/reserved IPs excluded by default (RFC1918 etc.) |
| Domains | From URLs, bare text, email addresses, and the `Received` chain |
| URLs | From plain text **and** HTML `href`/`src` attributes (hidden links) |
| Hashes | MD5 / SHA1 / SHA256 found in text + SHA256 computed for attachments |
| Emails | From/Reply-To/Return-Path and any address in the body |
| Attachments | Filename, type, size, SHA256 (if bytes present), `risky_extension` flag |

Defanged indicators (`hxxp://`, `evil[.]com`, `user[at]host`) are refanged
automatically. Each IOC carries a `sources` list showing *where* in the email
it was found (`from`, `headers`, `body`, `html`, `subject`, `body_url`, ...).

## CLI usage

```bash
# From an email-parser JSON result (recommended pipeline usage)
python3 scripts/parse_email.py mail.eml -o parsed.json          # email-parser skill
python3 scripts/ioc_extractor.py --input parsed.json --pretty

# Pipe parser output directly
python3 scripts/parse_email.py mail.eml --compact | python3 scripts/ioc_extractor.py

# Raw text scanning
python3 scripts/ioc_extractor.py --text "visit hxxp://evil[.]com now"
python3 scripts/ioc_extractor.py --file suspicious_body.txt --pretty

# Options
#   --no-refang        keep defanged notation untouched
#   --no-allowlist     don't drop well-known benign domains (w3.org, ...)
#   --include-private  keep RFC1918 / loopback IPs
#   -o result.json     write to file
#   --pretty           indent JSON
```

To also get attachment SHA256 hashes, run the parser with
`--include-attachment-data` so the extractor can hash the bytes.

## Input

- `--input` : JSON in the email-parser schema (`from`, `headers`, `body`,
  `attachments`, ...). Missing keys are tolerated.
- `--text` / `--file` : arbitrary raw text.
- stdin: auto-detected — JSON is tried first, otherwise treated as raw text.

## Output (single JSON object on stdout)

```jsonc
{
  "input_kind": "parsed_email",
  "iocs": {
    "ips":     [{"value": "203.0.113.7", "sources": ["headers"], "private": false}],
    "domains": [{"value": "evil.com",    "sources": ["body_url", "from"]}],
    "urls":    [{"value": "http://evil.com/login", "sources": ["html"]}],
    "hashes":  [{"value": "44d8...", "algo": "md5", "sources": ["body"]}],
    "emails":  [{"value": "ceo@evil.com", "sources": ["reply_to"]}]
  },
  "attachments": [{"filename": "inv.docm", "content_type": "...", "size_bytes": 123,
                   "sha256": "ab12...", "risky_extension": true}],
  "sender": {"email": "ceo@evil.com", "domain": "evil.com"},
  "counts": {"ips": 1, "domains": 1, "urls": 1, "hashes": 1, "emails": 1, "attachments": 1},
  "warnings": []
}
```

Exit codes: `0` success (even with zero IOCs), `1` invalid input, `2` unexpected error.

## Workflow for Claude

1. Make sure you have an email-parser JSON (run the `email-parser` skill first
   with `--include-attachment-data` when attachments exist).
2. Run the extractor with `--input parsed.json -o iocs.json`.
3. Feed the results onward:
   - `iocs.ips` + `iocs.domains` + `iocs.urls` + attachment `sha256` values →
     `ioc-orchestrator` skill (one command, space-separated).
   - `iocs.domains` (and sender IP) → `whois-lookup` skill.
4. When summarizing to the user, group by type, mention the `sources` of the
   most suspicious items (e.g. a URL that exists only in HTML `href` but not
   in the visible text), and flag `risky_extension: true` attachments.
