---
name: email-yara-scanner
description: Scan .msg (Outlook) and .eml (MIME) email files against user-provided YARA rules and report every matching rule as structured JSON. Use this skill whenever the user wants to run YARA rules on an email file, check an email for malicious indicators with YARA, analyze phishing/malware emails with custom detection rules, or asks anything like "scan this eml/msg with yara", "which yara rules match this email", or "run my rules against this message". The YARA rules are always supplied by the user as an external file or directory path — this skill never authors YARA rules itself.
---

# Email YARA Scanner

Scans a `.msg` or `.eml` email file with YARA rules loaded from an external path and prints the results as JSON on stdout.

## What it scans

For each email, the scanner runs the YARA rules against multiple "targets" so matches inside any layer of the email are caught:

1. **raw_file** — the untouched bytes of the email file itself
2. **body_text** / **body_html** — the decoded plain-text and HTML bodies
3. **attachment:<filename>** — the decoded bytes of every attachment
4. **headers** — the raw header block (for `.eml`) or reconstructed header text (for `.msg`)

## Usage

```bash
# Install dependencies once (see Requirements below)
pip install yara-python extract-msg --break-system-packages

# Scan a single email with a single rules file
python scripts/scan_email.py --file suspicious.eml --rules /path/to/rules.yar

# Rules can also be a directory: every *.yar / *.yara file inside is compiled
python scripts/scan_email.py --file invoice.msg --rules /opt/yara-rules/

# Write JSON to a file instead of stdout
python scripts/scan_email.py --file mail.eml --rules rules.yar --output result.json

# Adjust the YARA timeout (seconds, default 60)
python scripts/scan_email.py --file mail.eml --rules rules.yar --timeout 120
```

## Input

| Argument    | Required | Description                                                        |
|-------------|----------|--------------------------------------------------------------------|
| `--file`    | yes      | Path to the `.msg` or `.eml` file to scan                          |
| `--rules`   | yes      | Path to a YARA rules file (`.yar`/`.yara`) **or** a directory of them |
| `--output`  | no       | Path to write the JSON report (default: stdout)                    |
| `--timeout` | no       | YARA scan timeout per target in seconds (default: 60)              |

## Output

JSON object on stdout (or `--output` file). Exit codes: `0` = scan ran and ≥1 rule matched, `1` = scan ran and nothing matched, `2` = error (bad input, rules failed to compile, etc.). Shape:

```json
{
  "scanned_file": "suspicious.eml",
  "file_type": "eml",
  "rules_source": "/opt/yara-rules/",
  "scan_time_utc": "2026-07-19T12:00:00Z",
  "match_found": true,
  "total_matches": 2,
  "matches": [
    {
      "rule": "Phish_CredHarvest",
      "namespace": "default",
      "tags": ["phishing"],
      "meta": {"author": "analyst", "severity": "high"},
      "matched_in": "body_html",
      "strings": [
        {"identifier": "$url", "offset": 1042, "data": "hxxp://evil.example"}
      ]
    }
  ],
  "targets_scanned": ["raw_file", "headers", "body_text", "body_html", "attachment:invoice.zip"],
  "errors": []
}
```

## Requirements

- Python 3.8+
- `yara-python` (mandatory — script exits with code 2 if missing)
- `extract-msg` (only needed for `.msg` files; `.eml` works with the standard library alone)

## Notes for Claude

- Never write YARA rules for the user in this workflow; always ask for / use the rules path they provide.
- If the user uploads the email and rules, they land in `/mnt/user-data/uploads/` — pass those paths directly.
- If `extract-msg` is missing and the input is `.msg`, install it first, then rerun.
- Report the JSON back to the user; if `match_found` is false, say so explicitly rather than implying the file is clean (YARA coverage is only as good as the supplied rules).
