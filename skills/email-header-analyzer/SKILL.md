---
name: email-header-analyzer
description: Analyze email headers from a JSON object named "headers" to detect spoofing, phishing indicators, authentication failures (SPF/DKIM/DMARC), routing anomalies, and delivery delays. Use this skill whenever the user provides email header data (raw or JSON), asks to inspect an email's origin, verify sender authenticity, trace mail routing hops, check if an email is spoofed or suspicious, or mentions terms like "mail header", "Received chain", "SPF", "DKIM", "DMARC", "Return-Path", "phishing analizi", or "e-posta başlık analizi" — even if they don't explicitly say "analyze headers".
compatibility: Requires Python 3.8+. No external pip dependencies (standard library only).
---

# Email Header Analyzer

A skill that takes a JSON payload containing email header fields (the `headers` object)
and produces a structured security & routing analysis. It can be used by Claude directly
or executed standalone from the command line via the bundled Python script.

## Input format

The input is a JSON document with a top-level `headers` key. Header names are
case-insensitive. Values may be strings, or lists of strings for headers that appear
multiple times (most importantly `Received`).

```json
{
  "headers": {
    "From": "Alice <alice@example.com>",
    "Reply-To": "attacker@evil.example",
    "Return-Path": "<bounce@mailer.example.com>",
    "To": "bob@company.com",
    "Subject": "Invoice attached",
    "Date": "Fri, 17 Jul 2026 10:22:31 +0300",
    "Message-ID": "<abc123@mailer.example.com>",
    "Received": [
      "from mx1.company.com (mx1.company.com [203.0.113.10]) by inbox.company.com; Fri, 17 Jul 2026 07:22:40 +0000",
      "from mailer.example.com (unknown [198.51.100.7]) by mx1.company.com; Fri, 17 Jul 2026 07:22:35 +0000"
    ],
    "Authentication-Results": "mx1.company.com; spf=pass smtp.mailfrom=example.com; dkim=fail; dmarc=fail",
    "Received-SPF": "pass (mx1.company.com: domain of example.com designates 198.51.100.7 as permitted sender)"
  }
}
```

## Output format

The analyzer returns a JSON report with these sections:

- `summary`: one-line verdict and a `risk_score` from 0 (clean) to 100 (highly suspicious), plus a `risk_level` (`low` / `medium` / `high`).
- `identity`: parsed From / Reply-To / Return-Path addresses and domain alignment checks.
- `authentication`: SPF / DKIM / DMARC results extracted from `Authentication-Results` and `Received-SPF`.
- `routing`: parsed `Received` chain (hop-by-hop, oldest first) with per-hop delay in seconds and total transit time.
- `findings`: list of issues, each with `severity` (`info` / `warning` / `critical`), a machine-readable `code`, and a human-readable `message`.

## How to use (as Claude)

1. If the user pasted raw RFC 5322 headers instead of JSON, convert them into the
   `headers` JSON structure first (fold multi-line values, collect repeated `Received`
   headers into a list ordered top-to-bottom as they appear).
2. Save the JSON to a file (e.g. `/home/claude/headers.json`).
3. Run the script:

```bash
python3 scripts/analyze_headers.py --input headers.json --pretty
```

4. Interpret the JSON report for the user: lead with the verdict and risk level,
   explain each `critical`/`warning` finding in plain language, then walk through
   authentication and routing details only as far as they're relevant.

## How to use (standalone CLI)

```bash
# From a file
python3 scripts/analyze_headers.py --input headers.json

# From stdin (pipe)
cat headers.json | python3 scripts/analyze_headers.py

# Pretty-printed report
python3 scripts/analyze_headers.py -i headers.json --pretty

# Human-readable text summary instead of JSON
python3 scripts/analyze_headers.py -i headers.json --format text
```

Exit codes: `0` = analysis completed (regardless of verdict), `1` = invalid input
(bad JSON / missing `headers` key), `2` = file not found.

## Checks performed

- **From vs Reply-To mismatch** — classic phishing pattern where replies are diverted.
- **From vs Return-Path domain misalignment** — possible spoofing or bulk mailer.
- **SPF / DKIM / DMARC** — parsed from `Authentication-Results` / `Received-SPF`; any `fail`, `softfail`, `permerror`, or `none` is flagged with appropriate severity.
- **Received chain analysis** — hop count, per-hop delays (large delays flagged), unknown/unresolved relay hostnames, private IPs appearing mid-chain.
- **Message-ID domain vs From domain** — mismatch is a weak spoofing signal.
- **Missing critical headers** — absent `From`, `Date`, or `Message-ID` is unusual for legitimate mail.
- **Date sanity** — sending date far in the future relative to last Received timestamp.

## Notes

- The script uses only the Python standard library (`json`, `re`, `argparse`,
  `email.utils`, `datetime`), so it runs anywhere Python 3.8+ is available.
- The risk score is heuristic, not a definitive verdict — always present it as
  an indicator, and recommend the user verify through their mail provider for
  high-stakes decisions.
