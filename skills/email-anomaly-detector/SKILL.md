---
name: email-anomaly-detector
description: Analyze the plain-text BODY of an email to produce a spam score, detect brand impersonation (phishing-style brand abuse), and compute an overall anomaly score with a verdict. Use this skill whenever the user pastes email content, asks "is this email spam / phishing / fake?", wants to check whether a message impersonates a brand (PayPal, Amazon, bank, cargo company, etc.), asks for a risk/anomaly score of a message, or wants to batch-scan email bodies. Trigger even if the user does not say the word "spam" — mentions of suspicious email, phishing check, fake bank message, scam text, or "score this email" should all use this skill.
---

# Email Anomaly Detector

Analyzes **only the body text** of an email (no headers, no metadata) and produces:

1. **Spam score** (0–100) — content-based spam likelihood
2. **Brand detection** — which known brands are mentioned, and whether the mention pattern looks like impersonation
3. **Anomaly score** (0–100) — combined weighted score with a final verdict: `CLEAN`, `SUSPICIOUS`, or `ANOMALOUS`

Everything runs offline with the Python standard library only — no network, no API keys, no pip installs.

## How to run (CLI)

The whole skill is a single executable script: `scripts/email_analyzer.py`

```bash
# 1) Analyze an email body from a text file
python3 scripts/email_analyzer.py --file email_body.txt

# 2) Analyze inline text
python3 scripts/email_analyzer.py --text "Dear customer, your PayPal account is suspended..."

# 3) Pipe from stdin
cat email_body.txt | python3 scripts/email_analyzer.py

# 4) Machine-readable JSON output (for pipelines / jq)
python3 scripts/email_analyzer.py --file email_body.txt --json

# 5) Batch mode: analyze every .txt file in a directory
python3 scripts/email_analyzer.py --dir ./emails/ --json
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Verdict is CLEAN |
| 1 | Verdict is SUSPICIOUS |
| 2 | Verdict is ANOMALOUS |
| 3 | Usage / input error (no input provided, file not found) |

Exit codes make the script usable directly in shell pipelines and CI checks
(e.g. `python3 email_analyzer.py --file x.txt && echo "safe"`).

## Workflow for Claude

1. Get the email body from the user (pasted text or uploaded file). Strip headers if the user pasted a full raw email — only the body should be analyzed.
2. Save the body to a temp file (or pass with `--text` for short bodies).
3. Run the script with `--json` and read the structured result.
4. Explain the result to the user in plain language: the verdict, the top signals that fired, and which brand (if any) appears to be impersonated. Do not just dump raw JSON at the user.
5. For batch requests, use `--dir` and summarize per-file verdicts in a small table.

## What the analyzer looks at (signal summary)

- **Spam signals**: money/prize vocabulary, urgency & pressure phrases, ALL-CAPS ratio, exclamation density, "click here" style call-to-actions, unsubscribe-bait, medical/adult spam vocabulary.
- **Brand signals**: mentions of ~40 well-known global + Turkish brands (banks, cargo, e-commerce, tech). A brand mention **plus** credential-request or urgency language is scored as likely impersonation.
- **Anomaly signals**: raw IP URLs, lookalike/suspicious domains, URL shorteners, mixed-script (homoglyph) characters, excessive links, credential harvesting phrases ("verify your password"), mismatch between brand named in text and domains linked.

The final anomaly score is a weighted blend: `0.4 * spam + 0.6 * (brand-impersonation + technical anomalies)`, capped at 100.

## Interpreting scores

| Anomaly score | Verdict | Meaning |
|---------------|---------|---------|
| 0–29 | CLEAN | No meaningful risk signals in the body |
| 30–59 | SUSPICIOUS | Several risk signals; human review recommended |
| 60–100 | ANOMALOUS | Strong spam and/or brand impersonation pattern |

Always remind the user this is a heuristic content-only check: it cannot see headers, SPF/DKIM, or sender reputation, so it complements — not replaces — a real mail security gateway.
