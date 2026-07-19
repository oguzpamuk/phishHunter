---
name: email-triage-pipeline
description: Run a COMPLETE AI-assisted email security triage on a .eml or .msg file and decide whether the email is malicious. Automatically chains the whole toolchain in order - email-parser (parse), email-header-analyzer (spoofing/SPF/DKIM/DMARC), email-anomaly-detector (body spam & brand impersonation), ioc-extractor (IPs/domains/URLs/hashes/attachments), ioc-orchestrator (VirusTotal, AbuseIPDB, OTX, Hybrid Analysis, urlscan in parallel), and whois-lookup (domain age, registrar) - then aggregates every signal into a weighted final verdict (malicious/suspicious/clean) with reasons, optionally reinforced by an Anthropic-API LLM analyst assessment. Use this skill whenever the user uploads a suspicious email and asks "is this phishing / malicious / safe?", wants a full analysis or triage of an email, says "bu mail zararlı mı", "analiz et", "full triage", or asks to run the email security skills together end-to-end.
compatibility: Python 3.8+. Requires the sibling skills email-parser, email-header-analyzer, email-anomaly-detector, ioc-orchestrator (needs `requests` + API keys), and whois-lookup. Works degraded/offline without them (a bundled ioc_extractor fallback is included).
---

# Email Triage Pipeline (AI Verdict)

One command → full SOC-style investigation of an email → final verdict.

```
.eml / .msg
   │
   ▼
[1] email-parser ──────────► structured JSON (headers, body, attachments)
   │
   ├─► [2] email-header-analyzer   spoofing, SPF/DKIM/DMARC, routing (risk 0-100)
   ├─► [3] email-anomaly-detector  body spam & brand impersonation (score 0-100)
   └─► [4] ioc-extractor           IPs, domains, URLs, hashes, attachment SHA256
              │
              ├─► [5] ioc-orchestrator   VT + AbuseIPDB + OTX + HA + urlscan (parallel)
              └─► [6] whois-lookup       registrar, DOMAIN AGE, IP ownership
   │
   ▼
[7] VERDICT ENGINE  ── weighted score ──►  malicious / suspicious / clean
   │
   ▼ (optional --ai)
[8] Anthropic API  ──►  LLM analyst assessment + recommended actions
```

Every stage is fail-soft: missing skills, missing API keys, or no network
never abort the run — the report notes what was skipped and the verdict
confidence is lowered accordingly.

## Quick start (CLI)

```bash
# Full triage (uses whichever intel API keys are exported)
export VT_API_KEY=...; export ABUSEIPDB_API_KEY=...        # any subset
python3 scripts/triage_pipeline.py suspicious.eml -o report.json --pretty

# Human-readable analyst summary instead of JSON
python3 scripts/triage_pipeline.py suspicious.msg --format text

# Fully offline (no reputation APIs, no WHOIS)
python3 scripts/triage_pipeline.py mail.eml --skip-intel --skip-whois --format text

# Restrict intel sources, detonate attachments in sandboxes (asks nothing —
# ALWAYS confirm with the user first, uploads are community-visible!)
python3 scripts/triage_pipeline.py mail.eml --sources vt,otx --upload

# Add the LLM analyst assessment on top of the heuristic verdict
export ANTHROPIC_API_KEY=...
python3 scripts/triage_pipeline.py mail.eml --ai -o report.json --pretty
```

## Input

- Positional: one `.eml` or `.msg` file (format auto-detected).
- `--skills-root DIR` if the sibling skills are not in a standard location
  (auto-search order: `$EMAIL_TRIAGE_SKILLS_ROOT` → side-by-side install →
  `/mnt/skills/user` → `~/.claude/skills`).
- Stage toggles: `--skip-intel`, `--skip-whois`, `--skip-body`.
- Limits: `--max-urls N` (default 10), `--max-domains N` (default 10),
  `--timeout N` seconds per stage (default 600).
- Env keys (all optional): `VT_API_KEY`, `ABUSEIPDB_API_KEY`,
  `URLSCAN_API_KEY`, `OTX_API_KEY`, `HYBRID_ANALYSIS_API_KEY`,
  `ANTHROPIC_API_KEY` (only for `--ai`).

## Output

JSON report (stdout, or `-o file` + one-line verdict on stdout) containing:
`email` (compact summary), `header_analysis`, `body_analysis`, `iocs`,
`intel`, `whois` (with computed `age_days` per domain), `stages`
(per-stage ok/error/skipped), and:

```jsonc
"verdict": {
  "verdict": "malicious",          // malicious | suspicious | clean
  "score": 83.5,                   // weighted 0-100
  "confidence": "high",            // high | medium | low
  "signals": [                     // every scored contribution, explained
    {"signal": "intel_verdict_malicious", "points": 60,
     "detail": "ioc-orchestrator: 2 IOC(s) rated malicious: evil.com, 1.2.3.4"},
    {"signal": "header_risk", "points": 13.5, "detail": "header risk_score=45; ..."},
    {"signal": "very_young_domain", "points": 15, "detail": "evil.com (4d)"}
  ]
},
"ai_analysis": {                   // only with --ai
  "model": "claude-sonnet-4-6", "verdict": "malicious", "confidence": "high",
  "reasoning": "...", "recommended_actions": ["Block sender domain", "..."]
}
```

**Scoring model**: intel malicious +60 / suspicious +25 · header risk ×0.30
(max 30) · body anomaly ×0.20 (max 20) · domain <30 days +15 (<180d +8) ·
risky attachment extension +10 · HTML-only hidden links +5.
Thresholds: ≥70 malicious, ≥40 suspicious, else clean.

**Exit codes**: `0` clean, `1` suspicious, `2` malicious, `3` fatal error —
directly usable in shell automation and mail-gateway hooks.

## Workflow for Claude

1. Locate the uploaded email under `/mnt/user-data/uploads/`.
2. Check which intel API keys are available; tell the user which sources will
   be skipped. Never use `--upload` without explicit user consent.
3. Run: `python3 scripts/triage_pipeline.py <file> -o /home/claude/report.json --pretty`
   (progress is streamed on stderr).
4. Read the report and present it as an analyst would:
   - Lead with the **verdict, score, and confidence**.
   - Explain each fired signal in plain language (the `signals[].detail`
     strings are written for exactly this).
   - Call out per-source disagreements from `intel` and any very young
     domains from `whois`.
   - If `stages` shows errors, say which evidence is missing and how it
     limits confidence.
5. YOU are the AI layer when `--ai` is not used: after presenting the
   heuristic result, add your own reasoned judgement over the evidence — you
   may agree or disagree with the heuristic verdict, but always justify it
   from the collected data, and recommend concrete next actions (block,
   report, delete, or safe).
6. Deliver `report.json` to the user via the outputs directory when they
   want the raw data.

## PDF report (analyst deliverable)

Convert any JSON report into a polished, color-coded PDF with
`scripts/report_to_pdf.py` (requires `pip install reportlab`):

```bash
python3 scripts/triage_pipeline.py mail.eml -o report.json --pretty
python3 scripts/report_to_pdf.py report.json -o report.pdf
# options: --title "..."  --max-rows N (per-table truncation, default 25)
```

The PDF contains a verdict banner (red/orange/green), email summary, every
risk signal with its explanation, header findings by severity, IOC tables,
per-source threat-intel breakdown, WHOIS domain ages, the AI assessment
(when present), and the pipeline stage audit trail. Exit codes: `0` written,
`1` bad input, `2` rendering failure. When the user asks for a shareable /
management-friendly report, generate the PDF and deliver it via the outputs
directory.

## Notes

- The heuristic score is an indicator, not proof — for `suspicious` results
  encourage verification (e.g. contacting the purported sender out-of-band).
- WHOIS needs outbound TCP/43; the intel stage needs HTTPS + API keys. In a
  sandbox without network, run with `--skip-intel --skip-whois` (confidence
  will be "medium" at best).
- Large mailbox batches: loop in bash; exit codes make filtering trivial:
  `for f in *.eml; do python3 triage_pipeline.py "$f" -o "$f.json" || echo "FLAG: $f"; done`
