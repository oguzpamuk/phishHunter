# 📧 Email Security Triage Toolkit

**AI-assisted, end-to-end email threat analysis — built as modular [Claude Agent Skills](https://docs.claude.com/en/docs/agents-and-tools/agent-skills) that also run standalone from the command line.**

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Skills](https://img.shields.io/badge/agent%20skills-13-orange)
![Dependencies](https://img.shields.io/badge/deps-requests%20%C2%B7%20reportlab-brightgreen)
![Platform](https://img.shields.io/badge/platform-Claude.ai%20%7C%20Claude%20Code%20%7C%20CLI-lightgrey)

Give it a suspicious `.eml` or `.msg` file — get back a full SOC-style investigation and a weighted **malicious / suspicious / clean** verdict, with every signal explained.

---

## 🏗 Architecture

```
                              .eml / .msg
                                   │
                                   ▼
                        ┌─────────────────────┐
                        │  1. email-parser     │  structured JSON
                        └──────────┬──────────┘  (headers, body, attachments)
              ┌────────────────────┼────────────────────┐
              ▼                    ▼                    ▼
 ┌────────────────────┐ ┌──────────────────────┐ ┌───────────────────┐
 │ 2. email-header-   │ │ 3. email-anomaly-    │ │ 4. ioc-extractor  │
 │    analyzer        │ │    detector          │ │  IPs · domains    │
 │ SPF/DKIM/DMARC     │ │ spam score, brand    │ │  URLs · hashes    │
 │ spoofing, routing  │ │ impersonation        │ │  attachment SHA256│
 └─────────┬──────────┘ └──────────┬───────────┘ └────────┬──────────┘
           │                       │              ┌────────┴─────────┐
           │                       │              ▼                  ▼
           │                       │   ┌────────────────────┐ ┌─────────────┐
           │                       │   │ 5. ioc-orchestrator│ │ 6. whois-   │
           │                       │   │ VirusTotal         │ │    lookup   │
           │                       │   │ AbuseIPDB · OTX    │ │ registrar,  │
           │                       │   │ Hybrid Analysis    │ │ DOMAIN AGE, │
           │                       │   │ urlscan (parallel) │ │ IP owner    │
           │                       │   └─────────┬──────────┘ └──────┬──────┘
           └───────────────────────┴─────────────┴───────────────────┘
                                   │
                                   ▼
                        ┌─────────────────────┐
                        │ 7. VERDICT ENGINE   │  weighted 0–100 score
                        │ malicious/suspicious│  + explained signals
                        │ /clean + confidence │
                        └──────────┬──────────┘
                                   ▼  (optional --ai)
                        ┌─────────────────────┐
                        │ 8. LLM Analyst      │  Anthropic API assessment
                        │    Assessment       │  + recommended actions
                        └──────────┬──────────┘
                                   ▼  (optional)
                        ┌─────────────────────┐
                        │ 9. PDF Report       │  color-coded, shareable
                        │    Generator        │  analyst deliverable
                        └─────────────────────┘
```

Every stage is **fail-soft**: missing API keys, no network, or an absent skill never aborts the run — the report records what was skipped and the verdict confidence is lowered accordingly.

---

## 📦 Skills in this repository

| Skill | Role in pipeline | Network | External deps |
|---|---|---|---|
| [`email-triage-pipeline`](skills/email-triage-pipeline) | 🎯 **Master orchestrator + AI verdict** | optional | – |
| [`email-parser`](skills/email-parser) | Parse `.msg` / `.eml` → normalized JSON | no | – |
| [`email-header-analyzer`](skills/email-header-analyzer) | Spoofing, SPF/DKIM/DMARC, Received-chain analysis | no | – |
| [`email-anomaly-detector`](skills/email-anomaly-detector) | Body spam score + brand-impersonation detection | no | – |
| [`ioc-extractor`](skills/ioc-extractor) | Extract IPs/domains/URLs/hashes (incl. defanged) | no | – |
| [`ioc-orchestrator`](skills/ioc-orchestrator) | Parallel multi-source reputation fan-out | yes | `requests` |
| [`whois-lookup`](skills/whois-lookup) | Registrar, creation date → **domain age** | TCP/43 | – |
| [`virustotal`](skills/virustotal) | VT API v3 lookups & uploads | yes | `requests` |
| [`abuseipdb`](skills/abuseipdb) | IP abuse confidence & history | yes | `requests` |
| [`alienvault-otx`](skills/alienvault-otx) | OTX pulse / campaign intelligence | yes | `requests` |
| [`hybrid-analysis`](skills/hybrid-analysis) | Falcon Sandbox hash lookups & detonation | yes | `requests` |
| [`urlscan`](skills/urlscan) | Live URL scans + historical search | yes | `requests` |
| [`email-yara-scanner`](skills/email-yara-scanner) | Scan emails against user YARA rules | no | `yara-python` |

Each skill folder follows the standard Agent Skill layout — a `SKILL.md` (YAML frontmatter + instructions) plus self-contained CLI scripts under `scripts/` with detailed English comments documenting inputs, outputs, and exit codes.

---

## 🚀 Quick start

### Option A — Standalone CLI (no Claude required)

```bash
git clone https://github.com/<you>/email-security-triage.git
cd email-security-triage
pip install -r requirements.txt          # only `requests`, for the intel stage

# Export whichever intel API keys you have (all optional — missing ones are skipped)
export VT_API_KEY="..."
export ABUSEIPDB_API_KEY="..."
export OTX_API_KEY="..."
export URLSCAN_API_KEY="..."
export HYBRID_ANALYSIS_API_KEY="..."

# Full triage
python3 skills/email-triage-pipeline/scripts/triage_pipeline.py \
    suspicious.eml --skills-root skills -o report.json --pretty

# Human-readable analyst summary
python3 skills/email-triage-pipeline/scripts/triage_pipeline.py \
    suspicious.eml --skills-root skills --format text

# Fully offline (no reputation APIs, no WHOIS)
python3 skills/email-triage-pipeline/scripts/triage_pipeline.py \
    suspicious.eml --skills-root skills --skip-intel --skip-whois --format text

# Add an LLM analyst assessment on top of the heuristic verdict
export ANTHROPIC_API_KEY="..."
python3 skills/email-triage-pipeline/scripts/triage_pipeline.py \
    suspicious.eml --skills-root skills --ai -o report.json --pretty

# Turn the JSON report into a polished, color-coded PDF
python3 skills/email-triage-pipeline/scripts/report_to_pdf.py report.json -o report.pdf
```

Try it immediately with the bundled sample:

```bash
python3 skills/email-triage-pipeline/scripts/triage_pipeline.py \
    examples/sample_phishing.eml --skills-root skills \
    --skip-intel --skip-whois --format text
```

### Option B — Claude.ai / Claude Code

Install each skill folder as an Agent Skill (upload the folder or a packaged `.skill` file in Claude.ai → *Settings → Capabilities → Skills*, or drop the folders into `~/.claude/skills/` for Claude Code). Then simply ask:

> *"Is this email malicious?"* (attach the `.eml`/`.msg`)

Claude runs the whole pipeline and acts as the final AI analyst layer — reasoning over the collected evidence, agreeing or disagreeing with the heuristic verdict, and recommending actions.

---

## 📊 Example output

```
==============================================================
EMAIL TRIAGE REPORT — sample_phishing.eml
==============================================================
VERDICT : SUSPICIOUS   score=51.2/100   confidence=medium
Subject : Urgent: Your PayPal account is suspended - verify now!
From    : PayPal Security <security@paypal.com>
--------------------------------------------------------------
Signals:
  [+ 30.0] header_risk: header risk_score=100; critical: Reply-To domain
           (mail-secure-login.xyz) differs from From domain (paypal.com);
           SPF check failed; DKIM check failed ...
  [+  6.2] body_anomaly: body anomaly score=31.0; verdict=SUSPICIOUS
  [+   10] risky_attachment: risky attachment extension(s): invoice.docm
  [+    5] html_only_links: 2 URL(s) present only in HTML attributes
==============================================================
```

With live threat-intel keys the same email climbs into **MALICIOUS** territory (`+60` when any IOC is confirmed malicious). A full JSON report is available at [`examples/sample_triage_report.json`](examples/sample_triage_report.json).

### 📄 PDF reports

Every JSON report can be rendered as a shareable, management-friendly PDF — verdict banner color-coded by outcome (🔴 malicious / 🟠 suspicious / 🟢 clean), severity-highlighted header findings, IOC tables, per-source intel breakdown, WHOIS domain ages, the AI assessment, and a pipeline audit trail:

```bash
python3 skills/email-triage-pipeline/scripts/report_to_pdf.py report.json -o report.pdf \
    --title "Incident #2026-0719 — Phishing Triage"   # optional custom title
```

See [`examples/sample_triage_report.pdf`](examples/sample_triage_report.pdf) for what the output looks like.

---

## ⚖️ Verdict scoring model

| Signal | Points |
|---|---|
| Threat intel: any IOC rated **malicious** | +60 |
| Threat intel: any IOC rated **suspicious** | +25 |
| Header risk score (spoofing / auth failures) | ×0.30 (max 30) |
| Body anomaly score (spam / brand impersonation) | ×0.20 (max 20) |
| Domain registered **< 30 days** ago | +15 |
| Domain registered < 180 days ago | +8 |
| Risky attachment extension (`.exe`, `.docm`, `.iso`, …) | +10 |
| URLs present only in HTML attributes (hidden links) | +5 |

**Thresholds:** score ≥ 70 → `malicious` · ≥ 40 → `suspicious` · otherwise `clean`.
**Confidence:** `high` when the intel stage ran · `medium` offline · `low` when 2+ stages failed.

### Exit codes (automation-friendly)

| Code | Meaning |
|---|---|
| `0` | clean |
| `1` | suspicious |
| `2` | malicious |
| `3` | fatal error (unparseable input) |

Batch a whole mailbox in one line:

```bash
for f in *.eml; do
  python3 skills/email-triage-pipeline/scripts/triage_pipeline.py "$f" \
      --skills-root skills -o "$f.report.json" || echo "⚠️  FLAG: $f"
done
```

---

## 🔑 API keys

All keys are **optional** — sources without a key are skipped automatically and noted in the report.

| Env variable | Service | Free tier |
|---|---|---|
| `VT_API_KEY` | [VirusTotal](https://www.virustotal.com/gui/my-apikey) | ✅ |
| `ABUSEIPDB_API_KEY` | [AbuseIPDB](https://www.abuseipdb.com/account/api) | ✅ |
| `OTX_API_KEY` | [AlienVault OTX](https://otx.alienvault.com/api) | ✅ |
| `URLSCAN_API_KEY` | [urlscan.io](https://urlscan.io/user/profile/) | ✅ |
| `HYBRID_ANALYSIS_API_KEY` | [Hybrid Analysis](https://www.hybrid-analysis.com/apikeys) | ✅ |
| `ANTHROPIC_API_KEY` | [Anthropic](https://console.anthropic.com/) — only for `--ai` | – |

> ⚠️ **`--upload` warning:** uploading attachments to VirusTotal / Hybrid Analysis makes them visible to those communities. Never upload files containing sensitive data.

---

## 📁 Repository layout

```
.
├── README.md
├── requirements.txt
├── .gitignore
├── skills/                      # 13 Agent Skills (SKILL.md + scripts/)
│   ├── email-triage-pipeline/   #   ← master pipeline + verdict engine
│   │   └── scripts/
│   │       ├── triage_pipeline.py
│   │       ├── report_to_pdf.py #   ← JSON report → professional PDF
│   │       └── ioc_extractor.py #   (bundled fallback)
│   ├── email-parser/
│   ├── email-header-analyzer/
│   ├── email-anomaly-detector/
│   ├── ioc-extractor/
│   ├── ioc-orchestrator/
│   ├── whois-lookup/
│   ├── virustotal/  abuseipdb/  alienvault-otx/
│   ├── hybrid-analysis/  urlscan/
│   └── email-yara-scanner/
└── examples/
    ├── sample_phishing.eml      # synthetic test phishing email
    ├── sample_clean.eml         # synthetic clean email
    ├── sample_triage_report.json
    └── sample_triage_report.pdf # rendered PDF example
```

---

## 🛡 Disclaimer

The heuristic and AI verdicts are **decision-support indicators, not proof**. Always verify `suspicious` results through out-of-band channels before acting, and follow your organization's incident-response procedures. The sample emails in `examples/` are synthetic and reference documentation/test infrastructure only (RFC 5737 TEST-NET addresses).

## 🤝 Contributing

Issues and PRs are welcome — new intel sources plug in cleanly as additional skills consumed by `ioc-orchestrator`, and new verdict signals are a single `add(...)` call in the pipeline's verdict engine.

## 📄 License

Apache 2.0
