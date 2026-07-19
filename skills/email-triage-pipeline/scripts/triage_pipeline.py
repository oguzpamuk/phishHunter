#!/usr/bin/env python3
"""
triage_pipeline.py — Full email security triage pipeline with an AI-assisted
final verdict.

Chains the following skills, in order, over a single .eml or .msg file:

    1. email-parser            -> structured JSON (subject, headers, body,
                                  attachments)
    2. email-header-analyzer   -> spoofing / SPF-DKIM-DMARC / routing report
    3. email-anomaly-detector  -> body spam & brand-impersonation score
    4. ioc-extractor           -> IPs, domains, URLs, hashes, attachment SHA256s
    5. ioc-orchestrator        -> parallel VirusTotal / AbuseIPDB / OTX /
                                  Hybrid Analysis / urlscan reputation lookups
    6. whois-lookup            -> registration data & DOMAIN AGE for every
                                  relevant domain (+ sender IP ownership)
    7. verdict engine          -> weighted aggregation of every signal into a
                                  final malicious / suspicious / clean verdict
    8. (optional) --ai         -> sends the evidence bundle to the Anthropic
                                  API for an LLM-written analyst assessment

Each stage is OPTIONAL-FAIL: if a stage errors out (missing skill, no
network, missing API keys) the pipeline records the error and continues, so
you always get a report from whatever evidence was collectable.

============================================================================
INPUT
============================================================================
Positional argument:
    email_file            Path to a .eml (RFC 5322/MIME) or .msg (Outlook)
                          file. Format is auto-detected by the parser.

Skill discovery:
    --skills-root DIR     Directory that CONTAINS the skill folders
                          (email-parser/, ioc-orchestrator/, ...). If omitted,
                          the following locations are searched in order:
                            $EMAIL_TRIAGE_SKILLS_ROOT
                            <this script>/../..        (side-by-side install)
                            /mnt/skills/user           (Claude.ai)
                            ~/.claude/skills
                          A bundled fallback copy of ioc_extractor.py inside
                          this skill's scripts/ dir is used if the standalone
                          ioc-extractor skill is not installed.

Stage control:
    --skip-intel          Skip stage 5 (no reputation API calls). Use for
                          fully offline analysis.
    --skip-whois          Skip stage 6 (no WHOIS lookups).
    --skip-body           Skip stage 3 (body anomaly analysis).
    --sources LIST        Passed through to ioc-orchestrator, e.g.
                          "vt,abuseipdb,otx" (default: all with API keys set).
    --upload              Passed through to ioc-orchestrator: actually upload
                          attachments to VT / Hybrid Analysis sandboxes.
                          WARNING: uploaded files become community-visible.
    --max-urls N          Max URLs sent to reputation lookups (default 10).
    --max-domains N       Max domains sent to reputation/WHOIS (default 10).
    --timeout N           Per-stage subprocess timeout in seconds (default 600).

AI verdict (optional):
    --ai                  After the heuristic verdict, call the Anthropic API
                          with the full evidence bundle and include the
                          model's analyst assessment in the report.
                          Requires the ANTHROPIC_API_KEY environment variable
                          and outbound HTTPS access.
    --ai-model NAME       Model to use (default: claude-sonnet-4-6).

Output control:
    -o / --output FILE    Write the full JSON report to FILE (recommended —
                          reports can be large).
    --pretty              Pretty-print JSON.
    --format json|text    "text" prints a human-readable analyst summary
                          instead of JSON (default: json).

Environment variables consumed indirectly (by the orchestrator stage):
    VT_API_KEY, ABUSEIPDB_API_KEY, URLSCAN_API_KEY, OTX_API_KEY,
    HYBRID_ANALYSIS_API_KEY — any subset; missing sources are skipped.

============================================================================
OUTPUT — JSON report schema (stdout or --output)
============================================================================
{
  "pipeline_version": "1.0",
  "input_file": "/path/mail.eml",
  "started_utc": "...", "finished_utc": "...",
  "stages": {                       # per-stage status bookkeeping
    "parse":        {"status": "ok" | "error" | "skipped", "error": null},
    "headers":      {...}, "body_anomaly": {...}, "ioc_extract": {...},
    "intel":        {...}, "whois": {...}, "ai": {...}
  },
  "email": {                        # compact view of the parsed email
    "subject": "...", "from": {...}, "to": [...], "date": "...",
    "attachment_names": ["inv.docm"]
  },
  "header_analysis":  { ...full email-header-analyzer report... },
  "body_analysis":    { ...full email-anomaly-detector report... },
  "iocs":             { ...full ioc-extractor report... },
  "intel":            { ...full ioc-orchestrator report... },
  "whois": {
    "<domain-or-ip>": { ...whois-lookup JSON..., "age_days": 12 }, ...
  },
  "verdict": {                      # heuristic verdict engine result
    "verdict": "malicious" | "suspicious" | "clean",
    "score": 0-100,                 # weighted risk score
    "confidence": "high"|"medium"|"low",
    "signals": [                    # every scored contribution
      {"signal": "intel_verdict_malicious", "points": 60,
       "detail": "ioc-orchestrator: 2 IOC(s) rated malicious"}
    ]
  },
  "ai_analysis": {                  # present only with --ai
    "model": "...", "verdict": "...", "confidence": "...",
    "reasoning": "...", "recommended_actions": [...]
  }
}

============================================================================
EXIT CODES
============================================================================
  0  pipeline completed, final verdict = clean
  1  pipeline completed, final verdict = suspicious
  2  pipeline completed, final verdict = malicious
  3  fatal error (email could not be parsed at all / bad usage)
============================================================================
"""

import argparse
import base64
import datetime as dt
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request

PIPELINE_VERSION = "1.0"

# Map: skill folder name -> script filename inside its scripts/ directory.
SKILL_SCRIPTS = {
    "email-parser": "parse_email.py",
    "email-header-analyzer": "analyze_headers.py",
    "email-anomaly-detector": "email_analyzer.py",
    "ioc-extractor": "ioc_extractor.py",
    "ioc-orchestrator": "ioc_orchestrator.py",
    "whois-lookup": "whois_lookup.py",
}


# ---------------------------------------------------------------------------
# Skill / script discovery
# ---------------------------------------------------------------------------
def candidate_roots(cli_root):
    """Yield directories that may contain the sibling skill folders.

    Search order (first hit wins per skill):
      1. --skills-root CLI argument
      2. $EMAIL_TRIAGE_SKILLS_ROOT
      3. the parent-of-parent of this script (side-by-side layout:
         <root>/email-triage-pipeline/scripts/triage_pipeline.py)
      4. /mnt/skills/user   (Claude.ai user skills)
      5. ~/.claude/skills   (Claude Code user skills)
    """
    here = os.path.dirname(os.path.abspath(__file__))
    roots = [
        cli_root,
        os.environ.get("EMAIL_TRIAGE_SKILLS_ROOT"),
        os.path.dirname(os.path.dirname(here)),
        "/mnt/skills/user",
        os.path.expanduser("~/.claude/skills"),
    ]
    seen = set()
    for r in roots:
        if r and os.path.isdir(r) and r not in seen:
            seen.add(r)
            yield r


def find_script(skill_name, cli_root):
    """Locate the runnable script of a sibling skill.

    Input : skill_name — folder name, e.g. "ioc-orchestrator"
            cli_root   — value of --skills-root (may be None)
    Output: absolute path to the script, or None if not installed anywhere.

    Special case: for "ioc-extractor" a bundled fallback copy inside THIS
    skill's scripts/ directory is used when the standalone skill is absent,
    so the pipeline works out of the box.
    """
    fname = SKILL_SCRIPTS[skill_name]
    for root in candidate_roots(cli_root):
        p = os.path.join(root, skill_name, "scripts", fname)
        if os.path.isfile(p):
            return p
    if skill_name == "ioc-extractor":
        local = os.path.join(os.path.dirname(os.path.abspath(__file__)), fname)
        if os.path.isfile(local):
            return local
    return None


def run_script(path, args, timeout, stdin_text=None):
    """Execute a skill script as a subprocess and capture its JSON stdout.

    Input : path       — script path
            args       — list of CLI arguments
            timeout    — seconds before the subprocess is killed
            stdin_text — optional text piped to the process' stdin
    Output: (parsed_json_or_None, raw_stdout, raw_stderr, returncode)
            parsed_json is None when stdout is not valid JSON.
    """
    proc = subprocess.run(
        [sys.executable, path] + args,
        input=stdin_text, capture_output=True, text=True, timeout=timeout)
    data = None
    out = proc.stdout.strip()
    if out:
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            data = None
    return data, proc.stdout, proc.stderr, proc.returncode


# ---------------------------------------------------------------------------
# Individual pipeline stages
# ---------------------------------------------------------------------------
def stage_parse(script, email_file, tmpdir, timeout):
    """STAGE 1 — parse the .eml/.msg into structured JSON.

    Runs email-parser WITH --include-attachment-data so attachment bytes are
    available for hashing / optional sandbox upload. Attachment binaries are
    then written to <tmpdir>/attachments/ and their paths returned so the
    orchestrator can hash them, while the in-memory copy of the parsed dict
    has data_base64 kept (the ioc-extractor needs it for SHA256).

    Output: (parsed_dict, attachment_paths[])  — raises on parse failure.
    """
    out_json = os.path.join(tmpdir, "parsed.json")
    _, _, err, rc = run_script(
        script, [email_file, "--include-attachment-data", "-o", out_json],
        timeout)
    if rc != 0 or not os.path.isfile(out_json):
        raise RuntimeError(f"email-parser failed (rc={rc}): {err.strip()[:400]}")
    with open(out_json, "r", encoding="utf-8") as f:
        parsed = json.load(f)

    # Materialize attachments as real files for the intel stage.
    att_dir = os.path.join(tmpdir, "attachments")
    os.makedirs(att_dir, exist_ok=True)
    paths = []
    for i, att in enumerate(parsed.get("attachments") or []):
        b64 = att.get("data_base64")
        if not b64:
            continue
        # Sanitize the filename to avoid path traversal from hostile emails.
        safe = re.sub(r"[^A-Za-z0-9._-]", "_",
                      att.get("filename") or f"attachment_{i}")[:100]
        p = os.path.join(att_dir, f"{i}_{safe}")
        try:
            with open(p, "wb") as f:
                f.write(base64.b64decode(b64))
            paths.append(p)
        except Exception:
            pass  # hashing simply won't cover this attachment
    return parsed, paths


def stage_headers(script, parsed, tmpdir, timeout):
    """STAGE 2 — header security analysis.

    Input : parsed email dict (uses its "headers" object).
    Output: email-header-analyzer JSON report
            (summary.risk_score 0-100, findings[], authentication, routing).
    """
    hjson = os.path.join(tmpdir, "headers.json")
    with open(hjson, "w", encoding="utf-8") as f:
        json.dump({"headers": parsed.get("headers") or {}}, f)
    data, _, err, rc = run_script(script, ["--input", hjson], timeout)
    if data is None:
        raise RuntimeError(f"header analyzer failed (rc={rc}): "
                           f"{err.strip()[:400]}")
    return data


def stage_body(script, parsed, tmpdir, timeout):
    """STAGE 3 — body spam / brand-impersonation analysis.

    Input : parsed email dict (uses body.text, falling back to a crude
            tag-stripped version of body.html).
    Output: email-anomaly-detector JSON report (anomaly score + verdict),
            or None when the email has no usable body text.
    """
    body = (parsed.get("body") or {})
    text = body.get("text")
    if not text and body.get("html"):
        text = re.sub(r"<[^>]+>", " ", body["html"])
    if not text or not text.strip():
        return None
    bfile = os.path.join(tmpdir, "body.txt")
    with open(bfile, "w", encoding="utf-8") as f:
        f.write(text)
    data, _, err, rc = run_script(script, ["--file", bfile, "--json"], timeout)
    # NOTE: this script's exit code encodes the verdict (0/1/2), so a
    # non-zero rc is NOT an error as long as JSON came back.
    if data is None:
        raise RuntimeError(f"anomaly detector failed (rc={rc}): "
                           f"{err.strip()[:400]}")
    return data


def stage_iocs(script, tmpdir, timeout):
    """STAGE 4 — IOC extraction from the parsed email JSON.

    Input : parsed.json already on disk in tmpdir (written by stage 1).
    Output: ioc-extractor JSON report (iocs{}, attachments[], sender{}).
    """
    parsed_path = os.path.join(tmpdir, "parsed.json")
    data, _, err, rc = run_script(script, ["--input", parsed_path], timeout)
    if data is None:
        raise RuntimeError(f"ioc extractor failed (rc={rc}): "
                           f"{err.strip()[:400]}")
    return data


def select_iocs_for_intel(iocs_report, attachment_paths,
                          max_urls, max_domains):
    """Choose which IOCs are worth spending API quota on.

    Selection policy:
      * all public IPs (headers usually contain only a handful)
      * up to max_domains domains — sender domain first, then body/html ones
      * up to max_urls URLs
      * all hashes found in text
      * every materialized attachment file (hashed locally by orchestrator)
    Output: flat list of IOC strings / file paths for ioc_orchestrator.py.
    """
    iocs = iocs_report.get("iocs") or {}
    sender = (iocs_report.get("sender") or {}).get("domain")
    out = []
    out += [e["value"] for e in iocs.get("ips", []) if not e.get("private")]

    domains = [e["value"] for e in iocs.get("domains", [])]
    if sender in domains:                       # sender domain gets priority
        domains.remove(sender)
        domains.insert(0, sender)
    out += domains[:max_domains]
    out += [e["value"] for e in iocs.get("urls", [])][:max_urls]
    out += [e["value"] for e in iocs.get("hashes", [])]
    out += attachment_paths
    # Deduplicate, preserving order.
    seen, uniq = set(), []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq


def stage_intel(script, ioc_list, sources, upload, timeout):
    """STAGE 5 — multi-source reputation lookups via ioc-orchestrator.

    Input : ioc_list — strings (IPs/domains/URLs/hashes) + local file paths
            sources  — optional comma list restricting sources
            upload   — pass --upload (sandbox-detonate attachments)
    Output: ioc-orchestrator JSON ({"results":[...], "overall_verdict": ...})
            Exit code 2 from the orchestrator means "malicious found" and is
            treated as success here.
    """
    if not ioc_list:
        return {"results": [], "overall_verdict": "unknown",
                "note": "no IOCs selected for intel lookup"}
    args = list(ioc_list)
    if sources:
        args += ["--sources", sources]
    if upload:
        args += ["--upload"]
    data, _, err, rc = run_script(script, args, timeout)
    if data is None:
        raise RuntimeError(f"ioc orchestrator failed (rc={rc}): "
                           f"{err.strip()[:400]}")
    return data


def parse_whois_date(value):
    """Best-effort parse of a WHOIS date string to an aware datetime (UTC).

    Input : e.g. "2026-07-01T10:00:00Z", "2026-07-01", "01-Jul-2026".
    Output: datetime or None when unparseable.
    """
    if not value:
        return None
    v = str(value).strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y", "%d.%m.%Y"):
        try:
            d = dt.datetime.strptime(v.replace("Z", "+0000")
                                     if fmt.endswith("%z") else v, fmt)
            if d.tzinfo is None:
                d = d.replace(tzinfo=dt.timezone.utc)
            return d
        except ValueError:
            continue
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", v)   # last-resort ISO prefix
    if m:
        return dt.datetime(int(m[1]), int(m[2]), int(m[3]),
                           tzinfo=dt.timezone.utc)
    return None


def stage_whois(script, iocs_report, max_domains, timeout):
    """STAGE 6 — WHOIS registration data + domain-age computation.

    Queries: sender domain (always, if known), then other domains up to
    max_domains total, plus the first public IP (network ownership context).

    Output: dict {query -> whois JSON augmented with "age_days" (domains
            only; None when the creation date is unparseable)}.
            Per-query failures are stored as {"error": "..."} entries.
    """
    iocs = iocs_report.get("iocs") or {}
    sender = (iocs_report.get("sender") or {}).get("domain")
    targets = []
    if sender:
        targets.append(sender)
    for e in iocs.get("domains", []):
        if e["value"] not in targets:
            targets.append(e["value"])
        if len(targets) >= max_domains:
            break
    public_ips = [e["value"] for e in iocs.get("ips", [])
                  if not e.get("private")]
    if public_ips:
        targets.append(public_ips[0])

    results = {}
    now = dt.datetime.now(dt.timezone.utc)
    for t in targets:
        try:
            data, _, err, rc = run_script(script, [t], timeout)
            if data is None:
                results[t] = {"error": (err.strip()[:300] or f"rc={rc}")}
                continue
            if data.get("query_type") == "domain":
                created = parse_whois_date(data.get("creation_date"))
                data["age_days"] = (now - created).days if created else None
            results[t] = data
        except Exception as e:
            results[t] = {"error": str(e)[:300]}
    return results


# ---------------------------------------------------------------------------
# STAGE 7 — verdict engine
# ---------------------------------------------------------------------------
def compute_verdict(header_rep, body_rep, iocs_rep, intel_rep, whois_rep,
                    stages):
    """Aggregate every collected signal into one weighted 0-100 risk score.

    Scoring model (points are ADDED, total capped at 100):
      +60  ioc-orchestrator overall verdict = malicious
      +25  ioc-orchestrator overall verdict = suspicious
      +0.30 * header risk_score        (max 30)  — spoofing / auth failures
      +0.20 * body anomaly score       (max 20)  — spam / brand impersonation
      +15  any queried domain younger than 30 days
      +8   any queried domain younger than 180 days (if none < 30)
      +10  at least one attachment with a risky extension (.exe/.docm/...)
      +5   URLs present only in HTML href (link text mismatch potential)

    Verdict thresholds:  score >= 70 -> malicious
                         score >= 40 -> suspicious
                         otherwise   -> clean
    Confidence: "high" when the intel stage ran successfully, "medium" when
    only offline stages ran, "low" when 2+ stages failed.

    Output: {"verdict", "score", "confidence", "signals": [...]}.
    """
    signals = []

    def add(points, code, detail):
        if points > 0:
            signals.append({"signal": code, "points": round(points, 1),
                            "detail": detail})

    # --- Threat intelligence (strongest evidence) -----------------------
    if intel_rep:
        overall = intel_rep.get("overall_verdict")
        mal = [r["ioc"] for r in intel_rep.get("results", [])
               if r.get("overall_verdict") == "malicious"]
        susp = [r["ioc"] for r in intel_rep.get("results", [])
                if r.get("overall_verdict") == "suspicious"]
        if overall == "malicious":
            add(60, "intel_verdict_malicious",
                f"ioc-orchestrator: {len(mal)} IOC(s) rated malicious: "
                f"{', '.join(mal[:5])}")
        elif overall == "suspicious":
            add(25, "intel_verdict_suspicious",
                f"ioc-orchestrator: {len(susp)} IOC(s) rated suspicious: "
                f"{', '.join(susp[:5])}")

    # --- Header analysis ------------------------------------------------
    if header_rep:
        hs = ((header_rep.get("summary") or {}).get("risk_score")) or 0
        crit = [f["message"] for f in header_rep.get("findings", [])
                if f.get("severity") == "critical"]
        add(hs * 0.30, "header_risk",
            f"header risk_score={hs}"
            + (f"; critical: {'; '.join(crit[:3])}" if crit else ""))

    # --- Body anomaly ---------------------------------------------------
    if body_rep:
        # The anomaly detector exposes an overall anomaly score 0-100;
        # accept a couple of likely key names to stay schema-tolerant.
        bs = (body_rep.get("anomaly_score")
              or (body_rep.get("anomaly") or {}).get("score")
              or body_rep.get("score") or 0)
        try:
            bs = float(bs)
        except (TypeError, ValueError):
            bs = 0
        add(bs * 0.20, "body_anomaly",
            f"body anomaly score={bs}; verdict="
            f"{body_rep.get('verdict') or body_rep.get('final_verdict')}")

    # --- Domain age (WHOIS) ---------------------------------------------
    young30, young180 = [], []
    for q, w in (whois_rep or {}).items():
        age = w.get("age_days") if isinstance(w, dict) else None
        if age is None:
            continue
        if age < 30:
            young30.append(f"{q} ({age}d)")
        elif age < 180:
            young180.append(f"{q} ({age}d)")
    if young30:
        add(15, "very_young_domain",
            "domain(s) registered <30 days ago: " + ", ".join(young30[:5]))
    elif young180:
        add(8, "young_domain",
            "domain(s) registered <180 days ago: " + ", ".join(young180[:5]))

    # --- Attachments ----------------------------------------------------
    risky = [a["filename"] for a in (iocs_rep or {}).get("attachments", [])
             if a.get("risky_extension")]
    if risky:
        add(10, "risky_attachment",
            "risky attachment extension(s): " + ", ".join(map(str, risky[:5])))

    # --- Hidden HTML links ----------------------------------------------
    html_only = [u["value"] for u in ((iocs_rep or {}).get("iocs") or {})
                 .get("urls", [])
                 if set(u.get("sources", [])) <= {"html", "html_url"}]
    if html_only:
        add(5, "html_only_links",
            f"{len(html_only)} URL(s) present only in HTML attributes "
            f"(possible hidden/mismatched links)")

    score = min(100, round(sum(s["points"] for s in signals), 1))
    verdict = ("malicious" if score >= 70
               else "suspicious" if score >= 40 else "clean")

    failed = sum(1 for s in stages.values() if s["status"] == "error")
    intel_ok = stages.get("intel", {}).get("status") == "ok"
    confidence = ("low" if failed >= 2
                  else "high" if intel_ok else "medium")
    return {"verdict": verdict, "score": score,
            "confidence": confidence, "signals": signals}


# ---------------------------------------------------------------------------
# STAGE 8 — optional LLM assessment via the Anthropic API
# ---------------------------------------------------------------------------
AI_SYSTEM_PROMPT = (
    "You are a senior SOC analyst. You receive a JSON evidence bundle from an "
    "automated email triage pipeline (header analysis, body anomaly scores, "
    "extracted IOCs, multi-source threat intel verdicts, WHOIS data, and a "
    "heuristic verdict). Assess whether the email is malicious. Respond with "
    "ONLY a JSON object, no markdown fences, with exactly these keys: "
    '"verdict" ("malicious"|"suspicious"|"clean"), '
    '"confidence" ("high"|"medium"|"low"), '
    '"reasoning" (<=200 words, cite the specific evidence), '
    '"recommended_actions" (array of <=5 short strings).')


def ai_assess(report, model, timeout=120):
    """Send the (trimmed) evidence bundle to the Anthropic API.

    Input : report — the pipeline report assembled so far (large sub-blobs
                     are trimmed to keep the prompt compact)
            model  — Anthropic model id, e.g. "claude-sonnet-4-6"
    Output: dict with model verdict fields (see AI_SYSTEM_PROMPT), plus
            {"model": ...}. Raises RuntimeError on missing key / HTTP / parse
            failures so the caller can record the stage as errored.
    Requires: $ANTHROPIC_API_KEY and outbound HTTPS to api.anthropic.com.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY is not set")

    # Trim the bundle: the model needs the conclusions, not raw API dumps.
    evidence = {
        "email": report.get("email"),
        "header_analysis": {
            "summary": (report.get("header_analysis") or {}).get("summary"),
            "findings": (report.get("header_analysis") or {}).get("findings"),
            "authentication": (report.get("header_analysis") or {})
                              .get("authentication"),
        },
        "body_analysis": report.get("body_analysis"),
        "iocs": {
            "counts": (report.get("iocs") or {}).get("counts"),
            "sender": (report.get("iocs") or {}).get("sender"),
            "attachments": (report.get("iocs") or {}).get("attachments"),
            "urls": ((report.get("iocs") or {}).get("iocs") or {})
                    .get("urls", [])[:10],
        },
        "intel": {
            "overall_verdict": (report.get("intel") or {})
                               .get("overall_verdict"),
            "results": [
                {"ioc": r.get("ioc"), "type": r.get("detected_type"),
                 "verdict": r.get("overall_verdict"),
                 "breakdown": r.get("verdict_breakdown")}
                for r in (report.get("intel") or {}).get("results", [])],
        },
        "whois_domain_ages": {
            q: {"age_days": w.get("age_days"),
                "registrar": w.get("registrar"),
                "country": w.get("country")
                           or (w.get("registrant") or {}).get("country")}
            for q, w in (report.get("whois") or {}).items()
            if isinstance(w, dict) and "error" not in w},
        "heuristic_verdict": report.get("verdict"),
        "stage_errors": {k: v.get("error") for k, v in
                         report.get("stages", {}).items() if v.get("error")},
    }

    body = json.dumps({
        "model": model,
        "max_tokens": 1000,
        "system": AI_SYSTEM_PROMPT,
        "messages": [{"role": "user",
                      "content": "Evidence bundle:\n"
                                 + json.dumps(evidence, ensure_ascii=False)}],
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages", data=body,
        headers={"Content-Type": "application/json",
                 "x-api-key": api_key,
                 "anthropic-version": "2023-06-01"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    text = "".join(b.get("text", "") for b in payload.get("content", [])
                   if b.get("type") == "text")
    text = re.sub(r"^```(?:json)?|```$", "", text.strip(),
                  flags=re.MULTILINE).strip()
    result = json.loads(text)          # raises if the model broke format
    result["model"] = model
    return result


# ---------------------------------------------------------------------------
# Human-readable text rendering (--format text)
# ---------------------------------------------------------------------------
def render_text(report):
    """Turn the JSON report into a short analyst-friendly plain-text summary.

    Input : full report dict.  Output: multi-line string.
    """
    v = report["verdict"]
    lines = [
        "=" * 62,
        f"EMAIL TRIAGE REPORT — {os.path.basename(report['input_file'])}",
        "=" * 62,
        f"VERDICT : {v['verdict'].upper()}   score={v['score']}/100   "
        f"confidence={v['confidence']}",
    ]
    em = report.get("email") or {}
    frm = (em.get("from") or {})
    lines.append(f"Subject : {em.get('subject')}")
    lines.append(f"From    : {frm.get('name')} <{frm.get('email')}>")
    lines.append("-" * 62)
    lines.append("Signals:")
    for s in v["signals"]:
        lines.append(f"  [+{s['points']:>5}] {s['signal']}: {s['detail']}")
    if not v["signals"]:
        lines.append("  (no risk signals fired)")
    ai = report.get("ai_analysis")
    if ai:
        lines += ["-" * 62,
                  f"AI ({ai.get('model')}): {str(ai.get('verdict')).upper()} "
                  f"({ai.get('confidence')})",
                  f"  {ai.get('reasoning')}"]
        for a in ai.get("recommended_actions") or []:
            lines.append(f"  -> {a}")
    errs = {k: s["error"] for k, s in report["stages"].items()
            if s.get("error")}
    if errs:
        lines.append("-" * 62)
        lines.append("Stage errors (evidence incomplete):")
        for k, e in errs.items():
            lines.append(f"  {k}: {e}")
    lines.append("=" * 62)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Full email triage pipeline: parse -> headers -> body -> "
                    "IOC extract -> threat intel -> whois -> AI verdict.")
    ap.add_argument("email_file", help=".eml or .msg file to triage")
    ap.add_argument("--skills-root", help="directory containing skill folders")
    ap.add_argument("--skip-intel", action="store_true")
    ap.add_argument("--skip-whois", action="store_true")
    ap.add_argument("--skip-body", action="store_true")
    ap.add_argument("--sources", help="ioc-orchestrator source list "
                                      "(vt,abuseipdb,urlscan,otx,ha)")
    ap.add_argument("--upload", action="store_true",
                    help="upload attachments to VT/HA sandboxes")
    ap.add_argument("--max-urls", type=int, default=10)
    ap.add_argument("--max-domains", type=int, default=10)
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--ai", action="store_true",
                    help="add an Anthropic-API LLM assessment")
    ap.add_argument("--ai-model", default="claude-sonnet-4-6")
    ap.add_argument("--output", "-o")
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("--format", choices=["json", "text"], default="json")
    args = ap.parse_args(argv)

    if not os.path.isfile(args.email_file):
        print(f"error: file not found: {args.email_file}", file=sys.stderr)
        return 3

    stages = {k: {"status": "skipped", "error": None}
              for k in ("parse", "headers", "body_anomaly", "ioc_extract",
                        "intel", "whois", "ai")}
    report = {"pipeline_version": PIPELINE_VERSION,
              "input_file": os.path.abspath(args.email_file),
              "started_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "stages": stages}

    def progress(msg):
        # Progress goes to stderr so stdout stays pure JSON for piping.
        print(f"[triage] {msg}", file=sys.stderr)

    with tempfile.TemporaryDirectory(prefix="email_triage_") as tmpdir:
        # ---- STAGE 1: parse (fatal if it fails) ------------------------
        script = find_script("email-parser", args.skills_root)
        if not script:
            print("error: email-parser skill not found "
                  "(set --skills-root)", file=sys.stderr)
            return 3
        progress("1/7 parsing email ...")
        try:
            parsed, att_paths = stage_parse(script, args.email_file,
                                            tmpdir, args.timeout)
            stages["parse"]["status"] = "ok"
        except Exception as e:
            stages["parse"] = {"status": "error", "error": str(e)}
            report["finished_utc"] = dt.datetime.now(
                dt.timezone.utc).isoformat()
            print(json.dumps(report, indent=2))
            return 3
        report["email"] = {
            "subject": parsed.get("subject"),
            "from": parsed.get("from"), "to": parsed.get("to"),
            "date": parsed.get("date"),
            "attachment_names": [a.get("filename")
                                 for a in parsed.get("attachments") or []],
        }

        # ---- STAGE 2: header analysis ---------------------------------
        header_rep = None
        script = find_script("email-header-analyzer", args.skills_root)
        progress("2/7 analyzing headers ...")
        try:
            if not script:
                raise RuntimeError("email-header-analyzer skill not found")
            header_rep = stage_headers(script, parsed, tmpdir, args.timeout)
            stages["headers"]["status"] = "ok"
        except Exception as e:
            stages["headers"] = {"status": "error", "error": str(e)}
        report["header_analysis"] = header_rep

        # ---- STAGE 3: body anomaly ------------------------------------
        body_rep = None
        if not args.skip_body:
            script = find_script("email-anomaly-detector", args.skills_root)
            progress("3/7 analyzing body ...")
            try:
                if not script:
                    raise RuntimeError("email-anomaly-detector skill "
                                       "not found")
                body_rep = stage_body(script, parsed, tmpdir, args.timeout)
                stages["body_anomaly"]["status"] = "ok"
            except Exception as e:
                stages["body_anomaly"] = {"status": "error", "error": str(e)}
        report["body_analysis"] = body_rep

        # ---- STAGE 4: IOC extraction ----------------------------------
        iocs_rep = None
        script = find_script("ioc-extractor", args.skills_root)
        progress("4/7 extracting IOCs ...")
        try:
            if not script:
                raise RuntimeError("ioc-extractor script not found")
            iocs_rep = stage_iocs(script, tmpdir, args.timeout)
            stages["ioc_extract"]["status"] = "ok"
        except Exception as e:
            stages["ioc_extract"] = {"status": "error", "error": str(e)}
        report["iocs"] = iocs_rep

        # ---- STAGE 5: threat intel ------------------------------------
        intel_rep = None
        if not args.skip_intel and iocs_rep:
            script = find_script("ioc-orchestrator", args.skills_root)
            progress("5/7 querying threat intel sources ...")
            try:
                if not script:
                    raise RuntimeError("ioc-orchestrator skill not found")
                sel = select_iocs_for_intel(iocs_rep, att_paths,
                                            args.max_urls, args.max_domains)
                intel_rep = stage_intel(script, sel, args.sources,
                                        args.upload, args.timeout)
                stages["intel"]["status"] = "ok"
            except Exception as e:
                stages["intel"] = {"status": "error", "error": str(e)}
        report["intel"] = intel_rep

        # ---- STAGE 6: WHOIS -------------------------------------------
        whois_rep = None
        if not args.skip_whois and iocs_rep:
            script = find_script("whois-lookup", args.skills_root)
            progress("6/7 running WHOIS lookups ...")
            try:
                if not script:
                    raise RuntimeError("whois-lookup skill not found")
                whois_rep = stage_whois(script, iocs_rep,
                                        args.max_domains, args.timeout)
                stages["whois"]["status"] = "ok"
            except Exception as e:
                stages["whois"] = {"status": "error", "error": str(e)}
        report["whois"] = whois_rep

        # ---- STAGE 7: heuristic verdict -------------------------------
        progress("7/7 computing verdict ...")
        report["verdict"] = compute_verdict(header_rep, body_rep, iocs_rep,
                                            intel_rep, whois_rep, stages)

        # ---- STAGE 8 (optional): AI assessment ------------------------
        if args.ai:
            progress("8/8 requesting AI analyst assessment ...")
            try:
                report["ai_analysis"] = ai_assess(report, args.ai_model)
                stages["ai"]["status"] = "ok"
            except Exception as e:
                stages["ai"] = {"status": "error", "error": str(e)}

    report["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()

    # ---- Emit ----------------------------------------------------------
    if args.format == "text":
        out = render_text(report)
    else:
        out = json.dumps(report, indent=2 if args.pretty else None,
                         ensure_ascii=False)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out + "\n")
        progress(f"report written to {args.output}")
        # Still print a one-line verdict to stdout for scripting.
        print(json.dumps({"verdict": report["verdict"]["verdict"],
                          "score": report["verdict"]["score"],
                          "report": os.path.abspath(args.output)}))
    else:
        print(out)

    return {"clean": 0, "suspicious": 1,
            "malicious": 2}[report["verdict"]["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
