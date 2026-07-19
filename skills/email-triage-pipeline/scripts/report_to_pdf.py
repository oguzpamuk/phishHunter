#!/usr/bin/env python3
"""
report_to_pdf.py — Render an email-triage-pipeline JSON report as a
professional, shareable PDF document.

============================================================================
INPUT
============================================================================
Positional argument:
    report_json           Path to the JSON report produced by
                          triage_pipeline.py (the full report written with
                          `-o report.json`, NOT the one-line stdout summary).

Options:
    -o / --output FILE    Output PDF path.
                          Default: <report_json basename>.pdf next to the
                          input (e.g. report.json -> report.pdf).
    --title TEXT          Custom document title shown on the header band.
                          Default: "Email Security Triage Report".
    --max-rows N          Maximum rows rendered per IOC / intel / WHOIS
                          table before truncating with an "... N more"
                          footer row (default 25). Keeps huge reports
                          readable and the PDF small.

============================================================================
OUTPUT
============================================================================
A multi-section A4 PDF containing:

    1. Header band        — title, analyzed file, generation timestamp
    2. Verdict banner     — color-coded (red = malicious, orange =
                            suspicious, green = clean) with score/100,
                            confidence, and pipeline exit-code mapping
    3. Email summary      — subject, from, to, date, attachment names
    4. Risk signals       — every scored contribution from the verdict
                            engine (points + human explanation)
    5. Header analysis    — SPF/DKIM/DMARC results + findings by severity
    6. Body analysis      — anomaly score / spam verdict (when available)
    7. Extracted IOCs     — IPs, domains, URLs, hashes, attachments tables
    8. Threat intelligence— per-IOC verdicts and per-source breakdown
    9. WHOIS              — registrar, creation date, computed domain age
   10. AI analyst section — model verdict, reasoning, recommended actions
                            (only when the report contains "ai_analysis")
   11. Pipeline stages    — ok / error / skipped audit trail
   12. Footer disclaimer  — indicator-not-proof notice on every page

The script prints the absolute path of the written PDF on stdout.

============================================================================
EXIT CODES
============================================================================
    0  PDF written successfully
    1  input error (file missing / not valid triage JSON)
    2  PDF generation failure (reportlab missing or rendering error)

Dependency: reportlab  (`pip install reportlab`) — everything else is
standard library.
============================================================================
"""

import argparse
import datetime as dt
import json
import os
import sys
from xml.sax.saxutils import escape

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer,
                                    Table, TableStyle)
except ImportError:  # pragma: no cover
    print("error: reportlab is required — install with: pip install reportlab",
          file=sys.stderr)
    sys.exit(2)

# ---------------------------------------------------------------------------
# Visual theme: one accent color per verdict, reused across the banner,
# section headings, and table headers so the document reads at a glance.
# ---------------------------------------------------------------------------
VERDICT_THEME = {
    "malicious":  {"bg": colors.HexColor("#B71C1C"), "label": "MALICIOUS"},
    "suspicious": {"bg": colors.HexColor("#E65100"), "label": "SUSPICIOUS"},
    "clean":      {"bg": colors.HexColor("#1B5E20"), "label": "CLEAN"},
}
INK = colors.HexColor("#212121")          # body text
MUTED = colors.HexColor("#616161")        # secondary text
HEAD_BG = colors.HexColor("#263238")      # neutral table header
ROW_ALT = colors.HexColor("#F5F5F5")      # zebra striping
SEV_COLORS = {"critical": colors.HexColor("#B71C1C"),
              "warning": colors.HexColor("#E65100"),
              "info": colors.HexColor("#455A64")}

styles = getSampleStyleSheet()
S_BODY = ParagraphStyle("Body", parent=styles["Normal"], fontSize=9,
                        leading=12, textColor=INK)
S_CELL = ParagraphStyle("Cell", parent=S_BODY, fontSize=8, leading=10)
S_CELL_MONO = ParagraphStyle("CellMono", parent=S_CELL,
                             fontName="Courier", fontSize=7.5)
S_H2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=12,
                      spaceBefore=14, spaceAfter=6, textColor=HEAD_BG)
S_SMALL = ParagraphStyle("Small", parent=S_BODY, fontSize=7.5,
                         textColor=MUTED)


def esc(value, mono=False, max_len=300):
    """Return a Paragraph-safe escaped string for arbitrary report values.

    Input : value   — anything (None becomes an em-dash)
            mono    — unused here; kept for symmetry with cell()
            max_len — hard truncation so a single huge URL cannot blow up
                      the table layout
    Output: XML-escaped string with zero-width break opportunities inserted
            into long unbroken tokens (URLs/hashes) so reportlab can wrap
            them inside table cells.
    """
    if value is None or value == "":
        return "&#8212;"
    text = str(value)
    if len(text) > max_len:
        text = text[:max_len] + " …"
    text = escape(text)
    # Insert soft break opportunities every 40 chars inside unbroken runs.
    out, run = [], 0
    for ch in text:
        out.append(ch)
        run = 0 if ch in " \n\t-/&;" else run + 1
        if run >= 40:
            out.append("<br/>" if False else "&#8203;")  # zero-width space
            run = 0
    return "".join(out)


def cell(value, mono=False):
    """Wrap a value as a table-cell Paragraph (mono for IOC-like data)."""
    return Paragraph(esc(value), S_CELL_MONO if mono else S_CELL)


def make_table(header, rows, col_widths, max_rows, mono_cols=()):
    """Build a styled zebra table with truncation.

    Input : header     — list of column titles
            rows       — list of row value lists (raw values, not Paragraphs)
            col_widths — list of widths in mm (must match header length)
            max_rows   — truncate beyond this many rows
            mono_cols  — column indexes rendered in Courier (IOC values)
    Output: reportlab Table flowable, or a muted "none" Paragraph when rows
            is empty.
    """
    if not rows:
        return Paragraph("<i>none</i>", S_SMALL)
    shown = rows[:max_rows]
    data = [[Paragraph(f"<b>{escape(h)}</b>",
                       ParagraphStyle("th", parent=S_CELL,
                                      textColor=colors.white))
             for h in header]]
    for r in shown:
        # Values that are already Paragraph flowables (e.g. pre-colored
        # severity labels) are passed through untouched; everything else is
        # escaped and wrapped by cell().
        data.append([v if isinstance(v, Paragraph)
                     else cell(v, mono=(i in mono_cols))
                     for i, v in enumerate(r)])
    if len(rows) > max_rows:
        note = [Paragraph(f"<i>… {len(rows) - max_rows} more row(s) "
                          "omitted — see the JSON report</i>", S_SMALL)]
        note += [Paragraph("", S_CELL)] * (len(header) - 1)
        data.append(note)
    t = Table(data, colWidths=[w * mm for w in col_widths], repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), HEAD_BG),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#B0BEC5")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]
    for i in range(1, len(data)):
        if i % 2 == 0:
            style.append(("BACKGROUND", (0, i), (-1, i), ROW_ALT))
    t.setStyle(TableStyle(style))
    return t


def footer(canvas, doc):
    """Per-page footer: disclaimer left, page number right."""
    canvas.saveState()
    canvas.setFont("Helvetica", 6.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(
        15 * mm, 10 * mm,
        "Automated triage output — indicators, not proof. Verify suspicious "
        "results out-of-band and follow your IR procedures.")
    canvas.drawRightString(A4[0] - 15 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


# ---------------------------------------------------------------------------
# Section builders — each returns a list of flowables and tolerates the
# corresponding report section being None (stage skipped/errored).
# ---------------------------------------------------------------------------
def sec_banner(report, title):
    """Header band + color-coded verdict banner."""
    v = report.get("verdict") or {}
    theme = VERDICT_THEME.get(v.get("verdict"), VERDICT_THEME["suspicious"])
    gen = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    head = Table(
        [[Paragraph(f"<b>{escape(title)}</b>",
                    ParagraphStyle("t", parent=S_BODY, fontSize=15,
                                   textColor=colors.white)),
          Paragraph(f"Analyzed file: <b>{esc(os.path.basename(report.get('input_file', '?')))}</b>"
                    f"<br/>Generated: {gen} · Pipeline v"
                    f"{esc(report.get('pipeline_version'))}",
                    ParagraphStyle("m", parent=S_SMALL,
                                   textColor=colors.HexColor("#CFD8DC"),
                                   alignment=2))]],
        colWidths=[105 * mm, 75 * mm])
    head.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), HEAD_BG),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    banner = Table(
        [[Paragraph(f"<b>VERDICT: {theme['label']}</b>",
                    ParagraphStyle("v", parent=S_BODY, fontSize=14,
                                   textColor=colors.white)),
          Paragraph(f"Risk score: <b>{esc(v.get('score'))}/100</b>"
                    f" &nbsp;·&nbsp; Confidence: <b>{esc(v.get('confidence'))}</b>",
                    ParagraphStyle("v2", parent=S_BODY, fontSize=10,
                                   textColor=colors.white, alignment=2))]],
        colWidths=[90 * mm, 90 * mm])
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), theme["bg"]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    return [head, Spacer(1, 3), banner, Spacer(1, 8)]


def sec_email(report):
    """Section 3 — parsed email summary."""
    em = report.get("email") or {}
    frm = em.get("from") or {}
    to = ", ".join(f"{(t or {}).get('email')}" for t in (em.get("to") or []))
    rows = [["Subject", em.get("subject")],
            ["From", f"{frm.get('name') or ''} <{frm.get('email')}>"],
            ["To", to], ["Date", em.get("date")],
            ["Attachments", ", ".join(map(str, em.get("attachment_names") or []))
                            or None]]
    return [Paragraph("1. Email Summary", S_H2),
            make_table(["Field", "Value"], rows, [30, 150], 99)]


def sec_signals(report, max_rows):
    """Section 4 — verdict engine risk signals."""
    sig = (report.get("verdict") or {}).get("signals") or []
    rows = [[f"+{s.get('points')}", s.get("signal"), s.get("detail")]
            for s in sig]
    out = [Paragraph("2. Risk Signals (Verdict Engine)", S_H2)]
    if not rows:
        out.append(Paragraph("<i>No risk signals fired — no scored evidence "
                             "of maliciousness was found.</i>", S_BODY))
    else:
        out.append(make_table(["Points", "Signal", "Explanation"], rows,
                              [16, 42, 122], max_rows))
    return out


def sec_headers(report, max_rows):
    """Section 5 — header authentication + findings."""
    h = report.get("header_analysis")
    out = [Paragraph("3. Header Analysis", S_H2)]
    if not h:
        out.append(Paragraph("<i>Stage not available.</i>", S_SMALL))
        return out
    summ = h.get("summary") or {}
    auth = h.get("authentication") or {}
    out.append(Paragraph(
        f"{esc(summ.get('verdict'))}<br/>Header risk score: "
        f"<b>{esc(summ.get('risk_score'))}/100</b> "
        f"({esc(summ.get('risk_level'))}) &nbsp;·&nbsp; "
        f"SPF: <b>{esc(auth.get('spf'))}</b> · DKIM: "
        f"<b>{esc(auth.get('dkim'))}</b> · DMARC: "
        f"<b>{esc(auth.get('dmarc'))}</b>", S_BODY))
    out.append(Spacer(1, 4))
    rows = []
    for f in h.get("findings") or []:
        sev = f.get("severity", "info")
        color = SEV_COLORS.get(sev, MUTED).hexval()[2:]
        rows.append([Paragraph(f'<font color="#{color}"><b>'
                               f"{escape(sev.upper())}</b></font>", S_CELL),
                     f.get("code"), f.get("message")])
    if rows:
        out.append(make_table(["Severity", "Code", "Finding"], rows,
                              [20, 44, 116], max_rows))
    return out


def sec_body(report):
    """Section 6 — body anomaly summary (schema-tolerant)."""
    b = report.get("body_analysis")
    out = [Paragraph("4. Body Analysis", S_H2)]
    if not b:
        out.append(Paragraph("<i>Stage not available (no body text or "
                             "stage skipped).</i>", S_SMALL))
        return out
    score = (b.get("anomaly_score") or (b.get("anomaly") or {}).get("score")
             or b.get("score"))
    verdict = b.get("verdict") or b.get("final_verdict")
    brands = b.get("brands") or b.get("brand_detection") or b.get("brand")
    text = (f"Anomaly score: <b>{esc(score)}/100</b> &nbsp;·&nbsp; "
            f"Verdict: <b>{esc(verdict)}</b>")
    if brands:
        text += f"<br/>Brand signals: {esc(json.dumps(brands, ensure_ascii=False), max_len=400)}"
    out.append(Paragraph(text, S_BODY))
    return out


def sec_iocs(report, max_rows):
    """Section 7 — extracted IOC tables."""
    rep = report.get("iocs")
    out = [Paragraph("5. Extracted IOCs", S_H2)]
    if not rep:
        out.append(Paragraph("<i>Stage not available.</i>", S_SMALL))
        return out
    iocs = rep.get("iocs") or {}
    counts = rep.get("counts") or {}
    out.append(Paragraph(
        " · ".join(f"{k}: <b>{v}</b>" for k, v in counts.items()), S_SMALL))
    out.append(Spacer(1, 4))
    for key, title, cols, widths, mono in (
            ("ips", "IP addresses", ["IP", "Sources"], [60, 120], (0,)),
            ("domains", "Domains", ["Domain", "Sources"], [70, 110], (0,)),
            ("urls", "URLs", ["URL", "Sources"], [125, 55], (0,)),
            ("hashes", "Hashes", ["Hash", "Algo", "Sources"],
             [110, 20, 50], (0,))):
        entries = iocs.get(key) or []
        rows = [[e.get("value"),
                 *( [e.get("algo")] if key == "hashes" else [] ),
                 ", ".join(e.get("sources") or [])] for e in entries]
        out.append(Paragraph(f"<b>{title}</b>", S_BODY))
        out.append(make_table(cols, rows, widths, max_rows, mono_cols=mono))
        out.append(Spacer(1, 4))
    att_rows = [[a.get("filename"), a.get("content_type"),
                 a.get("size_bytes"),
                 "YES" if a.get("risky_extension") else "no",
                 a.get("sha256")] for a in rep.get("attachments") or []]
    out.append(Paragraph("<b>Attachments</b>", S_BODY))
    out.append(make_table(["Filename", "Type", "Bytes", "Risky ext",
                           "SHA256"], att_rows, [35, 35, 15, 15, 80],
                          max_rows, mono_cols=(4,)))
    return out


def sec_intel(report, max_rows):
    """Section 8 — threat intelligence per-IOC verdicts."""
    intel = report.get("intel")
    out = [Paragraph("6. Threat Intelligence", S_H2)]
    if not intel:
        err = (report.get("stages", {}).get("intel") or {}).get("error")
        out.append(Paragraph(f"<i>Stage not available"
                             f"{': ' + esc(err, max_len=150) if err else ''}."
                             "</i>", S_SMALL))
        return out
    out.append(Paragraph(
        f"Overall intel verdict: <b>{esc(intel.get('overall_verdict'))}</b>",
        S_BODY))
    rows = []
    for r in intel.get("results") or []:
        breakdown = " · ".join(f"{k}={v}" for k, v in
                               (r.get("verdict_breakdown") or {}).items())
        rows.append([r.get("ioc"), r.get("detected_type"),
                     r.get("overall_verdict"), breakdown])
    out.append(make_table(["IOC", "Type", "Verdict", "Per-source breakdown"],
                          rows, [60, 16, 22, 82], max_rows, mono_cols=(0,)))
    return out


def sec_whois(report, max_rows):
    """Section 9 — WHOIS registration data & domain ages."""
    w = report.get("whois")
    out = [Paragraph("7. WHOIS", S_H2)]
    if not w:
        out.append(Paragraph("<i>Stage not available.</i>", S_SMALL))
        return out
    rows = []
    for q, d in w.items():
        if not isinstance(d, dict):
            continue
        if "error" in d:
            rows.append([q, "—", "—", "—", f"error: {d['error']}"])
            continue
        age = d.get("age_days")
        rows.append([q, d.get("registrar") or d.get("organization"),
                     d.get("creation_date"),
                     f"{age} d" if age is not None else None,
                     d.get("country")
                     or (d.get("registrant") or {}).get("country")])
    out.append(make_table(["Query", "Registrar / Org", "Created",
                           "Age", "Country"], rows,
                          [45, 50, 40, 15, 30], max_rows, mono_cols=(0,)))
    return out


def sec_ai(report):
    """Section 10 — optional LLM analyst assessment."""
    ai = report.get("ai_analysis")
    if not ai:
        return []
    out = [Paragraph("8. AI Analyst Assessment", S_H2),
           Paragraph(f"Model: <b>{esc(ai.get('model'))}</b> &nbsp;·&nbsp; "
                     f"Verdict: <b>{esc(str(ai.get('verdict')).upper())}</b> "
                     f"({esc(ai.get('confidence'))})", S_BODY),
           Spacer(1, 3),
           Paragraph(esc(ai.get("reasoning"), max_len=2000), S_BODY)]
    actions = ai.get("recommended_actions") or []
    if actions:
        out.append(Spacer(1, 3))
        out.append(Paragraph("<b>Recommended actions</b>", S_BODY))
        for a in actions:
            out.append(Paragraph(f"• {esc(a)}", S_BODY))
    return out


def sec_stages(report):
    """Section 11 — pipeline audit trail."""
    rows = [[k, s.get("status"), s.get("error")]
            for k, s in (report.get("stages") or {}).items()]
    return [Paragraph("9. Pipeline Stages", S_H2),
            make_table(["Stage", "Status", "Error"], rows,
                       [30, 20, 130], 99)]


def build_pdf(report, out_path, title, max_rows):
    """Assemble every section and write the PDF.

    Input : report   — full triage report dict
            out_path — destination .pdf path
            title    — document title string
            max_rows — per-table truncation limit
    Output: none (writes the file; raises on rendering errors).
    """
    doc = SimpleDocTemplate(
        out_path, pagesize=A4,
        leftMargin=15 * mm, rightMargin=15 * mm,
        topMargin=14 * mm, bottomMargin=18 * mm,
        title=title, author="email-triage-pipeline")
    story = []
    story += sec_banner(report, title)
    story += sec_email(report)
    story += sec_signals(report, max_rows)
    story += sec_headers(report, max_rows)
    story += sec_body(report)
    story += sec_iocs(report, max_rows)
    story += sec_intel(report, max_rows)
    story += sec_whois(report, max_rows)
    story += sec_ai(report)
    story += sec_stages(report)
    doc.build(story, onFirstPage=footer, onLaterPages=footer)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Render a triage_pipeline.py JSON report as a "
                    "professional PDF.")
    ap.add_argument("report_json", help="JSON report from triage_pipeline.py")
    ap.add_argument("--output", "-o", help="output PDF path "
                    "(default: <input>.pdf)")
    ap.add_argument("--title", default="Email Security Triage Report")
    ap.add_argument("--max-rows", type=int, default=25,
                    help="max rows per table before truncation (default 25)")
    args = ap.parse_args(argv)

    # ---- Load & validate the report ------------------------------------
    try:
        with open(args.report_json, "r", encoding="utf-8") as f:
            report = json.load(f)
    except FileNotFoundError:
        print(f"error: file not found: {args.report_json}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"error: not valid JSON: {e}", file=sys.stderr)
        return 1
    if "verdict" not in report or "stages" not in report:
        print("error: this does not look like a triage_pipeline.py report "
              "(missing 'verdict'/'stages' keys). Did you pass the file "
              "written with -o, not the stdout summary line?",
              file=sys.stderr)
        return 1

    out_path = args.output or (
        os.path.splitext(args.report_json)[0] + ".pdf")
    try:
        build_pdf(report, out_path, args.title, args.max_rows)
    except Exception as e:
        print(f"error: PDF generation failed: {e}", file=sys.stderr)
        return 2
    print(os.path.abspath(out_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
