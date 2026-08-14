#!/usr/bin/env python3
"""
app.py — phishHunter Web UI server (pure Python standard library).

A zero-dependency web console for the email triage pipeline:

    Dashboard   /             verdict distribution, totals, recent analyses
    Analyze     /analyze      drag-&-drop upload + live per-stage progress
    Report      /report/{id}  full evidence report rendered in the browser
    History     /history      past analyses, filterable by verdict/filename

============================================================================
HOW IT WORKS
============================================================================
* Uploads land in  webui/data/uploads/<analysis_id>/<original name>.
* Each analysis runs triage_pipeline.py in a BACKGROUND THREAD with
  `--log-file webui/data/logs/<id>.log` — the pipeline's structured
  JSON-Lines audit log (stage_start / stage_end / stage_skip /
  pipeline_end) is the LIVE DATA SOURCE the progress API streams to the
  browser, so the UI shows exactly what ran, what was skipped, and where
  it failed, in real time.
* The finished JSON report is stored at webui/data/reports/<id>.json and
  indexed in a SQLite database (webui/data/phishhunter.db) for the
  dashboard and the filterable history page.

============================================================================
RUNNING
============================================================================
    python3 webui/app.py [--host 127.0.0.1] [--port 8787]
                         [--skills-root skills]

    Then open  http://127.0.0.1:8787

    Optional env for the intel stage (same as the CLI):
      VT_API_KEY, ABUSEIPDB_API_KEY, OTX_API_KEY, URLSCAN_API_KEY,
      HYBRID_ANALYSIS_API_KEY, ANTHROPIC_API_KEY

============================================================================
HTTP API (all JSON unless noted)
============================================================================
    GET  /                      dashboard page          (text/html)
    GET  /analyze               analyze page            (text/html)
    GET  /history               history page            (text/html)
    GET  /report/{id}           report page             (text/html)
    GET  /static/<file>         css/js assets

    POST /api/analyze           multipart form upload; fields:
                                  email      (file, .eml/.msg, required)
                                  skip_intel ("1" to skip threat intel)
                                  skip_whois ("1" to skip WHOIS)
                                  yara_rules (file, .yar/.yara, optional)
                                  ai         ("1" to add the LLM analyst)
                                → {"id": "<analysis id>"}
    GET  /api/analysis/{id}/progress
                                → {"status": "running|done|error",
                                   "stages": [ {stage,status,duration_s,
                                                error}... ],
                                   "verdict": {...}|null }
    GET  /api/analysis/{id}/report
                                → the full pipeline JSON report
    GET  /api/analyses?verdict=&q=&limit=
                                → {"items":[{id,filename,verdict,score,
                                    confidence,created_utc,status}...]}
    GET  /api/stats             → dashboard counters + recent list

============================================================================
SECURITY NOTES
============================================================================
* Binds to 127.0.0.1 by default — this console is meant for a single
  analyst workstation, not public exposure. Put a reverse proxy with
  auth in front of it before sharing on a network.
* Uploaded filenames are sanitized; files are stored under a per-analysis
  directory and never executed.
* The report endpoint only serves ids that exist in the local database.
============================================================================
"""

import argparse
import datetime as dt
import io
import json
import mimetypes
import os
import re
import sqlite3
import subprocess
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# ---------------------------------------------------------------------------
# Paths — everything the UI writes lives under webui/data/ so the repository
# tree stays clean and a single directory can be wiped to reset the console.
# ---------------------------------------------------------------------------
HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
DATA_DIR = os.path.join(HERE, "data")
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
REPORT_DIR = os.path.join(DATA_DIR, "reports")
LOG_DIR = os.path.join(DATA_DIR, "logs")
DB_PATH = os.path.join(DATA_DIR, "phishhunter.db")
TEMPLATE_DIR = os.path.join(HERE, "templates")
STATIC_DIR = os.path.join(HERE, "static")

PIPELINE = os.path.join(REPO_ROOT, "skills", "email-triage-pipeline",
                        "scripts", "triage_pipeline.py")

# The ordered stage list mirrored from the pipeline — used to render the
# progress rail in a stable order even before any event has fired.
STAGE_ORDER = ["parse", "headers", "body_anomaly", "body_ai", "yara",
               "ioc_extract", "image_ai", "intel", "whois", "ai"]
STAGE_LABELS = {
    "parse": "Parse email", "headers": "Header analysis",
    "body_anomaly": "Body scoring", "body_ai": "AI body analysis",
    "yara": "YARA scan", "image_ai": "AI image analysis",
    "ioc_extract": "IOC extraction", "intel": "Threat intel",
    "whois": "WHOIS enrichment", "ai": "AI analyst",
}

SKILLS_ROOT = os.path.join(REPO_ROOT, "skills")   # overridable via CLI


# ---------------------------------------------------------------------------
# Database — one table indexing every analysis for dashboard + history.
# ---------------------------------------------------------------------------
def db():
    """Open a SQLite connection (one per call — cheap, thread-safe usage)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create data dirs and the analyses table on first run."""
    for d in (DATA_DIR, UPLOAD_DIR, REPORT_DIR, LOG_DIR):
        os.makedirs(d, exist_ok=True)
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id           TEXT PRIMARY KEY,
                filename     TEXT NOT NULL,
                created_utc  TEXT NOT NULL,
                status       TEXT NOT NULL,      -- running | done | error
                verdict      TEXT,               -- malicious|suspicious|clean
                score        REAL,
                confidence   TEXT,
                error        TEXT
            )""")


def sanitize_filename(name):
    """Strip path components and dangerous characters from an upload name.

    Input : arbitrary client-supplied filename.
    Output: a safe basename limited to 120 chars, never empty.
    """
    base = os.path.basename(name or "")
    base = re.sub(r"[^A-Za-z0-9._ -]", "_", base).strip() or "upload.eml"
    return base[:120]


# ---------------------------------------------------------------------------
# Pipeline runner — executes the triage in a background thread.
# ---------------------------------------------------------------------------
def run_analysis(analysis_id, email_path, options):
    """Run triage_pipeline.py for one uploaded email (background thread).

    Input : analysis_id — UUID hex string, primary key in the DB
            email_path  — absolute path to the stored upload
            options     — {"skip_intel": bool, "skip_whois": bool,
                           "yara_rules": path|None, "ai": bool}
    Effect: writes the JSON report to REPORT_DIR/<id>.json, streams the
            audit log to LOG_DIR/<id>.log (consumed live by the progress
            API), and updates the DB row to done/error with the verdict.
    """
    report_path = os.path.join(REPORT_DIR, f"{analysis_id}.json")
    log_path = os.path.join(LOG_DIR, f"{analysis_id}.log")
    cmd = [sys.executable, PIPELINE, email_path,
           "--skills-root", SKILLS_ROOT,
           "-o", report_path,
           "--log-file", log_path, "--quiet"]
    if options.get("skip_intel"):
        cmd.append("--skip-intel")
    if options.get("skip_whois"):
        cmd.append("--skip-whois")
    if options.get("yara_rules"):
        cmd += ["--yara-rules", options["yara_rules"]]
    if options.get("ai"):
        cmd.append("--ai")

    try:
        # Exit codes 0/1/2 are verdicts, 3 is fatal — all non-exceptional.
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=1800)
        if os.path.isfile(report_path):
            with open(report_path, "r", encoding="utf-8") as f:
                report = json.load(f)
            v = report.get("verdict") or {}
            with db() as conn:
                conn.execute(
                    "UPDATE analyses SET status='done', verdict=?, score=?, "
                    "confidence=? WHERE id=?",
                    (v.get("verdict"), v.get("score"), v.get("confidence"),
                     analysis_id))
        else:
            with db() as conn:
                conn.execute(
                    "UPDATE analyses SET status='error', error=? WHERE id=?",
                    ((proc.stderr or "pipeline produced no report")[:500],
                     analysis_id))
    except Exception as e:
        with db() as conn:
            conn.execute(
                "UPDATE analyses SET status='error', error=? WHERE id=?",
                (str(e)[:500], analysis_id))


def read_progress(analysis_id):
    """Assemble the live progress view from the pipeline's audit log.

    Reads LOG_DIR/<id>.log (JSON Lines written by the pipeline's logging
    mechanism) and folds stage events into a per-stage table.

    Output: {"status": running|done|error,
             "stages": [{stage,label,status,duration_s,error}...] in
                        pipeline order,
             "verdict": {verdict,score,confidence}|None,
             "error": str|None }
    """
    with db() as conn:
        row = conn.execute("SELECT * FROM analyses WHERE id=?",
                           (analysis_id,)).fetchone()
    if not row:
        return None

    stages = {s: {"stage": s, "label": STAGE_LABELS[s], "status": "pending",
                  "duration_s": None, "error": None} for s in STAGE_ORDER}
    verdict = None
    log_path = os.path.join(LOG_DIR, f"{analysis_id}.log")
    if os.path.isfile(log_path):
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                name = ev.get("stage")
                etype = ev.get("event")
                if etype == "stage_start" and name in stages:
                    stages[name]["status"] = "running"
                elif etype == "stage_end" and name in stages:
                    stages[name]["status"] = ev.get("status", "ok")
                    stages[name]["duration_s"] = ev.get("duration_s")
                    stages[name]["error"] = ev.get("error")
                elif etype == "stage_skip" and name in stages:
                    stages[name]["status"] = "skipped"
                    stages[name]["error"] = ev.get("reason")
                elif etype == "verdict":
                    verdict = {"verdict": ev.get("verdict"),
                               "score": ev.get("score"),
                               "confidence": ev.get("confidence")}
    return {"status": row["status"],
            "stages": [stages[s] for s in STAGE_ORDER],
            "verdict": verdict or (
                {"verdict": row["verdict"], "score": row["score"],
                 "confidence": row["confidence"]}
                if row["verdict"] else None),
            "error": row["error"]}


# ---------------------------------------------------------------------------
# Minimal multipart/form-data parser (stdlib only, no cgi module — it was
# removed in Python 3.13). Handles the small forms this UI submits.
# ---------------------------------------------------------------------------
def parse_multipart(body, content_type):
    """Parse a multipart/form-data request body.

    Input : body         — raw request bytes
            content_type — the Content-Type header (contains boundary=)
    Output: dict field_name -> {"filename": str|None, "data": bytes}
            Text fields have filename=None and UTF-8 decodable data.
    """
    m = re.search(r'boundary="?([^";]+)"?', content_type or "")
    if not m:
        return {}
    boundary = b"--" + m.group(1).encode()
    fields = {}
    for part in body.split(boundary):
        part = part.strip(b"\r\n")
        if not part or part == b"--":
            continue
        if b"\r\n\r\n" not in part:
            continue
        head, data = part.split(b"\r\n\r\n", 1)
        head_text = head.decode("utf-8", errors="replace")
        name_m = re.search(r'name="([^"]+)"', head_text)
        if not name_m:
            continue
        file_m = re.search(r'filename="([^"]*)"', head_text)
        fields[name_m.group(1)] = {
            "filename": file_m.group(1) if file_m else None,
            "data": data,
        }
    return fields


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "phishHunter/1.0"

    # ---- small response helpers ----------------------------------------
    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False, default=str))

    def _page(self, template_name):
        """Serve an HTML template file verbatim (data is fetched via JS)."""
        path = os.path.join(TEMPLATE_DIR, template_name)
        if not os.path.isfile(path):
            return self._send(404, "not found", "text/plain")
        with open(path, "rb") as f:
            self._send(200, f.read(), "text/html; charset=utf-8")

    def log_message(self, fmt, *args):
        # Quiet default access log; keep errors visible.
        pass

    # ---- routing --------------------------------------------------------
    def do_GET(self):
        url = urlparse(self.path)
        parts = [p for p in url.path.split("/") if p]

        # Pages ------------------------------------------------------------
        if url.path == "/":
            return self._page("dashboard.html")
        if url.path == "/analyze":
            return self._page("analyze.html")
        if url.path == "/history":
            return self._page("history.html")
        if len(parts) == 2 and parts[0] == "report":
            return self._page("report.html")

        # Static assets -----------------------------------------------------
        if parts and parts[0] == "static":
            fpath = os.path.normpath(os.path.join(STATIC_DIR, *parts[1:]))
            if not fpath.startswith(STATIC_DIR) or not os.path.isfile(fpath):
                return self._send(404, "not found", "text/plain")
            ctype = mimetypes.guess_type(fpath)[0] or "application/octet-stream"
            with open(fpath, "rb") as f:
                return self._send(200, f.read(), ctype)

        # JSON API ----------------------------------------------------------
        if url.path == "/api/stats":
            return self.api_stats()
        if url.path == "/api/analyses":
            return self.api_analyses(parse_qs(url.query))
        if (len(parts) == 4 and parts[0] == "api" and parts[1] == "analysis"
                and parts[3] == "progress"):
            prog = read_progress(parts[2])
            return self._json(prog) if prog else self._json(
                {"error": "unknown analysis id"}, 404)
        if (len(parts) == 4 and parts[0] == "api" and parts[1] == "analysis"
                and parts[3] == "report"):
            rp = os.path.join(REPORT_DIR, f"{parts[2]}.json")
            if not re.fullmatch(r"[0-9a-f]{32}", parts[2]) \
                    or not os.path.isfile(rp):
                return self._json({"error": "report not found"}, 404)
            with open(rp, "rb") as f:
                return self._send(200, f.read())

        return self._send(404, "not found", "text/plain")

    def do_POST(self):
        url = urlparse(self.path)
        if url.path != "/api/analyze":
            return self._send(404, "not found", "text/plain")

        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 50 * 1024 * 1024:   # 50 MB upload cap
            return self._json({"error": "missing or oversized body"}, 400)
        body = self.rfile.read(length)
        fields = parse_multipart(body, self.headers.get("Content-Type"))

        email = fields.get("email")
        if not email or not email.get("filename"):
            return self._json({"error": "an .eml or .msg file is required"},
                              400)
        fname = sanitize_filename(email["filename"])
        if not fname.lower().endswith((".eml", ".msg")):
            return self._json(
                {"error": "unsupported file type — upload .eml or .msg"}, 400)

        analysis_id = uuid.uuid4().hex
        adir = os.path.join(UPLOAD_DIR, analysis_id)
        os.makedirs(adir, exist_ok=True)
        email_path = os.path.join(adir, fname)
        with open(email_path, "wb") as f:
            f.write(email["data"])

        # Optional YARA rules upload — stored next to the email.
        yara_path = None
        yara = fields.get("yara_rules")
        if yara and yara.get("filename"):
            yname = sanitize_filename(yara["filename"])
            if yname.lower().endswith((".yar", ".yara")):
                yara_path = os.path.join(adir, yname)
                with open(yara_path, "wb") as f:
                    f.write(yara["data"])

        def flag(name):
            fld = fields.get(name)
            return bool(fld and fld["data"].decode("utf-8",
                                                   "replace").strip() == "1")

        options = {"skip_intel": flag("skip_intel"),
                   "skip_whois": flag("skip_whois"),
                   "ai": flag("ai"), "yara_rules": yara_path}

        with db() as conn:
            conn.execute(
                "INSERT INTO analyses (id, filename, created_utc, status) "
                "VALUES (?,?,?,?)",
                (analysis_id, fname,
                 dt.datetime.now(dt.timezone.utc).isoformat(), "running"))

        threading.Thread(target=run_analysis,
                         args=(analysis_id, email_path, options),
                         daemon=True).start()
        return self._json({"id": analysis_id})

    # ---- API implementations -------------------------------------------
    def api_stats(self):
        """Dashboard counters: totals per verdict + 8 most recent runs."""
        with db() as conn:
            counts = {"malicious": 0, "suspicious": 0, "clean": 0,
                      "running": 0, "error": 0, "total": 0}
            for row in conn.execute(
                    "SELECT status, verdict, COUNT(*) c FROM analyses "
                    "GROUP BY status, verdict"):
                counts["total"] += row["c"]
                if row["status"] == "running":
                    counts["running"] += row["c"]
                elif row["status"] == "error":
                    counts["error"] += row["c"]
                elif row["verdict"] in counts:
                    counts[row["verdict"]] += row["c"]
            recent = [dict(r) for r in conn.execute(
                "SELECT id, filename, created_utc, status, verdict, score, "
                "confidence FROM analyses ORDER BY created_utc DESC LIMIT 8")]
        return self._json({"counts": counts, "recent": recent})

    def api_analyses(self, q):
        """History listing with optional filters.

        Query params: verdict=malicious|suspicious|clean|error|running
                      q=<substring of filename>   limit=<n, default 200>
        """
        clauses, params = [], []
        verdict = (q.get("verdict") or [""])[0]
        if verdict in ("malicious", "suspicious", "clean"):
            clauses.append("verdict = ?"); params.append(verdict)
        elif verdict in ("error", "running"):
            clauses.append("status = ?"); params.append(verdict)
        needle = (q.get("q") or [""])[0].strip()
        if needle:
            clauses.append("filename LIKE ?"); params.append(f"%{needle}%")
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        limit = min(int((q.get("limit") or ["200"])[0] or 200), 1000)
        with db() as conn:
            items = [dict(r) for r in conn.execute(
                f"SELECT id, filename, created_utc, status, verdict, score, "
                f"confidence FROM analyses {where} "
                f"ORDER BY created_utc DESC LIMIT ?", params + [limit])]
        return self._json({"items": items})


def main():
    global SKILLS_ROOT
    ap = argparse.ArgumentParser(description="phishHunter Web UI")
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address (default 127.0.0.1 — keep local; put "
                         "an authenticated reverse proxy in front to share)")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--skills-root",
                    help="directory containing the skill folders "
                         "(default: <repo>/skills)")
    args = ap.parse_args()
    if args.skills_root:
        SKILLS_ROOT = os.path.abspath(args.skills_root)

    if not os.path.isfile(PIPELINE):
        print(f"error: pipeline not found at {PIPELINE}", file=sys.stderr)
        sys.exit(1)
    init_db()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"phishHunter Web UI  →  http://{args.host}:{args.port}")
    print(f"  skills root : {SKILLS_ROOT}")
    print(f"  data dir    : {DATA_DIR}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
