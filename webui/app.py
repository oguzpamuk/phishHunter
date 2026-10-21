#!/usr/bin/env python3
"""
app.py — phishHunter Web UI server (pure Python standard library).

A zero-dependency web console for the email triage pipeline:

    Dashboard   /             verdict distribution, totals, recent analyses
    Analyze     /analyze      drag-&-drop upload + live per-stage progress
    Report      /report/{id}  full evidence report rendered in the browser
    History     /history      past analyses, filterable by verdict/filename
    Settings    /settings     retention, users, purge, audit trail (admin)
    Account     /account      change your password
    Log in      /login        the only page served without a session

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
                         [--config PATH | --no-config]
                         [--allow-host NAME[:PORT] ...] [--max-parallel 2]
                         [--stage-timeout 300] [--analysis-timeout 3600]
                         [--max-email-mb 50] [--read-timeout 30]
                         [--upload-timeout 120] [--max-connections 64]
                         [--max-memory-mb 4096]
                         [--tls-cert PEM --tls-key PEM | --behind-proxy]
    python3 webui/app.py --reset-admin     # new one-time admin password

    Then open  http://127.0.0.1:8787 and log in. On the first start an
    "admin" account is created and its one-time password is printed in
    this console; it must be changed at the first login.

    Optional env for the intel stage (same as the CLI):
      VT_API_KEY, ABUSEIPDB_API_KEY, OTX_API_KEY, URLSCAN_API_KEY,
      HYBRID_ANALYSIS_API_KEY, ANTHROPIC_API_KEY
    They are read at start-up from the private per-user config file
    (python3 easy_install.py --keys); exported variables
    win. --config PATH uses another file, --no-config disables it.
    Install and enter keys first with:  python3 easy_install.py

============================================================================
SECURITY MODEL
============================================================================
    Users and roles (webui/auth.py, stored in the SQLite database):
    * admin    - everything: full reports, settings, users, deletion.
    * readonly - starts analyses and reads every report, but the server
                 removes the email content first (webui/redact.py):
                 subject, recipients, display names, quoted body text,
                 text read from images and raw headers are hidden; e-mail
                 addresses show only ***@domain; URLs lose their query
                 string and fragment; other people's upload file names
                 become "email-<id>".
    * Passwords: scrypt (PBKDF2 fallback), at least 10 characters. New and
      reset accounts get a one-time password that must be changed first.
    * Sessions: random token in an HttpOnly, SameSite=Strict cookie (Secure
      under TLS / --behind-proxy); only its SHA-256 is stored. Idle
      timeout 30 min, absolute lifetime 12 h; a password change, disable
      or delete ends the user's other sessions.
    * Lockout: 5 failed logins within 15 min lock that user name and that
      client IP for 15 min (HTTP 429). --reset-admin lifts all lockouts.
    * Every login, user change, setting change and deletion goes to the
      audit table (Settings page).
    * Retention: analyses older than N days (default 30, 0 = forever) are
      deleted hourly; optionally the original email is deleted as soon as
      its analysis finishes. Admins can delete one analysis or all.
    * Network: binding beyond loopback is refused unless --tls-cert and
      --tls-key are given (HTTPS, TLS 1.2+) or --behind-proxy says a TLS
      reverse proxy is in front (then the last X-Forwarded-For entry is
      the client IP; add the proxy's name with --allow-host).

    Request hardening:
    * Host header allow-list: only loopback names (and --allow-host values)
      are answered, so a web page cannot use DNS rebinding to read reports.
    * CSRF: POST requires the X-PhishHunter-Request header and a matching
      Origin, which a cross-site page cannot send without CORS approval.
    * Every page gets a strict Content-Security-Policy with a per-response
      script nonce; API values are HTML-escaped before rendering.
    * webui/data is private (umask 077, dirs 700, files 600).
    * At most --max-parallel analyses run at once (HTTP 429 otherwise); a
      slot is taken only after an upload has fully arrived and validated.
    * Uploads are streamed to webui/data/incoming and parsed from disk
      (memory does not grow with the upload); emails above --max-email-mb
      get HTTP 413.
    * Connections silent for --read-timeout, or uploads slower than
      --upload-timeout, are dropped (408); above --max-connections new
      connections get 503.
    * Each analysis runs with --max-memory-mb and a CPU limit.

============================================================================
HTTP API (all JSON unless noted)
============================================================================
    GET  /                      dashboard page          (text/html)
    GET  /analyze               analyze page            (text/html)
    GET  /history               history page            (text/html)
    GET  /report/{id}           report page             (text/html)
    GET  /settings              settings page (admin)   (text/html)
    GET  /account, /login       account / login pages   (text/html)
    GET  /static/<file>         css/js assets (no session needed)

    Every route except /login, /static and POST /api/login needs a session
    cookie: pages redirect to /login, API calls get 401. A user with a
    one-time password gets 403 everywhere except /account until it is
    changed. Every POST needs the "X-PhishHunter-Request: 1" header.

    POST /api/login             {"username","password"} → {"username",
                                "role","must_change"} + session cookie
                                401 wrong credentials · 429 locked out
    POST /api/logout            ends the session
    GET  /api/me                → {"username","role","must_change"}
    POST /api/account/password  {"current","new"}

    POST /api/analyze           multipart form upload; REQUIRED header
                                "X-PhishHunter-Request: 1" (CSRF guard).
                                fields:
                                  email      (file, .eml/.msg, required)
                                  skip_intel ("1" to skip threat intel)
                                  skip_whois ("1" to skip WHOIS)
                                  share_urls ("1": submit URLs to VT and make
                                              urlscan scans public)
                                  yara_rules (file, .yar/.yara, optional)
                                  ai_body    ("1": AI body analysis)
                                  ai_images  ("1": AI image analysis)
                                  ai         ("1" to add the LLM analyst)
                                → {"id": "<analysis id>"}
                                  400 bad input · 403 cross-site / wrong
                                  Host · 408 too slow · 413 too large ·
                                  429 too many running analyses
    GET  /api/analysis/{id}/progress
                                → {"status": "running|done|error",
                                   "stages": [ {stage,status,duration_s,
                                                error}... ],
                                   "verdict": {...}|null }
    GET  /api/analysis/{id}/report
                                → the full pipeline JSON report
                                  (read-only users: redacted copy with
                                   "redacted": {...} added)
    GET  /api/analyses?verdict=&q=&limit=
                                → {"items":[{id,filename,verdict,score,
                                    confidence,created_utc,status}...]}
    GET  /api/stats             → dashboard counters + recent list

    Admin only (403 for read-only users):
    GET  /api/settings          → {"retention_days","delete_original_
                                   after_analysis"}
    POST /api/settings          {"retention_days": 0-3650,
                                 "delete_original_after_analysis": bool}
    GET  /api/users             → {"items":[{id,username,role,disabled,
                                   must_change,created_utc,last_login_utc}]}
    POST /api/users             {"username","role"} → {"id",
                                 "temporary_password"}
    POST /api/users/{id}        {"action": role|reset|disable|enable|
                                 delete, "role"} (not on yourself, except
                                 reset; the last admin is protected)
    GET  /api/audit             → {"items":[{ts_utc,username,action,
                                   detail}]}  (latest 200)
    POST /api/analysis/{id}/delete    delete one finished analysis
    POST /api/purge             {"confirm":"DELETE"} → {"deleted": n}

============================================================================
SECURITY NOTES
============================================================================
* Binds to 127.0.0.1 by default. To share it on a network use
  --tls-cert/--tls-key, or a TLS reverse proxy with --behind-proxy.
* Uploaded filenames are sanitized; files are stored under a per-analysis
  directory and never executed.
* The report endpoint only serves ids that exist in the local database.
============================================================================
"""

import argparse
import datetime as dt
import http.cookies
import json
import mimetypes
import mmap
import os
import re
import secrets
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, quote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import auth  # noqa: E402  users, sessions, settings, audit
import redact  # noqa: E402  email content removal for read-only users

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
# Uploads are streamed here first and deleted once handled.
INCOMING_DIR = os.path.join(DATA_DIR, "incoming")
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
# Security settings (filled in by main()).
#   ALLOWED_HOSTS  - exact "host:port" values accepted in the Host header.
#                    Anything else is refused: this defeats DNS-rebinding
#                    attacks where a malicious web page re-points its own
#                    domain at 127.0.0.1 to read reports from this console.
#   CSRF_HEADER    - POSTs must carry this header. Browsers cannot add a
#                    custom header to a cross-site request without a CORS
#                    preflight, which this server never approves, so a
#                    malicious page cannot start analyses (and spend your API
#                    quota) in the background.
#   MAX_PARALLEL   - concurrent analyses; extra uploads get HTTP 429.
# ---------------------------------------------------------------------------
ALLOWED_HOSTS = set()
CSRF_HEADER = "X-PhishHunter-Request"
# Authentication (see auth.py). The session cookie is HttpOnly and
# SameSite=Strict, and Secure whenever the console is served over TLS or
# behind a TLS-terminating proxy.
COOKIE_NAME = "ph_session"
SECURE_COOKIES = False
BEHIND_PROXY = False         # trust X-Forwarded-For for the client address
MAX_JSON = 16 * 1024         # body limit for JSON API requests
RETENTION_INTERVAL = 3600    # seconds between automatic clean-ups
MAX_PARALLEL = 2
STAGE_TIMEOUT = 300          # seconds per pipeline stage (--timeout)
ANALYSIS_TIMEOUT = 3600      # hard limit for one whole analysis
_slots = threading.BoundedSemaphore(MAX_PARALLEL)

# Upload / connection limits (all overridable on the command line).
#   MAX_EMAIL_MB    - largest email accepted; also passed to the pipeline.
#   READ_TIMEOUT    - seconds a connection may stay silent (headers or body)
#                     before it is dropped (socket timeout on every read).
#   UPLOAD_TIMEOUT  - total seconds allowed to receive one upload, so a
#                     client trickling a byte at a time cannot hold a
#                     connection forever.
#   MAX_CONNECTIONS - concurrent connections; extra ones get HTTP 503 and
#                     are closed, which bounds threads and memory.
#   MAX_MEMORY_MB / MAX_CPU_SECONDS - resource limits for every analysis
#                     process (passed to the pipeline, which applies them
#                     to itself and to all of its sub-skills).
MAX_EMAIL_MB = 50
READ_TIMEOUT = 30
UPLOAD_TIMEOUT = 120
MAX_CONNECTIONS = 64
MAX_MEMORY_MB = 4096
MAX_CPU_SECONDS = 1800
_conn_slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
# Multipart framing allowance on top of the email itself (form fields,
# headers, an optional YARA rules file).
MAX_FORM_EXTRA = 5 * 1024 * 1024
MAX_FORM_FIELDS = 16
MAX_FIELD_TEXT = 1024
CHUNK = 64 * 1024


# ---------------------------------------------------------------------------
# Database — one table indexing every analysis for dashboard + history.
# ---------------------------------------------------------------------------
def db():
    """Open a SQLite connection (one per call — cheap, thread-safe usage)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def secure_data_dir():
    """Make everything under webui/data private to the current user.

    Uploaded emails, reports, audit logs and the index contain recipient
    addresses and message content, so they must not be readable by other
    accounts on the machine. New files are already created private (main()
    sets umask 077); this also repairs folders created by older versions.
    POSIX only - on Windows the per-user profile ACLs apply.
    """
    if os.name != "posix":
        return
    for root, _dirs, files in os.walk(DATA_DIR):
        os.chmod(root, 0o700)
        for name in files:
            try:
                os.chmod(os.path.join(root, name), 0o600)
            except OSError:
                pass


def init_db():
    """Create private data dirs and the analyses table on first run."""
    for d in (DATA_DIR, UPLOAD_DIR, REPORT_DIR, LOG_DIR, INCOMING_DIR):
        os.makedirs(d, mode=0o700, exist_ok=True)
    # Leftovers of uploads interrupted by a crash or restart.
    for name in os.listdir(INCOMING_DIR):
        try:
            os.unlink(os.path.join(INCOMING_DIR, name))
        except OSError:
            pass
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
        # Columns added after the first release. SQLite has no "ADD COLUMN
        # IF NOT EXISTS", so existing databases are migrated by inspecting
        # the table and adding what is missing — an old console keeps its
        # history instead of needing a wipe.
        have = {row["name"] for row in conn.execute(
            "PRAGMA table_info(analyses)")}
        for col, ddl in (("ai_verdict", "TEXT"),
                         ("ai_confidence", "INTEGER"),
                         ("ai_agrees", "INTEGER"),
                         ("created_by", "TEXT")):
            if col not in have:
                conn.execute(f"ALTER TABLE analyses ADD COLUMN {col} {ddl}")
        # Runs that were still "running" when the server stopped can never
        # finish; mark them so they do not stay "running" forever.
        conn.execute("UPDATE analyses SET status='error', error=? "
                     "WHERE status='running'",
                     ("interrupted: the web UI was stopped during the run",))
        auth.init_schema(conn)
        admin_password = auth.ensure_admin(conn)
    secure_data_dir()
    return admin_password


# ---------------------------------------------------------------------------
# Deleting data - single analyses, everything, and automatic retention
# ---------------------------------------------------------------------------
def delete_analysis_files(analysis_id):
    """Remove the upload folder, report and log of one analysis."""
    if not re.fullmatch(r"[0-9a-f]{32}", analysis_id or ""):
        return
    shutil.rmtree(os.path.join(UPLOAD_DIR, analysis_id), ignore_errors=True)
    for path in (os.path.join(REPORT_DIR, f"{analysis_id}.json"),
                 os.path.join(LOG_DIR, f"{analysis_id}.log")):
        try:
            os.unlink(path)
        except OSError:
            pass


def delete_analysis(conn, analysis_id):
    """
    Delete one analysis (row + files).

    Output: True when it existed. Running analyses are not deleted.
    """
    row = conn.execute("SELECT status FROM analyses WHERE id=?",
                       (analysis_id,)).fetchone()
    if not row or row["status"] == "running":
        return False
    conn.execute("DELETE FROM analyses WHERE id=?", (analysis_id,))
    delete_analysis_files(analysis_id)
    return True


def purge_all(conn):
    """
    Delete every finished analysis with its upload, report and log.

    Output: number of analyses deleted. Running analyses are kept.
    """
    ids = [r["id"] for r in conn.execute(
        "SELECT id FROM analyses WHERE status != 'running'")]
    for analysis_id in ids:
        conn.execute("DELETE FROM analyses WHERE id=?", (analysis_id,))
        delete_analysis_files(analysis_id)
    return len(ids)


def apply_retention():
    """
    Delete analyses older than the "retention_days" setting (0 = never) and
    expired sessions. Output: number of analyses deleted.
    """
    with db() as conn:
        auth.cleanup(conn)
        days = int(auth.get_settings(conn).get("retention_days") or 0)
        if days <= 0:
            return 0
        cutoff = (dt.datetime.now(dt.timezone.utc)
                  - dt.timedelta(days=days)).isoformat()
        ids = [r["id"] for r in conn.execute(
            "SELECT id FROM analyses WHERE created_utc < ? AND "
            "status != 'running'", (cutoff,))]
        for analysis_id in ids:
            conn.execute("DELETE FROM analyses WHERE id=?", (analysis_id,))
            delete_analysis_files(analysis_id)
        if ids:
            auth.audit(conn, "system", "retention_delete",
                       f"{len(ids)} analyses older than {days} days")
        return len(ids)


def retention_loop():
    """Background thread: apply the retention policy once an hour."""
    while True:
        try:
            apply_retention()
        except Exception as exc:  # keep the thread alive; retry next hour
            print(f"[retention] failed: {exc}", file=sys.stderr)
        time.sleep(RETENTION_INTERVAL)


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
                           "yara_rules": path|None, "ai": bool,
                           "ai_body": bool, "ai_images": bool,
                           "share_urls": bool}
    Effect: writes the JSON report to REPORT_DIR/<id>.json, streams the
            audit log to LOG_DIR/<id>.log (consumed live by the progress
            API), and updates the DB row to done/error with the verdict.
    """
    report_path = os.path.join(REPORT_DIR, f"{analysis_id}.json")
    log_path = os.path.join(LOG_DIR, f"{analysis_id}.log")
    cmd = [sys.executable, PIPELINE, email_path,
           "--skills-root", SKILLS_ROOT,
           "-o", report_path,
           "--log-file", log_path, "--quiet",
           "--timeout", str(STAGE_TIMEOUT),
           "--max-email-mb", str(MAX_EMAIL_MB),
           "--max-memory-mb", str(MAX_MEMORY_MB),
           "--max-cpu-seconds", str(MAX_CPU_SECONDS),
           # The server loaded the key config once at start-up and the child
           # inherits os.environ; stop the pipeline re-reading it so the
           # server's --config / --no-config choice holds.
           "--no-config"]
    if options.get("skip_intel"):
        cmd.append("--skip-intel")
    if options.get("skip_whois"):
        cmd.append("--skip-whois")
    if options.get("yara_rules"):
        cmd += ["--yara-rules", options["yara_rules"]]
    if options.get("share_urls"):
        cmd.append("--share-urls")
    if options.get("ai_body"):
        cmd.append("--ai-body")
    if options.get("ai_images"):
        cmd.append("--ai-images")
    if options.get("ai"):
        cmd.append("--ai")

    try:
        # Exit codes 0/1/2 are verdicts, 3 is fatal — all non-exceptional.
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=ANALYSIS_TIMEOUT)
        if os.path.isfile(report_path):
            with open(report_path, "r", encoding="utf-8") as f:
                report = json.load(f)
            v = report.get("verdict") or {}
            ai = report.get("ai_analysis") or {}
            with db() as conn:
                conn.execute(
                    "UPDATE analyses SET status='done', verdict=?, score=?, "
                    "confidence=?, ai_verdict=?, ai_confidence=?, "
                    "ai_agrees=? WHERE id=?",
                    (v.get("verdict"), v.get("score"), v.get("confidence"),
                     ai.get("verdict"), ai.get("confidence_score"),
                     (None if ai.get("agrees_with_heuristic") is None
                      else int(bool(ai.get("agrees_with_heuristic")))),
                     analysis_id))
        else:
            with db() as conn:
                conn.execute(
                    "UPDATE analyses SET status='error', error=? WHERE id=?",
                    ((proc.stderr or "pipeline produced no report")[:500],
                     analysis_id))
    except subprocess.TimeoutExpired:
        with db() as conn:
            conn.execute(
                "UPDATE analyses SET status='error', error=? WHERE id=?",
                (f"analysis exceeded {ANALYSIS_TIMEOUT}s and was stopped",
                 analysis_id))
    except Exception as e:
        with db() as conn:
            conn.execute(
                "UPDATE analyses SET status='error', error=? WHERE id=?",
                (str(e)[:500], analysis_id))
    finally:
        try:
            with db() as conn:
                drop = auth.get_settings(conn).get(
                    "delete_original_after_analysis") == "1"
            if drop:
                # Keep the report, remove the email and its attachments.
                shutil.rmtree(os.path.join(UPLOAD_DIR, analysis_id),
                              ignore_errors=True)
        finally:
            _slots.release()


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
                    stages[name]["warning"] = ev.get("warning")
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
# Uploads: streamed to disk, parsed without loading them into memory
# ---------------------------------------------------------------------------
class UploadError(Exception):
    """An upload that cannot be accepted. .code is the HTTP status."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def receive_body(rfile, length, dest_fd):
    """Copy exactly `length` request-body bytes to a file, in chunks.

    Input : rfile   - the request stream (its socket has READ_TIMEOUT set)
            length  - Content-Length, already checked against the limit
            dest_fd - open file descriptor of a private temporary file
    Output: None. Memory use is one CHUNK regardless of the upload size.
    Raises: UploadError(408) when the client is silent for READ_TIMEOUT or
            the whole upload takes longer than UPLOAD_TIMEOUT;
            UploadError(400) when the connection closes early.
    read1() returns whatever one socket read delivers, so the overall
    deadline is checked even for a client that trickles bytes slowly.
    """
    deadline = time.monotonic() + UPLOAD_TIMEOUT
    remaining = length
    while remaining > 0:
        if time.monotonic() > deadline:
            raise UploadError(408, f"upload took longer than "
                                   f"{UPLOAD_TIMEOUT}s")
        try:
            chunk = rfile.read1(min(CHUNK, remaining))
        except (socket.timeout, TimeoutError):
            raise UploadError(408, f"client sent nothing for "
                                   f"{READ_TIMEOUT}s") from None
        if not chunk:
            raise UploadError(400, "connection closed before the upload "
                                   "was complete")
        os.write(dest_fd, chunk)
        remaining -= len(chunk)


def parse_multipart_file(path, content_type):
    """Locate the parts of a multipart/form-data body stored in a file.

    Input : path         - file holding the raw request body
            content_type - the Content-Type header (contains boundary=)
    Output: dict field_name -> {"filename": str|None,
                                "start": int, "end": int}
            start/end are byte offsets of the part's data in the file, so
            callers copy or read only what they need (see copy_part /
            read_part_text) - the body is never loaded into memory.
    Raises: UploadError(400) for a malformed body or too many fields.
    """
    m = re.search(r'boundary="?([^";]+)"?', content_type or "")
    if not m:
        raise UploadError(400, "multipart boundary missing")
    delim = b"--" + m.group(1).encode("latin-1", "replace")
    fields = {}
    with open(path, "rb") as fh:
        if os.fstat(fh.fileno()).st_size == 0:
            raise UploadError(400, "empty body")
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            pos = mm.find(delim)
            while pos != -1:
                start = pos + len(delim)
                if mm[start:start + 2] == b"--":          # closing delimiter
                    break
                nxt = mm.find(b"\r\n" + delim, start)
                if nxt == -1:
                    raise UploadError(400, "multipart body is truncated")
                head_end = mm.find(b"\r\n\r\n", start, nxt)
                if head_end == -1 or head_end - start > 8192:
                    raise UploadError(400, "malformed multipart part")
                head = mm[start:head_end].decode("utf-8", "replace")
                name_m = re.search(r'name="([^"]+)"', head)
                if name_m:
                    if len(fields) >= MAX_FORM_FIELDS:
                        raise UploadError(400, "too many form fields")
                    file_m = re.search(r'filename="([^"]*)"', head)
                    fields[name_m.group(1)] = {
                        "filename": file_m.group(1) if file_m else None,
                        "start": head_end + 4, "end": nxt}
                pos = nxt + 2
    return fields


def read_part_text(path, part):
    """Input: body file, part. Output: the part as text (max 1 KB)."""
    size = min(part["end"] - part["start"], MAX_FIELD_TEXT)
    with open(path, "rb") as fh:
        fh.seek(part["start"])
        return fh.read(size).decode("utf-8", "replace")


def copy_part(path, part, dest):
    """Copy one part's bytes from the body file to `dest`, in chunks.

    Input : path (body file), part (from parse_multipart_file), dest path.
    Output: number of bytes written. The destination is created 0600.
    """
    remaining = part["end"] - part["start"]
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with open(path, "rb") as src, os.fdopen(fd, "wb") as out:
        src.seek(part["start"])
        while remaining > 0:
            chunk = src.read(min(CHUNK, remaining))
            if not chunk:
                break
            out.write(chunk)
            remaining -= len(chunk)
    return part["end"] - part["start"]


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "phishHunter/1.0"

    # ---- small response helpers ----------------------------------------
    def _send(self, code, body, ctype="application/json; charset=utf-8",
              csp=None, headers=None):
        """Write a response with the console's security headers.

        Input : code, body (str|bytes), ctype, csp (page-specific policy;
                default denies everything - right for JSON/static files).
        """
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy",
                         csp or "default-src 'none'; frame-ancestors 'none'")
        for name, value in headers or ():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def _host_allowed(self):
        """Input: request headers. Output: True when Host is one of ours."""
        host = (self.headers.get("Host") or "").strip().lower()
        return host in ALLOWED_HOSTS

    def _same_origin_post(self):
        """CSRF check for POST: custom header present, Origin (if sent)
        names this console."""
        if self.headers.get(CSRF_HEADER) != "1":
            return False
        origin = self.headers.get("Origin")
        if origin:
            o = urlparse(origin)
            if o.scheme not in ("http", "https") or \
                    (o.netloc or "").lower() not in ALLOWED_HOSTS:
                return False
        return True

    def _json(self, obj, code=200, headers=None):
        self._send(code, json.dumps(obj, ensure_ascii=False, default=str),
                   headers=headers)

    def _redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    # ---- authentication helpers ------------------------------------------
    def _client_ip(self):
        """Output: client address used for lockout and the audit trail.

        With --behind-proxy this is the LAST X-Forwarded-For entry: the
        one the (single, trusted) reverse proxy appended. Earlier entries
        come from the client and can be forged, so using them would let an
        attacker dodge the per-IP lockout. Without the flag: the socket peer.
        """
        if BEHIND_PROXY:
            fwd = (self.headers.get("X-Forwarded-For") or "").split(",")[-1]
            if fwd.strip():
                return fwd.strip()[:64]
        return self.client_address[0]

    def _session_token(self):
        cookie = http.cookies.SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie") or "")
        except http.cookies.CookieError:
            return None
        morsel = cookie.get(COOKIE_NAME)
        return morsel.value if morsel else None

    def _user(self):
        """Output: the logged-in user dict (cached per request) or None."""
        if not hasattr(self, "_cached_user"):
            with db() as conn:
                self._cached_user = auth.session_user(conn,
                                                      self._session_token())
        return self._cached_user

    def _cookie(self, token, max_age):
        attrs = [f"{COOKIE_NAME}={token}", "Path=/", "HttpOnly",
                 "SameSite=Strict", f"Max-Age={max_age}"]
        if SECURE_COOKIES:
            attrs.append("Secure")
        return ("Set-Cookie", "; ".join(attrs))

    def _read_json(self):
        """Read a small JSON request body. Output: dict ({} when empty)."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise UploadError(400, "invalid Content-Length") from None
        if length > MAX_JSON:
            raise UploadError(413, "request too large")
        raw = b""
        while len(raw) < length:
            try:
                chunk = self.rfile.read1(length - len(raw))
            except (socket.timeout, TimeoutError):
                raise UploadError(408, "request timed out") from None
            if not chunk:
                break
            raw += chunk
        try:
            data = json.loads(raw.decode("utf-8") or "{}")
        except ValueError:
            raise UploadError(400, "invalid JSON") from None
        if not isinstance(data, dict):
            raise UploadError(400, "JSON object expected")
        return data

    def _page(self, template_name):
        """Serve an HTML template file verbatim (data is fetched via JS)."""
        path = os.path.join(TEMPLATE_DIR, template_name)
        if not os.path.isfile(path):
            return self._send(404, "not found", "text/plain")
        with open(path, "r", encoding="utf-8") as f:
            html = f.read()
        # A fresh nonce per response: only the page's own inline <script>
        # may run, so injected markup can never execute script even if an
        # escaping bug slipped through (defence in depth against XSS).
        nonce = secrets.token_urlsafe(18)
        html = html.replace("<script>", f'<script nonce="{nonce}">')
        csp = ("default-src 'self'; "
               f"script-src 'nonce-{nonce}'; "
               "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
               "font-src 'self' https://fonts.gstatic.com; "
               "img-src 'self' data:; connect-src 'self'; "
               "base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        self._send(200, html, "text/html; charset=utf-8", csp=csp)

    def log_message(self, fmt, *args):
        # Quiet default access log; keep errors visible.
        pass

    # ---- routing --------------------------------------------------------
    def do_GET(self):
        self.__dict__.pop("_cached_user", None)    # never reuse across requests
        if not self._host_allowed():
            return self._send(403, "host not allowed", "text/plain")
        try:
            return self._get()
        except Exception:
            return self._json({"error": "internal error"}, 500)

    def do_POST(self):
        self.__dict__.pop("_cached_user", None)
        if not self._host_allowed():
            return self._send(403, "host not allowed", "text/plain")
        if not self._same_origin_post():
            return self._json({"error": "cross-site request refused"}, 403)
        try:
            return self._post()
        except Exception:
            try:
                return self._json({"error": "internal error"}, 500)
            except OSError:
                return None

    def _get(self):
        url = urlparse(self.path)
        parts = [p for p in url.path.split("/") if p]

        # Public: login page and static files -------------------------------
        if url.path == "/login":
            if self._user() and not self._user()["must_change"]:
                return self._redirect("/")
            return self._page("login.html")
        if parts and parts[0] == "static":
            fpath = os.path.normpath(os.path.join(STATIC_DIR, *parts[1:]))
            if not fpath.startswith(STATIC_DIR + os.sep) or \
                    not os.path.isfile(fpath):
                return self._send(404, "not found", "text/plain")
            ctype = mimetypes.guess_type(fpath)[0] or "application/octet-stream"
            with open(fpath, "rb") as f:
                return self._send(200, f.read(), ctype)

        # Everything else needs a session -----------------------------------
        user = self._user()
        is_api = url.path.startswith("/api/")
        if not user:
            if is_api:
                return self._json({"error": "login required"}, 401)
            nxt = quote(url.path + (("?" + url.query) if url.query else ""))
            return self._redirect(f"/login?next={nxt}")
        if url.path == "/api/me":
            return self._json({"username": user["username"],
                               "role": user["role"],
                               "must_change": bool(user["must_change"])})
        if user["must_change"]:
            # A temporary password must be replaced before anything else.
            if url.path == "/account":
                return self._page("account.html")
            if is_api:
                return self._json({"error": "password change required"}, 403)
            return self._redirect("/account")
        is_admin = user["role"] == "admin"

        # Pages ------------------------------------------------------------
        if url.path == "/account":
            return self._page("account.html")
        if url.path == "/settings":
            return self._page("settings.html") if is_admin \
                else self._redirect("/")
        if url.path == "/":
            return self._page("dashboard.html")
        if url.path == "/analyze":
            return self._page("analyze.html")
        if url.path == "/history":
            return self._page("history.html")
        if len(parts) == 2 and parts[0] == "report":
            return self._page("report.html")

        # JSON API ----------------------------------------------------------
        if url.path in ("/api/settings", "/api/users", "/api/audit"):
            if not is_admin:
                return self._json({"error": "admin only"}, 403)
            with db() as conn:
                if url.path == "/api/settings":
                    return self._json(auth.get_settings(conn))
                if url.path == "/api/users":
                    return self._json({"items": auth.list_users(conn)})
                return self._json({"items": auth.recent_audit(conn, 200)})
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
            if is_admin:
                with open(rp, "rb") as f:
                    return self._send(200, f.read())
            # Read-only users get the report with the email content
            # removed - done here, so it never reaches the browser.
            with db() as conn:
                row = conn.execute("SELECT id, filename, created_by FROM "
                                   "analyses WHERE id=?",
                                   (parts[2],)).fetchone()
            name = (self._mask_rows([dict(row)])[0]["filename"]
                    if row else None)
            with open(rp, "r", encoding="utf-8") as f:
                return self._json(redact.redact_report(json.load(f), name))

        return self._send(404, "not found", "text/plain")

    def _post(self):
        url = urlparse(self.path)
        try:
            if url.path == "/api/login":
                return self._api_login(self._read_json())
            user = self._user()
            if not user:
                return self._json({"error": "login required"}, 401)
            if url.path == "/api/logout":
                with db() as conn:
                    auth.logout(conn, user["token_hash"])
                    auth.audit(conn, user["username"], "logout")
                return self._json({"ok": True},
                                  headers=[self._cookie("", 0)])
            if url.path == "/api/account/password":
                return self._api_password(user, self._read_json())
            if user["must_change"]:
                return self._json({"error": "password change required"}, 403)
            if url.path == "/api/analyze":
                return self._upload(user)
            if user["role"] != "admin":
                return self._json({"error": "admin only"}, 403)
            return self._admin_post(user, url.path, self._read_json())
        except UploadError as e:
            if e.code in (408, 413):
                self.close_connection = True
            try:
                return self._json({"error": str(e)}, e.code)
            except OSError:
                return None

    # ---- auth / admin endpoints -------------------------------------------
    def _api_login(self, data):
        with db() as conn:
            try:
                token, user = auth.login(conn, data.get("username"),
                                         data.get("password"),
                                         self._client_ip())
            except ValueError as e:
                code = 429 if "too many" in str(e) else 401
                return self._json({"error": str(e)}, code)
        return self._json({"username": user["username"], "role": user["role"],
                           "must_change": bool(user["must_change"])},
                          headers=[self._cookie(token,
                                                auth.SESSION_LIFETIME)])

    def _api_password(self, user, data):
        with db() as conn:
            try:
                auth.change_password(conn, user["id"], data.get("current"),
                                     data.get("new"), user["token_hash"])
            except ValueError as e:
                return self._json({"error": str(e)}, 400)
            auth.audit(conn, user["username"], "password_changed")
        return self._json({"ok": True})

    def _admin_post(self, user, path, data):
        """Admin-only actions: users, settings, deletion."""
        parts = [p for p in path.split("/") if p]
        who = user["username"]
        with db() as conn:
            try:
                if path == "/api/users":
                    uid, pw = auth.create_user(conn, data.get("username"),
                                               data.get("role"))
                    auth.audit(conn, who, "user_created",
                               f"{data.get('username')} ({data.get('role')})")
                    return self._json({"id": uid, "temporary_password": pw})
                if len(parts) == 3 and parts[:2] == ["api", "users"] and \
                        parts[2].isdigit():
                    target = int(parts[2])
                    if target == user["id"] and data.get("action") in (
                            "disable", "delete", "role"):
                        raise ValueError("you cannot disable, delete or "
                                         "demote your own account")
                    res = auth.update_user(conn, target, data.get("action"),
                                           data.get("role"))
                    auth.audit(conn, who, f"user_{data.get('action')}",
                               res["username"] + (f" -> {data.get('role')}"
                                                  if data.get("role") else ""))
                    return self._json(res)
                if path == "/api/settings":
                    res = auth.set_settings(conn, data)
                    auth.audit(conn, who, "settings_changed",
                               json.dumps(res, sort_keys=True))
                    return self._json(res)
                if path == "/api/purge":
                    if data.get("confirm") != "DELETE":
                        raise ValueError('type DELETE to confirm')
                    n = purge_all(conn)
                    auth.audit(conn, who, "purge", f"{n} analyses deleted")
                    return self._json({"deleted": n})
                if len(parts) == 4 and parts[:2] == ["api", "analysis"] and \
                        parts[3] == "delete":
                    if not delete_analysis(conn, parts[2]):
                        return self._json({"error": "not found or still "
                                                    "running"}, 404)
                    auth.audit(conn, who, "analysis_deleted", parts[2])
                    return self._json({"deleted": 1})
            except ValueError as e:
                return self._json({"error": str(e)}, 400)
        return self._send(404, "not found", "text/plain")

    def _upload(self, user):
        self._uploader = user["username"]

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self._json({"error": "invalid Content-Length"}, 400)
        limit = MAX_EMAIL_MB * 1024 * 1024 + MAX_FORM_EXTRA
        if length <= 0:
            return self._json({"error": "empty request"}, 400)
        if length > limit:
            self.close_connection = True
            return self._json({"error": f"upload larger than the "
                               f"{MAX_EMAIL_MB} MB limit"}, 413)

        # 1. Receive the whole body into a private temporary file. The
        #    analysis slot is NOT taken yet: a slow or stalled client can
        #    hold only its own connection, never the analysis capacity.
        fd, body_path = tempfile.mkstemp(prefix="upload-", dir=INCOMING_DIR)
        try:
            try:
                receive_body(self.rfile, length, fd)
            finally:
                os.close(fd)
            fields = parse_multipart_file(body_path,
                                          self.headers.get("Content-Type"))
            # 2. Validate, then 3. take a slot and start the analysis.
            return self._start_analysis(body_path, fields)
        except UploadError as e:
            if e.code in (408, 413):
                self.close_connection = True
            try:
                return self._json({"error": str(e)}, e.code)
            except OSError:          # client already gone (timeout)
                return None
        finally:
            try:
                os.unlink(body_path)
            except OSError:
                pass

    def _start_analysis(self, body_path, fields):
        """Validate a received upload, store it and start the pipeline.

        Input : body_path - temporary file holding the request body
                fields    - parse_multipart_file() result
        Output: response sent; True when an analysis thread was started
                (the thread then owns its concurrency slot).
        """
        email = fields.get("email")
        if not email or not email.get("filename"):
            raise UploadError(400, "an .eml or .msg file is required")
        fname = sanitize_filename(email["filename"])
        if not fname.lower().endswith((".eml", ".msg")):
            raise UploadError(400, "unsupported file type - upload .eml "
                                   "or .msg")
        if email["end"] - email["start"] > MAX_EMAIL_MB * 1024 * 1024:
            raise UploadError(413, f"email larger than the {MAX_EMAIL_MB} "
                                   f"MB limit")
        if email["end"] <= email["start"]:
            raise UploadError(400, "the email file is empty")

        def flag(name):
            fld = fields.get(name)
            return bool(fld and read_part_text(body_path, fld).strip() == "1")

        # Only a complete, valid upload reaches this point - now take an
        # analysis slot.
        if not _slots.acquire(blocking=False):
            raise UploadError(429, f"{MAX_PARALLEL} analyses are already "
                                   "running - try again shortly")
        try:
            analysis_id = uuid.uuid4().hex
            adir = os.path.join(UPLOAD_DIR, analysis_id)
            os.makedirs(adir, mode=0o700, exist_ok=True)
            email_path = os.path.join(adir, fname)
            copy_part(body_path, email, email_path)

            # Optional YARA rules upload - stored next to the email.
            yara_path = None
            yara = fields.get("yara_rules")
            if yara and yara.get("filename"):
                yname = sanitize_filename(yara["filename"])
                if yname.lower().endswith((".yar", ".yara")) and \
                        yara["end"] > yara["start"]:
                    yara_path = os.path.join(adir, yname)
                    copy_part(body_path, yara, yara_path)

            options = {"skip_intel": flag("skip_intel"),
                       "skip_whois": flag("skip_whois"),
                       "ai": flag("ai"), "ai_body": flag("ai_body"),
                       "ai_images": flag("ai_images"),
                       "share_urls": flag("share_urls"),
                       "yara_rules": yara_path}

            with db() as conn:
                conn.execute(
                    "INSERT INTO analyses (id, filename, created_utc, status, "
                    "created_by) VALUES (?,?,?,?,?)",
                    (analysis_id, fname,
                     dt.datetime.now(dt.timezone.utc).isoformat(), "running",
                     getattr(self, "_uploader", None)))

            threading.Thread(target=run_analysis,
                             args=(analysis_id, email_path, options),
                             daemon=True).start()
        except BaseException:
            _slots.release()
            raise
        self._json({"id": analysis_id})
        return True

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
            row = conn.execute(
                "SELECT COUNT(*) c FROM analyses WHERE ai_agrees = 0"
            ).fetchone()
            counts["ai_disagreements"] = row["c"] if row else 0
            recent = [dict(r) for r in conn.execute(
                "SELECT id, filename, created_utc, status, verdict, score, "
                "confidence, ai_verdict, ai_confidence, ai_agrees, created_by "
                "FROM analyses ORDER BY created_utc DESC LIMIT 8")]
        return self._json({"counts": counts,
                           "recent": self._mask_rows(recent)})

    def _mask_rows(self, rows):
        """Hide other people's upload filenames from read-only users.

        Input : list of analysis row dicts (with "filename", "created_by").
        Output: the same list. For a read-only user, rows uploaded by
                someone else get filename "email-<first 8 id chars>" -
                file names often repeat the email subject, which that role
                must not see. Admins get every row unchanged.
        """
        user = self._user() or {}
        if user.get("role") == "admin":
            return rows
        me = (user.get("username") or "").lower()
        for r in rows:
            if (r.get("created_by") or "").lower() != me:
                r["filename"] = "email-" + r["id"][:8]
        return rows

    def api_analyses(self, q):
        """History listing with optional filters.

        Query params: verdict=malicious|suspicious|clean|error|running
                      q=<substring of filename, or id prefix>   limit=<n, default 200>
                      (read-only users: filename search covers own uploads)
        """
        clauses, params = [], []
        verdict = (q.get("verdict") or [""])[0]
        if verdict in ("malicious", "suspicious", "clean"):
            clauses.append("verdict = ?"); params.append(verdict)
        elif verdict in ("error", "running"):
            clauses.append("status = ?"); params.append(verdict)
        if verdict == "disagree":
            # The most useful filter in the product: every run where the AI
            # reached a different conclusion from the rules.
            clauses.append("ai_agrees = 0")
        needle = (q.get("q") or [""])[0].strip()
        if needle:
            user = self._user() or {}
            if user.get("role") == "admin":
                clauses.append("(filename LIKE ? OR id LIKE ?)")
                params += [f"%{needle}%", f"{needle.lower()}%"]
            else:
                # Read-only: the filename search covers only your own
                # uploads, so it cannot be used to probe hidden names.
                clauses.append("((filename LIKE ? AND lower(created_by) = ?)"
                               " OR id LIKE ?)")
                params += [f"%{needle}%", (user.get("username") or "").lower(),
                           f"{needle.lower()}%"]
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        try:
            limit = int((q.get("limit") or ["200"])[0] or 200)
        except ValueError:
            limit = 200
        limit = max(1, min(limit, 1000))
        with db() as conn:
            items = [dict(r) for r in conn.execute(
                f"SELECT id, filename, created_utc, status, verdict, score, "
                f"confidence, ai_verdict, ai_confidence, ai_agrees, created_by "
                f"FROM analyses {where} "
                f"ORDER BY created_utc DESC LIMIT ?", params + [limit])]
        return self._json({"items": self._mask_rows(items)})


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a cap on concurrent connections.

    Each connection normally gets its own thread with no upper bound, so a
    client opening thousands of idle sockets could exhaust threads and
    memory. Above MAX_CONNECTIONS a connection receives "503 Service
    Unavailable" and is closed immediately; idle connections are dropped
    after READ_TIMEOUT by the handler's socket timeout.
    """
    daemon_threads = True

    def process_request(self, request, client_address):
        if not _conn_slots.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\n"
                                b"Content-Length: 0\r\n"
                                b"Connection: close\r\n\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            _conn_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            _conn_slots.release()


def build_allowed_hosts(bind_host, port, extra):
    """
    Input : bind_host (--host), port (--port), extra (--allow-host values,
            "name" or "name:port").
    Output: set of lowercase Host header values to accept.
    Rules : loopback names (127.0.0.1, localhost, [::1]) and a specific bind
            address are accepted as "name:port" (plus the bare name when the
            port is 80/443, where browsers omit it). An --allow-host value is
            accepted exactly as given and, without a port, also as
            "name:port" - covering reverse proxies that keep or rewrite the
            port. A wildcard bind (0.0.0.0 / ::) adds no names by itself.
    """
    def norm(h):
        h = h.strip().lower()
        if ":" in h and not h.startswith("[") and h.count(":") > 1:
            h = f"[{h}]"                     # bare IPv6 -> bracketed form
        return h

    names = {"127.0.0.1", "localhost", "[::1]"}
    if bind_host not in ("0.0.0.0", "::", ""):
        names.add(norm(bind_host))
    out = set()
    for n in names:
        out.add(f"{n}:{port}")
        if port in (80, 443):
            out.add(n)
    for h in extra or []:
        h = norm(h)
        if not h:
            continue
        out.add(h)
        has_port = h.rsplit(":", 1)[-1].isdigit() and not h.endswith("]")
        if not has_port:
            out.add(f"{h}:{port}")
    return out


def main():
    global SKILLS_ROOT, ALLOWED_HOSTS, MAX_PARALLEL, _slots, \
        STAGE_TIMEOUT, ANALYSIS_TIMEOUT, MAX_EMAIL_MB, READ_TIMEOUT, \
        UPLOAD_TIMEOUT, MAX_CONNECTIONS, _conn_slots, MAX_MEMORY_MB, \
        MAX_CPU_SECONDS, SECURE_COOKIES, BEHIND_PROXY
    ap = argparse.ArgumentParser(description="phishHunter Web UI")
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address (default 127.0.0.1). Binding beyond "
                         "loopback requires --tls-cert/--tls-key or "
                         "--behind-proxy, so passwords never cross the "
                         "network in clear text.")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--skills-root",
                    help="directory containing the skill folders "
                         "(default: <repo>/skills)")
    ap.add_argument("--config",
                    help="private API-key config file (default: the "
                         "per-user location or $PHISHHUNTER_CONFIG)")
    ap.add_argument("--no-config", action="store_true",
                    help="do not read the config file")
    ap.add_argument("--allow-host", action="append", default=[],
                    metavar="NAME[:PORT]",
                    help="extra Host header value to accept, e.g. the "
                         "name of an authenticated reverse proxy "
                         "(repeatable). Loopback names are always allowed.")
    ap.add_argument("--max-parallel", type=int, default=2,
                    help="maximum concurrent analyses (default 2)")
    ap.add_argument("--stage-timeout", type=int, default=300,
                    help="per-stage pipeline timeout in seconds "
                         "(default 300)")
    ap.add_argument("--analysis-timeout", type=int, default=3600,
                    help="hard limit for one analysis in seconds "
                         "(default 3600)")
    ap.add_argument("--max-email-mb", type=int, default=50,
                    help="largest email accepted, in MB (default 50)")
    ap.add_argument("--read-timeout", type=int, default=30,
                    help="seconds a connection may stay silent before it "
                         "is dropped (default 30)")
    ap.add_argument("--upload-timeout", type=int, default=120,
                    help="total seconds allowed to receive one upload "
                         "(default 120)")
    ap.add_argument("--max-connections", type=int, default=64,
                    help="concurrent connections; extra ones get HTTP 503 "
                         "(default 64)")
    ap.add_argument("--max-memory-mb", type=int, default=4096,
                    help="memory limit per analysis process in MB, 0 = none "
                         "(default 4096; POSIX only)")
    ap.add_argument("--tls-cert", metavar="PEM",
                    help="serve HTTPS with this certificate (with --tls-key)")
    ap.add_argument("--tls-key", metavar="PEM",
                    help="private key for --tls-cert")
    ap.add_argument("--behind-proxy", action="store_true",
                    help="a TLS-terminating reverse proxy is in front: mark "
                         "cookies Secure and take the client address from "
                         "X-Forwarded-For (for login lockout)")
    ap.add_argument("--reset-admin", action="store_true",
                    help="give the 'admin' account a new one-time password "
                         "(re-enabling it if needed), print it and exit")
    args = ap.parse_args()

    if args.reset_admin:
        os.umask(0o077)
        init_db()
        with db() as conn:
            pw = auth.reset_admin(conn)
        print("The 'admin' account has a new one-time password:\n\n"
              f"    {pw}\n\nIt must be changed at the next login.")
        return

    loopback = args.host in ("127.0.0.1", "localhost", "::1")
    if bool(args.tls_cert) != bool(args.tls_key):
        print("error: --tls-cert and --tls-key go together", file=sys.stderr)
        sys.exit(2)
    if not loopback and not (args.tls_cert or args.behind_proxy):
        print("error: refusing to listen on a network address without "
              "encryption - passwords would travel in clear text. Use "
              "--tls-cert/--tls-key, or --behind-proxy behind a TLS reverse "
              "proxy.", file=sys.stderr)
        sys.exit(2)
    SECURE_COOKIES = bool(args.tls_cert) or args.behind_proxy
    BEHIND_PROXY = args.behind_proxy

    # Everything the console writes (uploads, reports, logs, the index -
    # and the pipeline it starts) is created private to this user.
    os.umask(0o077)
    ALLOWED_HOSTS = build_allowed_hosts(args.host, args.port,
                                        args.allow_host)
    MAX_PARALLEL = max(1, args.max_parallel)
    _slots = threading.BoundedSemaphore(MAX_PARALLEL)
    STAGE_TIMEOUT = max(30, args.stage_timeout)
    ANALYSIS_TIMEOUT = max(STAGE_TIMEOUT, args.analysis_timeout)
    MAX_EMAIL_MB = max(1, args.max_email_mb)
    READ_TIMEOUT = max(1, args.read_timeout)
    UPLOAD_TIMEOUT = max(READ_TIMEOUT, args.upload_timeout)
    MAX_CONNECTIONS = max(4, args.max_connections)
    _conn_slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
    MAX_MEMORY_MB = max(0, args.max_memory_mb)
    MAX_CPU_SECONDS = ANALYSIS_TIMEOUT
    # Every connection's socket gets this timeout: silent clients (idle
    # sockets, stalled headers or bodies) are dropped instead of holding a
    # thread forever.
    Handler.timeout = READ_TIMEOUT
    if args.skills_root:
        SKILLS_ROOT = os.path.abspath(args.skills_root)

    # API keys: load the private config once; every analysis subprocess
    # inherits them. Shell variables win; only NAMES are printed. An unsafe
    # file is refused and the server does not start.
    cfg_line = "not loaded (--no-config)"
    if not args.no_config:
        sys.path.insert(0, os.path.dirname(PIPELINE))
        import phishhunter_config as phc  # shared, next to the pipeline
        cfg = phc.load(args.config)
        if cfg["error"]:
            print(f"error: {cfg['error']}", file=sys.stderr)
            sys.exit(2)
        if args.config and not cfg["found"]:
            print(f"error: config file not found: {cfg['path']}",
                  file=sys.stderr)
            sys.exit(2)
        cfg_line = (f"{cfg['path']} ({len(cfg['loaded'])} key(s) loaded)"
                    if cfg["found"] else
                    "none (add keys: python3 easy_install.py --keys)")
    keys = [k for k in ("VT_API_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY",
                        "URLSCAN_API_KEY", "HYBRID_ANALYSIS_API_KEY",
                        "ANTHROPIC_API_KEY")
            if os.environ.get(k, "").strip()]

    if not os.path.isfile(PIPELINE):
        print(f"error: pipeline not found at {PIPELINE}", file=sys.stderr)
        sys.exit(1)
    admin_password = init_db()
    server = BoundedThreadingHTTPServer((args.host, args.port), Handler)
    scheme = "http"
    if args.tls_cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(args.tls_cert, args.tls_key)
        # Handshake in the connection's own thread (with its read timeout),
        # so a client that never completes it cannot block new connections.
        server.socket = ctx.wrap_socket(server.socket, server_side=True,
                                        do_handshake_on_connect=False)
        scheme = "https"
    threading.Thread(target=retention_loop, daemon=True).start()
    print(f"phishHunter Web UI  →  {scheme}://{args.host}:{args.port}")
    print(f"  skills root : {SKILLS_ROOT}")
    print(f"  data dir    : {DATA_DIR}  (private: 700/600)")
    print(f"  accepts Host: {', '.join(sorted(ALLOWED_HOSTS))}")
    if not loopback:
        print("  listening beyond loopback: login required, cookies Secure; "
              "pass the public host name with --allow-host", file=sys.stderr)
    print(f"  key config  : {cfg_line}")
    print(f"  API keys    : {', '.join(keys) if keys else 'none set'}")
    if admin_password:
        print("\n  First start: an 'admin' account was created.\n"
              f"  One-time password:  {admin_password}\n"
              "  Log in and choose a new password. This is shown only "
              "once;\n  if lost, run: python3 webui/app.py --reset-admin\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
