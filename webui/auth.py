"""
auth.py - local users, sessions, lockout, settings and audit trail for the
phishHunter web console. Standard library only.

Purpose:
    The console has two roles:
      admin     - everything: analyses, full reports, settings, users,
                  deleting data, the audit trail
      readonly  - starts analyses and reads reports with the email content
                  removed (see redact.py); no settings, no deletion
    Users live in the console's SQLite database (webui/data/phishhunter.db,
    private to the OS user running the console).

Security properties:
    * Passwords: scrypt (n=2**14, r=8, p=1) with a 16-byte random salt;
      PBKDF2-HMAC-SHA256 with 600,000 iterations where scrypt is missing.
      Verification uses hmac.compare_digest. Minimum length 10.
    * Sessions: 32-byte random token in an HttpOnly, SameSite=Strict cookie
      (Secure behind TLS). Only the SHA-256 of the token is stored, so a
      leaked database does not reveal live sessions. Idle timeout 30 min,
      absolute lifetime 12 h, deleted on logout, password change and user
      changes.
    * Brute force: 5 failed logins for a username or a client address within
      15 minutes lock that username / address for 15 minutes. The login
      error never says which part was wrong.
    * First start: if there are no users, an "admin" account is created with
      a random one-time password that is printed once to the console; it
      must be changed at the first login. `python3 webui/app.py
      --reset-admin` repeats this for a forgotten password.
    * Audit: logins, password and user changes, settings changes and
      deletions are recorded with who did them.

Inputs / outputs:
    Every function takes an open sqlite3 connection (row_factory = Row) and
    returns plain values or dicts; nothing here touches HTTP.
"""

import base64
import hashlib
import hmac
import secrets
import time

ROLES = ("admin", "readonly")
MIN_PASSWORD = 10
IDLE_TIMEOUT = 30 * 60          # seconds without activity
SESSION_LIFETIME = 12 * 3600     # absolute
LOCK_THRESHOLD = 5
LOCK_WINDOW = 15 * 60
LOCK_DURATION = 15 * 60

DEFAULT_SETTINGS = {
    "retention_days": "30",              # 0 = keep forever
    "delete_original_after_analysis": "0",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    username       TEXT NOT NULL UNIQUE COLLATE NOCASE,
    pw_hash        TEXT NOT NULL,
    role           TEXT NOT NULL CHECK (role IN ('admin', 'readonly')),
    must_change    INTEGER NOT NULL DEFAULT 1,
    disabled       INTEGER NOT NULL DEFAULT 0,
    created_utc    TEXT NOT NULL,
    last_login_utc TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    created    REAL NOT NULL,
    last_seen  REAL NOT NULL,
    ip         TEXT
);
CREATE TABLE IF NOT EXISTS login_failures (
    key          TEXT PRIMARY KEY,
    count        INTEGER NOT NULL,
    first        REAL NOT NULL,
    locked_until REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_utc   TEXT NOT NULL,
    username TEXT,
    action   TEXT NOT NULL,
    detail   TEXT
);
"""


def _now_utc():
    """Output: current UTC time as an ISO-8601 string (seconds)."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def init_schema(conn):
    """Create the auth tables and default settings if they are missing."""
    conn.executescript(SCHEMA)
    for key, value in DEFAULT_SETTINGS.items():
        conn.execute("INSERT OR IGNORE INTO settings (key, value) "
                     "VALUES (?, ?)", (key, value))


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------
def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def hash_password(password):
    """
    Input:  plaintext password.
    Output: self-describing hash string:
              scrypt$16384$8$1$<salt>$<hash>
              pbkdf2_sha256$600000$<salt>$<hash>   (no scrypt available)
    """
    salt = secrets.token_bytes(16)
    pw = password.encode("utf-8")
    if hasattr(hashlib, "scrypt"):
        dk = hashlib.scrypt(pw, salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
        return f"scrypt$16384$8$1${_b64(salt)}${_b64(dk)}"
    dk = hashlib.pbkdf2_hmac("sha256", pw, salt, 600000)
    return f"pbkdf2_sha256$600000${_b64(salt)}${_b64(dk)}"


def verify_password(password, stored):
    """
    Input:  plaintext password, stored hash string.
    Output: True when they match (constant-time comparison).
    """
    try:
        parts = stored.split("$")
        pw = password.encode("utf-8")
        if parts[0] == "scrypt":
            n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
            salt, want = base64.b64decode(parts[4]), base64.b64decode(parts[5])
            got = hashlib.scrypt(pw, salt=salt, n=n, r=r, p=p,
                                 dklen=len(want))
        elif parts[0] == "pbkdf2_sha256":
            salt, want = base64.b64decode(parts[2]), base64.b64decode(parts[3])
            got = hashlib.pbkdf2_hmac("sha256", pw, salt, int(parts[1]))
        else:
            return False
        return hmac.compare_digest(got, want)
    except (ValueError, IndexError):
        return False


# A valid hash of a random value, so that an unknown username costs the
# same time as a wrong password (no username enumeration by timing).
_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def password_problem(password):
    """Input: proposed password. Output: error text, or None if acceptable."""
    if len(password or "") < MIN_PASSWORD:
        return f"password must be at least {MIN_PASSWORD} characters"
    if len(password) > 256:
        return "password is too long"
    return None


def temp_password():
    """Output: a random one-time password (about 96 bits)."""
    return secrets.token_urlsafe(12)


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
def _valid_username(name):
    return bool(name) and len(name) <= 64 and all(
        c.isalnum() or c in "._-@" for c in name)


def list_users(conn):
    """Output: list of user dicts (never the password hash)."""
    return [dict(r) for r in conn.execute(
        "SELECT id, username, role, must_change, disabled, created_utc, "
        "last_login_utc FROM users ORDER BY username")]


def get_user(conn, user_id):
    """Output: user row dict or None."""
    row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return dict(row) if row else None


def create_user(conn, username, role, password=None, must_change=True):
    """
    Input:  username, role ("admin"/"readonly"), optional password.
    Output: (user_id, password_used). When no password is given a temporary
            one is generated and must be changed at first login.
    Raises: ValueError with a user-facing message.
    """
    username = (username or "").strip()
    if not _valid_username(username):
        raise ValueError("username: 1-64 letters, digits or . _ - @")
    if role not in ROLES:
        raise ValueError("role must be admin or readonly")
    if conn.execute("SELECT 1 FROM users WHERE username=?",
                    (username,)).fetchone():
        raise ValueError("a user with this name already exists")
    if password is None:
        password = temp_password()
    else:
        problem = password_problem(password)
        if problem:
            raise ValueError(problem)
    cur = conn.execute(
        "INSERT INTO users (username, pw_hash, role, must_change, disabled, "
        "created_utc) VALUES (?, ?, ?, ?, 0, ?)",
        (username, hash_password(password), role, int(must_change),
         _now_utc()))
    return cur.lastrowid, password


def _active_admins(conn, excluding=None):
    return conn.execute(
        "SELECT COUNT(*) c FROM users WHERE role='admin' AND disabled=0 "
        "AND id != ?", (excluding or -1,)).fetchone()["c"]


def update_user(conn, user_id, action, role=None):
    """
    Apply an admin action to a user.

    Input:  action - "role" (with role), "reset", "disable", "enable",
                     "delete"
    Output: dict; for "reset" it contains the new temporary password.
    Raises: ValueError for invalid actions or when the change would leave
            no active admin.
    Sessions of the user are ended for every action except "enable".
    """
    user = get_user(conn, user_id)
    if not user:
        raise ValueError("user not found")
    is_last_admin = (user["role"] == "admin" and not user["disabled"]
                     and _active_admins(conn, excluding=user_id) == 0)
    result = {"username": user["username"]}
    if action == "role":
        if role not in ROLES:
            raise ValueError("role must be admin or readonly")
        if is_last_admin and role != "admin":
            raise ValueError("the last active admin cannot be demoted")
        conn.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))
    elif action == "reset":
        pw = temp_password()
        conn.execute("UPDATE users SET pw_hash=?, must_change=1 WHERE id=?",
                     (hash_password(pw), user_id))
        # A reset by an admin also lifts the account's login lockout.
        conn.execute("DELETE FROM login_failures WHERE key=?",
                     (f"user:{user['username'].lower()}",))
        result["temporary_password"] = pw
    elif action == "disable":
        if is_last_admin:
            raise ValueError("the last active admin cannot be disabled")
        conn.execute("UPDATE users SET disabled=1 WHERE id=?", (user_id,))
    elif action == "enable":
        conn.execute("UPDATE users SET disabled=0 WHERE id=?", (user_id,))
    elif action == "delete":
        if is_last_admin:
            raise ValueError("the last active admin cannot be deleted")
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    else:
        raise ValueError("unknown action")
    if action != "enable":
        conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
    return result


def change_password(conn, user_id, current, new, keep_token_hash=None):
    """
    Input:  user_id, current and new password, the caller's session token
            hash (kept; every other session of the user is ended).
    Raises: ValueError("current password is wrong" / policy text).
    """
    user = get_user(conn, user_id)
    if not user or not verify_password(current or "", user["pw_hash"]):
        raise ValueError("current password is wrong")
    problem = password_problem(new)
    if problem:
        raise ValueError(problem)
    if verify_password(new, user["pw_hash"]):
        raise ValueError("choose a password different from the current one")
    conn.execute("UPDATE users SET pw_hash=?, must_change=0 WHERE id=?",
                 (hash_password(new), user_id))
    conn.execute("DELETE FROM sessions WHERE user_id=? AND token_hash != ?",
                 (user_id, keep_token_hash or ""))


def ensure_admin(conn):
    """
    First start: create "admin" with a one-time password if no user exists.

    Output: the temporary password when an account was created, else None.
    """
    if conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]:
        return None
    _, pw = create_user(conn, "admin", "admin")
    audit(conn, "system", "bootstrap_admin", "first start")
    return pw


def reset_admin(conn):
    """
    Forgotten password: give "admin" a new one-time password, enable it and
    make it an admin again (creating it if needed). Clears all login
    lockouts.

    Output: the new temporary password.
    """
    row = conn.execute("SELECT id FROM users WHERE username='admin'"
                       ).fetchone()
    pw = temp_password()
    if row:
        conn.execute("UPDATE users SET pw_hash=?, must_change=1, disabled=0, "
                     "role='admin' WHERE id=?", (hash_password(pw), row["id"]))
        conn.execute("DELETE FROM sessions WHERE user_id=?", (row["id"],))
    else:
        create_user(conn, "admin", "admin", password=pw)
    # The operator is at the server console: lift every login lockout too,
    # so an attacker who deliberately locked "admin" cannot keep it locked.
    conn.execute("DELETE FROM login_failures")
    audit(conn, "system", "reset_admin", "from the command line")
    return pw


# ---------------------------------------------------------------------------
# Login, lockout, sessions
# ---------------------------------------------------------------------------
def _locked(conn, key, now):
    row = conn.execute("SELECT locked_until FROM login_failures WHERE key=?",
                       (key,)).fetchone()
    return bool(row and row["locked_until"] > now)


def _record_failure(conn, key, now):
    row = conn.execute("SELECT * FROM login_failures WHERE key=?",
                       (key,)).fetchone()
    if not row or now - row["first"] > LOCK_WINDOW:
        conn.execute("INSERT OR REPLACE INTO login_failures "
                     "(key, count, first, locked_until) VALUES (?, 1, ?, 0)",
                     (key, now))
        return
    count = row["count"] + 1
    locked = now + LOCK_DURATION if count >= LOCK_THRESHOLD else 0
    conn.execute("UPDATE login_failures SET count=?, locked_until=? "
                 "WHERE key=?", (count, locked, key))


def login(conn, username, password, ip):
    """
    Check credentials and open a session.

    Input:  username, password, client address.
    Output: (token, user_dict) on success.
    Raises: ValueError with a generic message on any failure:
            "invalid username or password" or "too many failed attempts".
    """
    now = time.time()
    uname = (username or "").strip().lower()
    keys = (f"user:{uname}", f"ip:{ip}")
    if any(_locked(conn, k, now) for k in keys):
        audit(conn, uname or "?", "login_locked", f"from {ip}")
        raise ValueError("too many failed attempts - try again later")
    row = conn.execute("SELECT * FROM users WHERE username=?",
                       (uname,)).fetchone()
    ok = verify_password(password or "",
                         row["pw_hash"] if row else _DUMMY_HASH)
    if not row or not ok or row["disabled"]:
        for k in keys:
            _record_failure(conn, k, now)
        audit(conn, uname or "?", "login_failed", f"from {ip}")
        raise ValueError("invalid username or password")
    for k in keys:
        conn.execute("DELETE FROM login_failures WHERE key=?", (k,))
    token = secrets.token_urlsafe(32)
    conn.execute("INSERT INTO sessions (token_hash, user_id, created, "
                 "last_seen, ip) VALUES (?, ?, ?, ?, ?)",
                 (token_hash(token), row["id"], now, now, ip))
    conn.execute("UPDATE users SET last_login_utc=? WHERE id=?",
                 (_now_utc(), row["id"]))
    audit(conn, row["username"], "login_ok", f"from {ip}")
    return token, dict(row)


def token_hash(token):
    """Input: session token. Output: its SHA-256 hex digest (stored form)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def session_user(conn, token):
    """
    Resolve a session cookie.

    Input:  token from the cookie (may be None).
    Output: user dict with "token_hash" added, or None when the session is
            unknown, expired (idle or absolute) or the user is disabled.
            A valid session's last_seen is refreshed.
    """
    if not token or len(token) > 100:
        return None
    th = token_hash(token)
    row = conn.execute(
        "SELECT s.created, s.last_seen, u.* FROM sessions s JOIN users u "
        "ON u.id = s.user_id WHERE s.token_hash=?", (th,)).fetchone()
    now = time.time()
    if not row:
        return None
    if (now - row["last_seen"] > IDLE_TIMEOUT
            or now - row["created"] > SESSION_LIFETIME or row["disabled"]):
        conn.execute("DELETE FROM sessions WHERE token_hash=?", (th,))
        return None
    conn.execute("UPDATE sessions SET last_seen=? WHERE token_hash=?",
                 (now, th))
    user = dict(row)
    user["token_hash"] = th
    return user


def logout(conn, token_hash_value):
    """End one session (input: its stored token hash)."""
    conn.execute("DELETE FROM sessions WHERE token_hash=?",
                 (token_hash_value,))


def cleanup(conn):
    """Remove expired sessions, old lockout rows and year-old audit rows."""
    now = time.time()
    conn.execute("DELETE FROM sessions WHERE last_seen < ? OR created < ?",
                 (now - IDLE_TIMEOUT, now - SESSION_LIFETIME))
    conn.execute("DELETE FROM login_failures WHERE first < ? AND "
                 "locked_until < ?", (now - LOCK_WINDOW, now))
    conn.execute("DELETE FROM audit WHERE ts_utc < ?",
                 (time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                time.gmtime(now - 365 * 86400)),))


# ---------------------------------------------------------------------------
# Settings and audit
# ---------------------------------------------------------------------------
def get_settings(conn):
    """Output: dict of all settings (strings)."""
    out = dict(DEFAULT_SETTINGS)
    out.update({r["key"]: r["value"]
                for r in conn.execute("SELECT key, value FROM settings")})
    return out


def set_settings(conn, values):
    """
    Input:  {"retention_days": int 0-3650,
             "delete_original_after_analysis": bool}
    Output: the stored settings. Raises ValueError for invalid input.
    """
    days = values.get("retention_days")
    if days is not None:
        try:
            days = int(days)
        except (TypeError, ValueError):
            raise ValueError("retention_days must be a whole number") \
                from None
        if not 0 <= days <= 3650:
            raise ValueError("retention_days must be between 0 and 3650")
        conn.execute("UPDATE settings SET value=? WHERE key=?",
                     (str(days), "retention_days"))
    if "delete_original_after_analysis" in values:
        conn.execute("UPDATE settings SET value=? WHERE key=?",
                     ("1" if values["delete_original_after_analysis"] else "0",
                      "delete_original_after_analysis"))
    return get_settings(conn)


def audit(conn, username, action, detail=""):
    """Append one audit record (who, what, detail)."""
    conn.execute("INSERT INTO audit (ts_utc, username, action, detail) "
                 "VALUES (?, ?, ?, ?)",
                 (_now_utc(), username, action, (detail or "")[:300]))


def recent_audit(conn, limit=100):
    """Output: the newest audit records, newest first."""
    return [dict(r) for r in conn.execute(
        "SELECT ts_utc, username, action, detail FROM audit "
        "ORDER BY id DESC LIMIT ?", (limit,))]
