#!/usr/bin/env python3
"""
phishhunter_config.py - secure per-user configuration file for API keys.

Purpose:
    One private file holds every API key phishHunter can use, so nothing
    has to be exported in each terminal. Shared by:
      * phishhunter.py      (launcher: install / config / analyze / web ...)
      * triage_pipeline.py  (CLI works without the launcher)
      * webui/app.py        (console picks keys up at start-up)
    It is ONE module imported by path - not a duplicated copy.

Where the file lives (OUTSIDE the repository on purpose, so it can never be
committed, zipped together with the code, or lost on a fresh clone):
    Linux / macOS : $XDG_CONFIG_HOME/phishhunter/config.ini
                    (default ~/.config/phishhunter/config.ini)
    Windows       : %APPDATA%\\phishhunter\\config.ini
    Override      : --config PATH  or  $PHISHHUNTER_CONFIG

File format (INI, no interpolation - "%" and "$" are literal):
    [intel]
    virustotal      = ...     -> VT_API_KEY
    abuseipdb       = ...     -> ABUSEIPDB_API_KEY
    otx             = ...     -> OTX_API_KEY
    urlscan         = ...     -> URLSCAN_API_KEY
    hybrid_analysis = ...     -> HYBRID_ANALYSIS_API_KEY
    [ai]
    anthropic       = ...     -> ANTHROPIC_API_KEY
    base_url        = ...     -> ANTHROPIC_BASE_URL (optional gateway)
    Empty values are ignored (the source is simply skipped).

Security properties:
    * Created atomically with mode 0600 inside a 0700 directory
      (os.open O_CREAT|O_EXCL - no window where it is world-readable).
    * Refused on POSIX (like OpenSSH does with private keys) when:
        - group or others have ANY permission on the file, or
        - the file is not owned by the current user, or
        - the directory is writable by group/others.
      The error names the exact fix (chmod 600 ... / `config fix-perms`).
    * Values are NEVER printed, logged or returned in reports - only the
      variable NAMES and where they came from.
    * `set` reads the value with getpass (hidden input: not echoed, not in
      shell history) and rewrites the file atomically (temp file 0600 +
      os.replace), keeping every comment line intact.
    * Never overrides a variable already exported in the shell: an explicit
      `export` always wins (handy for one-off overrides and CI secrets).
    * No encryption: a key stored on the same machine would protect nothing
      against an attacker who can already read your home directory, and a
      passphrase prompt on every run would defeat the purpose. Rely on file
      permissions, full-disk encryption, or a future OS-keychain backend.
    * Windows: per-user %APPDATA% is protected by the profile ACL; POSIX
      mode bits are not checked there.

CLI (the launcher wraps these; output never contains values):
    python3 phishhunter_config.py path            # print the file location
    python3 phishhunter_config.py init            # create the template
    python3 phishhunter_config.py set virustotal  # hidden prompt, saves it
    python3 phishhunter_config.py unset virustotal
    python3 phishhunter_config.py show            # names: set / empty
    python3 phishhunter_config.py fix-perms       # chmod 700 dir, 600 file
    Exit codes: 0 ok, 1 error (message on stderr), 2 refused (permissions)
"""

import configparser
import getpass
import os
import stat
import sys
import tempfile

APP = "phishhunter"
POINTER_ENV = "PHISHHUNTER_CONFIG"

# (section, option) -> environment variable consumed by the tools.
KEY_MAP = [
    ("intel", "virustotal", "VT_API_KEY",
     "VirusTotal - https://www.virustotal.com/gui/my-apikey"),
    ("intel", "abuseipdb", "ABUSEIPDB_API_KEY",
     "AbuseIPDB - https://www.abuseipdb.com/account/api"),
    ("intel", "otx", "OTX_API_KEY",
     "AlienVault OTX - https://otx.alienvault.com/api"),
    ("intel", "urlscan", "URLSCAN_API_KEY",
     "urlscan.io - https://urlscan.io/user/profile/"),
    ("intel", "hybrid_analysis", "HYBRID_ANALYSIS_API_KEY",
     "Hybrid Analysis - https://www.hybrid-analysis.com/apikeys"),
    ("ai", "anthropic", "ANTHROPIC_API_KEY",
     "Anthropic - https://console.anthropic.com/ (only for --ai stages)"),
    ("ai", "base_url", "ANTHROPIC_BASE_URL",
     "optional Anthropic-compatible gateway URL"),
]


class ConfigError(Exception):
    """Raised for unreadable / unsafe config files. exit_code 1 or 2."""

    def __init__(self, msg, exit_code=1):
        super().__init__(msg)
        self.exit_code = exit_code


# ---------------------------------------------------------------------------
# Location
# ---------------------------------------------------------------------------
def default_path():
    """
    Output: the per-user config path for this OS (see module docstring).
            The file does not have to exist.
    """
    if os.name == "nt":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
    else:
        base = (os.environ.get("XDG_CONFIG_HOME")
                or os.path.join(os.path.expanduser("~"), ".config"))
    return os.path.join(base, APP, "config.ini")


def resolve_path(explicit=None):
    """
    Input:  explicit - path from --config, or None.
    Output: absolute path: explicit > $PHISHHUNTER_CONFIG > default_path().
    """
    p = explicit or os.environ.get(POINTER_ENV, "").strip() or default_path()
    return os.path.abspath(os.path.expanduser(p))


def lookup(name):
    """
    Map a user-supplied key name to its KEY_MAP entry.

    Input:  "virustotal", "intel.virustotal" or "VT_API_KEY" (any case).
    Output: (section, option, env_var, help) or None.
    """
    n = name.strip().lower()
    for sec, opt, env, hlp in KEY_MAP:
        if n in (opt, f"{sec}.{opt}", env.lower()):
            return sec, opt, env, hlp
    return None


# ---------------------------------------------------------------------------
# Permission checks
# ---------------------------------------------------------------------------
def permission_problems(path):
    """
    Check that the file (and its directory) are private to the user.

    Input:  path to the config file.
    Output: list of problem strings ([] = safe). Always [] on Windows.
    """
    if os.name != "posix" or not os.path.exists(path):
        return []
    problems = []
    st = os.stat(path)
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        problems.append(f"{path} is owned by uid {st.st_uid}, not by you")
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        problems.append(f"{path} has mode {stat.S_IMODE(st.st_mode):o}; "
                        f"other users can access it")
    d = os.path.dirname(path)
    dmode = os.stat(d).st_mode
    if dmode & (stat.S_IWGRP | stat.S_IWOTH):
        problems.append(f"{d} is writable by other users (the file could "
                        f"be replaced)")
    return problems


def fix_permissions(path):
    """
    Input:  config path. Output: None. chmod 700 dir, 600 file (POSIX).
    """
    if os.name != "posix":
        return
    d = os.path.dirname(path)
    if os.path.isdir(d):
        os.chmod(d, 0o700)
    if os.path.isfile(path):
        os.chmod(path, 0o600)


# ---------------------------------------------------------------------------
# Template / creation
# ---------------------------------------------------------------------------
def template_text():
    """Output: the commented template written by init()."""
    lines = [
        "# phishHunter - private API key configuration",
        "#",
        "# Fill in only the keys you have; empty values are ignored and the",
        "# matching source is skipped. Easiest (hidden input, not saved in",
        "# shell history):   python3 phishhunter.py config set virustotal",
        "#",
        "# This file must stay private (mode 600). phishHunter refuses to",
        "# load it otherwise. Variables exported in your shell win over it.",
        "# Values are taken literally (no quotes needed, no % or $ expansion).",
        "",
    ]
    current = None
    for sec, opt, env, hlp in KEY_MAP:
        if sec != current:
            if current is not None:
                lines.append("")
            lines.append(f"[{sec}]")
            current = sec
        lines.append(f"# {hlp}  (sets {env})")
        lines.append(f"{opt} =")
    return "\n".join(lines) + "\n"


def init(path):
    """
    Create the config file from the template if it does not exist.

    Input:  path. Output: True when created, False when it already existed.
    The directory is created 0700; the file is created 0600 atomically.
    """
    d = os.path.dirname(path)
    os.makedirs(d, mode=0o700, exist_ok=True)
    if os.path.exists(path):
        return False
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(template_text())
    fix_permissions(path)
    return True


# ---------------------------------------------------------------------------
# Reading / loading
# ---------------------------------------------------------------------------
def read_values(path, check_permissions=True):
    """
    Parse the config file.

    Input:  path; check_permissions - refuse unsafe files (default True).
    Output: dict env_var -> value for every NON-empty known key.
    Raises: ConfigError(exit_code=2) for unsafe permissions,
            ConfigError(exit_code=1) for unreadable / malformed files.
    Unknown sections/options are ignored (forward compatible).
    """
    if check_permissions:
        problems = permission_problems(path)
        if problems:
            raise ConfigError(
                "refusing to load API keys: " + "; ".join(problems)
                + f". Fix: chmod 700 {os.path.dirname(path)} && chmod 600 "
                  f"{path}   (or: python3 phishhunter.py config fix-perms)",
                exit_code=2)
    cp = configparser.ConfigParser(interpolation=None)
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            cp.read_file(fh)
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"cannot read {path}: {exc.__class__.__name__}") from None
    except configparser.Error as exc:
        # The parser message can echo a line; keep only its type + line no.
        line = getattr(exc, "lineno", None)
        raise ConfigError(f"{path} is malformed ({exc.__class__.__name__}"
                          + (f" near line {line}" if line else "") + ")") from None
    out = {}
    for sec, opt, env, _ in KEY_MAP:
        if cp.has_option(sec, opt):
            val = cp.get(sec, opt).strip()
            if val:
                out[env] = val
    return out


def load(path=None, override=False):
    """
    Load the config into os.environ.

    Input:  path - explicit file (None -> resolve_path()); override - also
            replace variables already set (default False: shell wins).
    Output: report dict with NAMES only:
            {"path", "found", "loaded": [env vars set from the file],
             "kept_from_environment": [env vars the shell already had],
             "error": str|None, "refused": bool}
    Never raises: problems are returned in "error" so callers decide.
    """
    path = resolve_path(path)
    rep = {"path": path, "found": os.path.isfile(path), "loaded": [],
           "kept_from_environment": [], "error": None, "refused": False}
    if not rep["found"]:
        return rep
    try:
        values = read_values(path)
    except ConfigError as exc:
        rep["error"] = str(exc)
        rep["refused"] = exc.exit_code == 2
        return rep
    for env, val in values.items():
        if not override and os.environ.get(env, "").strip():
            rep["kept_from_environment"].append(env)
            continue
        os.environ[env] = val
        rep["loaded"].append(env)
    return rep


# ---------------------------------------------------------------------------
# Writing (line-based, keeps comments)
# ---------------------------------------------------------------------------
def set_value(path, name, value):
    """
    Store one key, preserving every other line and comment.

    Input:  path; name (see lookup()); value (str, "" clears it).
    Output: env var name that was written.
    Raises ConfigError for unknown names, newline in value, unsafe file.
    """
    entry = lookup(name)
    if not entry:
        raise ConfigError(f"unknown key '{name}'. Known: "
                          + ", ".join(o for _, o, _, _ in KEY_MAP))
    sec, opt, env, _ = entry
    if "\n" in value or "\r" in value:
        raise ConfigError("value must be a single line")
    init(path)
    problems = permission_problems(path)
    if problems:
        raise ConfigError("refusing to write: " + "; ".join(problems)
                          + " (python3 phishhunter.py config fix-perms)", 2)
    with open(path, "r", encoding="utf-8-sig") as fh:
        lines = fh.read().splitlines()

    out, cur, done = [], None, False
    for ln in lines:
        s = ln.strip()
        if s.startswith("[") and s.endswith("]"):
            if cur == sec and not done:          # leaving our section
                out.append(f"{opt} = {value}")
                done = True
            cur = s[1:-1].strip().lower()
            out.append(ln)
            continue
        key = s.split("=", 1)[0].strip().lower() if "=" in s else None
        if cur == sec and key == opt and not s.startswith(("#", ";")):
            if not done:
                out.append(f"{opt} = {value}")
                done = True
            continue                              # drop duplicates
        out.append(ln)
    if not done:
        # Our section is either the last one (cur == sec) or missing.
        if cur != sec:
            out += ["", f"[{sec}]"]
        out.append(f"{opt} = {value}")

    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix=".config.", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(out) + "\n")
        if os.name == "posix":
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return env


def status(path):
    """
    Input:  path. Output: list of dicts {"name", "env", "in_file": bool,
            "in_shell": bool} - booleans only, never values.
    Reads with permission checks disabled so `show` can still report.
    """
    try:
        values = read_values(path, check_permissions=False) \
            if os.path.isfile(path) else {}
    except ConfigError:
        values = {}
    return [{"name": opt, "env": env, "in_file": env in values,
             "in_shell": bool(os.environ.get(env, "").strip())}
            for _, opt, env, _ in KEY_MAP]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def cli(argv, path=None, prog="phishhunter_config.py"):
    """
    Input:  argv - [command, args...]; path - explicit config file.
    Output: exit code (0 ok, 1 error, 2 refused). Prints names only.
    """
    path = resolve_path(path)
    cmd = argv[0] if argv else "show"
    try:
        if cmd == "path":
            print(path)
        elif cmd == "init":
            created = init(path)
            print(("created " if created else "exists  ") + path)
            if created:
                print(f"next: {prog} set virustotal   (hidden input)")
        elif cmd in ("set", "unset"):
            if len(argv) < 2:
                print(f"usage: {prog} {cmd} NAME", file=sys.stderr)
                return 1
            entry = lookup(argv[1])
            if not entry:
                set_value(path, argv[1], "")     # raises unknown-key error
            if cmd == "unset":
                value = ""
            elif not sys.stdin.isatty():
                # Piped input (e.g. from a secret manager): first line only.
                value = sys.stdin.readline().strip()
            else:
                value = getpass.getpass(f"{entry[1]} ({entry[2]}) - input "
                                        f"is hidden: ").strip()
                if not value:
                    print("nothing entered - unchanged", file=sys.stderr)
                    return 1
            env = set_value(path, argv[1], value)
            print(f"{'cleared' if not value else 'saved'} {entry[1]} "
                  f"({env}) in {path}")
        elif cmd == "show":
            probs = permission_problems(path)
            print(f"config file : {path} "
                  f"({'exists' if os.path.isfile(path) else 'missing - run init'})")
            for p in probs:
                print(f"  !! {p}")
            for row in status(path):
                where = ("config file" if row["in_file"] else "")
                if row["in_shell"]:
                    where = ("shell (overrides config)" if row["in_file"]
                             else "shell")
                print(f"  {row['name']:<16} {row['env']:<24} "
                      f"{'set: ' + where if where else '-'}")
        elif cmd == "fix-perms":
            fix_permissions(path)
            probs = permission_problems(path)
            print("permissions ok" if not probs else "; ".join(probs))
            return 0 if not probs else 2
        else:
            print(f"unknown command '{cmd}' (path|init|set|unset|show|"
                  f"fix-perms)", file=sys.stderr)
            return 1
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code
    return 0


if __name__ == "__main__":
    sys.exit(cli(sys.argv[1:]))
