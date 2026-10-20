#!/usr/bin/env python3
"""
phishhunter.py - one-command launcher for phishHunter.

Purpose:
    Makes phishHunter easy to install and run:
      * Easy installation: `install` puts requirements.txt into the Python
        you already use (system, user, your own venv or conda). No virtual
        environment is required or created unless you ask for one.
      * Optional isolation: `install --venv` creates a project ".venv";
        from then on every command runs on it automatically (no
        `source .venv/bin/activate`) and it is re-synced whenever
        requirements.txt changes. Without --venv, no venv is ever created.
      * API keys: read from a private per-user config file OUTSIDE the
        repository (see `config`), so nothing is exported per terminal and
        keys can never be committed or zipped together with the code.
        Values exported in the shell always win. Values are never printed.
    Pure standard library; Linux, macOS and Windows; Python 3.8+.

Usage:
    python3 phishhunter.py install [--venv] [--yara] [--force]
        Default: install requirements into the CURRENT Python and create the
        config file. --venv: isolated project .venv instead (recommended
        when your OS Python refuses pip installs - PEP 668). --yara adds
        yara-python. --force rebuilds .venv.
        Requirements are optional: the core analysis (parse, headers, body,
        IOCs, WHOIS, verdict, AI stages, web UI) is pure standard library;
        `requests` enables threat-intel lookups, `reportlab` PDF reports.

    python3 phishhunter.py config set NAME      hidden prompt, saves a key
    python3 phishhunter.py config unset NAME    clears a key
    python3 phishhunter.py config show          which keys are set (no values)
    python3 phishhunter.py config path | init | fix-perms
        NAME: virustotal, abuseipdb, otx, urlscan, hybrid_analysis,
              anthropic, base_url  (or the env-var name, e.g. VT_API_KEY)

    python3 phishhunter.py analyze EMAIL [pipeline options...]
        Run the full triage pipeline. --skills-root is added automatically;
        every triage_pipeline.py option passes through, e.g.
          python3 phishhunter.py analyze mail.eml --format text
          python3 phishhunter.py analyze mail.eml --ai -o report.json --pretty

    python3 phishhunter.py pdf REPORT.json [-o out.pdf ...]
    python3 phishhunter.py web [--host H] [--port P ...]
    python3 phishhunter.py doctor
        Python / environment / dependency check, config file safety and
        which keys are set and from where - by NAME, never by value.
    python3 phishhunter.py run SCRIPT [args...]
        Run any repository script with the same environment and keys.

Global options (before the command):
    --config PATH   Use this config file (default: per-user location, or
                    $PHISHHUNTER_CONFIG)
    --no-config     Do not load the config file (shell variables only)
    --no-venv       Ignore .venv even if it exists (= PHISHHUNTER_NO_VENV=1)

Input/Output:
    The launcher prints short status lines to stderr only. The command it
    runs keeps its own stdout, stderr and EXIT CODE (pipeline: 0 clean /
    1 suspicious / 2 malicious / 3 fatal), so it is safe in scripts and CI.

Exit codes (launcher-level failures):
    2   config file refused (unsafe permissions / not owned by you)
    3   installation failed
    64  usage error
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
VENV_DIR = os.path.join(ROOT, ".venv")
REQUIREMENTS = os.path.join(ROOT, "requirements.txt")
SKILLS_ROOT = os.path.join(ROOT, "skills")
PIPELINE_DIR = os.path.join(SKILLS_ROOT, "email-triage-pipeline", "scripts")
PIPELINE = os.path.join(PIPELINE_DIR, "triage_pipeline.py")
PDF_SCRIPT = os.path.join(PIPELINE_DIR, "report_to_pdf.py")
WEBUI = os.path.join(ROOT, "webui", "app.py")
# Marker inside .venv: requirements hash + extras + installer mode, so a
# changed requirements.txt triggers a re-sync.
MARKER = os.path.join(VENV_DIR, ".phishhunter-install.json")
# Guard against re-exec loops if the venv interpreter cannot be detected.
REEXEC_FLAG = "PHISHHUNTER_LAUNCHER_IN_VENV"
# Tells child tools which config the launcher loaded (a PATH, never values)
# so their start-up lines and audit logs stay accurate.
LOADED_FROM = "PHISHHUNTER_CONFIG_LOADED_FROM"

sys.path.insert(0, PIPELINE_DIR)
import phishhunter_config as phc  # noqa: E402  (shared, next to pipeline)

# requirements.txt packages and the feature each enables. Everything else
# is standard library.
OPTIONAL_DEPS = (("requests", "threat-intel lookups (VirusTotal, AbuseIPDB, "
                              "OTX, urlscan, Hybrid Analysis)"),
                 ("reportlab", "PDF reports"))


def say(msg):
    """Print a launcher status line to stderr (stdout stays the tool's)."""
    sys.stderr.write(f"[phishhunter] {msg}\n")


def no_venv_requested(gargs):
    """Output: True when --no-venv or PHISHHUNTER_NO_VENV=1 is given."""
    return bool(gargs.no_venv or os.environ.get(
        "PHISHHUNTER_NO_VENV", "").strip().lower() in ("1", "true", "yes"))


# ---------------------------------------------------------------------------
# Dependencies in the current Python
# ---------------------------------------------------------------------------
def missing_deps():
    """Output: [(module, feature)] for requirements not importable here."""
    import importlib.util
    return [(m, why) for m, why in OPTIONAL_DEPS
            if importlib.util.find_spec(m) is None]


def warn_missing_deps():
    """
    Tell the user which features are unavailable and how to enable them.
    Never blocks: the core analysis runs on the standard library alone.
    """
    miss = missing_deps()
    for mod, why in miss:
        say(f"note: '{mod}' is not installed -> {why} unavailable")
    if miss:
        say("enable with: python3 phishhunter.py install --venv"
            if running_in_venv() else
            "enable with: python3 phishhunter.py install   "
            "(or --venv for an isolated environment)")


def pip_install(target_python, packages_args, installer="own-pip"):
    """
    Run pip for a target environment and explain common refusals.

    Input:  target_python - interpreter of the environment to install into
            packages_args - e.g. ["-r", "requirements.txt", "yara-python"]
            installer     - "own-pip" (target's pip) or "system-pip"
                            (pip-less venv filled via `pip --python`)
    Output: (ok: bool, reason: None | "pep668" | "no-pip" | "failed")
    """
    if installer == "system-pip":
        cmd = [base_python(), "-m", "pip", "--python", target_python]
    else:
        cmd = [target_python, "-m", "pip"]
    cmd += ["install", "--disable-pip-version-check", "-q"] + packages_args
    proc = subprocess.run(cmd, capture_output=True, text=True)
    err = (proc.stderr or "")
    if proc.returncode == 0:
        return True, None
    sys.stderr.write((proc.stdout or "")[-1500:] + err[-3000:])
    if "externally-managed-environment" in err:
        return False, "pep668"
    if "No module named pip" in err:
        return False, "no-pip"
    return False, "failed"


def explain_install_failure(reason):
    """Print guidance for a failed install into the CURRENT Python."""
    if reason == "pep668":
        say("this Python is managed by your OS / Homebrew (PEP 668) and "
            "refuses pip installs.")
        say("options: python3 phishhunter.py install --venv   (isolated, "
            "recommended)  |  Debian/Ubuntu: sudo apt install "
            "python3-requests python3-reportlab")
    elif reason == "no-pip":
        say("pip is not available for this Python. Install it (Debian/"
            "Ubuntu: sudo apt install python3-pip) or use the distro "
            "packages: sudo apt install python3-requests python3-reportlab")
    else:
        say("dependency installation failed (check network / proxy)")


def ask_yes(question):
    """Input: question. Output: True on y/yes/Enter; False when no TTY."""
    if not sys.stdin.isatty():
        return False
    try:
        ans = input(f"[phishhunter] {question} [Y/n] ").strip().lower()
    except EOFError:
        return False
    return ans in ("", "y", "yes", "e", "evet")


# ---------------------------------------------------------------------------
# Optional project virtual environment
# ---------------------------------------------------------------------------
def venv_python():
    """Output: path of the .venv interpreter for this OS."""
    if os.name == "nt":
        return os.path.join(VENV_DIR, "Scripts", "python.exe")
    return os.path.join(VENV_DIR, "bin", "python")


def running_in_venv():
    """Output: True when this process already runs on ROOT/.venv."""
    try:
        return os.path.realpath(sys.prefix) == os.path.realpath(VENV_DIR)
    except OSError:
        return False


def requirements_hash():
    """Output: sha256 of requirements.txt ("" when the file is missing)."""
    try:
        with open(REQUIREMENTS, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return ""


def read_marker():
    """Output: .venv install marker dict, or {} when absent/corrupt."""
    try:
        with open(MARKER, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def base_python():
    """
    Output: interpreter whose pip can fill a pip-less venv: the one
            recorded at creation time, else the base of the current one.
    """
    recorded = read_marker().get("installer_python")
    if recorded and os.path.isfile(recorded):
        return recorded
    return getattr(sys, "_base_executable", None) or sys.executable


def pip_supports_python_flag(python):
    """Output: True when `python -m pip` is >= 22.3 (has --python)."""
    try:
        out = subprocess.run([python, "-m", "pip", "--version"],
                             capture_output=True, text=True, timeout=60)
        major, minor = (int(x) for x in out.stdout.split()[1].split(".")[:2])
        return (major, minor) >= (22, 3)
    except (OSError, IndexError, ValueError, subprocess.SubprocessError):
        return False


def create_venv(force=False):
    """
    Create ROOT/.venv (only ever called by `install --venv`, or to re-sync
    an existing .venv).

    Input:  force - delete an existing .venv first.
    Output: installer mode: "own-pip" (normal venv) or "system-pip"
            (python3-venv/ensurepip missing: a pip-less venv is created and
            filled by the system pip via `pip --python`).
            SystemExit(3) with guidance when neither works.
    """
    if force and os.path.isdir(VENV_DIR):
        say("removing existing .venv")
        shutil.rmtree(VENV_DIR)
    if os.path.isfile(venv_python()):
        mode = read_marker().get("installer")
        if mode:
            return mode
        has_pip = subprocess.call([venv_python(), "-c", "import pip"],
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL) == 0
        return "own-pip" if has_pip else "system-pip"
    say("creating virtual environment in .venv")
    if subprocess.call([sys.executable, "-m", "venv", VENV_DIR]) == 0 \
            and os.path.isfile(venv_python()):
        return "own-pip"
    shutil.rmtree(VENV_DIR, ignore_errors=True)
    if pip_supports_python_flag(sys.executable):
        say("venv could not bootstrap pip (python3-venv missing?); "
            "creating a pip-less venv filled by the system pip")
        if subprocess.call([sys.executable, "-m", "venv", "--without-pip",
                            VENV_DIR]) == 0 and os.path.isfile(venv_python()):
            return "system-pip"
        shutil.rmtree(VENV_DIR, ignore_errors=True)
    say("could not create a virtual environment (Debian/Ubuntu: sudo apt "
        "install python3-venv). Without a venv: python3 phishhunter.py "
        "install")
    raise SystemExit(3)


def ensure_venv(extras=None, force=False):
    """
    Make sure .venv exists and matches requirements.txt (+ extras).

    Input:  extras - extra packages; None keeps what the last install had.
            force  - rebuild from scratch.
    Output: None; SystemExit(3) on failure (marker not written, so the
            next run retries).
    """
    installer = create_venv(force=force)
    marker = read_marker()
    wanted = sorted(set(extras if extras is not None
                        else marker.get("extras", [])))
    if (marker.get("requirements_sha256") == requirements_hash()
            and sorted(marker.get("extras", [])) == wanted):
        return
    say("installing dependencies into .venv")
    ok, reason = pip_install(venv_python(), ["-r", REQUIREMENTS] + wanted,
                             installer)
    if not ok:
        explain_install_failure(reason)
        raise SystemExit(3)
    with open(MARKER, "w", encoding="utf-8") as fh:
        json.dump({"requirements_sha256": requirements_hash(),
                   "extras": wanted, "installer": installer,
                   "installer_python": (base_python()
                                        if installer == "system-pip"
                                        else None)}, fh)


def reexec_in_venv(argv):
    """
    Restart this launcher with the .venv interpreter.

    Input:  argv - original arguments. Output: does not return.
    """
    env = dict(os.environ, **{REEXEC_FLAG: "1"})
    cmd = [venv_python(), os.path.abspath(__file__)] + argv
    if os.name == "nt":
        raise SystemExit(subprocess.call(cmd, env=env))
    os.execve(cmd[0], cmd, env)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def run_tool(script, args):
    """
    Run a repository script with the current interpreter.

    Input:  script path, arguments. Output: the script's exit code.
    """
    return subprocess.call([sys.executable, script] + list(args))


def cmd_install(gargs, rest):
    """
    `install`: dependencies (current Python by default, .venv on request)
    and the private config file.

    Output: exit code (0 ok, 3 failure).
    """
    ap = argparse.ArgumentParser(prog="phishhunter.py install")
    ap.add_argument("--venv", action="store_true",
                    help="use an isolated project .venv instead of the "
                         "current Python")
    ap.add_argument("--yara", action="store_true",
                    help="also install yara-python (YARA stage)")
    ap.add_argument("--force", action="store_true",
                    help="with --venv: delete and rebuild .venv")
    a = ap.parse_args(rest)
    extras = ["yara-python"] if a.yara else []

    if a.venv:
        ensure_venv(extras=extras or None, force=a.force)
        where = f"project .venv ({VENV_DIR})"
    else:
        say(f"installing requirements into the current Python "
            f"({sys.executable})")
        ok, reason = pip_install(sys.executable,
                                 ["-r", REQUIREMENTS] + extras)
        if not ok:
            explain_install_failure(reason)
            if reason == "pep668" and ask_yes(
                    "create an isolated project .venv instead?"):
                ensure_venv(extras=extras or None)
                where = f"project .venv ({VENV_DIR})"
            else:
                say("the core analysis still works without these packages "
                    "(threat intel and PDF stay disabled)")
                return 3
        else:
            where = f"current Python ({sys.prefix})"
            if os.path.isfile(venv_python()):
                say("note: a project .venv also exists and is preferred at "
                    "run time; delete .venv or pass --no-venv to use this "
                    "Python")

    cfg = phc.resolve_path(gargs.config)
    created = phc.init(cfg)
    say("installed into: " + where)
    say(("created private config file " if created
         else "config file: ") + cfg)
    say("next: python3 phishhunter.py config set virustotal   "
        "(hidden input; repeat for the keys you have)")
    say("then: python3 phishhunter.py analyze examples/sample_phishing.eml "
        "--format text")
    return 0


def cmd_doctor(gargs, cfg_report):
    """`doctor`: environment health report (never prints key values)."""
    ok = True
    print("phishHunter doctor")
    print(f"  python      : {sys.version.split()[0]} ({sys.executable})")
    if sys.version_info < (3, 8):
        print("  !! Python 3.8+ is required")
        ok = False
    if running_in_venv():
        env_desc = "project .venv"
    elif os.environ.get("CONDA_PREFIX") and os.path.realpath(sys.prefix) \
            == os.path.realpath(os.environ["CONDA_PREFIX"]):
        env_desc = "your conda environment"
    elif sys.prefix != getattr(sys, "base_prefix", sys.prefix):
        env_desc = "your own virtualenv"
    else:
        env_desc = "system / user Python (no venv - that is fine)"
    print(f"  environment : {env_desc}")
    missing = {m for m, _ in missing_deps()}
    for mod, why in OPTIONAL_DEPS + (("yara", "YARA stage"),
                                     ("cv2", "QR decoding fallback"),
                                     ("pyzbar", "QR decoding")):
        if mod in dict(OPTIONAL_DEPS):
            state = "missing" if mod in missing else "ok"
        else:
            import importlib.util
            state = "ok" if importlib.util.find_spec(mod) else "-"
        print(f"  {mod:<11} : {state:<8} {why}"
              + ("" if mod in dict(OPTIONAL_DEPS) else " (optional)"))
    if missing:
        print("  -> python3 phishhunter.py install   enables the missing "
              "features")
    path = cfg_report.get("path")
    print(f"  config file : {path}"
          + ("" if cfg_report.get("found") else "  (missing - run: "
             "python3 phishhunter.py config init)")
          + ("  [not loaded: --no-config]" if gargs.no_config else ""))
    for p in phc.permission_problems(path) if path else []:
        print(f"  !! {p}  -> python3 phishhunter.py config fix-perms")
        ok = False
    print("  API keys (values are never shown):")
    loaded = set(cfg_report.get("loaded", []))
    for _, name, env, _ in phc.KEY_MAP:
        if not os.environ.get(env, "").strip():
            src = "-"
        elif env in loaded:
            src = "set (config file)"
        else:
            src = "set (shell environment)"
        print(f"    {name:<16} {env:<24} {src}")
    if not any(os.environ.get(e, "").strip()
               for s, _, e, _ in phc.KEY_MAP if s == "intel"):
        print("  note: no intel key set - add one with: python3 "
              "phishhunter.py config set virustotal  (or run with "
              "--skip-intel)")
    print(f"  skills root : {SKILLS_ROOT} "
          f"({'ok' if os.path.isfile(PIPELINE) else 'MISSING'})")
    return 0 if ok else 1


def with_no_config(args):
    """Input: tool args. Output: args + --no-config (launcher loaded it)."""
    args = list(args)
    if "--no-config" not in args and "--config" not in args:
        args.append("--no-config")
    return args


def cmd_analyze(rest):
    """`analyze`: run triage_pipeline.py with --skills-root defaulted."""
    if not rest:
        say("usage: phishhunter.py analyze EMAIL [pipeline options]")
        return 64
    args = list(rest)
    if "--skills-root" not in args:
        args += ["--skills-root", SKILLS_ROOT]
    return run_tool(PIPELINE, with_no_config(args))


def cmd_run(rest):
    """`run`: execute an arbitrary repository script."""
    if not rest:
        say("usage: phishhunter.py run SCRIPT [args]")
        return 64
    script = rest[0]
    if not os.path.isfile(script):
        script = os.path.join(ROOT, script)
    if not os.path.isfile(script):
        say(f"script not found: {rest[0]}")
        return 64
    return run_tool(os.path.abspath(script), rest[1:])


COMMANDS = ("install", "config", "analyze", "pdf", "web", "doctor", "run")


def main(argv=None):
    """Entry point: global options, environment choice, keys, dispatch."""
    argv = list(sys.argv[1:] if argv is None else argv)
    ap = argparse.ArgumentParser(
        prog="phishhunter.py",
        description="phishHunter launcher - easy install, optional venv, "
                    "private API-key config.",
        epilog="commands: " + ", ".join(COMMANDS))
    ap.add_argument("--config", help="config file to use")
    ap.add_argument("--no-config", action="store_true",
                    help="do not load the config file")
    ap.add_argument("--no-venv", action="store_true",
                    help="ignore .venv even if it exists")
    ap.add_argument("command", choices=COMMANDS)
    ap.add_argument("rest", nargs=argparse.REMAINDER)
    gargs = ap.parse_args(argv)

    if gargs.command == "install":
        return cmd_install(gargs, gargs.rest)
    if gargs.command == "config":
        return phc.cli(gargs.rest, gargs.config,
                       prog="python3 phishhunter.py config")

    # Environment choice - a venv is NEVER created here:
    #   project .venv exists -> run on it (re-sync if requirements changed)
    #   otherwise            -> current Python; note missing optional deps
    if not no_venv_requested(gargs):
        if running_in_venv():
            ensure_venv()
        elif os.path.isfile(venv_python()):
            if os.environ.get(REEXEC_FLAG):
                say("project .venv did not activate; using current Python")
            else:
                ensure_venv()
                reexec_in_venv(argv)      # does not return
    if gargs.command != "doctor":
        warn_missing_deps()

    # API keys from the private config file (shell variables win).
    if gargs.no_config:
        report = {"path": phc.resolve_path(gargs.config), "found": False,
                  "loaded": [], "error": None, "refused": False}
        os.environ[LOADED_FROM] = "disabled"
    else:
        report = phc.load(gargs.config)
        if report["error"]:
            say(("ERROR: " if report["refused"] else "WARNING: ")
                + report["error"])
            if report["refused"] and gargs.command != "doctor":
                return 2
        os.environ[LOADED_FROM] = (report["path"] if report["found"]
                                   else "none")

    if gargs.command == "doctor":
        return cmd_doctor(gargs, report)
    if gargs.command == "analyze":
        return cmd_analyze(gargs.rest)
    if gargs.command == "pdf":
        return run_tool(PDF_SCRIPT, gargs.rest)
    if gargs.command == "web":
        return run_tool(WEBUI, with_no_config(gargs.rest))
    return cmd_run(gargs.rest)


if __name__ == "__main__":
    sys.exit(main())
