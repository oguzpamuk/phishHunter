#!/usr/bin/env python3
"""
easy_install.py - one-step installation for phishHunter.

Purpose:
    Gets a fresh clone ready to use in one command:
      1. installs requirements.txt (requests, reportlab) into the Python you
         already use - or into an isolated project ".venv" with --venv;
      2. creates the private API-key file (outside the repository);
      3. asks for each API key with hidden input (press Enter to skip).
    It only installs and configures. The tools themselves are run directly
    afterwards (triage_pipeline.py, report_to_pdf.py, webui/app.py) and read
    the keys from the same private file.

    Pure standard library; Linux, macOS and Windows; Python 3.8+.

Usage:
    python3 easy_install.py              install + key file + key prompts
    python3 easy_install.py --venv       same, but into a project .venv
    python3 easy_install.py --yara       also install yara-python
    python3 easy_install.py --no-keys    do not ask for keys (e.g. in CI)
    python3 easy_install.py --keys       only (re)enter API keys
    python3 easy_install.py --check      show Python, packages, key file and
                                         which keys are set (names only)
    python3 easy_install.py --fix-perms  make the key file private again
    python3 easy_install.py --venv --force   rebuild .venv from scratch

Inputs:
    Command-line options above; API keys typed at hidden prompts (getpass).
    Nothing is read from the repository except requirements.txt.

Outputs:
    * packages installed into the chosen Python / .venv
    * ~/.config/phishhunter/config.ini   (%APPDATA%\\phishhunter\\config.ini
      on Windows) - created 600 inside a 700 folder; key VALUES are only
      ever written there, never printed or logged
    * status lines on stderr, the "how to run" summary on stdout

Exit codes:
    0  done
    1  --check found a problem (Python too old, unsafe key file)
    3  installation failed (pip refused / no network / no venv support)

Notes:
    * Requirements are optional: without them everything works except
      threat-intel lookups (requests) and PDF reports (reportlab).
    * Some systems (recent Debian/Ubuntu, Homebrew) refuse pip installs into
      the system Python (PEP 668, "externally-managed-environment"). The
      script explains the options and, in a terminal, offers --venv.
    * --venv: if python3-venv/ensurepip is missing, a venv without pip is
      created and filled by the system pip (`pip --python`, pip >= 22.3).
      Run the tools with the venv's Python afterwards (printed at the end).
"""

import argparse
import getpass
import importlib.util
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
REQUIREMENTS = os.path.join(ROOT, "requirements.txt")
VENV_DIR = os.path.join(ROOT, ".venv")
PIPELINE_DIR = os.path.join(ROOT, "skills", "email-triage-pipeline",
                            "scripts")

sys.path.insert(0, PIPELINE_DIR)
import phishhunter_config as phc  # noqa: E402  (shared key-file module)

# requirements.txt packages and the feature each one enables.
REQUIRED = (("requests", "threat-intel lookups"),
            ("reportlab", "PDF reports"))
OPTIONAL = (("yara", "YARA stage (pip install yara-python)"),
            ("pyzbar", "QR decoding (pip install pyzbar)"),
            ("cv2", "QR decoding (pip install opencv-python-headless)"))


def say(msg):
    """Print a status line to stderr."""
    sys.stderr.write(f"[easy_install] {msg}\n")


def ask_yes(question):
    """Input: question. Output: True on Enter/y/yes; False without a TTY."""
    if not sys.stdin.isatty():
        return False
    try:
        ans = input(f"[easy_install] {question} [Y/n] ").strip().lower()
    except EOFError:
        return False
    return ans in ("", "y", "yes", "e", "evet")


# ---------------------------------------------------------------------------
# pip
# ---------------------------------------------------------------------------
def pip_install(target_python, packages, via_system_pip=False):
    """
    Install packages into the environment of target_python.

    Input:  target_python  - interpreter of the target environment
            packages       - pip arguments, e.g. ["-r", "requirements.txt"]
            via_system_pip - use THIS interpreter's pip with --python
                             (for a venv created without pip)
    Output: (ok: bool, reason: None | "pep668" | "no-pip" | "failed")
    """
    if via_system_pip:
        cmd = [sys.executable, "-m", "pip", "--python", target_python]
    else:
        cmd = [target_python, "-m", "pip"]
    cmd += ["install", "--disable-pip-version-check", "-q"] + packages
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode == 0:
        return True, None
    err = proc.stderr or ""
    sys.stderr.write((proc.stdout or "")[-1500:] + err[-3000:])
    if "externally-managed-environment" in err:
        return False, "pep668"
    if "No module named pip" in err:
        return False, "no-pip"
    return False, "failed"


def explain_failure(reason):
    """Print guidance after a failed install into the current Python."""
    if reason == "pep668":
        say("this Python is managed by your OS / Homebrew and refuses pip "
            "installs (PEP 668).")
        say("options: python3 easy_install.py --venv   |   Debian/Ubuntu: "
            "sudo apt install python3-requests python3-reportlab")
    elif reason == "no-pip":
        say("pip is not available for this Python (Debian/Ubuntu: sudo apt "
            "install python3-pip), or use: sudo apt install "
            "python3-requests python3-reportlab")
    else:
        say("installation failed - check your network / proxy")


# ---------------------------------------------------------------------------
# Optional project venv
# ---------------------------------------------------------------------------
def venv_python():
    """Output: path of the .venv interpreter for this OS."""
    if os.name == "nt":
        return os.path.join(VENV_DIR, "Scripts", "python.exe")
    return os.path.join(VENV_DIR, "bin", "python")


def pip_has_python_flag():
    """Output: True when this interpreter's pip is >= 22.3 (--python)."""
    try:
        out = subprocess.run([sys.executable, "-m", "pip", "--version"],
                             capture_output=True, text=True, timeout=60)
        major, minor = (int(x) for x in out.stdout.split()[1].split(".")[:2])
        return (major, minor) >= (22, 3)
    except (OSError, IndexError, ValueError, subprocess.SubprocessError):
        return False


def create_venv(force):
    """
    Create ROOT/.venv.

    Input:  force - delete an existing .venv first.
    Output: True when the venv has its own pip, False when it was created
            without pip (python3-venv missing) and must be filled by the
            system pip. Raises SystemExit(3) when no venv can be created.
    """
    if force and os.path.isdir(VENV_DIR):
        say("removing existing .venv")
        shutil.rmtree(VENV_DIR)
    if os.path.isfile(venv_python()):
        return subprocess.call([venv_python(), "-c", "import pip"],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL) == 0
    say("creating virtual environment in .venv")
    if subprocess.call([sys.executable, "-m", "venv", VENV_DIR]) == 0 \
            and os.path.isfile(venv_python()):
        return True
    shutil.rmtree(VENV_DIR, ignore_errors=True)
    if pip_has_python_flag():
        say("venv could not install pip (python3-venv missing?); creating a "
            "venv without pip, filled by the system pip")
        if subprocess.call([sys.executable, "-m", "venv", "--without-pip",
                            VENV_DIR]) == 0 and os.path.isfile(venv_python()):
            return False
        shutil.rmtree(VENV_DIR, ignore_errors=True)
    say("could not create a virtual environment (Debian/Ubuntu: sudo apt "
        "install python3-venv). Without --venv the packages go into your "
        "current Python.")
    raise SystemExit(3)


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------
def install(use_venv, yara, force):
    """
    Install requirements.txt (+ yara-python).

    Input:  use_venv, yara, force - command-line flags.
    Output: the interpreter the tools should be run with, or None when the
            installation failed (the caller exits with 3).
    """
    pkgs = ["-r", REQUIREMENTS] + (["yara-python"] if yara else [])
    if not use_venv:
        say(f"installing requirements into {sys.executable}")
        ok, reason = pip_install(sys.executable, pkgs)
        if ok:
            return sys.executable
        explain_failure(reason)
        if reason != "pep668" or not ask_yes(
                "create an isolated .venv for phishHunter instead?"):
            say("the core analysis still works without these packages "
                "(threat intel and PDF stay off)")
            return None
    own_pip = create_venv(force)
    say("installing requirements into .venv")
    ok, reason = pip_install(venv_python(), pkgs, via_system_pip=not own_pip)
    if not ok:
        explain_failure(reason)
        return None
    return venv_python()


def enter_keys(path):
    """
    Ask for every API key with hidden input and store the ones given.

    Input:  path - key file. Output: number of keys saved.
    Enter keeps the current value (or leaves it unset). Values are never
    echoed; only names are printed.
    """
    if not sys.stdin.isatty():
        say("not a terminal - skipping key prompts (run: python3 "
            "easy_install.py --keys)")
        return 0
    current = {row["env"]: row["in_file"] for row in phc.status(path)}
    print("\nAPI keys - all optional. Paste a key and press Enter, or just "
          "press Enter to skip. Input is hidden.")
    saved = 0
    for _sec, opt, env, hlp in phc.KEY_MAP:
        if opt == "base_url":
            continue
        state = "set, Enter keeps it" if current.get(env) else "not set"
        try:
            value = getpass.getpass(f"  {opt:<16} {hlp.split(' - ')[0]} "
                                    f"({state}): ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if value:
            phc.set_value(path, opt, value)
            saved += 1
    print(f"{saved} key(s) saved to {path}\n")
    return saved


def check(path):
    """
    Print an environment report (key NAMES only).

    Input:  path - key file. Output: 0 when fine, 1 on a problem.
    """
    ok = True
    print("phishHunter check")
    print(f"  python    : {sys.version.split()[0]}  ({sys.executable})")
    if sys.version_info < (3, 8):
        print("  !! Python 3.8 or newer is required")
        ok = False
    if os.path.isfile(venv_python()):
        print(f"  .venv     : present - run the tools with {venv_python()}")
    for mod, why in REQUIRED + OPTIONAL:
        found = importlib.util.find_spec(mod) is not None
        tag = "ok" if found else ("missing" if (mod, why) in REQUIRED
                                  else "-")
        print(f"  {mod:<10}: {tag:<8} {why}")
    print(f"  key file  : {path}"
          + ("" if os.path.isfile(path) else "  (missing)"))
    for problem in phc.permission_problems(path):
        print(f"  !! {problem}  -> python3 easy_install.py --fix-perms")
        ok = False
    for row in phc.status(path):
        if row["name"] == "base_url":
            continue
        if row["in_shell"]:
            state = "set (shell)"
        elif row["in_file"]:
            state = "set (key file)"
        else:
            state = "-"
        print(f"  {row['env']:<25} {state}")
    return 0 if ok else 1


def how_to_run(python):
    """Print the commands to use after installation."""
    py = (os.path.relpath(python, ROOT) if python == venv_python()
          else "python3")
    print("Ready. Run the tools with:")
    print(f"  {py} skills/email-triage-pipeline/scripts/triage_pipeline.py "
          f"examples/sample_phishing.eml --format text")
    print(f"  {py} skills/email-triage-pipeline/scripts/report_to_pdf.py "
          f"report.json -o report.pdf")
    print(f"  {py} webui/app.py")
    print("Change keys later with: python3 easy_install.py --keys")


def main(argv=None):
    """Entry point: parse options and run the requested steps."""
    ap = argparse.ArgumentParser(
        prog="easy_install.py",
        description="Install phishHunter's requirements and set up the "
                    "private API-key file.")
    ap.add_argument("--venv", action="store_true",
                    help="install into a project .venv instead of the "
                         "current Python")
    ap.add_argument("--force", action="store_true",
                    help="with --venv: rebuild .venv from scratch")
    ap.add_argument("--yara", action="store_true",
                    help="also install yara-python")
    ap.add_argument("--no-keys", action="store_true",
                    help="do not ask for API keys")
    ap.add_argument("--keys", action="store_true",
                    help="only (re)enter API keys, install nothing")
    ap.add_argument("--check", action="store_true",
                    help="show Python, packages and which keys are set")
    ap.add_argument("--fix-perms", action="store_true",
                    help="make the key file and its folder private")
    ap.add_argument("--config", metavar="PATH",
                    help="key file to use (default: per-user location or "
                         "$PHISHHUNTER_CONFIG)")
    args = ap.parse_args(argv)
    path = phc.resolve_path(args.config)

    if args.check:
        return check(path)
    if args.fix_perms:
        phc.fix_permissions(path)
        problems = phc.permission_problems(path)
        print("key file is private" if not problems else "; ".join(problems))
        return 0 if not problems else 1
    if args.keys:
        phc.init(path)
        enter_keys(path)
        return 0

    python = install(args.venv, args.yara, args.force)
    if python is None:
        return 3
    created = phc.init(path)
    say(("created private key file " if created else "key file: ") + path)
    if not args.no_keys:
        enter_keys(path)
    how_to_run(python)
    return 0


if __name__ == "__main__":
    sys.exit(main())
