#!/usr/bin/env python3
"""
scan_email.py — Scan a .msg or .eml email file with external YARA rules.

================================================================================
PURPOSE
================================================================================
This command-line tool takes an email file (Outlook .msg or standard MIME .eml)
and a path to YARA rules (a single .yar/.yara file OR a directory containing
multiple rule files), scans every layer of the email (raw bytes, headers,
text/HTML bodies, and each attachment), and prints a JSON report describing
every YARA rule that matched.

The tool NEVER contains or generates YARA rules itself — rules are always
loaded from the external path supplied by the user via --rules.

================================================================================
INPUT (command-line arguments)
================================================================================
  --file    <path>   REQUIRED. Path to the email file to scan.
                     Supported extensions: .eml (RFC 822 / MIME) and
                     .msg (Microsoft Outlook Compound File format).
  --rules   <path>   REQUIRED. Path to the YARA rules source:
                       * a single rules file (any extension accepted), or
                       * a directory — every *.yar and *.yara file inside
                         (recursively) is compiled into one rule set, each
                         file in its own namespace (the file stem) so that
                         duplicate rule names across files do not collide.
  --output  <path>   OPTIONAL. Write the JSON report to this file instead of
                     printing it to stdout.
  --timeout <int>    OPTIONAL. Per-target YARA scan timeout in seconds.
                     Default: 60.

================================================================================
OUTPUT (JSON on stdout, or --output file)
================================================================================
  {
    "scanned_file":   str,   # absolute path of the scanned email
    "file_type":      str,   # "eml" or "msg"
    "rules_source":   str,   # absolute path of the rules file/directory
    "scan_time_utc":  str,   # ISO-8601 UTC timestamp of the scan
    "match_found":    bool,  # true if at least one rule matched anywhere
    "total_matches":  int,   # number of (rule, target) match entries
    "matches": [             # one entry per rule match per target
      {
        "rule":       str,   # YARA rule name
        "namespace":  str,   # YARA namespace (rule file stem for directories)
        "tags":       [str], # tags declared on the rule
        "meta":       {},    # rule 'meta' section key/values
        "matched_in": str,   # which target matched: "raw_file", "headers",
                             # "body_text", "body_html", "attachment:<name>"
        "strings": [         # matched string instances (capped, see below)
          {
            "identifier": str,  # string identifier, e.g. "$url"
            "offset":     int,  # byte offset of the match within the target
            "data":       str   # matched bytes, UTF-8 decoded (lossy),
                                # truncated to 128 chars for readability
          }
        ]
      }
    ],
    "targets_scanned": [str],  # every target that was actually scanned
    "errors":          [str]   # non-fatal problems (e.g. one attachment
                               # failed to decode) — the scan still completes
  }

================================================================================
EXIT CODES
================================================================================
  0  scan completed, at least one YARA rule matched
  1  scan completed, no rule matched
  2  fatal error (missing file, rules failed to compile, missing dependency)

================================================================================
DEPENDENCIES
================================================================================
  yara-python   (required)                pip install yara-python
  extract-msg   (required for .msg only)  pip install extract-msg
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser

# --------------------------------------------------------------------------
# Dependency check: yara-python is mandatory for any scan. We fail fast with
# a clear, machine-readable JSON error on stderr-friendly exit code 2 so the
# calling agent knows exactly what to install.
# --------------------------------------------------------------------------
try:
    import yara  # provided by the 'yara-python' package
except ImportError:
    print(json.dumps({
        "error": "Missing dependency 'yara-python'. "
                 "Install it with: pip install yara-python"
    }))
    sys.exit(2)


# String data shown in the report is truncated to this many characters so a
# single huge match (e.g. an entire base64 blob) does not bloat the JSON.
MAX_STRING_DATA_LEN = 128
# At most this many matched-string instances are reported per rule match.
MAX_STRING_INSTANCES = 20


def compile_rules(rules_path):
    """
    Compile YARA rules from an external path.

    Input:
        rules_path (str): path to a single YARA rules file OR a directory.
                          For a directory, every *.yar / *.yara file found
                          recursively is included. Each file gets its own
                          namespace (its filename without extension) so rule
                          name collisions between files are impossible.

    Output:
        yara.Rules: the compiled rule set, ready for .match() calls.

    Raises:
        FileNotFoundError: if the path does not exist or a directory contains
                           no *.yar / *.yara files.
        yara.SyntaxError / yara.Error: if any rule file fails to compile.
    """
    if not os.path.exists(rules_path):
        raise FileNotFoundError(f"Rules path not found: {rules_path}")

    if os.path.isdir(rules_path):
        # Collect every rules file under the directory (recursive walk).
        filepaths = {}
        for root, _dirs, files in os.walk(rules_path):
            for fname in files:
                if fname.lower().endswith((".yar", ".yara")):
                    # Namespace = file stem, keeps rules from different files apart.
                    namespace = os.path.splitext(fname)[0]
                    # If two files share a stem, disambiguate with a counter.
                    base_ns, i = namespace, 1
                    while namespace in filepaths:
                        namespace = f"{base_ns}_{i}"
                        i += 1
                    filepaths[namespace] = os.path.join(root, fname)
        if not filepaths:
            raise FileNotFoundError(
                f"No *.yar / *.yara files found in directory: {rules_path}")
        return yara.compile(filepaths=filepaths)

    # Single rules file — compile it directly under the default namespace.
    return yara.compile(filepath=rules_path)


def parse_eml(raw_bytes):
    """
    Extract scan targets from a standard MIME .eml file.

    Input:
        raw_bytes (bytes): the full, unmodified bytes of the .eml file.

    Output:
        (targets, errors) tuple where:
          targets (dict[str, bytes]): mapping of target name -> bytes to scan.
              Keys produced: "headers", "body_text", "body_html",
              "attachment:<filename>" (one per attachment).
          errors (list[str]): non-fatal extraction problems.
    """
    targets = {}
    errors = []

    # policy.default gives us modern, convenient accessors (get_body, etc.)
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    # ---- headers: the raw header block ends at the first blank line ----
    header_end = raw_bytes.find(b"\r\n\r\n")
    if header_end == -1:
        header_end = raw_bytes.find(b"\n\n")
    if header_end != -1:
        targets["headers"] = raw_bytes[:header_end]

    # ---- bodies: prefer dedicated plain and HTML parts ----
    try:
        body_plain = msg.get_body(preferencelist=("plain",))
        if body_plain is not None:
            targets["body_text"] = body_plain.get_content().encode(
                "utf-8", errors="replace")
    except Exception as exc:  # decoding errors must not kill the whole scan
        errors.append(f"body_text extraction failed: {exc}")

    try:
        body_html = msg.get_body(preferencelist=("html",))
        if body_html is not None:
            targets["body_html"] = body_html.get_content().encode(
                "utf-8", errors="replace")
    except Exception as exc:
        errors.append(f"body_html extraction failed: {exc}")

    # ---- attachments: decoded payload bytes of each attachment part ----
    for part in msg.iter_attachments():
        fname = part.get_filename() or "unnamed"
        try:
            payload = part.get_payload(decode=True)  # base64/QP -> raw bytes
            if payload:
                targets[f"attachment:{fname}"] = payload
        except Exception as exc:
            errors.append(f"attachment '{fname}' extraction failed: {exc}")

    return targets, errors


def parse_msg(file_path):
    """
    Extract scan targets from an Outlook .msg file using extract-msg.

    Input:
        file_path (str): path to the .msg file on disk.

    Output:
        (targets, errors) tuple with the same shape as parse_eml():
          targets keys: "headers" (reconstructed From/To/Subject/Date text),
          "body_text", "body_html", "attachment:<filename>".
          errors: non-fatal extraction problems.

    Raises:
        ImportError: if the 'extract-msg' package is not installed.
    """
    try:
        import extract_msg  # imported lazily: only .msg inputs need it
    except ImportError:
        raise ImportError(
            "Missing dependency 'extract-msg' (needed for .msg files). "
            "Install it with: pip install extract-msg")

    targets = {}
    errors = []
    msg = extract_msg.Message(file_path)

    # ---- headers: rebuild a simple header text block from message fields ----
    header_lines = []
    for label, value in (("From", msg.sender), ("To", msg.to),
                         ("Cc", msg.cc), ("Subject", msg.subject),
                         ("Date", str(msg.date) if msg.date else None)):
        if value:
            header_lines.append(f"{label}: {value}")
    if header_lines:
        targets["headers"] = "\n".join(header_lines).encode(
            "utf-8", errors="replace")

    # ---- bodies ----
    try:
        if msg.body:
            targets["body_text"] = msg.body.encode("utf-8", errors="replace")
    except Exception as exc:
        errors.append(f"body_text extraction failed: {exc}")

    try:
        html = msg.htmlBody
        if html:
            # htmlBody may be bytes or str depending on the source message
            targets["body_html"] = html if isinstance(html, bytes) \
                else html.encode("utf-8", errors="replace")
    except Exception as exc:
        errors.append(f"body_html extraction failed: {exc}")

    # ---- attachments ----
    for att in msg.attachments:
        fname = att.longFilename or att.shortFilename or "unnamed"
        try:
            data = att.data
            if isinstance(data, bytes) and data:
                targets[f"attachment:{fname}"] = data
        except Exception as exc:
            errors.append(f"attachment '{fname}' extraction failed: {exc}")

    msg.close()
    return targets, errors


def run_yara(rules, targets, timeout):
    """
    Run the compiled YARA rules against every target buffer.

    Input:
        rules (yara.Rules): compiled rule set from compile_rules().
        targets (dict[str, bytes]): target name -> bytes to scan.
        timeout (int): per-target scan timeout in seconds.

    Output:
        (matches, errors) tuple where:
          matches (list[dict]): one JSON-ready dict per (rule, target) match,
              containing rule name, namespace, tags, meta, matched_in, and a
              capped list of matched string instances (identifier / offset /
              truncated data).
          errors (list[str]): per-target scan failures (e.g. timeout).
    """
    matches = []
    errors = []

    for target_name, data in targets.items():
        try:
            for m in rules.match(data=data, timeout=timeout):
                # Flatten matched strings; API differs across yara-python
                # versions, so handle both the modern StringMatch objects
                # and the legacy (offset, identifier, data) tuples.
                strings = []
                for s in m.strings:
                    if hasattr(s, "instances"):  # yara-python >= 4.x
                        for inst in s.instances:
                            strings.append({
                                "identifier": s.identifier,
                                "offset": inst.offset,
                                "data": inst.matched_data.decode(
                                    "utf-8", errors="replace"
                                )[:MAX_STRING_DATA_LEN],
                            })
                            if len(strings) >= MAX_STRING_INSTANCES:
                                break
                    else:  # legacy tuple form: (offset, identifier, data)
                        offset, ident, sdata = s
                        strings.append({
                            "identifier": ident,
                            "offset": offset,
                            "data": sdata.decode(
                                "utf-8", errors="replace"
                            )[:MAX_STRING_DATA_LEN],
                        })
                    if len(strings) >= MAX_STRING_INSTANCES:
                        break

                matches.append({
                    "rule": m.rule,
                    "namespace": m.namespace,
                    "tags": list(m.tags),
                    "meta": dict(m.meta),
                    "matched_in": target_name,
                    "strings": strings,
                })
        except yara.TimeoutError:
            errors.append(f"YARA timeout while scanning target '{target_name}'")
        except yara.Error as exc:
            errors.append(f"YARA error on target '{target_name}': {exc}")

    return matches, errors


def main():
    # ---------------- argument parsing ----------------
    parser = argparse.ArgumentParser(
        description="Scan a .msg or .eml email file with external YARA rules "
                    "and output the matches as JSON.")
    parser.add_argument("--file", required=True,
                        help="Path to the .msg or .eml file to scan")
    parser.add_argument("--rules", required=True,
                        help="Path to a YARA rules file or a directory of "
                             "*.yar / *.yara files")
    parser.add_argument("--output", default=None,
                        help="Optional path to write the JSON report "
                             "(default: print to stdout)")
    parser.add_argument("--timeout", type=int, default=60,
                        help="Per-target YARA scan timeout in seconds "
                             "(default: 60)")
    args = parser.parse_args()

    def fatal(message):
        """Print a JSON error object and exit with code 2 (fatal error)."""
        print(json.dumps({"error": message}, indent=2))
        sys.exit(2)

    # ---------------- validate inputs ----------------
    email_path = os.path.abspath(args.file)
    if not os.path.isfile(email_path):
        fatal(f"Email file not found: {email_path}")

    ext = os.path.splitext(email_path)[1].lower()
    if ext not in (".eml", ".msg"):
        fatal(f"Unsupported file type '{ext}'. Only .eml and .msg are supported.")

    # ---------------- compile the external YARA rules ----------------
    try:
        rules = compile_rules(os.path.abspath(args.rules))
    except (FileNotFoundError, yara.Error, yara.SyntaxError) as exc:
        fatal(f"Failed to load YARA rules: {exc}")

    # ---------------- build scan targets from the email ----------------
    with open(email_path, "rb") as fh:
        raw_bytes = fh.read()

    # The raw file bytes are always scanned as the first target, so rules
    # written against the on-disk representation (e.g. base64 blobs, header
    # anomalies) also fire.
    targets = {"raw_file": raw_bytes}
    errors = []

    try:
        if ext == ".eml":
            extracted, parse_errors = parse_eml(raw_bytes)
        else:  # ".msg"
            extracted, parse_errors = parse_msg(email_path)
        targets.update(extracted)
        errors.extend(parse_errors)
    except ImportError as exc:
        fatal(str(exc))  # missing extract-msg for .msg inputs
    except Exception as exc:
        # Parsing failed entirely — still scan raw_file, but record the issue.
        errors.append(f"Email parsing failed, scanning raw bytes only: {exc}")

    # ---------------- run YARA against every target ----------------
    matches, scan_errors = run_yara(rules, targets, args.timeout)
    errors.extend(scan_errors)

    # ---------------- assemble the JSON report ----------------
    report = {
        "scanned_file": email_path,
        "file_type": ext.lstrip("."),
        "rules_source": os.path.abspath(args.rules),
        "scan_time_utc": datetime.now(timezone.utc)
                                 .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "match_found": len(matches) > 0,
        "total_matches": len(matches),
        "matches": matches,
        "targets_scanned": sorted(targets.keys()),
        "errors": errors,
    }

    output_json = json.dumps(report, indent=2, ensure_ascii=False, default=str)

    # ---------------- emit the report ----------------
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output_json + "\n")
        # Also echo the destination so CLI users know where the report went.
        print(f"Report written to: {os.path.abspath(args.output)}")
    else:
        print(output_json)

    # Exit code 0 = matches found, 1 = clean run with no matches.
    sys.exit(0 if matches else 1)


if __name__ == "__main__":
    main()
