#!/usr/bin/env python3
"""
analyze_headers.py — Security & routing analysis of email headers.

============================================================================
INPUT
============================================================================
A JSON document with a top-level "headers" object. Header names are matched
case-insensitively. Values are strings, or lists of strings for repeated
headers (most importantly "Received", ordered top-to-bottom as they appear
in the raw email, i.e. newest hop first).

    { "headers": {
        "From": "Alice <alice@example.com>",
        "Reply-To": "attacker@evil.example",
        "Return-Path": "<bounce@mailer.example.com>",
        "Subject": "...", "Date": "...", "Message-ID": "<id@host>",
        "Received": ["from ... by ...; <date>", ...],
        "Authentication-Results": "...; spf=pass ...; dkim=fail; dmarc=fail",
        "Received-SPF": "pass (...)"
    } }

CLI:
    --input / -i FILE     read the JSON from FILE (default: stdin)
    --pretty              pretty-print the JSON report
    --format json|text    "text" prints a human-readable summary
                          (default: json)

============================================================================
OUTPUT (single JSON object on stdout)
============================================================================
    {
      "summary": {
        "verdict": "one-line human verdict",
        "risk_score": 0-100,           # heuristic; higher = more suspicious
        "risk_level": "low"|"medium"|"high"
      },
      "identity": {
        "from":        {"name": ..., "email": ..., "domain": ...},
        "reply_to":    {...} | null,
        "return_path": {...} | null,
        "alignment": {
          "from_vs_reply_to":   "aligned"|"mismatch"|"n/a",
          "from_vs_return_path":"aligned"|"mismatch"|"n/a",
          "from_vs_message_id": "aligned"|"mismatch"|"n/a"
        }
      },
      "authentication": { "spf": ..., "dkim": ..., "dmarc": ...,
                          "raw_authentication_results": ...,
                          "raw_received_spf": ... },
      "routing": {
        "hop_count": N,
        "total_transit_seconds": N | null,
        "hops": [                       # oldest first
          {"index": 1, "from_host": ..., "from_ip": ..., "by_host": ...,
           "timestamp": "ISO-8601" | null, "delay_seconds": N | null,
           "flags": ["unknown_reverse_dns", "private_ip", ...]}
        ]
      },
      "findings": [
        {"severity": "info"|"warning"|"critical",
         "code": "MACHINE_CODE", "message": "human explanation"}
      ]
    }

============================================================================
EXIT CODES
============================================================================
    0  analysis completed (regardless of verdict)
    1  invalid input (bad JSON / missing "headers" key)
    2  file not found
============================================================================
"""

import argparse
import ipaddress
import json
import re
import sys
from email.utils import parseaddr, parsedate_to_datetime

# Authentication results that count as a hard failure vs. a soft problem.
AUTH_FAIL = {"fail", "permerror"}
AUTH_SOFT = {"softfail", "temperror", "none", "neutral"}


def norm_headers(headers: dict) -> dict:
    """Lowercase all header names; keep values untouched.

    Input : raw "headers" dict from the JSON payload.
    Output: {lowercased_name: value} — repeated headers stay lists.
    """
    return {str(k).lower(): v for k, v in headers.items()}


def first(value):
    """Return the first element when a header arrived as a list."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def addr_info(raw):
    """Parse 'Display Name <user@dom>' into name/email/domain parts.

    Input : raw header string (or None).
    Output: {"name","email","domain"} or None if no address is present.
    """
    if not raw:
        return None
    name, email = parseaddr(str(raw))
    if not email or "@" not in email:
        return None
    return {"name": name or None, "email": email.lower(),
            "domain": email.rsplit("@", 1)[1].lower()}


def base_domain(domain):
    """Crude registrable-domain extraction: last two labels.

    'a.b.example.co' -> 'example.co'. Good enough for alignment checks
    without shipping a public-suffix list.
    """
    if not domain:
        return None
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def parse_auth_results(auth_raw, spf_raw):
    """Extract spf/dkim/dmarc results from Authentication-Results and
    Received-SPF header values.

    Input : the two raw header strings (either may be None).
    Output: {"spf": "pass|fail|...|None", "dkim": ..., "dmarc": ...}.
    Authentication-Results wins; Received-SPF fills SPF only if missing.
    """
    out = {"spf": None, "dkim": None, "dmarc": None}
    if auth_raw:
        text = " ".join(auth_raw) if isinstance(auth_raw, list) else auth_raw
        for mech in out:
            m = re.search(rf"\b{mech}\s*=\s*([a-zA-Z]+)", text)
            if m:
                out[mech] = m.group(1).lower()
    if out["spf"] is None and spf_raw:
        m = re.match(r"\s*([a-zA-Z]+)", first(spf_raw) or "")
        if m:
            out["spf"] = m.group(1).lower()
    return out


# Received line: "from <host> (<helo/rdns> [<ip>]) by <host> ...; <date>"
RE_RECV_FROM = re.compile(
    r"from\s+(?P<host>\S+)(?:\s+\((?P<paren>[^)]*)\))?", re.IGNORECASE)
RE_RECV_BY = re.compile(r"\bby\s+(?P<by>\S+)", re.IGNORECASE)
RE_RECV_IP = re.compile(r"\[(?P<ip>[0-9a-fA-F.:]+)\]")


def parse_received(lines):
    """Parse the Received chain into structured hops.

    Input : list of Received header strings, NEWEST first (header order).
    Output: list of hop dicts OLDEST first, each with per-hop delay in
            seconds computed from consecutive hop timestamps.
    """
    hops = []
    for line in lines:
        line = str(line)
        hop = {"from_host": None, "from_ip": None, "by_host": None,
               "timestamp": None, "delay_seconds": None, "flags": []}
        m = RE_RECV_FROM.search(line)
        if m:
            hop["from_host"] = m.group("host")
            paren = m.group("paren") or ""
            ipm = RE_RECV_IP.search(paren) or RE_RECV_IP.search(line)
            if ipm:
                hop["from_ip"] = ipm.group("ip")
            if "unknown" in paren.lower():
                hop["flags"].append("unknown_reverse_dns")
        m = RE_RECV_BY.search(line)
        if m:
            hop["by_host"] = m.group("by")
        # The date is everything after the last ';'.
        if ";" in line:
            try:
                d = parsedate_to_datetime(line.rsplit(";", 1)[1].strip())
                hop["timestamp"] = d.isoformat()
                hop["_dt"] = d
            except Exception:
                pass
        if hop["from_ip"]:
            try:
                if not ipaddress.ip_address(hop["from_ip"]).is_global:
                    hop["flags"].append("private_ip")
            except ValueError:
                hop["from_ip"] = None
        hops.append(hop)

    hops.reverse()                       # oldest hop first
    prev = None
    for i, hop in enumerate(hops, 1):
        hop["index"] = i
        cur = hop.pop("_dt", None)
        if cur and prev:
            hop["delay_seconds"] = int((cur - prev).total_seconds())
        if cur:
            prev = cur
    return hops


def analyze(headers: dict) -> dict:
    """Core analysis: run every check and build the full report dict.

    Input : normalized (lowercase-keyed) headers dict.
    Output: report dict following the schema in the module docstring.
    """
    findings = []

    def finding(severity, code, message):
        findings.append({"severity": severity, "code": code,
                         "message": message})

    # ------------------------------------------------------------------
    # Identity & alignment
    # ------------------------------------------------------------------
    frm = addr_info(first(headers.get("from")))
    reply_to = addr_info(first(headers.get("reply-to")))
    return_path = addr_info(first(headers.get("return-path")))
    msgid = first(headers.get("message-id"))
    msgid_domain = None
    if msgid:
        m = re.search(r"@([A-Za-z0-9.\-]+)", str(msgid))
        if m:
            msgid_domain = m.group(1).lower().rstrip(">")

    def align(a, b):
        if not a or not b:
            return "n/a"
        return "aligned" if base_domain(a) == base_domain(b) else "mismatch"

    alignment = {
        "from_vs_reply_to": align(frm and frm["domain"],
                                  reply_to and reply_to["domain"]),
        "from_vs_return_path": align(frm and frm["domain"],
                                     return_path and return_path["domain"]),
        "from_vs_message_id": align(frm and frm["domain"], msgid_domain),
    }
    if alignment["from_vs_reply_to"] == "mismatch":
        finding("critical", "REPLY_TO_MISMATCH",
                f"Reply-To domain ({reply_to['domain']}) differs from From "
                f"domain ({frm['domain']}) — replies are diverted to a "
                "different party, a classic phishing pattern.")
    if alignment["from_vs_return_path"] == "mismatch":
        finding("warning", "RETURN_PATH_MISALIGNED",
                f"Return-Path domain ({return_path['domain']}) does not "
                f"match From domain ({frm['domain']}) — possible spoofing "
                "or a bulk-mailing service.")
    if alignment["from_vs_message_id"] == "mismatch":
        finding("info", "MSGID_DOMAIN_MISMATCH",
                f"Message-ID domain ({msgid_domain}) differs from From "
                f"domain — weak spoofing signal (some providers do this "
                "legitimately).")

    # ------------------------------------------------------------------
    # Authentication (SPF / DKIM / DMARC)
    # ------------------------------------------------------------------
    auth = parse_auth_results(headers.get("authentication-results"),
                              headers.get("received-spf"))
    for mech, res in auth.items():
        if res in AUTH_FAIL:
            finding("critical", f"{mech.upper()}_FAIL",
                    f"{mech.upper()} check failed ({res}) — the sending "
                    "server is not authorized / the signature is invalid.")
        elif res in AUTH_SOFT:
            finding("warning", f"{mech.upper()}_WEAK",
                    f"{mech.upper()} result is '{res}' — authentication is "
                    "not established.")
    if all(v is None for v in auth.values()):
        finding("warning", "NO_AUTH_RESULTS",
                "No Authentication-Results / Received-SPF headers present — "
                "SPF/DKIM/DMARC could not be evaluated.")

    # ------------------------------------------------------------------
    # Routing (Received chain)
    # ------------------------------------------------------------------
    received = headers.get("received") or []
    if isinstance(received, str):
        received = [received]
    hops = parse_received(received)
    delays = [h["delay_seconds"] for h in hops
              if h.get("delay_seconds") is not None]
    total_transit = sum(delays) if delays else None
    if not hops:
        finding("warning", "NO_RECEIVED_CHAIN",
                "No Received headers — cannot trace the delivery path "
                "(normal only for locally generated mail).")
    for h in hops:
        if "unknown_reverse_dns" in h["flags"]:
            finding("warning", "UNKNOWN_RELAY",
                    f"Hop {h['index']}: relay {h['from_host']} has no valid "
                    "reverse DNS ('unknown') — common for botnet/compromised "
                    "senders.")
        if "private_ip" in h["flags"] and h["index"] not in (1, len(hops)):
            finding("info", "PRIVATE_IP_MID_CHAIN",
                    f"Hop {h['index']}: private IP {h['from_ip']} appears "
                    "mid-chain.")
        if (h.get("delay_seconds") or 0) > 3600:
            finding("warning", "LARGE_HOP_DELAY",
                    f"Hop {h['index']}: {h['delay_seconds']}s delay — "
                    "queuing, greylisting, or timestamp manipulation.")
        if (h.get("delay_seconds") or 0) < -300:
            finding("warning", "NEGATIVE_HOP_DELAY",
                    f"Hop {h['index']}: negative delay "
                    f"({h['delay_seconds']}s) — inconsistent timestamps.")

    # ------------------------------------------------------------------
    # Missing critical headers & date sanity
    # ------------------------------------------------------------------
    for hname, code in (("from", "MISSING_FROM"), ("date", "MISSING_DATE"),
                        ("message-id", "MISSING_MSGID")):
        if not first(headers.get(hname)):
            finding("warning", code,
                    f"'{hname.title()}' header is missing — unusual for "
                    "legitimate mail.")
    try:
        sent = parsedate_to_datetime(str(first(headers.get("date"))))
        last_ts = None
        for h in reversed(hops):
            if h.get("timestamp"):
                last_ts = parsedate_to_datetime(h["timestamp"]) \
                    if not re.match(r"\d{4}-", h["timestamp"]) else None
        # ISO timestamps: compare using fromisoformat instead.
        if last_ts is None and hops and hops[-1].get("timestamp"):
            import datetime as _dt
            last_ts = _dt.datetime.fromisoformat(hops[-1]["timestamp"])
        if sent and last_ts and (sent - last_ts).total_seconds() > 86400:
            finding("warning", "DATE_IN_FUTURE",
                    "Date header is more than a day ahead of the final "
                    "Received timestamp — likely forged sending time.")
    except Exception:
        pass

    # ------------------------------------------------------------------
    # Risk score: weighted sum of findings, capped at 100.
    #   critical = 25, warning = 10, info = 3
    # ------------------------------------------------------------------
    weights = {"critical": 25, "warning": 10, "info": 3}
    risk = min(100, sum(weights[f["severity"]] for f in findings))
    level = "high" if risk >= 60 else "medium" if risk >= 30 else "low"
    n_crit = sum(1 for f in findings if f["severity"] == "critical")
    n_warn = sum(1 for f in findings if f["severity"] == "warning")
    verdict = (
        "Headers show strong indicators of spoofing/phishing"
        if level == "high" else
        "Headers contain suspicious indicators worth reviewing"
        if level == "medium" else
        "Headers look consistent with legitimate mail")
    verdict += f" ({n_crit} critical, {n_warn} warning finding(s))."

    return {
        "summary": {"verdict": verdict, "risk_score": risk,
                    "risk_level": level},
        "identity": {"from": frm, "reply_to": reply_to,
                     "return_path": return_path, "alignment": alignment},
        "authentication": {
            **auth,
            "raw_authentication_results":
                first(headers.get("authentication-results")),
            "raw_received_spf": first(headers.get("received-spf")),
        },
        "routing": {"hop_count": len(hops),
                    "total_transit_seconds": total_transit, "hops": hops},
        "findings": findings,
    }


def render_text(report):
    """Compact human-readable rendering for --format text."""
    s = report["summary"]
    lines = [f"Verdict : {s['verdict']}",
             f"Risk    : {s['risk_score']}/100 ({s['risk_level']})",
             "Findings:"]
    for f in report["findings"]:
        lines.append(f"  [{f["severity"].upper():>8}] {f['code']}: "
                     f"{f['message']}")
    if not report["findings"]:
        lines.append("  (none)")
    a = report["authentication"]
    lines.append(f"Auth    : spf={a['spf']} dkim={a['dkim']} "
                 f"dmarc={a['dmarc']}")
    r = report["routing"]
    lines.append(f"Routing : {r['hop_count']} hop(s), total transit "
                 f"{r['total_transit_seconds']}s")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Analyze email headers (JSON with a 'headers' object) "
                    "for spoofing, auth failures, and routing anomalies.")
    ap.add_argument("--input", "-i", help="JSON file (default: stdin)")
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("--format", choices=["json", "text"], default="json")
    args = ap.parse_args(argv)

    try:
        raw = (open(args.input, "r", encoding="utf-8").read()
               if args.input else sys.stdin.read())
    except FileNotFoundError:
        print(f"error: file not found: {args.input}", file=sys.stderr)
        return 2
    try:
        payload = json.loads(raw)
        headers = payload["headers"]
        if not isinstance(headers, dict):
            raise KeyError
    except (json.JSONDecodeError, KeyError, TypeError):
        print("error: input must be JSON with a top-level 'headers' object",
              file=sys.stderr)
        return 1

    report = analyze(norm_headers(headers))
    if args.format == "text":
        print(render_text(report))
    else:
        print(json.dumps(report, indent=2 if args.pretty else None,
                         ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
