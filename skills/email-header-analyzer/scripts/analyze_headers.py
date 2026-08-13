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

# ---------------------------------------------------------------------------
# Consumer webmail providers. Perfectly legitimate for personal correspondence,
# but a red flag when the message claims to speak for an organisation, and a
# strong one when it is the Reply-To of a mail that looks corporate — the
# standard shape of business email compromise (BEC).
# ---------------------------------------------------------------------------
FREEMAIL_DOMAINS = {
    # global
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "msn.com", "yahoo.com", "ymail.com", "rocketmail.com", "aol.com",
    "icloud.com", "me.com", "mac.com", "proton.me", "protonmail.com",
    "gmx.com", "gmx.net", "mail.com", "zoho.com", "yandex.com", "yandex.ru",
    "tutanota.com", "fastmail.com", "hushmail.com",
    # disposable / throwaway, frequently used by attackers
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "temp-mail.org",
    "throwawaymail.com", "sharklasers.com", "yopmail.com",
    # regional (Turkey and neighbours)
    "yandex.com.tr", "mynet.com", "superonline.com", "ttmail.com",
}

# Organisation names commonly impersonated in the display name. Used only to
# spot "<brand> Security <someone@unrelated.tld>" — the body-level brand
# tables live in the email-anomaly-detector skill.
IMPERSONATED_TERMS = {
    "paypal", "amazon", "apple", "microsoft", "office365", "google", "netflix",
    "facebook", "instagram", "linkedin", "dhl", "fedex", "ups", "ptt", "visa",
    "mastercard", "stripe", "ziraat", "garanti", "akbank", "halkbank",
    "vakifbank", "isbank", "yapikredi", "papara", "trendyol", "hepsiburada",
    "turkcell", "vodafone", "bank", "banka", "helpdesk", "it support",
    "support team", "security team", "payroll", "hr department",
}

# Right-to-left override and friends: invisible characters that reverse how a
# string is displayed, used to disguise addresses and file names.
BIDI_CONTROLS = {"\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
                 "\u2066", "\u2067", "\u2068", "\u2069", "\u200f", "\u200e"}


def is_freemail(domain):
    """True when a domain is a consumer webmail or disposable-mail provider.

    Input : registrable domain string (or None)
    Output: bool
    """
    if not domain:
        return False
    d = domain.lower()
    return d in FREEMAIL_DOMAINS or base_domain(d) in FREEMAIL_DOMAINS


def looks_deceptive_subdomain(domain):
    """Detect a real brand domain buried in someone else's subdomain chain.

    `paypal.com.security-check.xyz` reads as "paypal.com" to a hurried human
    but is really a host under `security-check.xyz`. The trick is that a
    legitimate-looking domain (label + TLD-like label) appears somewhere other
    than the final two labels.

    Input : full hostname, e.g. "paypal.com.guvenlik.xyz"
    Output: the impersonated fragment ("paypal.com") or None.
    """
    if not domain:
        return None
    labels = domain.lower().strip(".").split(".")
    if len(labels) < 4:          # need at least brand.tld.something.tld
        return None
    # Look at every adjacent pair before the registrable domain itself.
    common_tlds = {"com", "net", "org", "gov", "edu", "co", "io", "tr",
                   "de", "fr", "uk", "ru"}
    for i in range(len(labels) - 3):
        if labels[i + 1] in common_tlds and len(labels[i]) > 2:
            return f"{labels[i]}.{labels[i + 1]}"
    return None


def has_punycode(domain):
    """True when any label of the domain is IDN/punycode-encoded (xn--).

    Punycode is legitimate for non-Latin scripts, but it is also how homograph
    attacks are transmitted: `xn--pypal-4ve.com` renders as `pаypal.com` with
    a Cyrillic 'а'. Worth surfacing so a human can decode it.
    """
    return bool(domain) and any(lbl.startswith("xn--")
                                for lbl in domain.lower().split("."))


def has_bidi_control(text):
    """True when a string contains bidirectional-override characters."""
    return bool(text) and any(ch in BIDI_CONTROLS for ch in text)


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
    # Sender-identity deception
    #
    # These checks look at WHO the message claims to be from, as opposed to
    # whether the transport authenticated it. They catch the cases where SPF,
    # DKIM and DMARC all pass — because the attacker really does own the
    # sending domain — but the message is still impersonating someone.
    # ------------------------------------------------------------------
    from_name = (frm or {}).get("name") or ""
    from_domain = (frm or {}).get("domain")

    # 1. Sender is a consumer webmail account.
    if is_freemail(from_domain):
        # Only interesting when the message presents itself as an
        # organisation; personal mail from a personal account is normal.
        claims_org = any(term in from_name.lower()
                         for term in IMPERSONATED_TERMS)
        if claims_org:
            finding("critical", "FREEMAIL_SENDER_IMPERSONATION",
                    f"Sender uses the consumer mail provider "
                    f"'{from_domain}' while presenting itself as "
                    f"'{from_name}' — organisations do not send official "
                    "mail from free webmail accounts.")
        else:
            finding("info", "FREEMAIL_SENDER",
                    f"Sender uses a consumer/disposable mail provider "
                    f"({from_domain}) — normal for personal mail, worth "
                    "noting for anything claiming to be official.")

    # 2. Reply-To points at a consumer webmail account.
    reply_domain = (reply_to or {}).get("domain")
    if reply_domain and is_freemail(reply_domain):
        if not is_freemail(from_domain):
            finding("critical", "FREEMAIL_REPLY_TO",
                    f"Replies are directed to a consumer mail account "
                    f"({reply_to['email']}) while the message comes from "
                    f"{from_domain} — the classic business email compromise "
                    "pattern.")
        else:
            finding("info", "FREEMAIL_REPLY_TO_CONSISTENT",
                    f"Reply-To is a consumer mail account "
                    f"({reply_domain}), consistent with the sender.")

    # 3 & 4. Display-name deception.
    if from_name:
        # An address inside the display name: many clients show only the
        # display name, so "support@bank.com" <attacker@evil.tld> looks
        # entirely legitimate at a glance.
        m = re.search(r"[\w.+-]+@([\w.-]+\.\w{2,})", from_name)
        if m:
            shown = m.group(1).lower()
            if base_domain(shown) != base_domain(from_domain or ""):
                finding("critical", "DISPLAY_NAME_SPOOFED_ADDRESS",
                        f"The display name contains the address "
                        f"'{m.group(0)}' but the message is really from "
                        f"{frm['email']} — mail clients often show only the "
                        "display name.")
        # A brand or department claimed in the display name while the actual
        # domain is unrelated.
        elif from_domain:
            name_l = from_name.lower()
            hit = next((t for t in IMPERSONATED_TERMS if t in name_l), None)
            if hit and hit not in from_domain.lower():
                finding("warning", "DISPLAY_NAME_BRAND_MISMATCH",
                        f"Display name claims '{from_name}' but the sending "
                        f"domain is {from_domain}, which is unrelated to "
                        f"'{hit}'.")
        # Invisible direction-control characters in the display name.
        if has_bidi_control(from_name):
            finding("critical", "DISPLAY_NAME_BIDI_OVERRIDE",
                    "The display name contains bidirectional-override "
                    "characters, which reverse how it is rendered and are "
                    "used to disguise the real sender.")

    # 5. A brand domain hidden inside someone else's subdomain chain.
    for label, dom in (("From", from_domain),
                       ("Reply-To", reply_domain),
                       ("Return-Path", (return_path or {}).get("domain"))):
        buried = looks_deceptive_subdomain(dom)
        if buried:
            finding("critical", "DECEPTIVE_SUBDOMAIN",
                    f"{label} host '{dom}' places '{buried}' in a subdomain "
                    f"of '{base_domain(dom)}' — it reads like {buried} but "
                    f"is controlled by {base_domain(dom)}.")

    # 6. Punycode / IDN domains, the transport form of homograph attacks.
    for label, dom in (("From", from_domain),
                       ("Reply-To", reply_domain),
                       ("Return-Path", (return_path or {}).get("domain"))):
        if has_punycode(dom):
            finding("warning", "PUNYCODE_DOMAIN",
                    f"{label} domain '{dom}' is IDN/punycode-encoded — it may "
                    "render as a familiar name using lookalike characters. "
                    "Decode it before trusting it.")

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
        "identity": {
            "from": frm, "reply_to": reply_to,
            "return_path": return_path, "alignment": alignment,
            # Machine-readable summary of the sender-deception checks, so
            # downstream consumers do not have to grep the findings list.
            "sender_flags": {
                "from_is_freemail": is_freemail(from_domain),
                "reply_to_is_freemail": is_freemail(reply_domain),
                "display_name": from_name or None,
                "deceptive_subdomain": looks_deceptive_subdomain(from_domain),
                "punycode": has_punycode(from_domain),
            }},
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
        lines.append(f"  [{f['severity'].upper():>8}] {f['code']}: "
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
