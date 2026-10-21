"""
redact.py - remove email content from a triage report for read-only users.

Purpose:
    The read-only role may start analyses and read reports, but must not
    see what the email says or who it was sent to. The server applies this
    filter before a report leaves it, so hidden data never reaches the
    browser (hiding it in the page alone would not be enough).

What is removed (replaced with "[hidden]" or emptied):
    * subject, display names, recipient list
    * raw Authentication-Results / Received-SPF header text
    * quoted body text ("matched text: '...'"), text read from images,
      decoded QR text beyond the URL path, YARA matched bytes
    * free-text AI explanations of the body and images (they may quote the
      message) and every "injection_evidence" quote
    * the server-side input path (and the uploaded file name, unless the
      caller passes a safe display name)

What is masked everywhere else (every string in the report):
    * e-mail addresses keep only the domain:   anna@corp.example -> ***@corp.example
    * URLs lose their query string and fragment, which is where victim
      addresses and tokens usually are:
          https://evil.example/login?u=anna@corp.example -> https://evil.example/login

What stays:
    verdicts, scores, confidence, signal names and points, header findings
    (with addresses masked), authentication results, routing, sender domain,
    domains, IPs, hashes, URLs (masked), attachment names and checks, threat
    intel, WHOIS, YARA rule names, the AI analyst's verdict and summary
    (masked).

Input / output:
    redact_report(report_dict) -> new dict (the input is not modified),
    with "redacted": {"role": "readonly", "note": ...} added.
"""

import copy
import re

HIDDEN = "[hidden]"

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+'-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
_URL_RE = re.compile(r"((?:https?|hxxps?)://[^\s\"'<>?#]+)[?#][^\s\"'<>]*",
                     re.IGNORECASE)
_QUOTE_PATTERNS = (
    re.compile(r"matched text: '.*?'(?=;|$)", re.DOTALL),
    re.compile(r'text in image: ".*?"(?=;|$)', re.DOTALL),
)


def mask_text(value):
    """
    Input:  any string.
    Output: the string with e-mail local parts replaced by *** and URL query
            strings / fragments removed.
    """
    value = _URL_RE.sub(r"\1", value)
    return _EMAIL_RE.sub(r"***@\1", value)


def _mask_all(obj):
    """Recursively apply mask_text to every string in lists / dicts."""
    if isinstance(obj, str):
        return mask_text(obj)
    if isinstance(obj, list):
        return [_mask_all(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _mask_all(v) for k, v in obj.items()}
    return obj


def _strip_quotes(text):
    """Replace quoted message text inside a signal detail with [hidden]."""
    for pat in _QUOTE_PATTERNS:
        text = pat.sub(lambda m: m.group(0).split(":")[0] + ": " + HIDDEN,
                       text)
    return text


def _hide(d, *keys):
    """Set the given keys of dict d to HIDDEN when present and non-empty."""
    if isinstance(d, dict):
        for k in keys:
            if d.get(k):
                d[k] = HIDDEN


def redact_report(report, display_name=None):
    """
    Input:  report       - full triage report (dict, as written by
                           triage_pipeline.py).
            display_name - what to show as the input file name (the web UI
                           passes the uploaded name for your own uploads
                           and "email-<id>" for other people's). None hides
                           the name.
    Output: a deep copy with the email content removed (see module doc).
    """
    r = copy.deepcopy(report or {})

    email = r.get("email") or {}
    _hide(email, "subject")
    if isinstance(email.get("from"), dict):
        _hide(email["from"], "name")
    if email.get("to"):
        email["to"] = []

    ha = r.get("header_analysis") or {}
    ident = ha.get("identity") or {}
    for part in ("from", "reply_to", "return_path"):
        if isinstance(ident.get(part), dict):
            _hide(ident[part], "name")
    _hide(ident.get("sender_flags") or {}, "display_name")
    _hide(ha.get("authentication") or {},
          "raw_authentication_results", "raw_received_spf")

    body = r.get("body_analysis") or {}
    body.pop("source", None)
    for sig in body.get("signals") or []:
        if isinstance(sig, dict) and isinstance(sig.get("detail"), str):
            sig["detail"] = _strip_quotes(sig["detail"])

    _hide(r.get("body_ai_analysis") or {}, "reasoning", "injection_evidence")
    img = r.get("image_ai_analysis") or {}
    _hide(img, "text_found", "reasoning", "injection_evidence")
    _hide(r.get("ai_analysis") or {}, "injection_evidence")

    for sig in (r.get("verdict") or {}).get("signals") or []:
        if isinstance(sig, dict) and isinstance(sig.get("detail"), str):
            sig["detail"] = _strip_quotes(sig["detail"])

    for match in (r.get("yara") or {}).get("matches") or []:
        if isinstance(match, dict):
            for s in match.get("strings") or []:
                if isinstance(s, dict) and "data" in s:
                    s["data"] = HIDDEN

    if r.get("input_file"):
        # Uploaded file names often repeat the subject line.
        r["input_file"] = display_name or HIDDEN

    r = _mask_all(r)
    r["redacted"] = {
        "role": "readonly",
        "note": "Email content is hidden for read-only users: subject, "
                "recipients, display names, quoted text, text read from "
                "images and raw headers. Addresses show only their domain "
                "and URLs are shown without query strings.",
    }
    return r
