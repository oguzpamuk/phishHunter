#!/usr/bin/env python3
"""
ioc_extractor.py — Extract Indicators of Compromise (IOCs) from a parsed
email JSON document (output of the `email-parser` skill) or from raw text.

============================================================================
INPUT
============================================================================
One of the following (mutually exclusive):

  --input <file.json>   A JSON file produced by the email-parser skill.
                        Expected (all keys optional, missing keys tolerated):
                          {
                            "from":        {"name": "...", "email": "..."},
                            "to":          [{"name": "...", "email": "..."}],
                            "headers":     {"Received": ["...", ...], ...},
                            "body":        {"text": "...", "html": "..."},
                            "attachments": [{"filename": "...",
                                             "content_type": "...",
                                             "size_bytes": 123,
                                             "data_base64": "..."   # optional
                                            }]
                          }

  --text "<string>"     Raw text to scan (e.g. a pasted email body).

  --file <file.txt>     Raw text file to scan.

  (stdin)               If none of the above is given, JSON *or* raw text is
                        read from stdin. The script first tries JSON; if that
                        fails, the input is treated as raw text.

Options:
  --no-refang           Do NOT normalize defanged IOCs (hxxp://, [.], (.)).
                        By default defanged indicators are refanged so that
                        "hxxp://evil[.]com" is extracted as "http://evil.com".
  --no-allowlist        Do NOT filter out well-known infrastructure domains
                        (w3.org, schema.org, fonts.googleapis.com, ...).
                        The allowlist is ONLY applied to body/HTML-derived
                        domains — sender domains and Received-chain hosts are
                        never filtered.
  --include-private     Include private/reserved IPs (RFC1918, loopback,
                        link-local) in the output. Excluded by default
                        because they are useless for reputation lookups.
  -o / --output <file>  Write the JSON result to a file instead of stdout.
  --pretty              Pretty-print the JSON output (2-space indent).

============================================================================
OUTPUT (stdout or --output file)
============================================================================
A single JSON object:

  {
    "input_kind": "parsed_email" | "raw_text",
    "iocs": {
      "ips":     [ {"value": "1.2.3.4",  "sources": ["headers"],
                    "private": false}, ... ],
      "domains": [ {"value": "evil.com", "sources": ["body_url","from"]},... ],
      "urls":    [ {"value": "http://evil.com/x", "sources": ["body"]}, ... ],
      "hashes":  [ {"value": "<hex>", "algo": "md5|sha1|sha256",
                    "sources": ["body"]}, ... ],
      "emails":  [ {"value": "a@b.com", "sources": ["from"]}, ... ]
    },
    "attachments": [
      { "filename": "invoice.doc", "content_type": "...", "size_bytes": 123,
        "sha256": "<hex or null>",       # computed only if data_base64 given
        "risky_extension": true }        # .exe/.js/.iso/macro-docs/... flag
    ],
    "sender": { "email": "...", "domain": "..." },     # null when unknown
    "counts": { "ips": N, "domains": N, "urls": N, "hashes": N,
                "emails": N, "attachments": N },
    "warnings": [ "non-fatal notes" ]
  }

"sources" tells WHERE each IOC was found:
  from / reply_to / return_path / headers / body / body_url / html / subject

============================================================================
EXIT CODES
============================================================================
  0  success (even when zero IOCs were found)
  1  invalid input (unreadable file, no input at all)
  2  unexpected internal error
============================================================================
"""

import argparse
import base64
import hashlib
import io
import ipaddress
import json
import re
import sys
import zipfile
from html import unescape
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Regular expressions for the individual IOC types.
# They are intentionally pragmatic (SOC-triage grade), not full RFC parsers.
# ---------------------------------------------------------------------------
RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
                     r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
# Simplified IPv6 (full + compressed forms with at least two colons).
RE_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b")
RE_URL = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'\)\]\}]+", re.IGNORECASE)
# Domain: at least one dot, valid TLD-ish ending, no leading/trailing dash.
RE_DOMAIN = re.compile(
    r"\b(?=.{4,253}\b)((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,24})\b")
RE_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,24}\b")
RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
# href/src attributes inside HTML bodies (catches links hidden behind text).
RE_HTML_LINK = re.compile(r"""(?:href|src)\s*=\s*["']([^"']+)["']""",
                          re.IGNORECASE)

# Full anchor elements, so the visible text can be compared with the target.
# A link that reads "https://www.bank.com" but points somewhere else is one
# of the most reliable phishing indicators there is, and it is invisible to
# any check that only looks at href values.
RE_ANCHOR = re.compile(
    r"<a\b[^>]*?href\s*=\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</a>",
    re.IGNORECASE | re.DOTALL)

# File-name endings that frequently carry malware in email attachments.
# Used to raise the "risky_extension" flag on attachments.
RISKY_EXTENSIONS = {
    ".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".hta", ".jar", ".msi", ".iso", ".img", ".lnk",
    ".chm", ".cpl", ".reg", ".dll", ".docm", ".xlsm", ".pptm", ".dotm",
    ".xlam", ".rtf", ".html", ".htm", ".svg", ".one", ".vhd", ".vhdx",
}

# Domains that appear in virtually every HTML email and are noise for
# reputation lookups. Applied ONLY to body/HTML-derived domains.
ALLOWLIST_DOMAINS = {
    "w3.org", "schema.org", "fonts.googleapis.com", "fonts.gstatic.com",
    "gstatic.com", "googleapis.com", "cdnjs.cloudflare.com", "jquery.com",
    "adobe.com", "microsoft.com", "office.com", "apple.com", "mozilla.org",
}

# TLD-lookalike file extensions: "invoice.zip" matches RE_DOMAIN because
# .zip / .mov ARE real TLDs, but inside email text they are usually files.
AMBIGUOUS_FILE_TLDS = {"zip", "mov"}

# ---------------------------------------------------------------------------
# File-type identification by content ("magic bytes") rather than by name.
#
# An attachment's extension is attacker-controlled text; its first bytes are
# not. Comparing the two catches the oldest trick in the book — a payload
# named invoice.pdf that is really a Windows executable — and it costs
# nothing because the bytes are already in memory for hashing.
#
# Each entry: (signature, offset, canonical type, extensions that are
# legitimate for that type).
# ---------------------------------------------------------------------------
MAGIC_SIGNATURES = [
    (b"MZ", 0, "pe-executable", {".exe", ".dll", ".scr", ".sys", ".cpl",
                                 ".ocx", ".msi", ".com"}),
    (b"\x7fELF", 0, "elf-executable", {".so", ".elf", ".bin", ""}),
    (b"\xca\xfe\xba\xbe", 0, "mach-o/java-class", {".class", ".jar"}),
    (b"%PDF", 0, "pdf", {".pdf"}),
    (b"PK\x03\x04", 0, "zip-container", {
        # OOXML, OpenDocument, JARs and plain archives all share this header.
        ".zip", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm",
        ".dotm", ".xlam", ".odt", ".ods", ".odp", ".jar", ".apk", ".epub",
        ".vsdx", ".onepkg", ".kmz", ".xpi", ".crx"}),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "ole2-compound", {
        # Legacy Office, .msg files and some installers.
        ".doc", ".xls", ".ppt", ".msg", ".msi", ".db", ".vsd"}),
    (b"Rar!\x1a\x07", 0, "rar-archive", {".rar"}),
    (b"7z\xbc\xaf\x27\x1c", 0, "7z-archive", {".7z"}),
    (b"\x1f\x8b", 0, "gzip", {".gz", ".tgz", ".gzip"}),
    (b"BZh", 0, "bzip2", {".bz2", ".tbz"}),
    (b"\xfd7zXZ", 0, "xz", {".xz"}),
    (b"ustar", 257, "tar", {".tar"}),
    (b"\x89PNG", 0, "png", {".png"}),
    (b"\xff\xd8\xff", 0, "jpeg", {".jpg", ".jpeg", ".jfif"}),
    (b"GIF8", 0, "gif", {".gif"}),
    (b"RIFF", 0, "riff", {".wav", ".avi", ".webp"}),
    (b"\x25\x21PS", 0, "postscript", {".ps", ".eps"}),
    (b"{\\rtf", 0, "rtf", {".rtf", ".doc"}),
    (b"\x4c\x00\x00\x00\x01\x14\x02\x00", 0, "windows-shortcut", {".lnk"}),
    (b"CWS", 0, "shockwave-flash", {".swf"}),
    (b"CD001", 32769, "iso-image", {".iso"}),
]

# Extensions that are dangerous whatever they contain — used to judge the
# CONTENTS of an archive, where the outer .zip looks harmless.
ARCHIVE_INNER_RISKY = RISKY_EXTENSIONS | {".sh", ".py", ".pl", ".rb"}

# Bidirectional-override characters. In a file name they reverse how the
# rest of the string renders, so "annexe\u202egpj.exe" is displayed as
# "annexeexe.jpg" — a classic way to disguise an executable.
BIDI_CONTROLS = {"\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
                 "\u2066", "\u2067", "\u2068", "\u2069", "\u200f", "\u200e"}

# A double extension is only interesting when the FINAL one is executable and
# the one before it is a document/media type the user was expecting.
DECOY_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                    ".txt", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4",
                    ".csv", ".rtf", ".htm", ".html", ".zip"}


def identify_magic(raw):
    """Identify a file's real type from its leading bytes.

    Input : raw — the attachment's decoded bytes (may be short or empty)
    Output: (type_name, allowed_extensions) or (None, None) when the type is
            not one we recognise. An unknown type is never reported as a
            mismatch: absence of a signature is not evidence of deception.
    """
    for sig, offset, name, exts in MAGIC_SIGNATURES:
        if len(raw) >= offset + len(sig) and \
                raw[offset:offset + len(sig)] == sig:
            return name, exts
    return None, None


def find_double_extension(fname):
    """Detect a decoy extension in front of an executable one.

    Input : file name, e.g. "fatura.pdf.exe"
    Output: the pair as a string ("pdf.exe") or None.

    Only the combination matters: "report.2024.xlsx" has two dots but no
    executable tail, and "setup.exe" is honest about what it is.
    """
    parts = fname.lower().rsplit(".", 2)
    if len(parts) < 3:
        return None
    decoy, final = "." + parts[1], "." + parts[2]
    if decoy in DECOY_EXTENSIONS and final in RISKY_EXTENSIONS:
        return f"{parts[1]}.{parts[2]}"
    return None


def inspect_archive(raw, fname):
    """List a ZIP archive's contents and judge what is inside.

    Input : raw   — the archive bytes
            fname — the attachment name, used only for messages
    Output: dict describing the archive, or None when the bytes are not a
            readable ZIP:
              {"entry_count", "entries" (first 25 names), "risky_entries",
               "encrypted", "nested_archive", "truncated"}

    Only ZIP is handled, because it is the one container the standard library
    can open. RAR and 7z are reported by magic-byte type but not expanded —
    that is noted rather than silently skipped.

    Encryption matters: a password-protected archive (with the password
    helpfully supplied in the email body) is the standard way to smuggle
    malware past scanners, so it is surfaced even though the contents cannot
    be read.
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
        infos = zf.infolist()
    except Exception:
        return None

    names = [i.filename for i in infos]
    # Bit 0x1 of the general-purpose flag marks an encrypted entry.
    encrypted = any(i.flag_bits & 0x1 for i in infos)
    risky, nested = [], []
    for n in names:
        low = n.lower()
        ext = ("." + low.rsplit(".", 1)[-1]) if "." in low else ""
        if ext in ARCHIVE_INNER_RISKY:
            risky.append(n)
        if ext in {".zip", ".rar", ".7z", ".gz", ".iso", ".img"}:
            nested.append(n)
    return {
        "entry_count": len(names),
        "entries": names[:25],
        "truncated": len(names) > 25,
        "risky_entries": risky[:25],
        "encrypted": encrypted,
        "nested_archive": nested[:10],
    }


def refang(text: str) -> str:
    """Normalize common defanging notations back to real indicators.

    Input : arbitrary text possibly containing 'hxxp://', '[.]', '(.)',
            '[:]', '{.}' or ' dot ' style obfuscation.
    Output: the same text with those notations replaced so the IOC regexes
            can match ('hxxp://a[.]b' -> 'http://a.b').
    """
    replacements = [
        (re.compile(r"h..ps?://", re.IGNORECASE), lambda m: "https://" if "s" in m.group(0).lower().split(":")[0][-1] else "http://"),
    ]
    out = re.sub(r"hxxps://", "https://", text, flags=re.IGNORECASE)
    out = re.sub(r"hxxp://", "http://", out, flags=re.IGNORECASE)
    out = re.sub(r"fxp://", "ftp://", out, flags=re.IGNORECASE)
    for pat in (r"\[\.\]", r"\(\.\)", r"\{\.\}", r"\[dot\]", r"\(dot\)"):
        out = re.sub(pat, ".", out, flags=re.IGNORECASE)
    out = re.sub(r"\[:\]", ":", out)
    out = re.sub(r"\[at\]|\(at\)", "@", out, flags=re.IGNORECASE)
    return out


def strip_html(html: str) -> str:
    """Very small HTML→text conversion: drop tags, unescape entities.

    Input : HTML string.
    Output: plain text suitable for regex scanning (links are ALSO harvested
            separately from href/src attributes before stripping).
    """
    text = re.sub(r"<script[\s\S]*?</script>", " ", html, flags=re.IGNORECASE)
    text = re.sub(r"<style[\s\S]*?</style>", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    return unescape(text)


class IOCStore:
    """Deduplicating collector.

    Keeps one entry per unique IOC value and merges the list of 'sources'
    (locations inside the email where the value was observed).
    """

    def __init__(self):
        # maps: value(lowercased where appropriate) -> dict entry
        self.ips = {}
        self.domains = {}
        self.urls = {}
        self.hashes = {}
        self.emails = {}

    @staticmethod
    def _add(bucket: dict, key: str, entry: dict, source: str):
        if key in bucket:
            if source not in bucket[key]["sources"]:
                bucket[key]["sources"].append(source)
        else:
            entry["sources"] = [source]
            bucket[key] = entry

    def add_ip(self, value: str, source: str):
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return
        self._add(self.ips, str(ip),
                  {"value": str(ip), "private": not ip.is_global}, source)

    def add_domain(self, value: str, source: str):
        v = value.strip(".").lower()
        # Skip pure-numeric labels (looks like an IP fragment) and 1-label.
        if "." not in v or RE_IPV4.fullmatch(v):
            return
        # "invoice.zip" style filename false positives from body text.
        tld = v.rsplit(".", 1)[-1]
        if tld in AMBIGUOUS_FILE_TLDS and source in ("body", "html", "subject"):
            return
        self._add(self.domains, v, {"value": v}, source)

    def add_url(self, value: str, source: str):
        v = value.rstrip(".,;:!?)('\"]")
        self._add(self.urls, v, {"value": v}, source)
        # Every URL also contributes its hostname as a domain or IP.
        try:
            host = urlparse(v).hostname or ""
        except ValueError:
            host = ""
        if host:
            if RE_IPV4.fullmatch(host):
                self.add_ip(host, source + "_url")
            else:
                self.add_domain(host, source + "_url")

    def add_hash(self, value: str, algo: str, source: str):
        self._add(self.hashes, value.lower(),
                  {"value": value.lower(), "algo": algo}, source)

    def add_email(self, value: str, source: str):
        v = value.lower()
        self._add(self.emails, v, {"value": v}, source)
        # The domain part of any email address is itself an IOC candidate.
        self.add_domain(v.split("@", 1)[1], source)


def scan_text(store: IOCStore, text: str, source: str):
    """Run every IOC regex over `text`, feeding results into `store`.

    Input : store  — IOCStore accumulator
            text   — plain text to scan
            source — label recorded in each IOC's "sources" list
    Output: none (mutates `store`).

    Order matters for hashes: SHA256 is matched first and its spans are
    masked, otherwise a SHA256 would additionally match as MD5/SHA1
    substrings.
    """
    if not text:
        return
    for m in RE_URL.finditer(text):
        store.add_url(m.group(0), source)
    # Mask URLs so their hostnames are not re-extracted as bare domains
    # with a plain "body" source (they were already added with "_url").
    masked = RE_URL.sub(" ", text)
    for m in RE_EMAIL.finditer(masked):
        store.add_email(m.group(0), source)
    masked_no_mail = RE_EMAIL.sub(" ", masked)
    for m in RE_IPV4.finditer(masked_no_mail):
        store.add_ip(m.group(0), source)
    for m in RE_IPV6.finditer(masked_no_mail):
        # Filter obvious false positives such as MAC-like "aa:bb:cc:dd:ee:ff"
        cand = m.group(0)
        try:
            ipaddress.ip_address(cand)
        except ValueError:
            continue
        store.add_ip(cand, source)
    # Hashes — longest first, then mask.
    tmp = masked_no_mail
    for m in RE_SHA256.finditer(tmp):
        store.add_hash(m.group(0), "sha256", source)
    tmp = RE_SHA256.sub(" ", tmp)
    for m in RE_SHA1.finditer(tmp):
        store.add_hash(m.group(0), "sha1", source)
    tmp = RE_SHA1.sub(" ", tmp)
    for m in RE_MD5.finditer(tmp):
        store.add_hash(m.group(0), "md5", source)
    for m in RE_DOMAIN.finditer(masked_no_mail):
        store.add_domain(m.group(1), source)


def find_anchor_mismatches(html, refang_fn):
    """Compare each link's visible text with where it actually points.

    Input : html       — the HTML body
            refang_fn  — the refang helper, applied to both sides so that a
                         defanged decoy is compared fairly
    Output: list of dicts, one per deceptive link:
              {"text_shown", "text_domain", "href", "href_domain"}

    Only links whose VISIBLE TEXT is itself a URL or bare domain are
    considered: "click here" pointing anywhere is normal, but text that
    reads like `https://www.bank.example/login` while the href goes to
    `evil.example` is a deliberate lie about the destination.

    Comparison is on the registrable domain, so `mail.bank.example` and
    `bank.example` are treated as the same organisation and tracking or
    redirect wrappers on the same domain do not produce noise.
    """
    mismatches = []
    for m in RE_ANCHOR.finditer(html or ""):
        href = refang_fn(m.group(1).strip())
        # Visible text with tags stripped, e.g. <b>bank.example</b>.
        shown = unescape(re.sub(r"<[^>]+>", "", m.group(2) or "")).strip()
        shown = refang_fn(shown)
        if not shown or not href.lower().startswith(("http://", "https://")):
            continue
        # Does the visible text claim to be a location?
        text_host = None
        um = RE_URL.search(shown)
        if um:
            try:
                text_host = urlparse(um.group(0)).hostname
            except ValueError:
                text_host = None
        else:
            dm = RE_DOMAIN.fullmatch(shown.strip().strip("/"))
            if dm:
                text_host = dm.group(1)
        if not text_host:
            continue
        try:
            href_host = urlparse(href).hostname or ""
        except ValueError:
            continue

        def registrable(host):
            parts = (host or "").lower().strip(".").split(".")
            return ".".join(parts[-2:]) if len(parts) >= 2 else host

        if registrable(text_host) and \
                registrable(text_host) != registrable(href_host):
            mismatches.append({
                "text_shown": shown[:200],
                "text_domain": text_host.lower(),
                "href": href[:300],
                "href_domain": (href_host or "").lower(),
            })
    return mismatches


def decode_qr_codes(image_bytes):
    """Decode any QR codes in an image, if a decoder is installed.

    Input : image_bytes — raw bytes of a PNG/JPEG/GIF/etc.
    Output: (payloads, status)
              payloads — list of decoded strings (usually URLs)
              status   — "decoded" | "no_decoder" | "unreadable" | "none"

    QR decoding needs a native library, which would break this skill's
    "standard library only" promise if it were mandatory. So it is optional:
    pyzbar first (most accurate), then OpenCV as a fallback. With neither
    installed the caller still learns that an image was present and can hand
    it to the AI image stage instead of silently ignoring it.

    Install one of:
        pip install pyzbar       (also needs the libzbar system package)
        pip install opencv-python-headless
    """
    # --- Preferred: pyzbar -------------------------------------------------
    try:
        from pyzbar.pyzbar import decode as zbar_decode   # type: ignore
        from PIL import Image                             # type: ignore
        img = Image.open(io.BytesIO(image_bytes))
        found = [d.data.decode("utf-8", "replace") for d in zbar_decode(img)
                 if d.data]
        return found, ("decoded" if found else "none")
    except ImportError:
        pass
    except Exception:
        return [], "unreadable"

    # --- Fallback: OpenCV --------------------------------------------------
    try:
        import cv2                                        # type: ignore
        import numpy as np                                # type: ignore
        arr = np.frombuffer(image_bytes, dtype=np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if img is None:
            return [], "unreadable"
        detector = cv2.QRCodeDetector()
        ok, payloads, _pts, _ = detector.detectAndDecodeMulti(img)
        if ok:
            found = [p for p in payloads if p]
            return found, ("decoded" if found else "none")
        return [], "none"
    except ImportError:
        return [], "no_decoder"
    except Exception:
        return [], "unreadable"


# Inline images embedded directly in the HTML rather than attached, e.g.
# <img src="data:image/png;base64,iVBORw0KGgo...">. Attackers use these to
# ship a lure that no text-based check can read.
RE_DATA_URI_IMAGE = re.compile(
    r"""data:image/(png|jpe?g|gif|bmp|webp);base64,([A-Za-z0-9+/=\s]{40,})""",
    re.IGNORECASE)


def collect_images(parsed, html):
    """Gather every image carried by the message, from both places it hides.

    Input : parsed — the email-parser output (for inline/attached parts)
            html   — the HTML body (for data: URIs)
    Output: list of {"source", "name", "bytes", "size_bytes"} dicts.
            "source" is "attachment" or "data-uri" so the report can say
            where each image came from.

    Only images are returned; other attachments are handled elsewhere.
    """
    images = []
    for att in parsed.get("attachments") or []:
        ctype = (att.get("content_type") or "").lower()
        name = att.get("filename") or att.get("content_id") or "inline-image"
        looks_image = ctype.startswith("image/") or \
            name.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp",
                                   ".webp"))
        if not looks_image or not att.get("data_base64"):
            continue
        try:
            raw = base64.b64decode(att["data_base64"])
        except Exception:
            continue
        images.append({"source": "attachment", "name": name, "bytes": raw,
                       "size_bytes": len(raw)})

    for i, m in enumerate(RE_DATA_URI_IMAGE.finditer(html or "")):
        try:
            raw = base64.b64decode(re.sub(r"\s+", "", m.group(2)))
        except Exception:
            continue
        images.append({"source": "data-uri",
                       "name": f"embedded-image-{i + 1}.{m.group(1).lower()}",
                       "bytes": raw, "size_bytes": len(raw)})
    return images


def measure_visible_text(html, text_body):
    """Estimate how much readable text the message actually has.

    Input : html      — HTML body (may be None)
            text_body — plain-text body (may be None)
    Output: character count of the visible text, ignoring markup and
            whitespace runs.

    Used to spot the "the whole email is one picture" technique: a message
    with images but almost no text has deliberately put its content beyond
    the reach of every text-based check, including the AI body stage.
    """
    if text_body and text_body.strip():
        return len(re.sub(r"\s+", " ", text_body).strip())
    if html:
        return len(re.sub(r"\s+", " ", strip_html(html)).strip())
    return 0


def extract_from_parsed_email(parsed: dict, store: IOCStore,
                              warnings: list, do_refang: bool):
    """Walk a parsed-email JSON dict and harvest IOCs from each region.

    Input : parsed   — dict following the email-parser output schema
            store    — IOCStore accumulator
            warnings — list collecting non-fatal notes
            do_refang— whether defanged notations should be normalized
    Output: (sender_info, attachments_out)
            sender_info     — {"email": ..., "domain": ...} or None
            attachments_out — list of attachment summary dicts (see module
                              docstring, "attachments" section)
    """
    prep = (lambda s: refang(s)) if do_refang else (lambda s: s)

    anchor_mismatches = []
    images_out = []
    visible_chars = 0
    # --- Envelope / identity fields -------------------------------------
    sender_info = None
    frm = parsed.get("from") or {}
    if isinstance(frm, dict) and frm.get("email"):
        store.add_email(frm["email"], "from")
        sender_info = {"email": frm["email"].lower(),
                       "domain": frm["email"].split("@")[-1].lower()}

    headers = parsed.get("headers") or {}
    # Header names are matched case-insensitively.
    hmap = {str(k).lower(): v for k, v in headers.items()} \
        if isinstance(headers, dict) else {}

    for hname, src in (("reply-to", "reply_to"),
                       ("return-path", "return_path")):
        val = hmap.get(hname)
        if isinstance(val, str):
            for m in RE_EMAIL.finditer(val):
                store.add_email(m.group(0), src)

    # --- Received chain: relay hostnames + IPs --------------------------
    received = hmap.get("received")
    if received:
        lines = received if isinstance(received, list) else [received]
        for line in lines:
            scan_text(store, prep(str(line)), "headers")

    # --- Subject --------------------------------------------------------
    if parsed.get("subject"):
        scan_text(store, prep(str(parsed["subject"])), "subject")

    # --- Bodies ---------------------------------------------------------
    body = parsed.get("body") or {}
    if body.get("text"):
        scan_text(store, prep(body["text"]), "body")
    if body.get("html"):
        html = body["html"]
        # Harvest explicit link targets first (href / src attributes).
        for m in RE_HTML_LINK.finditer(html):
            target = prep(m.group(1).strip())
            if target.lower().startswith(("http://", "https://", "ftp://")):
                store.add_url(target, "html")
        scan_text(store, prep(strip_html(html)), "html")
        # Links whose visible text lies about their destination.
        anchor_mismatches.extend(find_anchor_mismatches(html, prep))

    # --- Embedded images and QR codes -----------------------------------
    # A QR code is just a URL the recipient cannot read, so any payload we
    # decode is fed into the normal IOC pipeline: it gets reputation
    # lookups, WHOIS age and everything else a typed link would get.
    html_body = body.get("html") or ""
    images = collect_images(parsed, html_body)
    visible_chars = measure_visible_text(html_body, body.get("text"))
    for img in images:
        payloads, status = decode_qr_codes(img["bytes"])
        entry = {"source": img["source"], "name": img["name"],
                 "size_bytes": img["size_bytes"], "qr_status": status,
                 "qr_payloads": payloads}
        for payload in payloads:
            refanged = prep(payload)
            if refanged.lower().startswith(("http://", "https://", "ftp://")):
                store.add_url(refanged, "qr_code")
            else:
                # Non-URL QR payloads still matter: mailto:, tel:, WIFI:,
                # or a bare domain are all worth showing the analyst.
                scan_text(store, refanged, "qr_code")
        images_out.append(entry)
        if status == "no_decoder":
            warnings.append(
                "QR decoding unavailable — install pyzbar or "
                "opencv-python-headless to read codes inside images")

    # --- Attachments ----------------------------------------------------
    attachments_out = []
    for att in parsed.get("attachments") or []:
        fname = att.get("filename") or ""
        ext = ("." + fname.rsplit(".", 1)[-1].lower()) if "." in fname else ""
        sha256 = None
        raw = None
        data_b64 = att.get("data_base64")
        if data_b64:
            # SHA256 of the raw attachment bytes — directly consumable by
            # the ioc-orchestrator / VirusTotal hash lookups.
            try:
                raw = base64.b64decode(data_b64)
                sha256 = hashlib.sha256(raw).hexdigest()
                store.add_hash(sha256, "sha256", "attachment")
            except Exception:
                warnings.append(f"attachment '{fname}': base64 decode failed")
        # --- Content-based checks (only possible when bytes are present) --
        # Each of these looks at what the file IS rather than what it is
        # called, so none of them can be defeated by renaming.
        magic_type = None
        extension_mismatch = None
        archive = None
        if raw is not None:
            magic_type, allowed = identify_magic(raw)
            if magic_type and ext and ext not in allowed:
                # Known type, but the extension is not one that type uses.
                extension_mismatch = (
                    f"declared '{ext}' but the content is {magic_type}")
            if magic_type in ("zip-container", "rar-archive", "7z-archive"):
                archive = inspect_archive(raw, fname)
                if archive is None and magic_type != "zip-container":
                    # RAR/7z cannot be expanded with the standard library.
                    archive = {"entry_count": None, "entries": [],
                               "truncated": False, "risky_entries": [],
                               "encrypted": None, "nested_archive": [],
                               "note": f"{magic_type} contents not inspected "
                                       "(no stdlib reader)"}

        double_ext = find_double_extension(fname)
        bidi = any(ch in BIDI_CONTROLS for ch in fname)

        attachments_out.append({
            "filename": fname or None,
            "content_type": att.get("content_type"),
            "size_bytes": att.get("size_bytes"),
            "sha256": sha256,
            "risky_extension": ext in RISKY_EXTENSIONS,
            # Real type from the leading bytes; None when unrecognised.
            "magic_type": magic_type,
            # Set when the extension contradicts the content.
            "extension_mismatch": extension_mismatch,
            # "pdf.exe" style decoy, or None.
            "double_extension": double_ext,
            # Bidirectional-override characters hiding the real extension.
            "bidi_filename": bidi,
            # ZIP listing: contents, risky entries, encryption flag.
            "archive": archive,
        })
    return (sender_info, attachments_out, anchor_mismatches,
            {"images": images_out, "visible_text_chars": visible_chars})


def build_result(store: IOCStore, input_kind: str, sender, attachments,
                 warnings, use_allowlist: bool, include_private: bool,
                 anchor_mismatches=None, media=None):
    """Assemble the final JSON-serializable result dict.

    Applies output filters:
      * allowlist   — drop well-known benign domains that were ONLY seen in
                      body/html sources (never sender/header sources).
      * private IPs — dropped unless include_private is True.
    """
    def keep_domain(entry):
        if not use_allowlist:
            return True
        v = entry["value"]
        listed = any(v == d or v.endswith("." + d) for d in ALLOWLIST_DOMAINS)
        if not listed:
            return True
        # Keep it anyway if it was seen in an identity/header context.
        trusted_only = {"body", "html", "subject", "body_url", "html_url"}
        return any(s not in trusted_only for s in entry["sources"])

    ips = [e for e in store.ips.values()
           if include_private or not e["private"]]
    dropped_priv = len(store.ips) - len(ips)
    if dropped_priv:
        warnings.append(f"{dropped_priv} private/reserved IP(s) excluded "
                        "(use --include-private to keep them)")

    domains = [e for e in store.domains.values() if keep_domain(e)]

    iocs = {
        "ips": sorted(ips, key=lambda e: e["value"]),
        "domains": sorted(domains, key=lambda e: e["value"]),
        "urls": sorted(store.urls.values(), key=lambda e: e["value"]),
        "hashes": sorted(store.hashes.values(), key=lambda e: e["value"]),
        "emails": sorted(store.emails.values(), key=lambda e: e["value"]),
    }
    return {
        "input_kind": input_kind,
        "iocs": iocs,
        "attachments": attachments,
        # Links whose visible text names a different domain than the target.
        "anchor_mismatches": anchor_mismatches or [],
        # Embedded images, any QR payloads decoded from them, and how much
        # readable text the message actually had.
        "media": media or {"images": [], "visible_text_chars": 0},
        "sender": sender,
        "counts": {k: len(v) for k, v in iocs.items()}
                  | {"attachments": len(attachments)},
        "warnings": warnings,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Extract IOCs (IPs, domains, URLs, hashes, emails) from "
                    "a parsed email JSON or raw text.")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--input", "-i", help="parsed email JSON file "
                     "(email-parser output)")
    src.add_argument("--text", help="raw text to scan")
    src.add_argument("--file", help="raw text file to scan")
    ap.add_argument("--no-refang", action="store_true",
                    help="do not normalize defanged IOCs (hxxp, [.])")
    ap.add_argument("--no-allowlist", action="store_true",
                    help="do not filter well-known benign domains")
    ap.add_argument("--include-private", action="store_true",
                    help="keep private/reserved IPs in the output")
    ap.add_argument("--output", "-o", help="write JSON result to this file")
    ap.add_argument("--pretty", action="store_true",
                    help="pretty-print the JSON output")
    args = ap.parse_args(argv)

    warnings = []
    store = IOCStore()
    sender, attachments, anchor_mismatches = None, [], []
    media = {"images": [], "visible_text_chars": 0}
    do_refang = not args.no_refang

    try:
        # ------------------------------------------------------------------
        # 1. Acquire input — parsed JSON, raw text, raw file, or stdin.
        # ------------------------------------------------------------------
        if args.input:
            with open(args.input, "r", encoding="utf-8", errors="replace") as f:
                parsed = json.load(f)
            input_kind = "parsed_email"
            (sender, attachments, anchor_mismatches, media) = \
                extract_from_parsed_email(parsed, store, warnings, do_refang)
        elif args.text is not None:
            input_kind = "raw_text"
            scan_text(store, refang(args.text) if do_refang else args.text,
                      "body")
        elif args.file:
            with open(args.file, "r", encoding="utf-8", errors="replace") as f:
                raw = f.read()
            input_kind = "raw_text"
            scan_text(store, refang(raw) if do_refang else raw, "body")
        else:
            raw = sys.stdin.read()
            if not raw.strip():
                print("error: no input provided (see --help)",
                      file=sys.stderr)
                return 1
            try:
                parsed = json.loads(raw)
                if not isinstance(parsed, dict):
                    raise ValueError
                input_kind = "parsed_email"
                (sender, attachments, anchor_mismatches, media) = \
                    extract_from_parsed_email(parsed, store, warnings,
                                              do_refang)
            except (json.JSONDecodeError, ValueError):
                input_kind = "raw_text"
                scan_text(store, refang(raw) if do_refang else raw, "body")
    except FileNotFoundError as e:
        print(f"error: file not found: {e.filename}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"error: invalid JSON input: {e}", file=sys.stderr)
        return 1
    except Exception as e:  # pragma: no cover — safety net
        print(f"error: unexpected failure: {e}", file=sys.stderr)
        return 2

    # ----------------------------------------------------------------------
    # 2. Assemble + emit the result.
    # ----------------------------------------------------------------------
    result = build_result(store, input_kind, sender, attachments, warnings,
                          use_allowlist=not args.no_allowlist,
                          include_private=args.include_private,
                          anchor_mismatches=anchor_mismatches,
                          media=media)
    text = json.dumps(result, indent=2 if args.pretty else None,
                      ensure_ascii=False)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
