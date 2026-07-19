#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parse_email.py — Parse .eml (RFC 5322 / MIME) and .msg (Outlook / MS-OXMSG)
email files into a single, normalized JSON structure.

================================================================================
USAGE (command line)
================================================================================
    python3 parse_email.py <input_file> [options]

    Options:
        --include-attachment-data   Embed attachment binary content in the JSON
                                    output as Base64 strings (key: "data_base64").
                                    Off by default to keep output small.
        --output <path>, -o <path>  Write JSON to a file instead of stdout.
        --compact                   Emit compact (single-line) JSON.
                                    Default output is pretty-printed (indent=2).

    Exit codes:
        0  success
        1  file not found / unreadable
        2  unsupported or corrupt file format
        3  unexpected internal error

================================================================================
INPUT
================================================================================
    A single email file. The format is auto-detected from the file content
    (NOT from the extension):
        * Files starting with the OLE2/CFB magic bytes
          D0 CF 11 E0 A1 B1 1A E1  -> parsed as Outlook .msg
        * Anything else            -> parsed as .eml (RFC 5322 message)

================================================================================
OUTPUT (JSON schema)
================================================================================
    {
      "format":       "eml" | "msg",          # detected source format
      "subject":      str | null,             # message subject
      "from":         {"name": str|null, "email": str|null} | null,
      "to":           [ {"name", "email"} ],  # list of recipients (To)
      "cc":           [ {"name", "email"} ],  # list of recipients (Cc)
      "bcc":          [ {"name", "email"} ],  # list of recipients (Bcc)
      "date":         str | null,             # ISO-8601 date (sent time)
      "message_id":   str | null,             # Message-ID header value
      "headers":      { header_name: value or [values] },  # all transport headers
      "body": {
        "text":       str | null,             # plain-text body
        "html":       str | null              # HTML body
      },
      "attachments": [
        {
          "filename":     str | null,         # attachment file name
          "content_type": str | null,         # MIME type, e.g. "application/pdf"
          "size_bytes":   int | null,         # size of the decoded payload
          "content_id":   str | null,         # Content-ID (for inline images)
          "is_inline":    bool,               # true for inline/embedded parts
          "data_base64":  str                 # ONLY with --include-attachment-data
        }
      ],
      "warnings":     [ str ]                 # non-fatal parsing issues
    }

The script is 100% standard library (no pip installs needed). The .msg support
is implemented via a built-in minimal reader for the Compound File Binary (CFB)
container format plus the MAPI property streams defined in MS-OXMSG.
"""

import argparse
import base64
import json
import re
import struct
import sys
from datetime import datetime, timedelta, timezone

# ==============================================================================
# SECTION 1 — EML PARSING (RFC 5322 / MIME) using the Python `email` package
# ==============================================================================

from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime


def _addr_list(msg, header_name):
    """
    Extract a list of address dicts from a given address header.

    Input:
        msg          : email.message.EmailMessage object
        header_name  : header to read, e.g. "To", "Cc", "Bcc", "From"
    Output:
        list of {"name": str|None, "email": str|None} for every address found.
        Returns an empty list when the header is absent.
    """
    raw_values = msg.get_all(header_name, [])
    result = []
    # getaddresses() correctly splits "Name <a@b>, c@d" style header values
    for name, email_addr in getaddresses(raw_values):
        if not name and not email_addr:
            continue
        result.append({"name": name or None, "email": email_addr or None})
    return result


def parse_eml(data, include_attachment_data=False):
    """
    Parse raw .eml bytes into the normalized result dictionary.

    Input:
        data                    : bytes  — full raw content of the .eml file
        include_attachment_data : bool   — embed attachment bytes as Base64
    Output:
        dict following the JSON schema documented at the top of this file.
    """
    warnings = []
    # policy.default gives us the modern EmailMessage API (get_body, iter_attachments)
    msg = BytesParser(policy=policy.default).parsebytes(data)

    # ---- Headers: collect every header; repeated headers become a list -------
    headers = {}
    for key, value in msg.items():
        value = str(value)
        if key in headers:
            # A header may legally appear multiple times (e.g. "Received")
            if isinstance(headers[key], list):
                headers[key].append(value)
            else:
                headers[key] = [headers[key], value]
        else:
            headers[key] = value

    # ---- Sent date -> ISO-8601 string ----------------------------------------
    date_iso = None
    if msg.get("Date"):
        try:
            date_iso = parsedate_to_datetime(msg["Date"]).isoformat()
        except Exception as exc:
            warnings.append(f"Could not parse Date header: {exc}")

    # ---- From (single address expected, keep the first one) ------------------
    from_list = _addr_list(msg, "From")

    # ---- Bodies: prefer the dedicated plain/html alternatives ----------------
    body_text = None
    body_html = None
    try:
        part = msg.get_body(preferencelist=("plain",))
        if part is not None:
            body_text = part.get_content()
    except Exception as exc:
        warnings.append(f"Failed to extract text body: {exc}")
    try:
        part = msg.get_body(preferencelist=("html",))
        if part is not None:
            body_html = part.get_content()
    except Exception as exc:
        warnings.append(f"Failed to extract HTML body: {exc}")

    # ---- Attachments (regular + inline parts that carry a filename/CID) ------
    attachments = []
    for part in msg.walk():
        # Skip multipart containers themselves; only leaves carry payloads
        if part.is_multipart():
            continue
        disposition = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()
        content_id = part.get("Content-ID")
        is_attachment = disposition == "attachment"
        is_inline = disposition == "inline" or (content_id is not None and not is_attachment)
        # A part counts as an attachment when it is explicitly marked as one,
        # or when it is an inline part with a filename / Content-ID
        # (typically embedded images), excluding the main text/html bodies.
        if not (is_attachment or (is_inline and (filename or content_id))):
            continue
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception as exc:
            payload = b""
            warnings.append(f"Failed to decode attachment '{filename}': {exc}")
        entry = {
            "filename": filename,
            "content_type": part.get_content_type(),
            "size_bytes": len(payload),
            "content_id": content_id.strip("<>") if content_id else None,
            "is_inline": bool(is_inline),
        }
        if include_attachment_data:
            entry["data_base64"] = base64.b64encode(payload).decode("ascii")
        attachments.append(entry)

    return {
        "format": "eml",
        "subject": msg.get("Subject"),
        "from": from_list[0] if from_list else None,
        "to": _addr_list(msg, "To"),
        "cc": _addr_list(msg, "Cc"),
        "bcc": _addr_list(msg, "Bcc"),
        "date": date_iso,
        "message_id": msg.get("Message-ID"),
        "headers": headers,
        "body": {"text": body_text, "html": body_html},
        "attachments": attachments,
        "warnings": warnings,
    }


# ==============================================================================
# SECTION 2 — CFB (Compound File Binary) READER — the container of .msg files
# ==============================================================================
# A .msg file is an OLE2 "compound file": a mini file-system with storages
# (directories) and streams (files). Reference: [MS-CFB].

# Special sector index values used inside FAT / miniFAT chains
FREESECT   = 0xFFFFFFFF   # unallocated sector
ENDOFCHAIN = 0xFFFFFFFE   # terminates a sector chain
FATSECT    = 0xFFFFFFFD   # sector holds FAT data
DIFSECT    = 0xFFFFFFFC   # sector holds DIFAT data

CFB_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


class DirEntry:
    """One 128-byte directory entry of a compound file (storage or stream)."""
    __slots__ = ("name", "type", "left", "right", "child", "start", "size", "sid")

    def __init__(self, name, etype, left, right, child, start, size, sid):
        self.name = name    # str   : entry name (UTF-16 decoded)
        self.type = etype   # int   : 1=storage, 2=stream, 5=root storage
        self.left = left    # int   : SID of left sibling in red-black tree
        self.right = right  # int   : SID of right sibling
        self.child = child  # int   : SID of first child (storages only)
        self.start = start  # int   : first sector of the stream data
        self.size = size    # int   : stream length in bytes
        self.sid = sid      # int   : this entry's own index


class CompoundFile:
    """
    Minimal read-only CFB parser.

    Input : raw bytes of a .msg (or any OLE2 compound) file.
    Output: an in-memory tree where each storage is represented as
            {"streams": {name: bytes}, "storages": {name: subtree}}
            accessible via self.root.
    """

    def __init__(self, data):
        self.data = data
        if data[:8] != CFB_MAGIC:
            raise ValueError("Not an OLE2/CFB file (bad magic bytes)")

        # ---- Parse the 512-byte header ---------------------------------------
        (sector_shift,) = struct.unpack_from("<H", data, 30)   # 9 -> 512-byte sectors, 12 -> 4096
        (mini_shift,)   = struct.unpack_from("<H", data, 32)   # usually 6 -> 64-byte mini sectors
        (num_fat,)      = struct.unpack_from("<I", data, 44)   # number of FAT sectors
        (first_dir,)    = struct.unpack_from("<I", data, 48)   # first directory sector
        (mini_cutoff,)  = struct.unpack_from("<I", data, 56)   # streams below this size live in mini stream
        (first_minifat,) = struct.unpack_from("<I", data, 60)  # first miniFAT sector
        (num_minifat,)  = struct.unpack_from("<I", data, 64)
        (first_difat,)  = struct.unpack_from("<I", data, 68)   # first extra DIFAT sector
        (num_difat,)    = struct.unpack_from("<I", data, 72)

        self.sector_size = 1 << sector_shift
        self.mini_size = 1 << mini_shift
        self.mini_cutoff = mini_cutoff

        # ---- DIFAT: list of the sector indices that contain the FAT ----------
        difat = list(struct.unpack_from("<109I", data, 76))
        next_difat = first_difat
        for _ in range(num_difat):
            if next_difat in (FREESECT, ENDOFCHAIN):
                break
            sec = self._sector(next_difat)
            entries = struct.unpack("<%dI" % (self.sector_size // 4), sec)
            difat.extend(entries[:-1])       # last entry = pointer to next DIFAT sector
            next_difat = entries[-1]
        fat_sectors = [s for s in difat if s not in (FREESECT, ENDOFCHAIN)][:num_fat]

        # ---- FAT: one uint32 per sector, forming linked chains ----------------
        self.fat = []
        for s in fat_sectors:
            self.fat.extend(struct.unpack("<%dI" % (self.sector_size // 4), self._sector(s)))

        # ---- Directory: chain of sectors holding 128-byte entries -------------
        dir_bytes = self._read_chain(first_dir)
        self.entries = []
        for i in range(len(dir_bytes) // 128):
            self.entries.append(self._parse_dir_entry(dir_bytes[i * 128:(i + 1) * 128], i))

        root = self.entries[0]

        # ---- Mini FAT + mini stream (small streams live inside the root stream)
        self.minifat = []
        if num_minifat and first_minifat not in (FREESECT, ENDOFCHAIN):
            mf = self._read_chain(first_minifat)
            self.minifat = list(struct.unpack("<%dI" % (len(mf) // 4), mf))
        # The "mini stream" container is the root entry's own stream data
        self.mini_stream = self._read_chain(root.start)[:root.size] if root.size else b""

        # ---- Build the storage/stream tree starting at the root ---------------
        self.root = self._build_storage(root)

    # ---- Low-level helpers ----------------------------------------------------

    def _sector(self, index):
        """Return the raw bytes of regular sector `index` (header = sector -1)."""
        off = (index + 1) * self.sector_size
        return self.data[off:off + self.sector_size]

    def _read_chain(self, start):
        """Follow a FAT chain from `start` and concatenate all its sectors."""
        out, sec, guard = [], start, 0
        while sec not in (ENDOFCHAIN, FREESECT) and guard <= len(self.fat):
            out.append(self._sector(sec))
            sec = self.fat[sec] if sec < len(self.fat) else ENDOFCHAIN
            guard += 1
        return b"".join(out)

    def _read_mini_chain(self, start, size):
        """Follow a miniFAT chain inside the mini stream container."""
        out, sec, guard = [], start, 0
        while sec not in (ENDOFCHAIN, FREESECT) and guard <= len(self.minifat):
            off = sec * self.mini_size
            out.append(self.mini_stream[off:off + self.mini_size])
            sec = self.minifat[sec] if sec < len(self.minifat) else ENDOFCHAIN
            guard += 1
        return b"".join(out)[:size]

    def _read_stream(self, entry):
        """Read a stream's full content, choosing FAT vs miniFAT automatically."""
        if entry.size < self.mini_cutoff and entry.type != 5:
            return self._read_mini_chain(entry.start, entry.size)
        return self._read_chain(entry.start)[:entry.size]

    @staticmethod
    def _parse_dir_entry(raw, sid):
        """Decode one 128-byte directory entry."""
        (name_len,) = struct.unpack_from("<H", raw, 64)
        name = raw[:max(0, name_len - 2)].decode("utf-16-le", errors="replace") if name_len >= 2 else ""
        etype = raw[66]
        left, right, child = struct.unpack_from("<3I", raw, 68)
        (start,) = struct.unpack_from("<I", raw, 116)
        (size,) = struct.unpack_from("<Q", raw, 120)
        return DirEntry(name, etype, left, right, child, start, size & 0xFFFFFFFF, sid)

    def _tree_members(self, sid, acc):
        """Walk the red-black sibling tree collecting every member of a storage."""
        if sid in (FREESECT,) or sid >= len(self.entries):
            return
        e = self.entries[sid]
        self._tree_members(e.left, acc)
        acc.append(e)
        self._tree_members(e.right, acc)

    def _build_storage(self, entry):
        """Recursively materialize a storage into dicts of streams/sub-storages."""
        members = []
        self._tree_members(entry.child, members)
        node = {"streams": {}, "storages": {}}
        for m in members:
            if m.type == 2:                                   # stream
                node["streams"][m.name] = self._read_stream(m)
            elif m.type == 1:                                 # storage
                node["storages"][m.name] = self._build_storage(m)
        return node


# ==============================================================================
# SECTION 3 — MSG PARSING (MAPI properties on top of the CFB container)
# ==============================================================================
# Property streams are named "__substg1.0_" + 4-hex property id + 4-hex type.
# Fixed-size properties (numbers, timestamps) live in "__properties_version1.0".

# MAPI property types we care about
PT_UNICODE = 0x001F   # UTF-16LE string
PT_STRING8 = 0x001E   # 8-bit string in the message code page
PT_BINARY  = 0x0102   # raw bytes
PT_SYSTIME = 0x0040   # Windows FILETIME (in the fixed properties stream)
PT_LONG    = 0x0003   # 32-bit integer (in the fixed properties stream)

_SUBSTG_RE = re.compile(r"^__substg1\.0_([0-9A-Fa-f]{4})([0-9A-Fa-f]{4})$")


def _filetime_to_iso(ft):
    """
    Convert a Windows FILETIME to an ISO-8601 UTC string.

    Input : ft — int, 100-nanosecond intervals since 1601-01-01 UTC.
    Output: str like "2026-07-18T09:30:00+00:00", or None when ft == 0.
    """
    if not ft:
        return None
    try:
        base = datetime(1601, 1, 1, tzinfo=timezone.utc)
        return (base + timedelta(microseconds=ft // 10)).isoformat()
    except OverflowError:
        return None


class MsgStorage:
    """
    Wrapper around one storage node (message root, a recipient, an attachment)
    that exposes convenient typed accessors for MAPI properties.
    """

    def __init__(self, node, codepage="cp1252"):
        self.node = node
        self.codepage = codepage           # used to decode PT_STRING8 values
        self.props = {}                    # variable-length props: {prop_id_hex: (type, bytes)}
        for name, blob in node["streams"].items():
            m = _SUBSTG_RE.match(name)
            if m:
                self.props[m.group(1).upper()] = (int(m.group(2), 16), blob)
        # Fixed-length properties (ints, timestamps) from __properties_version1.0
        self.fixed = {}                    # {prop_id_hex: (type, int_value)}
        raw = node["streams"].get("__properties_version1.0", b"")
        self._parse_fixed(raw)

    def _parse_fixed(self, raw):
        """
        Parse the fixed-property stream. The header size varies by context:
        32 bytes (message root), 24 (embedded message), 8 (recipient/attachment).
        Each following record is 16 bytes: tag(4) + flags(4) + value(8).
        We simply try each known header offset and keep the first that yields
        well-formed records.
        """
        for header in (32, 24, 8):
            if len(raw) < header or (len(raw) - header) % 16:
                continue
            parsed = {}
            ok = True
            for off in range(header, len(raw), 16):
                tag, _flags, value = struct.unpack_from("<IIQ", raw, off)
                ptype = tag & 0xFFFF
                pid = (tag >> 16) & 0xFFFF
                if pid == 0 and ptype == 0:
                    continue
                # Sanity check: property types are small known constants
                if ptype > 0x1102:
                    ok = False
                    break
                parsed[f"{pid:04X}"] = (ptype, value)
            if ok and parsed:
                self.fixed = parsed
                return

    # ---- Typed accessors ------------------------------------------------------

    def get_string(self, pid):
        """Return a string property (PT_UNICODE / PT_STRING8) or None."""
        item = self.props.get(pid.upper())
        if not item:
            return None
        ptype, blob = item
        if ptype == PT_UNICODE:
            return blob.decode("utf-16-le", errors="replace").rstrip("\x00")
        if ptype == PT_STRING8:
            return blob.decode(self.codepage, errors="replace").rstrip("\x00")
        return None

    def get_binary(self, pid):
        """Return a binary property (PT_BINARY) or None."""
        item = self.props.get(pid.upper())
        return item[1] if item and item[0] == PT_BINARY else None

    def get_int(self, pid):
        """Return an integer fixed property (e.g. PT_LONG) or None."""
        item = self.fixed.get(pid.upper())
        return (item[1] & 0xFFFFFFFF) if item else None

    def get_time(self, pid):
        """Return a PT_SYSTIME fixed property as ISO-8601 string or None."""
        item = self.fixed.get(pid.upper())
        return _filetime_to_iso(item[1]) if item and item[0] == PT_SYSTIME else None


def _parse_transport_headers(raw_headers):
    """
    Parse the PidTagTransportMessageHeaders string (raw RFC 5322 header block)
    into a {name: value} dict, merging folded continuation lines.

    Input : raw_headers — str, the header block as stored in the .msg file
    Output: dict of headers (repeated headers become lists)
    """
    headers = {}
    if not raw_headers:
        return headers
    current_key = None
    for line in raw_headers.splitlines():
        if not line.strip():
            break  # blank line = end of the header block
        if line[:1] in (" ", "\t") and current_key:
            # Folded continuation of the previous header line
            prev = headers[current_key]
            if isinstance(prev, list):
                prev[-1] += " " + line.strip()
            else:
                headers[current_key] = prev + " " + line.strip()
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            key, value = key.strip(), value.strip()
            current_key = key
            if key in headers:
                if isinstance(headers[key], list):
                    headers[key].append(value)
                else:
                    headers[key] = [headers[key], value]
            else:
                headers[key] = value
    return headers


def parse_msg(data, include_attachment_data=False):
    """
    Parse raw Outlook .msg bytes into the normalized result dictionary.

    Input:
        data                    : bytes — full raw content of the .msg file
        include_attachment_data : bool  — embed attachment bytes as Base64
    Output:
        dict following the JSON schema documented at the top of this file.
    """
    warnings = []
    cfb = CompoundFile(data)
    root_node = cfb.root

    # Determine the message code page (PidTagMessageCodepage, 3FFD) so we can
    # decode legacy PT_STRING8 (non-Unicode) properties correctly.
    probe = MsgStorage(root_node)
    codepage = "cp1252"
    cp = probe.get_int("3FFD") or probe.get_int("3FDE")
    if cp:
        try:
            b"".decode(f"cp{cp}")
            codepage = f"cp{cp}"
        except LookupError:
            warnings.append(f"Unknown code page {cp}; falling back to cp1252")
    msg = MsgStorage(root_node, codepage)

    # ---- Sender ---------------------------------------------------------------
    # 0C1A = sender display name; 5D01/5D02 = SMTP address; 0C1F = fallback
    # address that may be an internal Exchange (X.500) address.
    sender_name = msg.get_string("0C1A") or msg.get_string("0042")
    sender_email = (msg.get_string("5D01") or msg.get_string("5D02")
                    or msg.get_string("0C1F") or msg.get_string("0065"))
    if sender_email and "@" not in sender_email:
        warnings.append("Sender address is not SMTP (likely an Exchange X.500 address)")
    from_obj = None
    if sender_name or sender_email:
        from_obj = {"name": sender_name, "email": sender_email}

    # ---- Recipients (storages named __recip_version1.0_#XXXXXXXX) -------------
    to_list, cc_list, bcc_list = [], [], []
    for name in sorted(root_node["storages"]):
        if not name.startswith("__recip_version1.0_"):
            continue
        r = MsgStorage(root_node["storages"][name], codepage)
        addr = {
            "name": r.get_string("3001"),                       # display name
            "email": (r.get_string("39FE")                       # SMTP address
                      or r.get_string("3003")                    # email address
                      or r.get_string("5FF6")),
        }
        rtype = r.get_int("0C15") or 1                           # 1=To, 2=Cc, 3=Bcc
        {1: to_list, 2: cc_list, 3: bcc_list}.get(rtype, to_list).append(addr)

    # Fall back to the display strings when no recipient storages exist
    if not to_list and msg.get_string("0E04"):
        to_list = [{"name": n.strip(), "email": None}
                   for n in msg.get_string("0E04").split(";") if n.strip()]

    # ---- Bodies ---------------------------------------------------------------
    body_text = msg.get_string("1000")                           # PidTagBody
    body_html = None
    html_bin = msg.get_binary("1013")                            # PidTagHtml (bytes)
    if html_bin:
        try:
            body_html = html_bin.decode("utf-8")
        except UnicodeDecodeError:
            body_html = html_bin.decode(codepage, errors="replace")
    elif msg.get_string("1013"):
        body_html = msg.get_string("1013")
    if body_text is None and body_html is None and msg.get_binary("1009"):
        warnings.append("Body only available as compressed RTF (property 1009); not decoded")

    # ---- Transport headers, subject, dates, message id ------------------------
    headers = _parse_transport_headers(msg.get_string("007D"))
    subject = msg.get_string("0037") or headers.get("Subject")
    message_id = msg.get_string("1035") or headers.get("Message-ID")
    # 0039 = client submit time (sent), 0E06 = delivery time
    date_iso = msg.get_time("0039") or msg.get_time("0E06")
    if not date_iso and headers.get("Date"):
        try:
            date_iso = parsedate_to_datetime(str(headers["Date"])).isoformat()
        except Exception:
            pass

    # ---- Attachments (storages named __attach_version1.0_#XXXXXXXX) -----------
    attachments = []
    for name in sorted(root_node["storages"]):
        if not name.startswith("__attach_version1.0_"):
            continue
        a_node = root_node["storages"][name]
        a = MsgStorage(a_node, codepage)
        payload = a.get_binary("3701")                           # attachment content
        embedded = a_node["storages"].get("__substg1.0_3701000D")  # embedded .msg
        entry = {
            "filename": a.get_string("3707") or a.get_string("3704")
                        or a.get_string("3001"),
            "content_type": a.get_string("370E"),
            "size_bytes": len(payload) if payload is not None else None,
            "content_id": a.get_string("3712"),
            "is_inline": bool(a.get_string("3712")),
        }
        if embedded is not None:
            entry["content_type"] = entry["content_type"] or "message/rfc822"
            entry["is_embedded_message"] = True
        if include_attachment_data and payload is not None:
            entry["data_base64"] = base64.b64encode(payload).decode("ascii")
        attachments.append(entry)

    return {
        "format": "msg",
        "subject": subject,
        "from": from_obj,
        "to": to_list,
        "cc": cc_list,
        "bcc": bcc_list,
        "date": date_iso,
        "message_id": message_id,
        "headers": headers,
        "body": {"text": body_text, "html": body_html},
        "attachments": attachments,
        "warnings": warnings,
    }


# ==============================================================================
# SECTION 4 — CLI ENTRY POINT
# ==============================================================================

def main(argv=None):
    """
    Command-line entry point.

    Input : argv — optional list of CLI arguments (defaults to sys.argv[1:])
    Output: prints/writes the JSON result; returns the process exit code.
    """
    ap = argparse.ArgumentParser(
        description="Parse a .msg or .eml email file and output its parts as JSON.")
    ap.add_argument("input", help="Path to the .msg or .eml file")
    ap.add_argument("--include-attachment-data", action="store_true",
                    help="Embed attachment content as Base64 in the JSON output")
    ap.add_argument("-o", "--output", help="Write JSON to this file instead of stdout")
    ap.add_argument("--compact", action="store_true",
                    help="Emit compact single-line JSON (default: pretty-printed)")
    args = ap.parse_args(argv)

    # ---- Read the input file --------------------------------------------------
    try:
        with open(args.input, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        print(f"ERROR: cannot read '{args.input}': {exc}", file=sys.stderr)
        return 1

    # ---- Detect the format from magic bytes and dispatch ----------------------
    try:
        if data[:8] == CFB_MAGIC:
            result = parse_msg(data, args.include_attachment_data)
        else:
            result = parse_eml(data, args.include_attachment_data)
    except (ValueError, struct.error, IndexError) as exc:
        # ValueError: bad magic; struct.error/IndexError: truncated/corrupt container
        print(f"ERROR: unsupported or corrupt file: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # pragma: no cover — safety net
        print(f"ERROR: unexpected failure: {exc}", file=sys.stderr)
        return 3

    # ---- Serialize and emit ---------------------------------------------------
    text = json.dumps(result, ensure_ascii=False,
                      indent=None if args.compact else 2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
