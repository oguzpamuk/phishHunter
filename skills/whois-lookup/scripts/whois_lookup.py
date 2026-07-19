#!/usr/bin/env python3
"""
whois_lookup.py - Query WHOIS information for a domain name or an IP address
and return the parsed result as structured JSON.

=============================================================================
OVERVIEW
=============================================================================
This script talks directly to WHOIS servers over TCP port 43 (the classic
WHOIS protocol, RFC 3912). No third-party Python packages are required;
only the Python standard library is used, so it runs anywhere Python 3.8+
is available.

Resolution strategy:
  1. Detect whether the input is an IP address (IPv4/IPv6) or a domain name.
  2. For IP addresses  -> query ARIN first; follow referral to the correct
     Regional Internet Registry (RIPE, APNIC, LACNIC, AFRINIC) if needed.
  3. For domain names  -> ask IANA (whois.iana.org) which WHOIS server is
     authoritative for the TLD, then query that server. If the registry
     response contains a "Registrar WHOIS Server" referral, follow it to
     get the most detailed record.
  4. Parse the raw "Key: Value" text response into a normalized JSON object.

=============================================================================
COMMAND LINE USAGE
=============================================================================
  python3 whois_lookup.py <domain-or-ip> [options]

  Examples:
    python3 whois_lookup.py example.com
    python3 whois_lookup.py 8.8.8.8
    python3 whois_lookup.py example.com --raw          # include raw text
    python3 whois_lookup.py example.com --pretty       # pretty-print JSON
    python3 whois_lookup.py example.com --timeout 15   # custom timeout

  Options:
    --raw          Include the full raw WHOIS text in the JSON output
                   under the "raw" key. Off by default to keep output small.
    --pretty       Pretty-print the JSON with 2-space indentation.
    --timeout N    Socket timeout in seconds for each WHOIS query
                   (default: 10 seconds).
    --server HOST  Skip auto-discovery and query this WHOIS server directly.

=============================================================================
INPUT
=============================================================================
  A single positional argument: either
    * a domain name, e.g. "example.com", "sub.example.co.uk"
      (a leading "http://", "https://", "www." or trailing path is stripped
       automatically, so full URLs are also accepted), or
    * an IPv4 address, e.g. "8.8.8.8", or
    * an IPv6 address, e.g. "2001:4860:4860::8888".

=============================================================================
OUTPUT (JSON, printed to stdout)
=============================================================================
  For a DOMAIN query the JSON object contains:
    {
      "query":            "<the cleaned input>",
      "query_type":       "domain",
      "whois_server":     "<server that produced the final answer>",
      "domain_name":      "<registered domain>",
      "registrar":        "<sponsoring registrar name>",
      "registrar_url":    "<registrar website>",
      "registrar_iana_id":"<IANA registrar ID>",
      "creation_date":    "<registration date>",
      "updated_date":     "<last update date>",
      "expiration_date":  "<expiry date>",
      "status":           ["clientTransferProhibited", ...],
      "name_servers":     ["ns1.example.com", ...],
      "dnssec":           "signedDelegation | unsigned | null",
      "registrant": {                       # WHOIS privacy may redact these
          "name": ..., "organization": ..., "country": ..., "email": ...
      },
      "admin_email":      "<admin contact email or null>",
      "tech_email":       "<tech contact email or null>",
      "abuse_email":      "<registrar abuse contact email or null>",
      "raw":              "<full raw text, only when --raw is passed>"
    }

  For an IP query the JSON object contains:
    {
      "query":         "<ip>",
      "query_type":    "ipv4" | "ipv6",
      "whois_server":  "<RIR server that answered>",
      "net_range":     "<start - end of the allocated block>",
      "cidr":          "<CIDR notation of the block>",
      "net_name":      "<network name>",
      "organization":  "<owning organization>",
      "org_id":        "<registry org handle>",
      "country":       "<ISO country code>",
      "registry":      "ARIN | RIPE | APNIC | LACNIC | AFRINIC",
      "creation_date": "<allocation date>",
      "updated_date":  "<last modification date>",
      "abuse_email":   "<abuse contact email or null>",
      "raw":           "<full raw text, only when --raw is passed>"
    }

  Fields that cannot be found in the WHOIS response are set to null
  (or an empty list for list-typed fields), so the JSON shape is stable
  and safe to consume programmatically.

=============================================================================
EXIT CODES
=============================================================================
  0  success - JSON printed to stdout
  1  invalid input (empty / unparseable argument)
  2  network error (connection failure, timeout) - a JSON error object
     with an "error" key is still printed to stdout for easy scripting.
=============================================================================
"""

import argparse
import ipaddress
import json
import re
import socket
import sys

# ---------------------------------------------------------------------------
# Constants: well-known WHOIS servers
# ---------------------------------------------------------------------------
IANA_WHOIS = "whois.iana.org"      # Root server used to discover TLD servers
ARIN_WHOIS = "whois.arin.net"      # Default starting point for IP lookups
WHOIS_PORT = 43                    # Standard WHOIS TCP port (RFC 3912)

# Map RIR referral keywords found in ARIN responses to their WHOIS hosts.
RIR_SERVERS = {
    "ripe": "whois.ripe.net",
    "apnic": "whois.apnic.net",
    "lacnic": "whois.lacnic.net",
    "afrinic": "whois.afrinic.net",
    "arin": "whois.arin.net",
}


# ---------------------------------------------------------------------------
# Low-level WHOIS query over TCP port 43
# ---------------------------------------------------------------------------
def whois_query(server: str, query: str, timeout: float = 10.0) -> str:
    """
    Send a raw WHOIS query to `server` and return the full text response.

    Input:
        server  - hostname of the WHOIS server (e.g. "whois.verisign-grs.com")
        query   - the query string to send (domain or IP). Some servers need
                  special prefixes; ARIN, for example, uses "n + <ip>" to
                  return the most specific network, which we add here.
        timeout - socket timeout in seconds.

    Output:
        The decoded response text (UTF-8 with latin-1 fallback).

    Raises:
        OSError / socket.timeout on network problems.
    """
    # ARIN needs "n + " prefix to return the most specific matching network
    # instead of a summary list of all matches.
    payload = query
    if server == ARIN_WHOIS and _looks_like_ip(query):
        payload = f"n + {query}"

    with socket.create_connection((server, WHOIS_PORT), timeout=timeout) as sock:
        sock.settimeout(timeout)
        # WHOIS protocol: send the query followed by CRLF, then read until EOF.
        sock.sendall((payload + "\r\n").encode("utf-8"))
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)

    raw = b"".join(chunks)
    # Most servers are UTF-8; a few legacy ones send latin-1 bytes.
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1", errors="replace")


# ---------------------------------------------------------------------------
# Input classification helpers
# ---------------------------------------------------------------------------
def _looks_like_ip(value: str) -> bool:
    """Return True if `value` parses as an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def clean_target(raw_input: str) -> str:
    """
    Normalize user input into a bare domain or IP.

    Input:  possibly messy string like "https://www.Example.COM/path?q=1"
    Output: cleaned lowercase target like "example.com"
    """
    target = raw_input.strip().lower()
    # Strip URL scheme if the user pasted a full URL.
    target = re.sub(r"^[a-z][a-z0-9+.-]*://", "", target)
    # Drop any path / query string after the hostname.
    target = target.split("/")[0].split("?")[0]
    # Drop a port suffix like "example.com:443" (but keep IPv6 colons intact).
    if not _looks_like_ip(target) and target.count(":") == 1:
        target = target.split(":")[0]
    # Strip a leading "www." for domain queries (not valid for IPs anyway).
    if target.startswith("www.") and not _looks_like_ip(target):
        target = target[4:]
    return target


# ---------------------------------------------------------------------------
# Generic "Key: Value" parser for WHOIS text
# ---------------------------------------------------------------------------
def parse_key_values(text: str) -> dict:
    """
    Parse a WHOIS response into {lowercase_key: [values...]}.

    WHOIS records repeat keys (e.g. multiple "Name Server:" lines), so every
    key maps to a LIST of values, preserving order and skipping comments.

    Input:  raw WHOIS response text
    Output: dict like {"name server": ["ns1...", "ns2..."], "registrar": [...]}
    """
    result: dict = {}
    for line in text.splitlines():
        line = line.strip()
        # Skip empty lines and comment lines used by many registries.
        if not line or line.startswith(("%", "#", ">>>", "--")):
            continue
        # Only split on the FIRST colon; values may contain colons (URLs, IPv6).
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if not value:
            continue
        result.setdefault(key, []).append(value)
    return result


def first(kv: dict, *keys: str):
    """
    Return the first value found for any of the given candidate keys.

    Input:  kv   - dict produced by parse_key_values()
            keys - key names to try, in priority order
    Output: the first matching string value, or None if no key matched.
    """
    for k in keys:
        if k in kv and kv[k]:
            return kv[k][0]
    return None


def all_values(kv: dict, *keys: str) -> list:
    """
    Collect ALL values across the given candidate keys (deduplicated,
    order-preserving). Used for repeatable fields like name servers/status.
    """
    seen, out = set(), []
    for k in keys:
        for v in kv.get(k, []):
            norm = v.lower()
            if norm not in seen:
                seen.add(norm)
                out.append(v)
    return out


def find_email(text: str, context_words: list) -> str | None:
    """
    Heuristic: find an email address on a line that also contains one of the
    context words (e.g. "abuse"). Used when structured keys are missing.

    Input:  text          - raw WHOIS response
            context_words - lowercase words that must appear on the same line
    Output: first matching email string, or None.
    """
    email_re = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
    for line in text.splitlines():
        low = line.lower()
        if any(w in low for w in context_words):
            m = email_re.search(line)
            if m:
                return m.group(0)
    return None


# ---------------------------------------------------------------------------
# Domain lookup pipeline
# ---------------------------------------------------------------------------
def discover_tld_server(domain: str, timeout: float) -> tuple[str | None, str]:
    """
    Ask IANA which WHOIS server is authoritative for the domain's TLD.

    Input:  domain  - e.g. "example.com"
    Output: (server_hostname_or_None, raw_iana_response_text)
    """
    text = whois_query(IANA_WHOIS, domain, timeout)
    m = re.search(r"^whois:\s*(\S+)", text, re.MULTILINE | re.IGNORECASE)
    return (m.group(1) if m else None, text)


def lookup_domain(domain: str, timeout: float, forced_server: str | None) -> dict:
    """
    Full domain WHOIS pipeline: IANA -> registry -> registrar referral.

    Input:  domain        - cleaned domain name
            timeout       - per-query socket timeout
            forced_server - if set, query only this server (skip discovery)
    Output: (parsed_json_dict, raw_text_of_final_answer)
    """
    if forced_server:
        server = forced_server
    else:
        server, _ = discover_tld_server(domain, timeout)
        if not server:
            # Fallback guess: whois.nic.<tld> works for many newer TLDs.
            server = "whois.nic." + domain.rsplit(".", 1)[-1]

    raw = whois_query(server, domain, timeout)
    kv = parse_key_values(raw)
    final_server = server

    # Follow the registrar referral for richer data (thin registries like
    # .com only store minimal data; the registrar has the full record).
    referral = first(kv, "registrar whois server", "whois server", "refer")
    if referral and not forced_server:
        referral = referral.replace("http://", "").replace("https://", "").strip("/")
        if referral and referral != server:
            try:
                referral_raw = whois_query(referral, domain, timeout)
                # Only accept the referral answer if it actually mentions
                # the domain (guards against empty/error responses).
                if domain.split(".")[0] in referral_raw.lower():
                    raw = referral_raw
                    kv = parse_key_values(raw)
                    final_server = referral
            except OSError:
                pass  # Keep registry-level data if the registrar is down.

    result = {
        "query": domain,
        "query_type": "domain",
        "whois_server": final_server,
        "domain_name": (first(kv, "domain name", "domain") or domain).lower(),
        "registrar": first(kv, "registrar", "sponsoring registrar", "registrar name"),
        "registrar_url": first(kv, "registrar url"),
        "registrar_iana_id": first(kv, "registrar iana id"),
        "creation_date": first(kv, "creation date", "created", "registered on",
                               "registration date", "created on", "domain registration date"),
        "updated_date": first(kv, "updated date", "last updated", "changed",
                              "last modified", "modified"),
        "expiration_date": first(kv, "registry expiry date", "expiration date",
                                 "expiry date", "expires", "expire", "paid-till",
                                 "expires on", "renewal date"),
        "status": all_values(kv, "domain status", "status"),
        "name_servers": [ns.lower().split()[0] for ns in
                         all_values(kv, "name server", "nserver", "nameserver", "name servers")],
        "dnssec": first(kv, "dnssec"),
        "registrant": {
            "name": first(kv, "registrant name", "registrant"),
            "organization": first(kv, "registrant organization", "registrant organisation", "org"),
            "country": first(kv, "registrant country"),
            "email": first(kv, "registrant email"),
        },
        "admin_email": first(kv, "admin email", "administrative contact email"),
        "tech_email": first(kv, "tech email", "technical contact email"),
        "abuse_email": first(kv, "registrar abuse contact email")
                       or find_email(raw, ["abuse"]),
    }
    return result, raw


# ---------------------------------------------------------------------------
# IP lookup pipeline
# ---------------------------------------------------------------------------
def lookup_ip(ip: str, timeout: float, forced_server: str | None) -> dict:
    """
    IP WHOIS pipeline: ARIN first, then follow referral to the owning RIR.

    Input:  ip            - cleaned IPv4/IPv6 address
            timeout       - per-query socket timeout
            forced_server - if set, query only this server
    Output: (parsed_json_dict, raw_text_of_final_answer)
    """
    addr = ipaddress.ip_address(ip)
    server = forced_server or ARIN_WHOIS
    raw = whois_query(server, ip, timeout)
    final_server = server

    # ARIN answers for non-ARIN space with a "ResourceLink"/referral pointing
    # at the correct RIR. Detect it and re-query the right registry.
    if not forced_server:
        low = raw.lower()
        for rir_key, rir_host in RIR_SERVERS.items():
            if rir_host == server:
                continue
            if rir_host in low or f"({rir_key})" in low:
                try:
                    raw = whois_query(rir_host, ip, timeout)
                    final_server = rir_host
                except OSError:
                    pass
                break

    kv = parse_key_values(raw)

    # Registry name inference from the answering server hostname.
    registry = next((name.upper() for name, host in RIR_SERVERS.items()
                     if host == final_server), None)

    result = {
        "query": ip,
        "query_type": f"ipv{addr.version}",
        "whois_server": final_server,
        "net_range": first(kv, "netrange", "inetnum", "inet6num"),
        "cidr": first(kv, "cidr", "route", "route6"),
        "net_name": first(kv, "netname"),
        "organization": first(kv, "organization", "org-name", "orgname",
                              "owner", "descr"),
        "org_id": first(kv, "orgid", "org", "ownerid"),
        "country": first(kv, "country"),
        "registry": registry,
        "creation_date": first(kv, "regdate", "created"),
        "updated_date": first(kv, "updated", "last-modified", "changed"),
        "abuse_email": first(kv, "orgabuseemail", "abuse-mailbox", "abuse-c email")
                       or find_email(raw, ["abuse"]),
    }
    return result, raw


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def main() -> int:
    """
    Parse CLI arguments, dispatch to the correct pipeline and print JSON.

    Output goes to stdout as a single JSON object. On network failure a
    JSON object with an "error" key is printed and exit code 2 is returned,
    so calling scripts can always safely json.parse the stdout.
    """
    parser = argparse.ArgumentParser(
        description="Query WHOIS for a domain or IP and print JSON.")
    parser.add_argument("target", help="Domain name, URL, or IP address")
    parser.add_argument("--raw", action="store_true",
                        help="Include full raw WHOIS text under the 'raw' key")
    parser.add_argument("--pretty", action="store_true",
                        help="Pretty-print the JSON output")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="Socket timeout per query in seconds (default 10)")
    parser.add_argument("--server",
                        help="Query this WHOIS server directly (skip discovery)")
    args = parser.parse_args()

    target = clean_target(args.target)
    if not target:
        print(json.dumps({"error": "empty or invalid target"}))
        return 1

    try:
        if _looks_like_ip(target):
            result, raw = lookup_ip(target, args.timeout, args.server)
        else:
            result, raw = lookup_domain(target, args.timeout, args.server)
    except (OSError, socket.timeout) as exc:
        # Network problem: still emit machine-readable JSON on stdout.
        print(json.dumps({"query": target, "error": f"network error: {exc}"}))
        return 2

    if args.raw:
        result["raw"] = raw

    indent = 2 if args.pretty else None
    print(json.dumps(result, indent=indent, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
