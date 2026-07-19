---
name: whois-lookup
description: >
  Query WHOIS registration information for any domain name or IP address and
  return the result as structured JSON. Use this skill whenever the user asks
  about domain ownership, domain registration/expiry dates, registrar info,
  name servers, who owns an IP address, which organization or country an IP
  belongs to, IP network ranges (RIR data from ARIN/RIPE/APNIC/LACNIC/AFRINIC),
  abuse contact emails, or says things like "whois", "domain lookup",
  "bu domain kimin", "IP sorgula", "alan adı bilgisi" — even if they don't
  explicitly say the word "whois".
---

# WHOIS Lookup

Query WHOIS data for a domain or IP address over the classic WHOIS protocol
(TCP port 43) and get a normalized JSON result. No external Python packages
are needed — the bundled script uses only the standard library.

## When to use

- The user wants registration details of a domain (registrar, creation /
  expiration dates, name servers, DNSSEC, status codes, contacts).
- The user wants ownership details of an IP address (organization, country,
  network range/CIDR, responsible RIR, abuse contact).
- The input may be a bare domain, a full URL, an IPv4 or an IPv6 address —
  the script cleans and classifies the input automatically.

## How to run

```bash
python3 scripts/whois_lookup.py <domain-or-ip> [--pretty] [--raw] [--timeout N] [--server HOST]
```

Examples:

```bash
# Domain lookup, human-friendly JSON
python3 scripts/whois_lookup.py example.com --pretty

# IP lookup
python3 scripts/whois_lookup.py 8.8.8.8 --pretty

# Full URL input is fine; scheme/path are stripped automatically
python3 scripts/whois_lookup.py "https://www.example.com/page" --pretty

# Include the raw WHOIS text alongside the parsed fields
python3 scripts/whois_lookup.py example.com --raw --pretty

# Query a specific WHOIS server directly (skip auto-discovery)
python3 scripts/whois_lookup.py example.com --server whois.verisign-grs.com
```

## Input

One positional argument: a domain name, a URL, an IPv4, or an IPv6 address.

## Output

A single JSON object on stdout. Field sets:

**Domain queries** → `query`, `query_type` ("domain"), `whois_server`,
`domain_name`, `registrar`, `registrar_url`, `registrar_iana_id`,
`creation_date`, `updated_date`, `expiration_date`, `status[]`,
`name_servers[]`, `dnssec`, `registrant{name,organization,country,email}`,
`admin_email`, `tech_email`, `abuse_email`, and optionally `raw`.

**IP queries** → `query`, `query_type` ("ipv4"/"ipv6"), `whois_server`,
`net_range`, `cidr`, `net_name`, `organization`, `org_id`, `country`,
`registry` (ARIN/RIPE/APNIC/LACNIC/AFRINIC), `creation_date`,
`updated_date`, `abuse_email`, and optionally `raw`.

Missing fields are `null` (or `[]` for lists), so the JSON shape is stable.

Exit codes: `0` success, `1` invalid input, `2` network error (an
`{"error": ...}` JSON object is still printed for easy scripting).

## Notes & caveats

- Requires outbound TCP access to port 43. In sandboxed environments without
  network egress, the script will exit with code 2 and a JSON error object;
  tell the user to run it in an environment with network access.
- Many registries redact registrant contact data (GDPR / WHOIS privacy), so
  `registrant.*` fields being `null` is normal, not a parsing failure.
- Thin registries (e.g. `.com`) hold minimal data; the script automatically
  follows the "Registrar WHOIS Server" referral to fetch the full record.
- For IPs, the script starts at ARIN and follows referrals to the correct
  Regional Internet Registry automatically.
- Interpret and summarize the JSON for the user after running; don't just
  dump raw JSON unless they asked for JSON output specifically.
