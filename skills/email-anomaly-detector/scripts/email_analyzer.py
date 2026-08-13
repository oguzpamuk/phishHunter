#!/usr/bin/env python3
"""
email_analyzer.py — Spam / Brand-Impersonation / Anomaly scorer for EMAIL BODY text.

================================================================================
PURPOSE
================================================================================
This is a self-contained CLI tool (Python 3.8+, standard library only) that
analyzes ONLY the body text of an email and produces three things:

  1. SPAM SCORE (0-100)
       Content-based likelihood that the message is unsolicited bulk/spam mail.
  2. BRAND DETECTION
       Which well-known brands are mentioned in the body, and whether the
       surrounding language pattern suggests brand IMPERSONATION (phishing).
  3. ANOMALY SCORE (0-100) + VERDICT
       A weighted combination of spam + impersonation + technical anomalies,
       mapped to one of: CLEAN / SUSPICIOUS / ANOMALOUS.

No network access is required. No third-party packages are required.

================================================================================
INPUT
================================================================================
The email body can be supplied in exactly one of four ways:

  --text "..."      Inline string on the command line (good for short bodies).
  --file PATH       Path to a UTF-8 text file containing ONE email body.
  --dir  PATH       Directory: every *.txt file inside is analyzed (batch mode).
  (stdin)           If none of the above is given, the body is read from stdin,
                    e.g.:  cat body.txt | python3 email_analyzer.py

IMPORTANT: The input is expected to be the BODY ONLY. Raw headers (From:,
Received:, DKIM-Signature:, ...) should be stripped by the caller beforehand;
this tool intentionally does not parse MIME or header metadata.

================================================================================
OUTPUT
================================================================================
Two output formats, selected with --json:

  DEFAULT (human-readable):
      A formatted report printed to stdout, showing scores, verdict,
      detected brands, and every triggered signal with its point weight.

  --json (machine-readable):
      A single JSON object (or a JSON array in --dir batch mode) with schema:

      {
        "source":            "<file path | 'inline' | 'stdin'>",
        "spam_score":        0-100 (int),
        "anomaly_score":     0-100 (int),
        "verdict":           "CLEAN" | "SUSPICIOUS" | "ANOMALOUS",
        "brands_detected": [
          {
            "brand":              "paypal",
            "mention_count":      2,
            "impersonation_risk": "low" | "medium" | "high",
            "reasons":            ["urgency language near brand mention", ...]
          }
        ],
        "signals": [
          {
            "category": "spam" | "brand" | "anomaly",
            "name":     "short signal identifier",
            "detail":   "human-readable explanation with evidence",
            "points":   int (contribution to that category's raw score)
          }
        ],
        "stats": {
          "char_count":        int,   # total characters in the body
          "word_count":        int,   # whitespace-separated tokens
          "url_count":         int,   # number of URLs found in the body
          "caps_ratio":        float, # UPPERCASE letters / all letters
          "exclamation_count": int    # number of '!' characters
        }
      }

EXIT CODES (usable in shell pipelines):
  0 = CLEAN,  1 = SUSPICIOUS,  2 = ANOMALOUS,  3 = usage/input error.
  In batch (--dir) mode the exit code reflects the WORST verdict found.

================================================================================
SCORING MODEL (heuristic, fully deterministic)
================================================================================
  spam_raw    = sum of spam signal points          -> clamped to 0-100
  brand_raw   = sum of brand impersonation points  -> clamped to 0-100
  anomaly_raw = sum of technical anomaly points    -> clamped to 0-100

  anomaly_score = clamp( 0.4 * spam_raw + 0.6 * max(brand_raw, anomaly_raw)
                         + 0.2 * min(brand_raw, anomaly_raw) )

  verdict:  0-29 CLEAN | 30-59 SUSPICIOUS | 60-100 ANOMALOUS
================================================================================
"""

import argparse
import json
import re
import sys
import unicodedata
from pathlib import Path

# ==============================================================================
# CONFIGURATION / KNOWLEDGE TABLES
# All detection vocabularies live here so they are easy to audit and extend.
# ==============================================================================

# --- Spam vocabulary --------------------------------------------------------
# Each entry: (compiled-regex-pattern-string, points, human label).
# Patterns are matched case-insensitively against the whole body.
# Points are intentionally small per-signal; spam emails typically trip many.
SPAM_PATTERNS = [
    # Money / prize bait — classic advance-fee and lottery spam vocabulary
    (r"\b(you (have )?won|winner|lottery|jackpot|prize|congratulations)\b", 12, "prize/lottery bait"),
    (r"\b(million (dollars|usd|euros)|inheritance|unclaimed funds?)\b",      15, "large-money bait"),
    (r"\b(free (money|gift|iphone|trial)|no cost|risk[- ]free)\b",           10, "free-offer bait"),
    (r"(\$|€|£|₺)\s?\d{1,3}([.,]\d{3})+",                                    6,  "large currency amount"),
    # Urgency / pressure — pushes the reader to act before thinking
    (r"\b(urgent|immediately|act now|right away|final (notice|warning))\b",  10, "urgency pressure"),
    (r"\b(within (24|48) hours|expires? (today|soon)|last chance)\b",        10, "deadline pressure"),
    (r"\b(account (will be )?(suspended|closed|terminated|locked))\b",       12, "account-threat pressure"),
    # Call-to-action bait — generic click lures common in bulk mail
    (r"\b(click (here|below|the link)|open the attachment)\b",               8,  "click-bait CTA"),
    (r"\b(verify|confirm|update) (your )?(account|identity|information|details)\b", 12, "verification lure"),
    # Financial-offer spam
    (r"\b(work from home|be your own boss|extra income|easy money)\b",       10, "get-rich-quick offer"),
    (r"\b(cheap|discount|lowest price)s?\b.{0,40}\b(meds?|pills?|viagra|pharmacy)\b", 15, "pharma spam"),
    (r"\b(hot singles|adult content|xxx)\b",                                 15, "adult spam"),
    (r"\b(crypto(currency)? (investment|profit)|guaranteed returns?)\b",     12, "investment spam"),
    # List-mail fingerprints — bulk-mailer footer language
    (r"\b(unsubscribe|opt[- ]?out|remove me from this list)\b",              4,  "bulk-mail footer language"),
    (r"\bdear (customer|user|friend|beneficiary|sir/madam)\b",               6,  "impersonal greeting"),
]

# --- Known brands -----------------------------------------------------------
# Brands frequently abused in phishing. Mentioning a brand is NOT bad by
# itself; risk rises when a mention co-occurs with credential/urgency language
# or with links that do not belong to the brand (checked later).
# Mapping: canonical brand name -> tuple of legitimate domain suffixes.
KNOWN_BRANDS = {
    # Fictional brand used only by examples/sample_phishing.eml so the shipped
    # demo exercises brand-impersonation detection without naming a real
    # company. ".example" is reserved for documentation by RFC 2606, so this
    # entry can never collide with a real domain. Safe to delete.
    "globalpay":  ("globalpay.example",),
    # Global tech / e-commerce
    "paypal":     ("paypal.com",),
    "amazon":     ("amazon.com", "amazon.com.tr"),
    "apple":      ("apple.com", "icloud.com"),
    "microsoft":  ("microsoft.com", "live.com", "outlook.com"),
    "google":     ("google.com", "gmail.com"),
    "netflix":    ("netflix.com",),
    "facebook":   ("facebook.com", "meta.com"),
    "instagram":  ("instagram.com",),
    "whatsapp":   ("whatsapp.com",),
    "linkedin":   ("linkedin.com",),
    "spotify":    ("spotify.com",),
    "ebay":       ("ebay.com",),
    "alibaba":    ("alibaba.com",),
    # Shipping / cargo — very common phishing themes
    "dhl":        ("dhl.com",),
    "fedex":      ("fedex.com",),
    "ups":        ("ups.com",),
    "aras kargo": ("araskargo.com.tr",),
    "yurtiçi kargo": ("yurticikargo.com",),
    "mng kargo":  ("mngkargo.com.tr",),
    "ptt":        ("ptt.gov.tr",),
    # Banks & payments (global + Turkish)
    "visa":       ("visa.com",),
    "mastercard": ("mastercard.com",),
    "stripe":     ("stripe.com",),
    "ziraat":     ("ziraatbank.com.tr",),
    "garanti":    ("garantibbva.com.tr",),
    "akbank":     ("akbank.com",),
    "yapı kredi": ("yapikredi.com.tr",),
    "yapi kredi": ("yapikredi.com.tr",),
    "iş bankası": ("isbank.com.tr",),
    "is bankasi": ("isbank.com.tr",),
    "halkbank":   ("halkbank.com.tr",),
    "vakıfbank":  ("vakifbank.com.tr",),
    "vakifbank":  ("vakifbank.com.tr",),
    "papara":     ("papara.com",),
    # Turkish e-commerce / services
    "trendyol":   ("trendyol.com",),
    "hepsiburada":("hepsiburada.com",),
    "n11":        ("n11.com",),
    "sahibinden": ("sahibinden.com",),
    "getir":      ("getir.com",),
    "turkcell":   ("turkcell.com.tr",),
    "vodafone":   ("vodafone.com", "vodafone.com.tr"),
    "e-devlet":   ("turkiye.gov.tr",),
}

# Credential-harvesting phrases: when found NEAR a brand mention they strongly
# indicate impersonation rather than a legitimate transactional email.
CREDENTIAL_PATTERNS = [
    r"\b(password|passcode|şifre|parola)\b",
    r"\b(card number|kart numaras[ıi]|cvv|cvc|pin)\b",
    r"\b(login|log in|sign in|giriş yap)\b",
    r"\b(social security|tc kimlik|identity number)\b",
    r"\b(verify|confirm|doğrula|onayla)\b",
]

# URL shorteners — legitimate, but heavily abused to hide phishing targets.
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc",
}

# Regex that extracts URLs (http/https or bare www.) from free text.
URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"')\]]+", re.IGNORECASE)

# Verdict thresholds on the final anomaly score.
THRESHOLD_SUSPICIOUS = 30
THRESHOLD_ANOMALOUS = 60


# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

def clamp(value: float, lo: int = 0, hi: int = 100) -> int:
    """Clamp a numeric value into [lo, hi] and return it as an int score."""
    return int(max(lo, min(hi, round(value))))


def extract_domain(url: str) -> str:
    """
    Extract the bare hostname from a URL string.

    Input : url  — e.g. "https://secure-paypal.account-check.ru/login?x=1"
    Output: str  — e.g. "secure-paypal.account-check.ru" (lowercased, no port)
    """
    host = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
    host = host.split("/")[0].split("?")[0].split("#")[0]
    host = host.split(":")[0]          # drop :port if present
    return host.lower().lstrip("www.") if host.startswith("www.") else host.lower()


def domain_matches(domain: str, legit_suffixes: tuple) -> bool:
    """
    Check whether `domain` is the legitimate domain itself or a subdomain of it.

    Input : domain         — hostname found in the email body
            legit_suffixes — tuple of official domains for a brand
    Output: bool           — True if the domain legitimately belongs to the brand

    Example: domain_matches("mail.paypal.com", ("paypal.com",)) -> True
             domain_matches("paypal.com.evil.ru", ("paypal.com",)) -> False
    """
    return any(domain == suf or domain.endswith("." + suf) for suf in legit_suffixes)


# Homoglyph normalization map: visually-identical Cyrillic/Greek letters that
# attackers substitute into brand names to evade keyword filters. Brand
# detection runs on NORMALIZED text so "PayPаl" (Cyrillic 'а') still matches.
HOMOGLYPH_MAP = str.maketrans({
    # Cyrillic -> Latin lookalikes
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ԁ": "d", "ј": "j", "һ": "h", "ԛ": "q", "ѡ": "w",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X",
    # Greek -> Latin lookalikes
    "ο": "o", "ν": "v", "α": "a", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z",
    "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P",
    "Τ": "T", "Υ": "Y", "Χ": "X",
})


def normalize_homoglyphs(text: str) -> str:
    """
    Replace common Cyrillic/Greek lookalike characters with their Latin
    equivalents so that keyword/brand matching cannot be evaded by
    character substitution.

    Input : text — raw email body
    Output: str  — same text with lookalike characters mapped to Latin
    """
    return text.translate(HOMOGLYPH_MAP)


def find_mixed_script_words(text: str):
    """
    Detect homoglyph tricks: words that mix Latin letters with visually similar
    Cyrillic/Greek letters (e.g. "PayPаl" where 'а' is Cyrillic U+0430).
    Attackers use this to slip brand names past naive keyword filters.

    Input : text — full email body
    Output: list[str] — up to 5 offending words (deduplicated, order preserved)
    """
    suspicious = []
    for word in re.findall(r"\S{3,}", text):
        scripts = set()
        for ch in word:
            if ch.isalpha():
                try:
                    name = unicodedata.name(ch)
                except ValueError:
                    continue
                if name.startswith("LATIN"):
                    scripts.add("LATIN")
                elif name.startswith("CYRILLIC"):
                    scripts.add("CYRILLIC")
                elif name.startswith("GREEK"):
                    scripts.add("GREEK")
        # A single word mixing Latin with Cyrillic/Greek is almost never
        # legitimate prose — flag it.
        if "LATIN" in scripts and (scripts & {"CYRILLIC", "GREEK"}):
            if word not in suspicious:
                suspicious.append(word)
        if len(suspicious) >= 5:
            break
    return suspicious


# ==============================================================================
# ANALYSIS PASSES
# Each pass returns (raw_points, list_of_signal_dicts). Signal dicts share the
# schema: {"category", "name", "detail", "points"} — see module docstring.
# ==============================================================================

def analyze_spam(body: str, stats: dict):
    """
    PASS 1 — Spam scoring based on vocabulary and writing-style statistics.

    Input : body  — email body text (original casing preserved)
            stats — precomputed body statistics (see compute_stats)
    Output: (raw_points: int, signals: list[dict])
    """
    signals = []
    points = 0

    # 1a. Vocabulary patterns: each regex hit contributes its fixed weight once.
    for pattern, weight, label in SPAM_PATTERNS:
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            points += weight
            signals.append({
                "category": "spam",
                "name": label,
                "detail": f"matched text: '{match.group(0)[:60]}'",
                "points": weight,
            })

    # 1b. SHOUTING: high uppercase ratio is a classic bulk-spam style marker.
    #     Only meaningful on bodies with enough letters to compute a ratio.
    if stats["letter_count"] >= 40 and stats["caps_ratio"] > 0.3:
        weight = 10 if stats["caps_ratio"] > 0.5 else 6
        points += weight
        signals.append({
            "category": "spam",
            "name": "excessive capitalization",
            "detail": f"{stats['caps_ratio']:.0%} of letters are uppercase",
            "points": weight,
        })

    # 1c. Exclamation density: more than ~1 per 40 words reads as hype/spam.
    if stats["word_count"] > 0:
        excl_per_word = stats["exclamation_count"] / stats["word_count"]
        if stats["exclamation_count"] >= 3 and excl_per_word > 0.025:
            points += 6
            signals.append({
                "category": "spam",
                "name": "exclamation overload",
                "detail": f"{stats['exclamation_count']} '!' in {stats['word_count']} words",
                "points": 6,
            })

    return points, signals


def analyze_brands(body: str, urls: list):
    """
    PASS 2 — Brand detection and impersonation risk assessment.

    Logic: a brand mention alone is neutral. Risk escalates when the mention
    co-occurs (within a ±120-char window) with credential-request phrases,
    or when the body links to domains that do NOT belong to the named brand.

    Input : body — email body text
            urls — list of URL strings already extracted from the body
    Output: (raw_points: int, signals: list[dict], brands: list[dict])
            `brands` follows the "brands_detected" schema in the module docstring.
    """
    signals = []
    brands = []
    points = 0
    lower = body.lower()
    domains = [extract_domain(u) for u in urls]

    for brand, legit in KNOWN_BRANDS.items():
        # Find every mention position so we can inspect the local context.
        positions = [m.start() for m in re.finditer(re.escape(brand), lower)]
        if not positions:
            continue

        reasons = []
        brand_pts = 0

        # 2a. Credential language near the brand name (context window ±120 chars).
        for pos in positions:
            window = lower[max(0, pos - 120): pos + 120]
            if any(re.search(p, window, re.IGNORECASE) for p in CREDENTIAL_PATTERNS):
                reasons.append("credential/verification language near brand mention")
                brand_pts += 20
                break  # count this reason once per brand

        # 2b. Urgency language anywhere + brand mention = pressure phishing combo.
        if re.search(r"\b(urgent|immediately|suspended|expires?|24 hours|hemen|acil)\b",
                     lower):
            reasons.append("urgency language combined with brand mention")
            brand_pts += 10

        # 2c. Domain mismatch: the body names the brand but links elsewhere.
        #     This is the strongest single impersonation indicator we have.
        if domains:
            foreign = [d for d in domains if not domain_matches(d, legit)]
            # Lookalike domains: brand string embedded in a non-official domain,
            # e.g. "paypal-security.xyz" — near-certain impersonation.
            lookalikes = [d for d in foreign
                          if brand.replace(" ", "") in d.replace("-", "").replace(".", "")]
            if lookalikes:
                reasons.append(f"lookalike domain(s): {', '.join(lookalikes[:3])}")
                brand_pts += 35
            elif foreign and not any(domain_matches(d, legit) for d in domains):
                reasons.append(
                    f"brand named but all links point elsewhere: {', '.join(foreign[:3])}")
                brand_pts += 15

        # Map accumulated brand points to a categorical risk label.
        risk = "high" if brand_pts >= 35 else "medium" if brand_pts >= 15 else "low"
        brands.append({
            "brand": brand,
            "mention_count": len(positions),
            "impersonation_risk": risk,
            "reasons": reasons,
        })
        points += brand_pts
        if brand_pts:
            signals.append({
                "category": "brand",
                "name": f"possible impersonation of '{brand}'",
                "detail": "; ".join(reasons),
                "points": brand_pts,
            })

    return points, signals, brands


def analyze_anomalies(body: str, urls: list, stats: dict):
    """
    PASS 3 — Technical anomaly detection independent of vocabulary.

    Input : body  — email body text
            urls  — extracted URL list
            stats — precomputed body statistics
    Output: (raw_points: int, signals: list[dict])
    """
    signals = []
    points = 0
    domains = [extract_domain(u) for u in urls]

    # 3a. Raw IP address used as a link target — legit senders essentially
    #     never do this; phishing kits frequently do.
    ip_urls = [d for d in domains if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", d)]
    if ip_urls:
        points += 25
        signals.append({
            "category": "anomaly",
            "name": "raw IP address link",
            "detail": f"links to IP host(s): {', '.join(ip_urls[:3])}",
            "points": 25,
        })

    # 3b. URL shorteners hide the real destination from the reader.
    short = [d for d in domains if d in URL_SHORTENERS]
    if short:
        points += 12
        signals.append({
            "category": "anomaly",
            "name": "URL shortener",
            "detail": f"shortened link(s): {', '.join(sorted(set(short)))}",
            "points": 12,
        })

    # 3c. Link flooding: unusually many URLs for the amount of text.
    if len(urls) >= 5 and stats["word_count"] > 0 and \
            len(urls) / max(stats["word_count"], 1) > 0.03:
        points += 8
        signals.append({
            "category": "anomaly",
            "name": "excessive links",
            "detail": f"{len(urls)} URLs in {stats['word_count']} words",
            "points": 8,
        })

    # 3d. Homoglyph / mixed-script words — filter-evasion technique.
    mixed = find_mixed_script_words(body)
    if mixed:
        points += 20
        signals.append({
            "category": "anomaly",
            "name": "mixed-script (homoglyph) characters",
            "detail": f"suspicious word(s): {', '.join(mixed)}",
            "points": 20,
        })

    # 3e. Suspicious top-level domains that are cheap and abuse-heavy.
    bad_tlds = [d for d in domains
                if re.search(r"\.(xyz|top|click|link|live|icu|tk|ml|ga|cf|gq)$", d)]
    if bad_tlds:
        points += 12
        signals.append({
            "category": "anomaly",
            "name": "high-abuse TLD",
            "detail": f"domain(s) on abuse-prone TLDs: {', '.join(bad_tlds[:3])}",
            "points": 12,
        })

    # 3f. Extremely short body that still contains a link — classic
    #     "see attached invoice / click this" lure with no real content.
    if stats["word_count"] < 15 and urls:
        points += 10
        signals.append({
            "category": "anomaly",
            "name": "minimal body with link",
            "detail": f"only {stats['word_count']} words but contains {len(urls)} link(s)",
            "points": 10,
        })

    return points, signals


# ==============================================================================
# ORCHESTRATION
# ==============================================================================

def compute_stats(body: str) -> dict:
    """
    Compute basic writing-style statistics used by multiple passes.

    Input : body — email body text
    Output: dict with keys:
        char_count        — total characters
        word_count        — whitespace-separated tokens
        letter_count      — alphabetic characters only
        caps_ratio        — uppercase letters / all letters (0.0 if no letters)
        exclamation_count — number of '!' characters
        url_count         — number of URLs found
    """
    letters = [c for c in body if c.isalpha()]
    upper = sum(1 for c in letters if c.isupper())
    urls = URL_RE.findall(body)
    return {
        "char_count": len(body),
        "word_count": len(body.split()),
        "letter_count": len(letters),
        "caps_ratio": (upper / len(letters)) if letters else 0.0,
        "exclamation_count": body.count("!"),
        "url_count": len(urls),
    }


def analyze(body: str, source: str) -> dict:
    """
    Run all three analysis passes over one email body and build the final
    result object.

    Input : body   — the email body text to analyze
            source — label describing where the body came from
                     (file path, "inline", or "stdin"); echoed into the output
    Output: dict matching the JSON schema documented in the module docstring.
    """
    stats = compute_stats(body)
    urls = URL_RE.findall(body)

    spam_pts, spam_sigs = analyze_spam(body, stats)
    # Brand matching runs on homoglyph-NORMALIZED text so that character
    # substitution tricks (e.g. "PayPаl" with Cyrillic 'а') cannot hide a
    # brand name. Homoglyph presence itself is still flagged separately
    # by analyze_anomalies() using the ORIGINAL body.
    brand_pts, brand_sigs, brands = analyze_brands(normalize_homoglyphs(body), urls)
    anomaly_pts, anomaly_sigs = analyze_anomalies(body, urls, stats)

    spam_score = clamp(spam_pts)
    brand_score = clamp(brand_pts)
    tech_score = clamp(anomaly_pts)

    # Weighted blend (see module docstring): brand impersonation and technical
    # anomalies dominate (0.6 major + 0.2 minor), spam vocabulary supports (0.4).
    major, minor = max(brand_score, tech_score), min(brand_score, tech_score)
    anomaly_score = clamp(0.4 * spam_score + 0.6 * major + 0.2 * minor)

    # ESCALATION RULE: a "high" impersonation-risk brand (credential harvesting
    # plus lookalike domain) is conclusive on its own — force the score to at
    # least the ANOMALOUS threshold regardless of how mild the rest looks.
    if any(b["impersonation_risk"] == "high" for b in brands):
        anomaly_score = max(anomaly_score, THRESHOLD_ANOMALOUS)

    if anomaly_score >= THRESHOLD_ANOMALOUS:
        verdict = "ANOMALOUS"
    elif anomaly_score >= THRESHOLD_SUSPICIOUS:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    # letter_count is internal-only; drop it from the public stats block.
    public_stats = {k: (round(v, 3) if isinstance(v, float) else v)
                    for k, v in stats.items() if k != "letter_count"}

    return {
        "source": source,
        "spam_score": spam_score,
        "anomaly_score": anomaly_score,
        "verdict": verdict,
        "brands_detected": brands,
        "signals": spam_sigs + brand_sigs + anomaly_sigs,
        "stats": public_stats,
    }


# ==============================================================================
# OUTPUT RENDERING
# ==============================================================================

def render_human(result: dict) -> str:
    """
    Render one analysis result as a human-readable text report.

    Input : result — dict returned by analyze()
    Output: str — multi-line formatted report for terminal display
    """
    lines = []
    bar = "=" * 62
    lines.append(bar)
    lines.append(f" EMAIL BODY ANALYSIS — {result['source']}")
    lines.append(bar)
    lines.append(f" Spam score    : {result['spam_score']:>3}/100")
    lines.append(f" Anomaly score : {result['anomaly_score']:>3}/100")
    lines.append(f" VERDICT       : {result['verdict']}")
    lines.append("-" * 62)

    if result["brands_detected"]:
        lines.append(" Brands detected:")
        for b in result["brands_detected"]:
            lines.append(f"   • {b['brand']} (mentions: {b['mention_count']}, "
                         f"impersonation risk: {b['impersonation_risk']})")
            for r in b["reasons"]:
                lines.append(f"       - {r}")
    else:
        lines.append(" Brands detected: none")

    lines.append("-" * 62)
    if result["signals"]:
        lines.append(" Triggered signals:")
        for s in result["signals"]:
            lines.append(f"   [{s['category']:>7}] +{s['points']:<3} {s['name']}")
            lines.append(f"             {s['detail']}")
    else:
        lines.append(" Triggered signals: none")

    st = result["stats"]
    lines.append("-" * 62)
    lines.append(f" Stats: {st['word_count']} words, {st['url_count']} URLs, "
                 f"caps ratio {st['caps_ratio']:.0%}, "
                 f"{st['exclamation_count']} exclamation mark(s)")
    lines.append(bar)
    return "\n".join(lines)


VERDICT_EXIT = {"CLEAN": 0, "SUSPICIOUS": 1, "ANOMALOUS": 2}


# ==============================================================================
# CLI ENTRY POINT
# ==============================================================================

def main(argv=None) -> int:
    """
    Parse CLI arguments, gather input bodies, analyze, print, and return
    the exit code (worst verdict across all analyzed bodies).
    """
    parser = argparse.ArgumentParser(
        prog="email_analyzer.py",
        description="Spam / brand-impersonation / anomaly scorer for email BODY text.",
    )
    src = parser.add_mutually_exclusive_group()
    src.add_argument("--text", help="email body as an inline string")
    src.add_argument("--file", help="path to a UTF-8 text file with one email body")
    src.add_argument("--dir", help="directory: analyze every *.txt file inside")
    parser.add_argument("--json", action="store_true",
                        help="emit machine-readable JSON instead of a text report")
    args = parser.parse_args(argv)

    # ---- Gather (source_label, body_text) pairs from the chosen input mode ----
    jobs = []
    try:
        if args.text is not None:
            jobs.append(("inline", args.text))
        elif args.file:
            jobs.append((args.file, Path(args.file).read_text(encoding="utf-8",
                                                              errors="replace")))
        elif args.dir:
            files = sorted(Path(args.dir).glob("*.txt"))
            if not files:
                print(f"error: no *.txt files found in {args.dir}", file=sys.stderr)
                return 3
            for f in files:
                jobs.append((str(f), f.read_text(encoding="utf-8", errors="replace")))
        else:
            # No explicit source: fall back to stdin (supports piping).
            if sys.stdin.isatty():
                parser.print_help(sys.stderr)
                return 3
            jobs.append(("stdin", sys.stdin.read()))
    except OSError as exc:
        print(f"error: cannot read input: {exc}", file=sys.stderr)
        return 3

    # Reject empty bodies early — scoring empty text is meaningless.
    jobs = [(s, b) for s, b in jobs if b.strip()]
    if not jobs:
        print("error: input body is empty", file=sys.stderr)
        return 3

    # ---- Analyze every body and render output ---------------------------------
    results = [analyze(body, source) for source, body in jobs]

    if args.json:
        # Single input -> single object; batch -> array. Keeps jq usage simple.
        payload = results[0] if len(results) == 1 else results
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        for r in results:
            print(render_human(r))
            print()

    # Exit code = worst verdict encountered (useful for shell pipelines).
    return max(VERDICT_EXIT[r["verdict"]] for r in results)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        # Occurs when output is piped into a consumer that exits early
        # (e.g. `... --json | head`). Exit quietly instead of a traceback.
        sys.stderr.close()
        sys.exit(0)
