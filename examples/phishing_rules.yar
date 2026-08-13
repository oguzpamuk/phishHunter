/*
    phishing_rules.yar — Example YARA rules for the phishHunter pipeline.

    These are DEMO rules, intentionally simple, meant to show how the
    optional YARA stage feeds matches into the verdict engine. Run them via:

        python3 skills/email-triage-pipeline/scripts/triage_pipeline.py \
            examples/sample_phishing.eml --skills-root skills \
            --yara-rules examples/phishing_rules.yar --format text

    Each rule sets meta.severity ("high" | "medium" | "low"), which the
    verdict engine maps to points: high/critical=+50, medium=+25, low=+12.
    Replace these with your own production rules — phishHunter never authors
    detection logic itself; you bring your own.

    The scanner runs every rule against each layer of the email separately
    (raw_file, headers, body_text, body_html, attachment:<name>), so a rule
    matches whichever part of the message actually contains the pattern.
*/

rule Phish_CredHarvest_Language
{
    meta:
        author      = "phishHunter-example"
        severity    = "high"
        description = "Credential-harvesting urgency + account-suspension lures"
        reference   = "demo rule — replace with production logic"
    strings:
        // Common social-engineering pressure phrases (case-insensitive).
        $urgency1 = "account has been suspended"  nocase
        $urgency2 = "verify immediately"          nocase
        $urgency3 = "within 24 hours"             nocase
        $action   = "click here"                  nocase
        $verify   = "verify your account"         nocase
    condition:
        // Two or more independent lures in the same message is a strong
        // phishing indicator, so we require at least 2 of the 5 strings.
        2 of them
}

rule Phish_Suspicious_Lookalike_Domain
{
    meta:
        author      = "phishHunter-example"
        severity    = "medium"
        description = "Login/verify lookalike domains often used in phishing"
        reference   = "demo rule — replace with production logic"
    strings:
        // Substrings frequently seen in throwaway credential-phishing hosts.
        $d1 = "secure-login"    nocase
        $d2 = "account-verify"  nocase
        $d3 = "signin-update"   nocase
        $d4 = "-security."      nocase
    condition:
        any of them
}

rule Phish_Macro_Attachment_Marker
{
    meta:
        author      = "phishHunter-example"
        severity    = "high"
        description = "Office open-XML macro markers in attachment bytes"
        reference   = "demo rule — replace with production logic"
    strings:
        // vbaProject.bin is present in macro-enabled Office documents; its
        // appearance in an attachment layer is worth flagging for review.
        $macro1 = "vbaProject.bin"
        $macro2 = "Microsoft Office Word"  nocase
        $autoopen = "AutoOpen"             nocase
    condition:
        $macro1 or ($macro2 and $autoopen)
}
