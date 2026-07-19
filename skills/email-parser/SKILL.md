---
name: email-parser
description: Parse email files (.msg Outlook files and .eml RFC 5322/MIME files) into structured JSON. Use this skill whenever the user uploads or mentions a .msg or .eml file, or asks to extract email parts such as subject, sender, recipients (to/cc/bcc), date, headers, plain-text body, HTML body, or attachments from an email file. Also use it when the user wants to convert emails to JSON, batch-process email files, inspect email metadata/headers, or list/extract attachments from Outlook or standard email messages. Works fully offline with pure Python (no pip installs required).
---

# Email Parser (.msg / .eml → JSON)

Parse Outlook `.msg` files and standard `.eml` files into one normalized JSON
structure containing all the parts of the email.

## Quick start

Run the bundled script from the command line:

```bash
# Basic usage — prints pretty JSON to stdout
python3 scripts/parse_email.py /path/to/message.eml

# Outlook file, write result to a JSON file
python3 scripts/parse_email.py /path/to/message.msg -o result.json

# Include attachment binary content as Base64 in the JSON
python3 scripts/parse_email.py message.msg --include-attachment-data

# Compact single-line JSON (useful for piping)
python3 scripts/parse_email.py message.eml --compact
```

The format is auto-detected from file content (OLE2 magic bytes → `.msg`,
otherwise `.eml`), so a wrong file extension is not a problem.

## Input

- One email file: `.msg` (Outlook / MS-OXMSG) or `.eml` (RFC 5322 / MIME).
- No third-party dependencies; only the Python 3 standard library is used
  (the `.msg` container is parsed by a built-in CFB reader).

## Output — JSON schema

```jsonc
{
  "format": "eml" | "msg",              // detected source format
  "subject": "…",
  "from":  { "name": "…", "email": "…" },
  "to":   [ { "name": "…", "email": "…" } ],
  "cc":   [ … ],
  "bcc":  [ … ],
  "date": "2026-07-18T09:30:00+00:00",  // ISO-8601 sent time
  "message_id": "<…>",
  "headers": { "Header-Name": "value or [values]" },
  "body": { "text": "…", "html": "…" },
  "attachments": [
    {
      "filename": "report.pdf",
      "content_type": "application/pdf",
      "size_bytes": 12345,
      "content_id": null,               // set for inline images
      "is_inline": false,
      "data_base64": "…"                // only with --include-attachment-data
    }
  ],
  "warnings": [ "non-fatal parsing notes" ]
}
```

Exit codes: `0` success, `1` file unreadable, `2` corrupt/unsupported format,
`3` unexpected error.

## Workflow for Claude

1. Locate the uploaded file under `/mnt/user-data/uploads/`.
2. Run `python3 scripts/parse_email.py <file>` (add `-o out.json` for large
   emails so the full result lands on disk instead of flooding the context).
3. Read the JSON and answer the user's question, or deliver the JSON file via
   the outputs directory.
4. To extract attachment bytes to real files, re-run with
   `--include-attachment-data` and Base64-decode the `data_base64` fields, or
   import the script (`from parse_email import parse_msg, parse_eml`) and use
   the returned dict directly.

## Notes and limitations

- `.msg` bodies stored **only** as compressed RTF (property `1009`) are not
  decoded; a note is added to `warnings` and text/HTML bodies stay `null`.
- Sender addresses from Exchange may be X.500 (`/O=…`) instead of SMTP; the
  script prefers SMTP properties (`5D01`, `39FE`) and warns otherwise.
- Embedded `.msg` attachments are listed with `is_embedded_message: true`;
  their inner content is not recursively expanded.
- Batch processing: loop the script over files in bash, e.g.
  `for f in *.msg *.eml; do python3 scripts/parse_email.py "$f" -o "${f%.*}.json"; done`
