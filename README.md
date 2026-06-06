# Wayback Machine Sensitive URL Scanner
This is a legitimate bug bounty reconnaissance tool — checking Wayback Machine snapshots for sensitive info exposure is a standard and ethical part of security research. Let me build this properly. Now let me install the dependencies and verify the script runs cleanly: All clean. Let me copy to the output folder and present it:  Here's your **Wayback Machine Sensitive URL Scanner** — ready to drop in your bounty folder.

---

## What it does

**Step 1 — Smart pre-filtering**
Before touching the archive, it skips obvious garbage: images, fonts, zips, PDFs, CSS, media. It only queues URLs with sensitive extensions (`.php`, `.js`, `.json`, `.env`, `.config`, `.log`, `.sql`, `.bak`, `.yml`, etc.) or no extension (dynamic pages).

**Step 2 — Wayback CDX API lookup**
For each URL it queries the CDX API (not the main site), asking for up to 10 daily-collapsed `200 OK` / `text/html` snapshots within your chosen time window. No snapshot = skip cleanly.

**Step 3 — Selective download**
Downloads the snapshot raw HTML. Rejects anything non-text by Content-Type, and anything suspiciously tiny (redirect/error pages < 200 chars).

**Step 4 — Pattern analysis (30+ patterns)**
Scans the raw HTML (including JS blocks, inline comments, `<meta>` tags) for:

| Category | Examples |
|---|---|
| Credentials | AWS keys, generic API keys, hardcoded passwords |
| Tokens | JWT, Bearer, OAuth, GitHub PAT, Slack, Stripe, SendGrid |
| PII | Emails, SSNs, phone numbers, credit cards |
| Infrastructure | DB connection strings, JDBC URLs, S3 buckets, internal hostnames |
| Dev artifacts | Stack traces, `DEBUG=True`, `.env` vars, git merge conflicts, TODO comments with creds |

**Step 5 — HTML report**
Saves the raw snapshot HTML per-finding, then generates a dark-themed `report_YYYYMMDD_HHMMSS.html` with a summary table and expandable findings — all in your output folder.

---

## Setup & Usage

```bash
pip install requests beautifulsoup4

# Default (reads interestingEXT.txt, saves to ./wayback_results/)
python wayback_scanner.py

# Custom input, custom output
python wayback_scanner.py -i scope_urls.txt -o ./recon_out

# More threads, shorter lookback window
python wayback_scanner.py -t 10 --years 2
python wayback_scanner.py --debug
python wayback_scanner.py -i interestingEXT.txt --years 7 --debug
```

---

## Output structure

```
wayback_results/
├── report_20260606_143021.html        ← master findings report (open this)
├── 20230412_example.com__api__keys.html   ← raw snapshot with AWS key hit
├── 20221109_app.target.com__config.html   ← raw snapshot with DB string
└── ...
```

The report links directly to each saved snapshot file, so you can open the raw HTML locally to verify findings before reporting them.
