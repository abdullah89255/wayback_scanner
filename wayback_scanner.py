#!/usr/bin/env python3
"""
Wayback Machine Sensitive URL Scanner
Bug Bounty Recon Tool

Usage:
    python wayback_scanner.py                        # uses interestingEXT.txt
    python wayback_scanner.py -i urls.txt            # custom input file
    python wayback_scanner.py -i urls.txt -o ./out   # custom output dir
    python wayback_scanner.py --threads 10           # parallel workers
    python wayback_scanner.py --years 3              # only last N years
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path

import requests
from bs4 import BeautifulSoup

# ──────────────────────────────────────────────
# SENSITIVE PATTERN DEFINITIONS
# ──────────────────────────────────────────────

SENSITIVE_PATTERNS = {
    # Credentials & Secrets
    "AWS Access Key":         r'(?:AKIA|AIPA|ASIA|AROA)[A-Z0-9]{16}',
    "AWS Secret Key":         r'(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key[\s]*[=:]\s*["\']?([A-Za-z0-9/+=]{40})',
    "Generic API Key":        r'(?i)(?:api[_\-]?key|apikey|api[_\-]?token)\s*[=:]\s*["\']?([A-Za-z0-9\-_]{16,64})',
    "Generic Secret":         r'(?i)(?:secret|password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']',
    "Bearer Token":           r'(?i)bearer\s+([A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*)',
    "Basic Auth in URL":      r'https?://[^:@\s]+:[^@\s]+@[^\s]+',
    "Private Key Header":     r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
    "PGP Private Key":        r'-----BEGIN PGP PRIVATE KEY BLOCK-----',

    # Tokens & Auth
    "JWT Token":              r'eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]+',
    "OAuth Token":            r'(?i)(?:oauth[_\-]?token|access[_\-]?token)\s*[=:]\s*["\']?([A-Za-z0-9\-_.~+/]{20,})',
    "GitHub Token":           r'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}',
    "Slack Token":            r'xox[baprs]-[0-9A-Za-z\-]{10,48}',
    "Stripe Key":             r'(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}',
    "Twilio SID":             r'AC[a-f0-9]{32}',
    "Google API Key":         r'AIza[0-9A-Za-z\-_]{35}',
    "Heroku API Key":         r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    "SendGrid Key":           r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}',
    "Mailchimp API Key":      r'[0-9a-f]{32}-us[0-9]{1,2}',

    # PII
    "Email Address":          r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
    "Phone Number (US)":      r'\b(?:\+1[\s\-.]?)?\(?[0-9]{3}\)?[\s\-.]?[0-9]{3}[\s\-.]?[0-9]{4}\b',
    "SSN":                    r'\b(?!000|666|9\d{2})\d{3}[\s\-]\d{2}[\s\-]\d{4}\b',
    "Credit Card":            r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6011[0-9]{12})\b',
    "IP Address (internal)":  r'\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}\b',

    # Infrastructure
    "Database Connection":    r'(?i)(?:mongodb|mysql|postgresql|redis|amqp)://[^\s<>"]+',
    "JDBC Connection":        r'(?i)jdbc:[a-z]+://[^\s<>"]+',
    "S3 Bucket":              r's3://[a-z0-9.\-_]{3,63}',
    "Internal Hostname":      r'(?i)(?:hostname|host)\s*[=:]\s*["\']?([a-z0-9\-]+\.(?:internal|local|corp|intranet))',
    "Debug/Stack Trace":      r'(?i)(?:Traceback \(most recent|at [A-Za-z]+\.[A-Za-z]+\(|Exception in thread|NullPointerException|Fatal error:)',
    "Config/Env Variable":    r'(?i)(?:APP_ENV|DATABASE_URL|SECRET_KEY|DEBUG\s*=\s*[Tt]rue|FLASK_ENV\s*=\s*development)',

    # Source / Dev Artifacts
    "TODO/FIXME Comment":     r'(?i)(?://|#|/\*)\s*(?:TODO|FIXME|HACK|XXX|BUG)\b[^\n]{0,120}',
    "Hardcoded Password Comment": r'(?i)(?://|#)\s*(?:password|passwd|pwd)\s*[=:]\s*\S+',
    "Git Merge Conflict":      r'<{7} HEAD',
    "Commented Credentials":   r'(?i)<!--.*?(?:password|secret|token|key)\s*[=:][^>]{4,}-->',
}

# Extensions we consider "sensitive" and worth downloading
SENSITIVE_EXTENSIONS = {
    '.html', '.htm', '.php', '.asp', '.aspx', '.jsp', '.json', '.xml',
    '.js', '.ts', '.env', '.config', '.cfg', '.ini', '.yaml', '.yml',
    '.txt', '.log', '.sql', '.bak', '.backup', '.old', '.conf',
    '.properties', '.py', '.rb', '.pl', '.sh', '.bash',
}

# Extensions to always skip (binaries, media, etc.)
SKIP_EXTENSIONS = {
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.webp',
    '.mp4', '.mp3', '.avi', '.mov', '.wmv', '.flv', '.ogg', '.wav',
    '.zip', '.gz', '.tar', '.rar', '.7z', '.bz2',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.ttf', '.woff', '.woff2', '.eot', '.otf',
    '.exe', '.dll', '.so', '.dylib', '.bin',
    '.css',  # skip pure CSS (rarely sensitive)
}

WAYBACK_CDX_API = "http://web.archive.org/cdx/search/cdx"
WAYBACK_BASE    = "https://web.archive.org/web"


# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────

def log(msg, level="INFO"):
    colors = {"INFO": "\033[94m", "OK": "\033[92m", "WARN": "\033[93m",
              "FAIL": "\033[91m", "HEAD": "\033[1;96m", "RESET": "\033[0m"}
    ts = datetime.now().strftime("%H:%M:%S")
    c  = colors.get(level, "")
    r  = colors["RESET"]
    print(f"{c}[{ts}] [{level}] {msg}{r}", flush=True)


def sanitize_filename(url: str, timestamp: str) -> str:
    """Turn a URL + timestamp into a safe filename."""
    parsed = urllib.parse.urlparse(url)
    path   = parsed.path.strip("/").replace("/", "__") or "index"
    query  = parsed.query[:40].replace("&", "_").replace("=", "-") if parsed.query else ""
    name   = f"{parsed.netloc}__{path}"
    if query:
        name += f"__{query}"
    name   = re.sub(r'[^\w\-.]', '_', name)[:180]
    return f"{timestamp}_{name}.html"


def get_extension(url: str) -> str:
    path = urllib.parse.urlparse(url).path
    ext  = os.path.splitext(path)[1].lower()
    return ext


def is_sensitive_url(url: str) -> bool:
    """Quick pre-filter: skip obviously non-sensitive URLs."""
    ext = get_extension(url)
    if ext in SKIP_EXTENSIONS:
        return False
    # If it has a known sensitive ext, accept
    if ext in SENSITIVE_EXTENSIONS:
        return True
    # Accept URLs with no extension (dynamic pages)
    if not ext:
        return True
    return False


# ──────────────────────────────────────────────
# WAYBACK API
# ──────────────────────────────────────────────

def fetch_snapshots(url: str, years: int, session: requests.Session) -> list[dict]:
    """Query CDX API for available snapshots of a URL."""
    from_date = (datetime.utcnow() - timedelta(days=365 * years)).strftime("%Y%m%d")
    params = {
        "url":      url,
        "output":   "json",
        "fl":       "timestamp,statuscode,mimetype,original",
        "collapse":  "timestamp:8",   # one snapshot per day max
        "from":      from_date,
        "filter":   ["statuscode:200", "mimetype:text/html"],
        "limit":    "10",             # max 10 snapshots per URL
    }
    try:
        r = session.get(WAYBACK_CDX_API, params=params, timeout=20)
        r.raise_for_status()
        rows = r.json()
        if len(rows) <= 1:   # first row is header
            return []
        keys    = rows[0]
        results = [dict(zip(keys, row)) for row in rows[1:]]
        return results
    except Exception as e:
        log(f"CDX error for {url}: {e}", "WARN")
        return []


def download_snapshot(timestamp: str, original_url: str, session: requests.Session) -> str | None:
    """Download a specific Wayback snapshot and return raw HTML."""
    archive_url = f"{WAYBACK_BASE}/{timestamp}if_/{original_url}"
    try:
        r = session.get(archive_url, timeout=30, allow_redirects=True)
        r.raise_for_status()
        ct = r.headers.get("Content-Type", "")
        if "text" not in ct and "html" not in ct and "javascript" not in ct:
            log(f"  Skipping non-text content ({ct}) for {original_url}", "WARN")
            return None
        # Skip very small responses (error pages, redirects)
        if len(r.text) < 200:
            return None
        return r.text
    except Exception as e:
        log(f"  Download error: {e}", "WARN")
        return None


# ──────────────────────────────────────────────
# ANALYSIS
# ──────────────────────────────────────────────

def analyze_html(html: str, url: str) -> list[dict]:
    """Scan HTML for sensitive patterns. Returns list of findings."""
    findings = []
    soup     = BeautifulSoup(html, "html.parser")
    # Use raw text for pattern matching (includes JS, comments, etc.)
    raw_text = html

    for pattern_name, regex in SENSITIVE_PATTERNS.items():
        try:
            matches = re.findall(regex, raw_text)
            if matches:
                # Deduplicate and cap at 5 examples per pattern
                unique = list(dict.fromkeys(str(m).strip() for m in matches))[:5]
                findings.append({
                    "pattern": pattern_name,
                    "count":   len(matches),
                    "samples": unique,
                })
        except re.error:
            continue

    return findings


# ──────────────────────────────────────────────
# REPORT GENERATION
# ──────────────────────────────────────────────

REPORT_CSS = """
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       background:#0f1117; color:#e0e0e0; margin:0; padding:20px; }
h1   { color:#58a6ff; border-bottom:1px solid #30363d; padding-bottom:10px; }
h2   { color:#f0883e; margin-top:30px; font-size:1.1em; }
h3   { color:#8b949e; font-size:.95em; }
.finding { background:#161b22; border:1px solid #30363d; border-radius:6px;
           padding:12px 16px; margin:8px 0; }
.finding .label { color:#58a6ff; font-weight:bold; font-size:.9em; }
.finding .count { background:#388bfd26; color:#79c0ff; padding:2px 8px;
                  border-radius:12px; font-size:.8em; margin-left:6px; }
.sample { font-family:monospace; font-size:.82em; color:#f0883e;
          word-break:break-all; margin:4px 0 0 0; padding:4px 8px;
          background:#0d1117; border-radius:4px; }
.meta  { color:#8b949e; font-size:.85em; margin:4px 0; }
.url   { color:#58a6ff; word-break:break-all; }
.badge-high { color:#f85149; } .badge-med { color:#d29922; }
.badge-low  { color:#3fb950; }
.summary-box { background:#161b22; border:1px solid #30363d; border-radius:8px;
               padding:16px; max-width:600px; margin-bottom:24px; }
.summary-box span { font-size:2em; font-weight:bold; color:#58a6ff; }
table { border-collapse:collapse; width:100%; margin:16px 0; }
th,td { border:1px solid #30363d; padding:8px 12px; text-align:left; font-size:.88em; }
th    { background:#161b22; color:#8b949e; }
tr:hover { background:#161b22; }
"""

def severity_badge(count: int) -> str:
    if count >= 5:
        return '<span class="badge-high">● HIGH</span>'
    if count >= 2:
        return '<span class="badge-med">● MED</span>'
    return '<span class="badge-low">● LOW</span>'


def build_html_report(all_results: list[dict], output_path: str):
    total_urls     = len(all_results)
    total_findings = sum(len(r["findings"]) for r in all_results)
    total_snaps    = sum(r["snapshots_checked"] for r in all_results)
    urls_with_hits = sum(1 for r in all_results if r["findings"])
    now            = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Build findings table rows
    table_rows = ""
    for r in sorted(all_results, key=lambda x: -len(x["findings"])):
        if not r["findings"]:
            continue
        patterns = ", ".join(f["pattern"] for f in r["findings"])
        table_rows += f"""
        <tr>
          <td><a class="url" href="{r['url']}" target="_blank">{r['url'][:80]}{'…' if len(r['url'])>80 else ''}</a></td>
          <td>{r['snapshots_checked']}</td>
          <td>{len(r['findings'])}</td>
          <td>{patterns[:100]}</td>
          <td><a href="{r.get('saved_as','#')}">View</a></td>
        </tr>"""

    # Build detail sections
    details = ""
    for r in sorted(all_results, key=lambda x: -len(x["findings"])):
        if not r["findings"]:
            continue
        details += f"""
        <h2>🔍 {r['url']}</h2>
        <p class="meta">Snapshot: {r.get('snapshot_ts','N/A')} &nbsp;|&nbsp; Checks: {r['snapshots_checked']} &nbsp;|&nbsp;
           <a class="url" href="{r.get('archive_url','#')}" target="_blank">Archive URL</a> &nbsp;|&nbsp;
           <a class="url" href="{r.get('saved_as','#')}">Saved HTML</a></p>
        """
        for f in r["findings"]:
            details += f"""
        <div class="finding">
          <span class="label">{f['pattern']}</span>
          <span class="count">{f['count']} match{'es' if f['count']!=1 else ''}</span>
          {severity_badge(f['count'])}
          {''.join(f'<p class="sample">{s[:300]}</p>' for s in f['samples'])}
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Wayback Scanner Report — {now}</title>
  <style>{REPORT_CSS}</style>
</head>
<body>
  <h1>🕵️ Wayback Machine Sensitive URL Report</h1>
  <p class="meta">Generated: {now}</p>

  <div class="summary-box">
    <table>
      <tr><th>URLs scanned</th><th>Snapshots checked</th><th>URLs with findings</th><th>Total findings</th></tr>
      <tr>
        <td><span>{total_urls}</span></td>
        <td><span>{total_snaps}</span></td>
        <td><span>{urls_with_hits}</span></td>
        <td><span>{total_findings}</span></td>
      </tr>
    </table>
  </div>

  <h2>📋 Summary Table</h2>
  <table>
    <tr><th>URL</th><th>Snapshots</th><th>Findings</th><th>Patterns</th><th>File</th></tr>
    {table_rows if table_rows else '<tr><td colspan="5" style="color:#3fb950">No sensitive findings detected.</td></tr>'}
  </table>

  <h2>🔎 Detailed Findings</h2>
  {details if details else '<p style="color:#3fb950">✅ No sensitive data found in any snapshot.</p>'}
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)


# ──────────────────────────────────────────────
# CORE WORKER
# ──────────────────────────────────────────────

def process_url(url: str, output_dir: Path, years: int, session: requests.Session) -> dict:
    url = url.strip()
    result = {
        "url":               url,
        "snapshots_checked": 0,
        "findings":          [],
        "saved_as":          None,
        "archive_url":       None,
        "snapshot_ts":       None,
    }

    if not url or url.startswith("#"):
        return result

    if not is_sensitive_url(url):
        log(f"SKIP (non-sensitive ext): {url}", "WARN")
        return result

    log(f"Checking: {url}")
    snapshots = fetch_snapshots(url, years, session)

    if not snapshots:
        log(f"  No snapshots found", "WARN")
        return result

    log(f"  Found {len(snapshots)} snapshot(s)")

    best_findings = []
    best_html     = None
    best_snap     = None

    for snap in snapshots:
        ts   = snap["timestamp"]
        html = download_snapshot(ts, url, session)
        result["snapshots_checked"] += 1
        time.sleep(0.5)   # be polite to archive.org

        if not html:
            continue

        findings = analyze_html(html, url)
        if len(findings) > len(best_findings):
            best_findings = findings
            best_html     = html
            best_snap     = ts

        if best_findings:
            break   # take the first snapshot that has findings

    if best_findings and best_html:
        result["findings"]    = best_findings
        result["snapshot_ts"] = best_snap
        result["archive_url"] = f"{WAYBACK_BASE}/{best_snap}/{url}"

        fname    = sanitize_filename(url, best_snap)
        fpath    = output_dir / fname
        with open(fpath, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(best_html)

        result["saved_as"] = str(fpath)
        log(f"  ✅ {len(best_findings)} pattern(s) found → {fname}", "OK")
    else:
        log(f"  No sensitive data found in snapshots", "INFO")

    return result


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Wayback Machine Sensitive URL Scanner for Bug Bounty Recon"
    )
    parser.add_argument("-i", "--input",   default="interestingEXT.txt",
                        help="Input file with URLs (default: interestingEXT.txt)")
    parser.add_argument("-o", "--output",  default="wayback_results",
                        help="Output directory (default: ./wayback_results)")
    parser.add_argument("-t", "--threads", type=int, default=5,
                        help="Parallel threads (default: 5)")
    parser.add_argument("-y", "--years",   type=int, default=5,
                        help="Only check snapshots from last N years (default: 5)")
    parser.add_argument("--no-color",      action="store_true",
                        help="Disable colored output")
    args = parser.parse_args()

    # ── Setup ──────────────────────────────────
    input_file = Path(args.input)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    if not input_file.exists():
        log(f"Input file not found: {input_file}", "FAIL")
        sys.exit(1)

    urls = [u.strip() for u in input_file.read_text().splitlines() if u.strip() and not u.startswith("#")]
    if not urls:
        log("No URLs found in input file.", "FAIL")
        sys.exit(1)

    log(f"Loaded {len(urls)} URL(s) from {input_file}", "HEAD")
    log(f"Output directory: {output_dir.resolve()}", "HEAD")
    log(f"Threads: {args.threads} | Lookback: {args.years} year(s)", "HEAD")
    print()

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; BugBountyRecon/1.0)",
    })
    session.max_redirects = 5

    # ── Process URLs ────────────────────────────
    all_results = []

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {
            pool.submit(process_url, url, output_dir, args.years, session): url
            for url in urls
        }
        for future in as_completed(futures):
            try:
                result = future.result()
                all_results.append(result)
            except Exception as e:
                log(f"Worker error for {futures[future]}: {e}", "FAIL")

    # ── Final Report ────────────────────────────
    print()
    log("Generating HTML report…", "HEAD")
    report_path = output_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    build_html_report(all_results, str(report_path))

    urls_hit   = sum(1 for r in all_results if r["findings"])
    total_find = sum(len(r["findings"]) for r in all_results)

    log(f"Done! URLs with findings : {urls_hit}/{len(urls)}", "OK")
    log(f"Total pattern matches    : {total_find}", "OK")
    log(f"Report saved to          : {report_path.resolve()}", "OK")


if __name__ == "__main__":
    main()
