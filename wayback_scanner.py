#!/usr/bin/env python3
"""
Wayback Machine Sensitive URL Scanner  —  Bug Bounty Recon Tool
Fixes vs v1:
  - CDX: removed mimetype filter (catches JS/JSON/config/plain-text archives)
  - CDX: removed strict statuscode:200 filter (use !=404 instead)
  - CDX: increased limit, spread across years with smarter sampling
  - Download: removed Content-Type gate (was blocking JS/JSON/config files)
  - Download: use /web/<ts>id_/ flag (identity mode) instead of if_ — avoids
    Wayback toolbar injection and redirect quirks
  - Download: retry with exponential backoff on 429/503/connection errors
  - Analysis: strip Wayback banner HTML before scanning to kill false positives
  - Worker: scan ALL snapshots, pick richest; don't break on first hit
  - Worker: verbose logging so you can see exactly what's happening per URL

Usage:
    python wayback_scanner.py                       # reads interestingEXT.txt
    python wayback_scanner.py -i urls.txt -o ./out
    python wayback_scanner.py --threads 5 --years 3
    python wayback_scanner.py --debug               # print per-URL detail
"""

import argparse
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

# ══════════════════════════════════════════════════════════════
# SENSITIVE PATTERNS
# ══════════════════════════════════════════════════════════════

SENSITIVE_PATTERNS = {
    # ── Cloud / service keys ──────────────────────────────────
    "AWS Access Key ID":        r'(?:AKIA|AIPA|ASIA|AROA)[A-Z0-9]{16}',
    "AWS Secret Access Key":    r'(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key[\s]*[=:]\s*["\']?([A-Za-z0-9/+=]{40})',
    "Google API Key":           r'AIza[0-9A-Za-z\-_]{35}',
    "GitHub Token":             r'(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{36,}',
    "Slack Token":              r'xox[baprs]-[0-9A-Za-z\-]{10,48}',
    "Stripe Key":               r'(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}',
    "Twilio SID/Token":         r'AC[a-f0-9]{32}|SK[a-f0-9]{32}',
    "SendGrid Key":             r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}',
    "Mailchimp Key":            r'[0-9a-f]{32}-us[0-9]{1,2}',
    "Firebase URL":             r'https://[a-z0-9\-]+\.firebaseio\.com',
    "Cloudinary URL":           r'cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[a-z]+',

    # ── Generic secrets ───────────────────────────────────────
    "Generic API Key":          r'(?i)["\']?(?:api[_\-]?key|apikey|api[_\-]?token)["\']?\s*[=:]\s*["\']([A-Za-z0-9\-_\.]{16,80})["\']',
    "Generic Secret/Password":  r'(?i)["\']?(?:secret|password|passwd|pwd|pass)["\']?\s*[=:]\s*["\']([^"\'\\]{8,80})["\']',
    "Bearer Token":             r'(?i)Authorization["\']?\s*[=:]\s*["\']?Bearer\s+([A-Za-z0-9\-_=.]{20,})',
    "Basic Auth in URL":        r'https?://[^:@\s<>"]{1,60}:[^@\s<>"]{1,60}@[^\s<>"]+',
    "Private Key Block":        r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY',
    "PGP Private Key":          r'-----BEGIN PGP PRIVATE KEY BLOCK',

    # ── JWT / OAuth ───────────────────────────────────────────
    "JWT Token":                r'eyJ[A-Za-z0-9\-_=]{10,}\.eyJ[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_.+/=]{10,}',
    "OAuth/Access Token":       r'(?i)["\']?(?:oauth[_\-]?token|access[_\-]?token|refresh[_\-]?token)["\']?\s*[=:]\s*["\']([A-Za-z0-9\-_.~+/]{20,})["\']',

    # ── Database / infra ──────────────────────────────────────
    "Database Connection URL":  r'(?i)(?:mongodb(?:\+srv)?|mysql|postgresql|postgres|redis|amqp|mssql)://[^\s<>"\']{10,}',
    "JDBC Connection String":   r'(?i)jdbc:[a-z:]+//[^\s<>"\']{5,}',
    "S3 Bucket URI":            r's3://[a-z0-9.\-_]{3,63}',
    "Internal Hostname":        r'(?i)["\']([a-z0-9\-]{2,60}\.(?:internal|local|corp|intranet|lan))["\']',
    "Private IP Address":       r'\b(?:10\.[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}\b',

    # ── PII ───────────────────────────────────────────────────
    "Email Address":            r'[a-zA-Z0-9._%+\-]{2,}@[a-zA-Z0-9.\-]{2,}\.[a-zA-Z]{2,6}',
    "US Phone Number":          r'\b(?:\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b',
    "SSN":                      r'\b(?!000|666|9\d{2})\d{3}[\s\-]\d{2}[\s\-]\d{4}\b',
    "Credit Card Number":       r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6011[0-9]{12})\b',

    # ── Dev / debug artifacts ─────────────────────────────────
    "Stack Trace":              r'(?i)(?:Traceback \(most recent call|at [A-Za-z_$][A-Za-z0-9_$]*\.[A-Za-z_$][A-Za-z0-9_$]*\s*\(|Exception in thread|NullPointerException|Fatal error:|Unhandled exception)',
    "Debug Mode Enabled":       r'(?i)(?:DEBUG\s*[=:]\s*(?:true|1|on)|APP_DEBUG\s*=\s*true|FLASK_ENV\s*=\s*development|NODE_ENV\s*=\s*development)',
    "Env Variable Exposed":     r'(?i)(?:DATABASE_URL|SECRET_KEY|APP_KEY|ENCRYPTION_KEY|SIGNING_SECRET)\s*[=:]\s*[^\s<>"\']{8,}',
    "Hardcoded Credential Comment": r'(?i)(?://|#|<!--|/\*)\s*(?:password|passwd|secret|token|api_key)\s*[=:]\s*\S{4,}',
    "TODO With Sensitive Context":  r'(?i)(?://|#)\s*(?:TODO|FIXME|HACK)\b[^\n]{0,80}(?:auth|password|secret|token|key|cred)[^\n]{0,40}',
    "Git Merge Conflict Marker":    r'(?:^|\n)<{7} (?:HEAD|[a-z])',
    "Internal Path Disclosure":     r'(?i)(?:/home/[a-z_][a-z0-9_]{0,30}/|/var/www/|/srv/|/opt/[a-z]|C:\\\\Users\\\\|C:\\\\inetpub\\\\)',
    "Version Control URL (internal)": r'(?i)(?:svn|git)(?:\+ssh)?://[a-z0-9.\-_]+(?:\.internal|\.local|\.corp)',
}

# ── File extension filters ────────────────────────────────────
SENSITIVE_EXTENSIONS = {
    '.html', '.htm', '.php', '.php3', '.php4', '.php5', '.phtml',
    '.asp', '.aspx', '.jsp', '.jspx', '.cfm',
    '.js', '.mjs', '.ts',
    '.json', '.xml', '.yaml', '.yml', '.toml',
    '.env', '.config', '.cfg', '.ini', '.conf', '.properties',
    '.txt', '.log', '.sql', '.bak', '.backup', '.old', '.orig', '.swp',
    '.py', '.rb', '.pl', '.sh', '.bash', '.zsh',
    '.htaccess', '.htpasswd',
}

SKIP_EXTENSIONS = {
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.ico', '.tiff', '.svg',
    '.mp4', '.mp3', '.avi', '.mov', '.mkv', '.wmv', '.flv', '.ogg', '.wav', '.webm',
    '.zip', '.gz', '.tar', '.rar', '.7z', '.bz2', '.xz', '.tgz',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods',
    '.ttf', '.woff', '.woff2', '.eot', '.otf',
    '.exe', '.dll', '.so', '.dylib', '.bin', '.apk', '.ipa',
    '.css', '.map',
}

# Wayback CDX + download endpoints
CDX_API      = "https://web.archive.org/cdx/search/cdx"
WB_BASE      = "https://web.archive.org/web"

# ══════════════════════════════════════════════════════════════
# LOGGING
# ══════════════════════════════════════════════════════════════

DEBUG_MODE = False

def log(msg, level="INFO"):
    colors = {
        "INFO":  "\033[94m",
        "OK":    "\033[92m",
        "WARN":  "\033[93m",
        "FAIL":  "\033[91m",
        "HEAD":  "\033[1;96m",
        "DEBUG": "\033[90m",
        "RESET": "\033[0m",
    }
    if level == "DEBUG" and not DEBUG_MODE:
        return
    ts = datetime.now().strftime("%H:%M:%S")
    c  = colors.get(level, "")
    r  = colors["RESET"]
    print(f"{c}[{ts}][{level:5}] {msg}{r}", flush=True)

# ══════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════

def sanitize_filename(url: str, timestamp: str) -> str:
    parsed = urllib.parse.urlparse(url)
    path   = parsed.path.strip("/").replace("/", "__") or "index"
    query  = parsed.query[:50].replace("&", "_").replace("=", "-") if parsed.query else ""
    name   = f"{parsed.netloc}__{path}"
    if query:
        name += f"__{query}"
    name = re.sub(r'[^\w\-.]', '_', name)[:180]
    return f"{timestamp}_{name}.html"


def get_ext(url: str) -> str:
    path = urllib.parse.urlparse(url).path
    return os.path.splitext(path)[1].lower()


def is_scannable_url(url: str) -> bool:
    ext = get_ext(url)
    if ext in SKIP_EXTENSIONS:
        return False
    if ext in SENSITIVE_EXTENSIONS or ext == "":
        return True
    return False   # unknown extension — skip


def retry_get(session: requests.Session, url: str, params=None, timeout=25, max_tries=4) -> requests.Response | None:
    """GET with exponential backoff on rate-limit / transient errors."""
    wait = 2
    for attempt in range(1, max_tries + 1):
        try:
            r = session.get(url, params=params, timeout=timeout, allow_redirects=True)
            if r.status_code == 429 or r.status_code == 503:
                log(f"  Rate-limited ({r.status_code}), waiting {wait}s … (attempt {attempt}/{max_tries})", "WARN")
                time.sleep(wait)
                wait *= 2
                continue
            return r
        except requests.exceptions.ConnectionError as e:
            log(f"  Connection error (attempt {attempt}/{max_tries}): {e}", "WARN")
            time.sleep(wait)
            wait *= 2
        except requests.exceptions.Timeout:
            log(f"  Timeout (attempt {attempt}/{max_tries})", "WARN")
            time.sleep(wait)
            wait *= 2
    return None

# ══════════════════════════════════════════════════════════════
# CDX SNAPSHOT LOOKUP
# ══════════════════════════════════════════════════════════════

def fetch_snapshots(url: str, years: int, session: requests.Session) -> list[dict]:
    """
    Query CDX API.  Key fixes vs v1:
      - NO mimetype filter  →  catches JS, JSON, plain-text, config archives
      - statuscode filter   →  !=404 (keeps 200, 301, 302, 500 — archive may
                                      have the real content under a redirect)
      - collapse=timestamp:6 → one snapshot per month (not per day) so we get
                                better spread across the year range
      - limit=20             → more candidates to find the best snapshot
    """
    from_date = (datetime.utcnow() - timedelta(days=365 * years)).strftime("%Y%m%d")
    params = {
        "url":      url,
        "output":   "json",
        "fl":       "timestamp,statuscode,mimetype,original",
        "collapse": "timestamp:6",      # one per month
        "from":     from_date,
        "filter":   "statuscode:!404",  # exclude only hard 404s
        "limit":    "20",
    }
    log(f"  CDX lookup: {url}", "DEBUG")
    r = retry_get(session, CDX_API, params=params, timeout=20)
    if r is None:
        log(f"  CDX request failed (all retries exhausted)", "WARN")
        return []
    if r.status_code != 200:
        log(f"  CDX returned HTTP {r.status_code}", "WARN")
        return []
    try:
        rows = r.json()
    except Exception:
        log(f"  CDX returned non-JSON: {r.text[:120]}", "WARN")
        return []

    if len(rows) <= 1:      # only header row or empty
        return []

    keys    = rows[0]
    results = [dict(zip(keys, row)) for row in rows[1:]]
    log(f"  CDX found {len(results)} snapshot(s): "
        + ", ".join(s["timestamp"][:8] for s in results[:5])
        + (" …" if len(results) > 5 else ""), "DEBUG")
    return results

# ══════════════════════════════════════════════════════════════
# SNAPSHOT DOWNLOAD
# ══════════════════════════════════════════════════════════════

# Wayback injects a banner toolbar into every page it serves.
# Using the  id_  modifier requests the *identity* (raw original) copy —
# no banner, no rewriting of links, just the archived bytes.
# This is critical: the toolbar contains scripts with tokens that would
# trigger false positives, and also rewrites URLs which breaks pattern matching.
WB_ID_FLAG = "id_"   # raw original bytes, no Wayback injections

# Minimum content length to be worth scanning
MIN_CONTENT_LEN = 100

# Content-types we are happy to scan as text
TEXT_TYPES = (
    "text/",
    "application/json",
    "application/javascript",
    "application/x-javascript",
    "application/xml",
    "application/x-www-form-urlencoded",
    "application/x-sh",
    "application/xhtml",
)


def download_snapshot(timestamp: str, original_url: str, session: requests.Session) -> tuple[str | None, str]:
    """
    Download raw snapshot content.  Returns (text, archive_url).
    Key fixes vs v1:
      - Use /web/<ts>id_/<url>  instead of /web/<ts>if_/<url>
        id_ = identity/raw bytes; if_ = framed Wayback view (has toolbar HTML)
      - Accept any text-like Content-Type, not just text/html
      - No hard minimum on size (100 bytes is enough for a bare config file)
    """
    archive_url = f"{WB_BASE}/{timestamp}{WB_ID_FLAG}/{original_url}"
    log(f"  Fetching: {archive_url}", "DEBUG")

    r = retry_get(session, archive_url, timeout=35)
    if r is None:
        log(f"  Download failed (all retries)", "WARN")
        return None, archive_url

    if r.status_code not in (200, 206):
        log(f"  HTTP {r.status_code} for snapshot", "DEBUG")
        return None, archive_url

    ct = r.headers.get("Content-Type", "").lower()

    # Accept anything text-like
    is_text = any(ct.startswith(t) for t in TEXT_TYPES)
    if not is_text:
        # Still try if content-type is missing or generic
        if ct and "octet-stream" not in ct and "binary" not in ct:
            is_text = True   # be permissive

    if not is_text:
        log(f"  Skipping binary content-type: {ct}", "DEBUG")
        return None, archive_url

    try:
        text = r.content.decode(r.apparent_encoding or "utf-8", errors="replace")
    except Exception:
        text = r.text

    if len(text) < MIN_CONTENT_LEN:
        log(f"  Content too short ({len(text)} bytes), skipping", "DEBUG")
        return None, archive_url

    # Strip any residual Wayback banner HTML that id_ might not fully suppress
    text = strip_wayback_artifacts(text)

    log(f"  Downloaded {len(text):,} chars (ct={ct[:40]})", "DEBUG")
    return text, archive_url


def strip_wayback_artifacts(html: str) -> str:
    """
    Remove Wayback Machine injected content so it doesn't cause false positives.
    Strips the <!-- BEGIN WAYBACK ... --> comment blocks and the toolbar <div>.
    """
    # Comment blocks injected by Wayback
    html = re.sub(r'<!-- BEGIN WAYBACK TOOLBAR INSERT -->.*?<!-- END WAYBACK TOOLBAR INSERT -->',
                  '', html, flags=re.DOTALL)
    # Inline script Wayback sometimes injects
    html = re.sub(r'<script[^>]*>[\s\S]*?archive\.org[\s\S]*?</script>', '', html,
                  flags=re.IGNORECASE)
    return html

# ══════════════════════════════════════════════════════════════
# ANALYSIS
# ══════════════════════════════════════════════════════════════

def analyze_content(text: str) -> list[dict]:
    """
    Scan raw content for sensitive patterns.
    Returns sorted list of findings (highest hit-count first).
    """
    findings = []
    for name, pattern in SENSITIVE_PATTERNS.items():
        try:
            matches = re.findall(pattern, text, re.MULTILINE)
        except re.error:
            continue
        if not matches:
            continue
        # re.findall returns strings or tuples (if groups); normalise to strings
        samples = []
        for m in matches:
            s = m if isinstance(m, str) else (m[0] if m else "")
            s = s.strip()
            if s and s not in samples:
                samples.append(s)
            if len(samples) >= 5:
                break
        findings.append({
            "pattern": name,
            "count":   len(matches),
            "samples": samples,
        })
    findings.sort(key=lambda f: -f["count"])
    return findings

# ══════════════════════════════════════════════════════════════
# HTML REPORT
# ══════════════════════════════════════════════════════════════

REPORT_CSS = """
*{box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
     background:#0d1117;color:#c9d1d9;margin:0;padding:24px}
h1{color:#58a6ff;border-bottom:1px solid #21262d;padding-bottom:10px;margin-bottom:6px}
h2{color:#e3b341;font-size:1.05em;margin:28px 0 4px}
.meta{color:#8b949e;font-size:.83em;margin:2px 0 12px}
.badge{display:inline-block;padding:2px 9px;border-radius:10px;font-size:.78em;font-weight:600;margin-left:6px}
.high{background:#f8514926;color:#f85149}.med{background:#d2992226;color:#e3b341}.low{background:#3fb95026;color:#3fb950}
.finding{background:#161b22;border:1px solid #21262d;border-radius:6px;padding:10px 14px;margin:6px 0}
.pat{color:#79c0ff;font-weight:600;font-size:.9em}
.cnt{color:#8b949e;font-size:.82em;margin-left:8px}
.sample{font-family:'SFMono-Regular',Consolas,monospace;font-size:.8em;color:#ffa657;
        background:#0d1117;border-radius:4px;padding:3px 7px;margin:3px 0;
        word-break:break-all;display:block;border-left:3px solid #30363d}
table{border-collapse:collapse;width:100%;margin:12px 0;font-size:.88em}
th,td{border:1px solid #21262d;padding:7px 11px;text-align:left}
th{background:#161b22;color:#8b949e;white-space:nowrap}
tr:hover td{background:#161b22}
a{color:#58a6ff;text-decoration:none}a:hover{text-decoration:underline}
.url{word-break:break-all}
.stats{display:flex;gap:16px;flex-wrap:wrap;margin:16px 0}
.stat{background:#161b22;border:1px solid #21262d;border-radius:8px;
      padding:12px 20px;min-width:120px;text-align:center}
.stat .n{font-size:2em;font-weight:700;color:#58a6ff;display:block}
.stat .l{font-size:.8em;color:#8b949e}
.zero{color:#3fb950;padding:12px;background:#161b22;border-radius:6px}
"""

def severity(count):
    if count >= 5: return "high", "HIGH"
    if count >= 2: return "med",  "MED"
    return "low", "LOW"

def html_escape(s):
    return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

def build_report(all_results: list[dict], output_path: str):
    now         = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_urls  = len(all_results)
    total_snaps = sum(r["snapshots_checked"] for r in all_results)
    hits        = [r for r in all_results if r["findings"]]
    total_finds = sum(len(r["findings"]) for r in all_results)

    # Summary table
    trows = ""
    for r in sorted(hits, key=lambda x: -len(x["findings"])):
        pats = html_escape(", ".join(f["pattern"] for f in r["findings"])[:120])
        fname = os.path.basename(r.get("saved_as","")) or "—"
        link  = f'<a href="{html_escape(r.get("saved_as","#"))}">📄 {html_escape(fname[:50])}</a>' if r.get("saved_as") else "—"
        trows += (f'<tr><td class="url"><a href="{html_escape(r["url"])}" target="_blank">'
                  f'{html_escape(r["url"][:90])}{"…" if len(r["url"])>90 else ""}</a></td>'
                  f'<td>{r["snapshots_checked"]}</td>'
                  f'<td>{len(r["findings"])}</td>'
                  f'<td>{pats}</td>'
                  f'<td>{link}</td></tr>\n')

    # Detail sections
    details = ""
    for r in sorted(hits, key=lambda x: -len(x["findings"])):
        snap_ts   = r.get("snapshot_ts","N/A")
        arch_url  = html_escape(r.get("archive_url","#"))
        saved     = html_escape(r.get("saved_as",""))
        saved_lnk = f'<a href="{saved}">Saved snapshot</a>' if saved else "not saved"
        details  += f"""
<h2>🔍 <span class="url">{html_escape(r['url'])}</span></h2>
<p class="meta">
  Snapshot: <code>{snap_ts}</code> &nbsp;·&nbsp;
  Snapshots checked: {r['snapshots_checked']} &nbsp;·&nbsp;
  <a href="{arch_url}" target="_blank">Archive URL</a> &nbsp;·&nbsp;
  {saved_lnk}
</p>"""
        for f in r["findings"]:
            cls, lbl = severity(f["count"])
            samples_html = "".join(
                f'<span class="sample">{html_escape(s[:300])}</span>'
                for s in f["samples"]
            )
            details += f"""
<div class="finding">
  <span class="pat">{html_escape(f['pattern'])}</span>
  <span class="cnt">{f['count']} match{'es' if f['count']!=1 else ''}</span>
  <span class="badge {cls}">{lbl}</span>
  {samples_html}
</div>"""

    no_hits_section = ""
    no_hits = [r for r in all_results if not r["findings"]]
    if no_hits:
        rows = "".join(
            f'<tr><td class="url">{html_escape(r["url"])}</td>'
            f'<td>{r["snapshots_checked"]}</td>'
            f'<td>{html_escape(r.get("skip_reason",""))}</td></tr>\n'
            for r in no_hits
        )
        no_hits_section = f"""
<h2>⬜ URLs with no findings</h2>
<table><tr><th>URL</th><th>Snapshots checked</th><th>Reason / note</th></tr>
{rows}</table>"""

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Wayback Scanner Report — {now}</title>
  <style>{REPORT_CSS}</style>
</head>
<body>
<h1>🕵️ Wayback Machine Sensitive URL Report</h1>
<p class="meta">Generated: {now}</p>

<div class="stats">
  <div class="stat"><span class="n">{total_urls}</span><span class="l">URLs scanned</span></div>
  <div class="stat"><span class="n">{total_snaps}</span><span class="l">Snapshots checked</span></div>
  <div class="stat"><span class="n">{len(hits)}</span><span class="l">URLs with findings</span></div>
  <div class="stat"><span class="n">{total_finds}</span><span class="l">Pattern matches</span></div>
</div>

<h2>📋 Findings Summary</h2>
{'<table><tr><th>URL</th><th>Snapshots</th><th>Patterns hit</th><th>Pattern names</th><th>Saved file</th></tr>' + trows + '</table>'
  if trows else '<p class="zero">✅ No sensitive findings detected.</p>'}

<h2>🔎 Detailed Findings</h2>
{details if details else '<p class="zero">✅ No sensitive data found in any snapshot.</p>'}

{no_hits_section}
</body></html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(page)

# ══════════════════════════════════════════════════════════════
# CORE WORKER
# ══════════════════════════════════════════════════════════════

def process_url(url: str, output_dir: Path, years: int, session: requests.Session) -> dict:
    url = url.strip()
    result = {
        "url":               url,
        "snapshots_checked": 0,
        "findings":          [],
        "saved_as":          None,
        "archive_url":       None,
        "snapshot_ts":       None,
        "skip_reason":       "",
    }

    if not url or url.startswith("#"):
        result["skip_reason"] = "comment/empty line"
        return result

    if not is_scannable_url(url):
        ext = get_ext(url)
        log(f"SKIP [{ext}] {url}", "WARN")
        result["skip_reason"] = f"non-sensitive extension ({ext})"
        return result

    log(f"▶ {url}")
    snapshots = fetch_snapshots(url, years, session)

    if not snapshots:
        log(f"  ↳ No CDX snapshots found (URL may never have been crawled)", "WARN")
        result["skip_reason"] = "no CDX snapshots found"
        return result

    log(f"  ↳ {len(snapshots)} CDX snapshot(s) — scanning all …")

    best_findings  = []
    best_text      = None
    best_snap      = None
    best_arch_url  = None

    for snap in snapshots:
        ts = snap["timestamp"]
        log(f"  → snapshot {ts}  status={snap.get('statuscode','?')}  mime={snap.get('mimetype','?')}")

        text, arch_url = download_snapshot(ts, url, session)
        result["snapshots_checked"] += 1
        time.sleep(0.6)   # be polite to archive.org

        if text is None:
            continue

        findings = analyze_content(text)
        log(f"    patterns matched: {len(findings)}")

        # Keep the snapshot with the most findings
        if len(findings) > len(best_findings):
            best_findings = findings
            best_text     = text
            best_snap     = ts
            best_arch_url = arch_url

    if best_findings and best_text:
        result["findings"]    = best_findings
        result["snapshot_ts"] = best_snap
        result["archive_url"] = best_arch_url

        fname = sanitize_filename(url, best_snap)
        fpath = output_dir / fname
        with open(fpath, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(best_text)
        result["saved_as"] = str(fpath)

        pattern_names = ", ".join(f["pattern"] for f in best_findings[:3])
        log(f"  ✅ {len(best_findings)} finding(s): {pattern_names}  →  {fname}", "OK")
    else:
        log(f"  ℹ  {result['snapshots_checked']} snapshot(s) checked — no sensitive patterns found")
        result["skip_reason"] = f"{result['snapshots_checked']} snapshot(s) checked, no patterns matched"

    return result

# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Wayback Machine Sensitive URL Scanner — Bug Bounty Recon"
    )
    parser.add_argument("-i", "--input",   default="interestingEXT.txt",
                        help="Input file with URLs (default: interestingEXT.txt)")
    parser.add_argument("-o", "--output",  default="wayback_results",
                        help="Output directory (default: ./wayback_results)")
    parser.add_argument("-t", "--threads", type=int, default=3,
                        help="Parallel threads — keep low to avoid 429s (default: 3)")
    parser.add_argument("-y", "--years",   type=int, default=5,
                        help="Look back N years (default: 5)")
    parser.add_argument("--debug",         action="store_true",
                        help="Verbose debug output per URL/snapshot")
    args = parser.parse_args()

    global DEBUG_MODE
    DEBUG_MODE = args.debug

    input_file = Path(args.input)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    if not input_file.exists():
        log(f"Input file not found: {input_file}", "FAIL")
        sys.exit(1)

    urls = [
        u.strip() for u in input_file.read_text(encoding="utf-8", errors="replace").splitlines()
        if u.strip() and not u.strip().startswith("#")
    ]
    if not urls:
        log("No URLs found in input file.", "FAIL")
        sys.exit(1)

    log(f"Loaded {len(urls)} URL(s) from {input_file}", "HEAD")
    log(f"Output : {output_dir.resolve()}", "HEAD")
    log(f"Threads: {args.threads}  |  Lookback: {args.years} yr(s)  |  Debug: {args.debug}", "HEAD")
    print()

    session = requests.Session()
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )
    })

    all_results = []

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {
            pool.submit(process_url, url, output_dir, args.years, session): url
            for url in urls
        }
        for future in as_completed(futures):
            try:
                all_results.append(future.result())
            except Exception as e:
                log(f"Worker crash for {futures[future]}: {e}", "FAIL")

    print()
    log("Generating HTML report …", "HEAD")
    rpath = output_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    build_report(all_results, str(rpath))

    hits       = sum(1 for r in all_results if r["findings"])
    total_find = sum(len(r["findings"]) for r in all_results)
    log(f"URLs with findings  : {hits}/{len(urls)}", "OK")
    log(f"Total pattern hits  : {total_find}", "OK")
    log(f"Report              : {rpath.resolve()}", "OK")


if __name__ == "__main__":
    main()
