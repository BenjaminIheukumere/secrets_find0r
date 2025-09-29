#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Secrets Find0r (token-level highlight)
- Only the matched token inside the context is highlighted (red background) on screen
- File export is a plain ASCII table without ANSI colors
- Robust SMB enumeration (UNC '\\*', visited-set, timeouts, port check)
- Optional inclusion of unknown/no-extension files with size cap
- Legacy Office parsing via olefile, PDF via PyPDF2 (optional)
- Multithreaded, progress bars, customizable keywords
- Configurable maximum directory depth to avoid extremely deep recursion
- FIX: Properly close SMB sockets and limit concurrent file scans to avoid 'Too many open files'
"""

import os
import sys
import io
import re
import zipfile
import socket
import ipaddress
import getpass
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from impacket.smbconnection import SMBConnection
from tqdm import tqdm

# Optional parsers
try:
    import PyPDF2
    HAS_PYPDF2 = True
except Exception:
    HAS_PYPDF2 = False

try:
    import olefile
    HAS_OLEFILE = True
except Exception:
    HAS_OLEFILE = False

# ---------- Configurable params ----------
THREADS_ENUM = 32                  # workers for host/share/file enumeration
THREADS_FILES = 8                  # workers for file download/scan (keep modest to avoid many sockets)
MAX_FILE_BYTES = 4 * 1024 * 1024   # max bytes to download per file
MAX_UNKNOWN_BYTES = 256 * 1024     # cap for unknown/no-extension files if included
MAX_DIR_DEPTH = 2                  # max directory depth (root '\' = 0); None = unlimited
PORT_PROBE_TIMEOUT = 0.5           # TCP connect timeout for port 445
SMB_CONNECT_TIMEOUT = 5            # SMBConnection connect timeout
SMB_OP_TIMEOUT = 5                 # SMB operation timeout

# Exclude default/admin shares (configurable)
EXCLUDE_SHARES = {
    'ADMIN$', 'IPC$', 'PRINT$', 'FAX$',  # service shares
    #'SYSVOL', 'NETLOGON',                # AD system shares
}
# Regex for admin drive shares like C$, D$, E$, ...
EXCLUDE_SHARE_REGEX = re.compile(r'^[A-Z]\$$')

KEYWORDS = [
    "password", "passwort", "passwd", "secret", "apikey", "api_key",
    "token", "connectionstring", "connection_string", "dbpassword", "db_pass",
    "username", "userid", "user", "credential", "creds", "secrets", "keyvault"
]

# Regex patterns to catch credentials / connection strings (byte-level)
REGEX_PATTERNS = [
    re.compile(rb'([Pp]assword)\s*[:=]\s*([^\s,;\'"]+)', re.I),
    re.compile(rb'([Uu]sername|[Uu]ser)\s*[:=]\s*([^\s,;\'"]+)', re.I),
    re.compile(rb'([Uu]id|[Uu]serid)\s*[:=]\s*([^\s,;\'"]+)', re.I),
    re.compile(rb'(password|passwd)\s*=\s*[^;\'"]+', re.I),
    # re.compile(rb'([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})')
]

# Supported extensions (extended)
EXTS_TEXT = {
    '.txt', '.csv', '.json', '.html', '.htm', '.eml', '.rtf',
    '.ps1', '.psm1', '.psd1', '.msf', '.ini', '.conf', '.cnf',
    '.config', '.xml', '.log', '.env', '.properties', '.yaml', '.yml',
    '.bat', '.cmd', '.vbs'
}
EXTS_OFFICE_XML = {'.docx', '.pptx', '.xlsx'}
EXTS_PDF = {'.pdf'}
EXTS_BINARY_OFFICE = {'.doc', '.xls', '.ppt'}
SUPPORTED_EXTS = EXTS_TEXT | EXTS_OFFICE_XML | EXTS_PDF | EXTS_BINARY_OFFICE

class C:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'
    BG_RED = '\033[41m'
    RESET = '\033[0m'

# Banner & imprint
BANNER = r"""
  /$$$$$$                                            /$$                   
 /$$__  $$                                          | $$                   
| $$  \__/  /$$$$$$   /$$$$$$$  /$$$$$$   /$$$$$$  /$$$$$$   /$$$$$$$      
|  $$$$$$  /$$__  $$ /$$_____/ /$$__  $$ /$$__  $$|_  $$_/  /$$_____/      
 \____  $$| $$$$$$$$| $$      | $$  \__/| $$$$$$$$  | $$   |  $$$$$$       
 /$$  \ $$| $$_____/| $$      | $$      | $$_____/  | $$ /$$\____  $$      
|  $$$$$$/|  $$$$$$$|  $$$$$$$| $$      |  $$$$$$$  |  $$$$//$$$$$$$/      
 \______/  \_______/ \_______/|__/       \_______/   \___/ |_______/       
                                                                           
                                                                           
                                                                           
          /$$$$$$$$ /$$                 /$$  /$$$$$$                          
         | $$_____/|__/                | $$ /$$$_  $$                         
         | $$       /$$ /$$$$$$$   /$$$$$$$| $$$$\ $$  /$$$$$$                
         | $$$$$   | $$| $$__  $$ /$$__  $$| $$ $$ $$ /$$__  $$               
         | $$__/   | $$| $$  \ $$| $$  | $$| $$\ $$$$| $$  \__/               
         | $$      | $$| $$  | $$| $$  | $$| $$ \ $$$| $$                     
         | $$      | $$| $$  | $$|  $$$$$$$|  $$$$$$/| $$                     
         |__/      |__/|__/  |__/ \_______/ \______/ |__/                     
                                                                           
"""
imprint = r"""
                  Secrets Find0r v1.0
           by Benjamin Iheukumere | SafeLink IT
               b.iheukumere@safelink-it.com
"""

ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

# ---------- Utilities ----------
def to_text(b: bytes):
    """Decode bytes to text using common fallbacks."""
    for enc in ('utf-8', 'latin-1', 'cp1252'):
        try:
            return b.decode(enc, errors='ignore')
        except Exception:
            continue
    return b.decode('utf-8', errors='ignore')

def port_open(ip, port=445, timeout=PORT_PROBE_TIMEOUT) -> bool:
    """Lightweight TCP check to skip dead hosts quickly."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False

def file_ext(path: str) -> str:
    """Return lowercase file extension (including dot)."""
    return os.path.splitext(path)[1].lower()

def strip_ansi(s: str) -> str:
    """Remove ANSI escape sequences."""
    return ANSI_RE.sub('', s or '')

def visible_len(s: str) -> int:
    """Compute string length without ANSI escape codes (for table layout)."""
    return len(strip_ansi(s))

# ----- Highlight helpers -----
def make_snippet_with_highlights(text: str, start_idx: int, end_idx: int, terms):
    """Build a context snippet around [start:end] and highlight only the matched terms."""
    s = max(0, start_idx - 60)
    e = min(len(text), end_idx + 140)
    snippet = text[s:e]
    for term in sorted(set(t for t in terms if t), key=len, reverse=True):
        try:
            snippet = re.sub(
                re.escape(term),
                lambda m: f"{C.BG_RED}{m.group(0)}{C.END}",
                snippet,
                flags=re.I
            )
        except re.error:
            continue
    return f"...{snippet.strip()}..."

def highlight_by_terms_in_text(text: str, terms):
    """Highlight each term wherever it appears in a short text (case-insensitive)."""
    out = text
    for term in sorted(set(terms), key=len, reverse=True):
        out = re.sub(re.escape(term), lambda m: f"{C.BG_RED}{m.group(0)}{C.END}", out, flags=re.I)
    return out

# ---------- Extractors ----------
def extract_text_from_office_xml(data_bytes: bytes) -> str:
    """Best-effort text extraction for docx/pptx/xlsx (ZIP/XML)."""
    texts = []
    try:
        z = zipfile.ZipFile(io.BytesIO(data_bytes))
        try:
            for name in z.namelist():
                if name.endswith(('.xml', '.rels')):
                    try:
                        txt = z.read(name)
                        s = re.sub(rb'<[^>]+>', b' ', txt)  # strip tags
                        texts.append(to_text(s))
                    except Exception:
                        continue
        finally:
            z.close()
    except Exception:
        pass
    return "\n".join(texts)

def extract_text_from_pdf(data_bytes: bytes) -> str:
    """Extract text from PDF if PyPDF2 is available."""
    if not HAS_PYPDF2:
        return ""
    texts = []
    try:
        reader = PyPDF2.PdfReader(io.BytesIO(data_bytes))
        for p in reader.pages:
            try:
                texts.append(p.extract_text() or "")
            except Exception:
                continue
    except Exception:
        pass
    return "\n".join(texts)

def extract_text_from_ole(data_bytes: bytes) -> str:
    """Extract rough text from legacy Office (doc/xls/ppt) using olefile."""
    if not HAS_OLEFILE:
        return ""
    texts = []
    try:
        ole = olefile.OleFileIO(io.BytesIO(data_bytes))
        try:
            for stream in ole.listdir(streams=True, storages=False):
                try:
                    path = "/".join(stream)
                    raw = ole.openstream(path).read()
                    texts.append(to_text(raw))
                except Exception:
                    continue
        finally:
            try:
                ole.close()
            except Exception:
                pass
    except Exception:
        pass
    return "\n".join(texts)

# ---------- Scanners (token-level highlighting) ----------
def scan_text_for_keywords(text: str, keywords_lower):
    """Return highlighted snippets for each keyword occurrence (token-only highlight)."""
    results = []
    lower = text.lower()
    for kw in keywords_lower:
        for m in re.finditer(re.escape(kw), lower):
            results.append(make_snippet_with_highlights(text, m.start(), m.end(), [kw]))
    return results

def scan_bytes_for_patterns(bdata: bytes, keywords_lower):
    """
    Keyword & regex scanning on bytes; snippets are built on decoded text with
    only the matched tokens highlighted.
    """
    results = []
    text = to_text(bdata)

    # Keywords
    results.extend(scan_text_for_keywords(text, keywords_lower))

    # Regexes
    for pat in REGEX_PATTERNS:
        for mb in pat.finditer(bdata):
            full = mb.group(0).decode(errors='ignore')
            groups = [g.decode(errors='ignore') if isinstance(g, (bytes, bytearray)) else str(g)
                      for g in mb.groups() if g]
            lower_text = text.lower()
            anchor_terms = groups if groups else [full]
            idx = -1
            for t in anchor_terms:
                if not t:
                    continue
                i = lower_text.find(t.lower())
                if i >= 0:
                    idx = i
                    anchor = t
                    break
            if idx >= 0:
                snippet = make_snippet_with_highlights(text, idx, idx + len(anchor), anchor_terms)
            else:
                snippet = highlight_by_terms_in_text(full, anchor_terms)
            results.append(snippet)

    # Deduplicate preserving order
    seen = set(); out = []
    for r in results:
        if r not in seen:
            seen.add(r); out.append(r)
    return out

# ---------- SMB helpers ----------
def _is_dir_entry(e):
    """Robustly decide if an SMB listPath entry is a directory."""
    # 1) Preferred API
    for attr in ("isDirectory", "is_directory"):
        try:
            return bool(getattr(e, attr)())
        except Exception:
            pass
    # 2) Attribute bit (FILE_ATTRIBUTE_DIRECTORY = 0x10)
    for attr_getter in ("get_attributes", "getAttributes", "get_attr"):
        try:
            attrs = getattr(e, attr_getter)()
            if isinstance(attrs, int):
                return bool(attrs & 0x10)
        except Exception:
            pass
    # 3) Fallback boolean field
    try:
        return bool(getattr(e, "is_directory"))
    except Exception:
        return False

def _new_conn(host, username, password):
    """Create and login an SMBConnection with configured timeouts."""
    conn = SMBConnection(host, host, sess_port=445, timeout=SMB_CONNECT_TIMEOUT)
    try:
        conn.setTimeout(SMB_OP_TIMEOUT)
    except Exception:
        pass
    if username:
        if "\\" in username:
            domain, user = username.split("\\", 1)
        else:
            domain, user = '', username
        conn.login(user, password, domain)
    else:
        conn.login('', '')
    return conn

def share_is_excluded(name: str) -> bool:
    """Return True if share name should be excluded (admin/system shares)."""
    if not name:
        return True
    up = name.upper()
    if up in EXCLUDE_SHARES:
        return True
    if EXCLUDE_SHARE_REGEX.match(up):   # C$, D$, E$, ...
        return True
    return False

def download_file_smb_by_conn(host, username, password, share, path, max_bytes=MAX_FILE_BYTES) -> bytes:
    """Download up to max_bytes from a file via a fresh SMB connection (always closed)."""
    buf = io.BytesIO()
    got = 0
    conn = None
    try:
        conn = _new_conn(host, username, password)
        def callback(data):
            nonlocal got
            if not data:
                return
            take = data
            if got + len(take) > max_bytes:
                take = take[:max_bytes - got]
            buf.write(take)
            got += len(take)
            if got >= max_bytes:
                raise IOError("MAX_BYTES_REACHED")
        conn.getFile(share, path, callback)
    except Exception:
        return b''
    finally:
        if conn:
            try:
                conn.logoff()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass
    return buf.getvalue()

def enumerate_files_on_host(host, username, password, keywords_lower, include_unknown=True):
    """Enumerate interesting files on all accessible shares of a host, honoring MAX_DIR_DEPTH."""
    tasks = []
    if not port_open(host, 445, timeout=PORT_PROBE_TIMEOUT):
        return tasks

    conn = None
    try:
        conn = _new_conn(host, username, password)
    except Exception:
        return tasks

    # List shares
    shares = []
    try:
        for s in conn.listShares():
            try:
                raw = s.get('shi1_netname') if isinstance(s, dict) else s['shi1_netname']
                if isinstance(raw, bytes):
                    name = raw.rstrip(b'\x00').decode(errors='ignore')
                else:
                    name = raw[:-1] if isinstance(raw, str) and raw.endswith('\x00') else raw
            except Exception:
                name = None
            if not name:
                continue
            if share_is_excluded(name):
                continue
            shares.append(name)
    except Exception:
        pass

    # Traverse shares
    try:
        for share in shares:
            stack = ['\\']
            visited = set()
            while stack:
                cur = stack.pop()
                key = (share, cur)
                if key in visited:
                    continue
                visited.add(key)

                # Build pattern and normalized current dir
                if cur in ('\\', ''):
                    pattern = '\\*'
                    current_dir = '\\'
                else:
                    p = cur.replace('/', '\\').lstrip('\\')
                    pattern = p + '\\*'
                    current_dir = '\\' + p if not p.startswith('\\') else p

                try:
                    entries = conn.listPath(share, pattern)
                except Exception:
                    continue

                for e in entries:
                    # Obtain name robustly
                    fname = None
                    for getter in ('get_longname', 'getFileName', 'get_shortname'):
                        try:
                            fname = getattr(e, getter)()
                            if fname:
                                break
                        except Exception:
                            pass
                    if not fname or fname in ('.', '..'):
                        continue

                    # Full path within the share
                    if current_dir in ('\\', ''):
                        full = '\\' + fname
                    else:
                        full = current_dir.rstrip('\\') + '\\' + fname

                    # Directory?
                    if _is_dir_entry(e):
                        # Enforce max directory depth if configured
                        if MAX_DIR_DEPTH is not None:
                            depth = full.count('\\') - 1  # root '\' -> 0
                            if depth > MAX_DIR_DEPTH:
                                continue
                        stack.append(full)
                        continue

                    # File filter
                    name_l = fname.lower()
                    ext = os.path.splitext(name_l)[1]
                    interesting_name = any(kw in name_l for kw in ["pass", "pwd", "secret", "cred", "token", "key"])
                    if ext in SUPPORTED_EXTS:
                        tasks.append((host, share, full))
                    elif include_unknown and (ext == "" or ext not in SUPPORTED_EXTS):
                        if interesting_name:
                            tasks.append((host, share, full + f"|unknown<{MAX_UNKNOWN_BYTES}>"))
    finally:
        if conn:
            try:
                conn.logoff()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass

    return tasks

# ---------- File processing ----------
def process_file_task_reconnect(task, username, password, keywords_lower):
    """Reconnect for each file, download (capped), extract text, and scan for matches."""
    host, share, filepath = task
    limit = MAX_FILE_BYTES
    if "|unknown<" in filepath:
        path_only, marker = filepath.split("|unknown<", 1)
        filepath = path_only
        try:
            limit = min(limit, int(marker.rstrip(">").strip()))
        except Exception:
            limit = min(limit, MAX_UNKNOWN_BYTES)

    try:
        b = download_file_smb_by_conn(host, username, password, share, filepath, max_bytes=limit)
        if not b:
            return None
        ext = file_ext(filepath)

        matches = []
        if ext in EXTS_OFFICE_XML:
            text = extract_text_from_office_xml(b)
            if text:
                matches.extend(scan_text_for_keywords(text, keywords_lower))
            matches.extend(scan_bytes_for_patterns(b, keywords_lower))

        elif ext in EXTS_PDF:
            text = extract_text_from_pdf(b)
            if text:
                matches.extend(scan_text_for_keywords(text, keywords_lower))
            else:
                matches.extend(scan_bytes_for_patterns(b, keywords_lower))

        elif ext in EXTS_TEXT:
            text = to_text(b)
            matches.extend(scan_text_for_keywords(text, keywords_lower))
            matches.extend(scan_bytes_for_patterns(b, keywords_lower))

        elif ext in EXTS_BINARY_OFFICE:
            text = extract_text_from_ole(b) if HAS_OLEFILE else ""
            if text:
                matches.extend(scan_text_for_keywords(text, keywords_lower))
            matches.extend(scan_bytes_for_patterns(b, keywords_lower))

        else:
            matches.extend(scan_bytes_for_patterns(b, keywords_lower))

        if matches:
            # Unique preserve order
            seen = set(); uniq = []
            for m in matches:
                if m not in seen:
                    seen.add(m); uniq.append(m)
            return {"host": host, "share": share, "path": filepath, "matches": uniq}
    except Exception:
        return None
    return None

# ---------- Pretty table rendering (ANSI-aware) ----------
def wrap_ansi_lines(s: str, width: int):
    """Wrap string to given visible width, preserving ANSI sequences."""
    if width <= 0:
        return [s or ""]
    s = s or ""
    out = []
    line = []
    vis = 0
    i = 0
    last_space_idx = -1
    while i < len(s):
        # ANSI sequence?
        if s[i] == '\x1b':
            m = ANSI_RE.match(s, i)
            if m:
                line.append(m.group(0))
                i = m.end()
                continue
        ch = s[i]
        i += 1
        line.append(ch)
        if ch == ' ':
            last_space_idx = len(line) - 1
        # count visible
        vis += 0 if ch == '\x1b' else 1
        # wrap when exceeding width
        if vis > width:
            break_at = last_space_idx if last_space_idx != -1 else len(line) - 1
            cur = ''.join(line[:break_at]).rstrip()
            out.append(cur)
            rem = line[break_at + 1:] if break_at == last_space_idx else line[break_at:]
            line = rem
            vis = visible_len(''.join(rem))
            last_space_idx = -1
    out.append(''.join(line))
    return [seg if seg != "" else "" for seg in out] or [""]

def compute_widths(headers, rows, term_w):
    """
    Decide column widths from content (visible lengths), respecting terminal width.
    Strategy: use minimums, grow towards desired content lengths, cap to terminal.
    """
    cols = len(headers)
    # minimums & caps
    if cols == 2:
        minw = [12, 20]
        caps = [24, 9999]
    else:
        minw = [15, 14, 30, 28]
        caps = [24, 22, 60, 9999]

    desired = [max(minw[i], visible_len(headers[i])) for i in range(cols)]
    sample_rows = rows[:400]
    for r in sample_rows:
        for i in range(cols):
            desired[i] = max(desired[i], min(caps[i], visible_len(str(r[i]))))

    overhead = (cols + 1) + 2 * cols  # borders + spaces
    max_line = max(60, term_w)
    widths = minw[:]
    available = max_line - overhead
    min_sum = sum(widths)

    if min_sum > available:
        # shrink proportionally, but keep at least 5 chars per column
        scale = available / float(min_sum) if min_sum else 1.0
        widths = [max(5, int(w * scale)) for w in widths]
        return widths

    remaining = available - min_sum
    grow = [max(0, min(caps[i], desired[i]) - widths[i]) for i in range(cols)]
    total_grow = sum(grow)
    if total_grow > 0 and remaining > 0:
        for i in range(cols):
            add = int(remaining * (grow[i] / total_grow)) if total_grow else 0
            widths[i] += add
        used = sum(widths)
        extra = available - used
        if extra > 0:
            widths[-1] += extra
    else:
        widths[-1] += remaining
    return widths

def render_table(rows, headers):
    """Render an ANSI-aware ASCII table with clean, aligned columns."""
    term_w = shutil.get_terminal_size((120, 24)).columns
    cols = len(headers)
    widths = compute_widths(headers, rows, term_w)

    def hline():
        return "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    def fmt_row(cells):
        wrapped_cols = [wrap_ansi_lines(str(cells[i]), widths[i]) for i in range(cols)]
        max_lines = max(len(wc) for wc in wrapped_cols)
        lines = []
        for li in range(max_lines):
            parts = []
            for i in range(cols):
                val = wrapped_cols[i][li] if li < len(wrapped_cols[i]) else ""
                pad_vis = widths[i] - visible_len(val)
                pad_vis = 0 if pad_vis < 0 else pad_vis
                parts.append(" " + val + (" " * pad_vis) + " ")
            lines.append("|" + "|".join(parts) + "|")
        return "\n".join(lines)

    out = [hline(), fmt_row(headers), hline()]
    for r in rows:
        out.append(fmt_row(r))
        out.append(hline())
    return "\n".join(out)

def format_screen_rows(found):
    """Format results for screen (first match per file, with ANSI highlights)."""
    rows = []
    for item in found:
        host = item['host']
        share = item['share']
        path = item['path']
        match = item['matches'][0] if item['matches'] else ''
        rows.append([host, share, path, match])
    return rows

def format_plain_rows(found):
    """Format results for file output (strip ANSI)."""
    rows = []
    for item in found:
        host = item['host']
        share = item['share']
        path = item['path']
        match = item['matches'][0] if item['matches'] else ''
        match_plain = strip_ansi(match)
        rows.append([host, share, path, match_plain])
    return rows

def print_results_table(found):
    """Print results table to screen (with highlights)."""
    if not found:
        print(f"{C.WARNING}No secrets found.{C.END}")
        return
    headers_scr = [f"{C.BOLD}Host{C.END}", f"{C.BOLD}Share{C.END}", f"{C.BOLD}Path{C.END}", f"{C.BOLD}Match{C.END}"]
    print("\n" + render_table(format_screen_rows(found), headers_scr) + "\n")

def plain_results_table(found):
    """Build plain results table for saving to file."""
    headers = ["Host", "Share", "Path", "Match"]
    return render_table(format_plain_rows(found), headers)

# ---------- Main ----------
def clear_screen():
    """Clear terminal screen."""
    os.system('clear' if os.name == 'posix' else 'cls')

def main():
    clear_screen()
    print(C.OKCYAN + BANNER + C.END)
    print(C.OKBLUE + imprint + C.END)

    # Credentials
    username = input("Username (leave empty for anonymous): ").strip()
    password = getpass.getpass("Password: ") if username else ""

    # CIDR
    while True:
        cidr = input("CIDR to scan (e.g. 192.168.1.0/24): ").strip()
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            break
        except Exception:
            print("Invalid CIDR, try again.")

    # Include unknown/no-extension files?
    choose_unknown = input("Include unknown/no-extension files if name looks sensitive? [Y/n]: ").strip().lower()
    include_unknown = (choose_unknown in ("", "y", "yes"))

    # Keywords
    custom = input("Use default keyword list? [Y/n]: ").strip().lower()
    if custom in ("n", "no"):
        kws = input("Enter comma-separated keywords (e.g. password,secret,token): ").strip()
        keywords_lower = [k.strip().lower() for k in kws.split(",") if k.strip()]
    else:
        keywords_lower = [k.lower() for k in KEYWORDS]

    hosts = [str(h) for h in network.hosts()]
    prefix = username if username else "anon"
    output_file = f"{prefix}_secrets_found_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    print(f"Enumerating shares and candidate files on {len(hosts)} hosts (enum threads={THREADS_ENUM})...")

    # Stage 1: enumerate files per host
    file_tasks = []
    with ThreadPoolExecutor(max_workers=min(THREADS_ENUM, max(4, len(hosts)))) as ex:
        futures = {ex.submit(enumerate_files_on_host, host, username, password, keywords_lower, include_unknown): host
                   for host in hosts}
        for fut in tqdm(as_completed(futures), total=len(futures), desc="Enumerating shares (that'll take a while)", unit="host"):
            try:
                tasks = fut.result()
                if tasks:
                    file_tasks.extend(tasks)
            except Exception:
                continue

    if not file_tasks:
        print("No candidate files found (no shares with supported/selected file types). Exiting.")
        return

    print(f"Found {len(file_tasks)} candidate files. Scanning files for secrets (file threads={THREADS_FILES})...")

    # Stage 2: scan files (use smaller thread pool to limit open sockets)
    found = []
    with ThreadPoolExecutor(max_workers=THREADS_FILES) as ex:
        futures = {ex.submit(process_file_task_reconnect, task, username, password, keywords_lower): task
                   for task in file_tasks}
        for fut in tqdm(as_completed(futures), total=len(futures), desc="Scanning files", unit="file"):
            try:
                res = fut.result()
                if res:
                    found.append(res)
            except Exception:
                continue

    # Output (screen) & save (file)
    print_results_table(found)

    # Write the report at the very end (we kept sockets low and closed earlier)
    plain_table = plain_results_table(found)
    with open(output_file, "w", encoding="utf-8") as fh:
        fh.write(f"Secrets Find0r results - {datetime.now().isoformat()}\n")
        fh.write(plain_table + "\n")
    print(f"Results saved to: {output_file}")

if __name__ == "__main__":
    main()
