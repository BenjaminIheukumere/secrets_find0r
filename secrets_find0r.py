#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Secrets Find0r (token-level highlight) with robust Kerberos/NTLM auth
- Token-only highlight with red background on matches (screen)
- Plain ASCII table (no colors) for file output
- Exclude admin shares (ADMIN$, IPC$, PRINT$, [A-Z]$)
- Robust SMB enumeration with recursion depth limit
- Optional include of unknown/no-extension files when names look sensitive
- Legacy Office via olefile; PDF via pypdf with pdfminer.six fallback
- Multithreaded, progress bars, customizable keywords
- Kerberos or NTLM auth; NTLM supports LM:NT or NT-only hashes
- SPN control via --target-name (e.g. filesrv01.contoso.local)
- Interactive and CLI modes; Kerberos auth test + error loop in interactive

Output-Änderungen:
- Sofortiges, thread-sicheres Anhängen jedes Findings in die Output-Datei (TSV)
- Datei im Append-Modus (kein Überschreiben)
- Optionale Live-Ausgabe auf stdout (Standard: nein)
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
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from impacket.smbconnection import SMBConnection
from tqdm import tqdm

# Optional parsers
try:
    import pypdf as PyPDF2  # Prefer pypdf (modern fork of PyPDF2)
    HAS_PYPDF2 = True
except Exception:
    HAS_PYPDF2 = False

# Optional: pdfminer.six fallback for tougher PDFs
try:
    from pdfminer_high_level_patch import extract_text as pdfminer_extract_text  # try patched name first if present
except Exception:
    try:
        from pdfminer.high_level import extract_text as pdfminer_extract_text
        HAS_PDFMINER = True
    except Exception:
        pdfminer_extract_text = None
        HAS_PDFMINER = False
else:
    HAS_PDFMINER = True

try:
    import olefile
    HAS_OLEFILE = True
except Exception:
    HAS_OLEFILE = False

# Email parsing
import email
from email import policy
from email.parser import BytesParser
try:
    import extract_msg
    HAS_EXTRACT_MSG = True
except Exception:
    HAS_EXTRACT_MSG = False

# ---------- Configurable params (defaults; can be overridden by CLI) ----------
THREADS_ENUM = 32                    # workers for host/share/file enumeration
THREADS_FILES = 8                    # workers for file download/scan
MAX_FILE_BYTES = 128 * 1024 * 1024   # max bytes to download per file - Default: 128 MB
MAX_UNKNOWN_BYTES = 256 * 1024       # cap for unknown/no-extension files if included
MAX_DIR_DEPTH = 2                    # max directory depth (root '\' = 0); None = unlimited
PORT_PROBE_TIMEOUT = 0.5             # TCP connect timeout for port 445
SMB_CONNECT_TIMEOUT = 5              # SMBConnection connect timeout
SMB_OP_TIMEOUT = 5                   # SMB operation timeout

# Exclude default/admin shares (configurable)
EXCLUDE_SHARES = {
    'ADMIN$', 'IPC$', 'PRINT$', 'FAX$',
    # 'SYSVOL', 'NETLOGON',  # re-enable exclusion if desired
}
EXCLUDE_SHARE_REGEX = re.compile(r'^[A-Z]\$$')  # C$, D$, E$, ...

KEYWORDS_DEFAULT = [
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
]

# Supported extensions (extended)
EXTS_TEXT = {
    '.txt', '.csv', '.json', '.html', '.htm', '.rtf',
    '.ps1', '.psm1', '.psd1', '.msf', '.ini', '.conf', '.cnf',
    '.config', '.xml', '.log', '.env', '.properties', '.yaml', '.yml',
    '.bat', '.cmd', '.vbs'
}
EXTS_OFFICE_XML = {'.docx', '.pptx', '.xlsx'}
EXTS_PDF = {'.pdf'}
EXTS_BINARY_OFFICE = {'.doc', '.xls', '.ppt'}
EXTS_EMAIL = {'.eml', '.msg'}
SUPPORTED_EXTS = EXTS_TEXT | EXTS_OFFICE_XML | EXTS_PDF | EXTS_BINARY_OFFICE | EXTS_EMAIL

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
                  Secrets Find0r v1.6
           by Benjamin Iheukumere | SafeLink IT
               b.iheukumere@safelink-it.com
"""

ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')
ANSI_RE_FULL = re.compile(r'\x1b\[[0-9;]*m')

# ---------- Utilities ----------
def clear_screen():
    if sys.stdout.isatty():
        os.system('clear' if os.name == 'posix' else 'cls')

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

def parse_ntlm_hash(s: str):
    """
    Parse NTLM hash input. Accepts:
      - NT only: 32 hex chars
      - LM:NT   : "LMHASH:NTHASH" (each 32 hex; LM may be 32 zeros)
    Returns (lmhash, nthash) or (None, None) if invalid.
    """
    if not s:
        return (None, None)
    s = s.strip()
    if ':' in s:
        lm, nt = s.split(':', 1)
        lm = lm.strip()
        nt = nt.strip()
        if re.fullmatch(r'[0-9a-fA-F]{32}', lm) and re.fullmatch(r'[0-9a-fA-F]{32}', nt):
            return (lm, nt)
        return (None, None)
    else:
        if re.fullmatch(r'[0-9a-fA-F]{32}', s):
            return ('0' * 32, s)
        return (None, None)

def first_network_host_str(network):
    """
    Return the first usable host in the network as a string, or None.
    Works even if `network.hosts()` returns a list or if `network` is already a list of IPs.
    """
    try:
        if hasattr(network, "hosts") and callable(network.hosts):
            it = network.hosts()
            try:
                h = next(it)
                return str(h)
            except TypeError:
                hosts_list = list(network.hosts())
                return str(hosts_list[0]) if hosts_list else None
            except StopIteration:
                return None
        if isinstance(network, (list, tuple)) and network:
            return str(network[0])
    except Exception:
        pass
    return None

# ---------- Safe stderr silencer ----------
_STDERR_LOCK = threading.Lock()
_DEVNULL = open(os.devnull, 'w')

class _QuietStderr:
    def __enter__(self):
        self._prev = sys.stderr
        with _STDERR_LOCK:
            sys.stderr = _DEVNULL
        return self
    def __exit__(self, exc_type, exc, tb):
        with _STDERR_LOCK:
            sys.stderr = self._prev
        return False

def quiet_stderr():
    return _QuietStderr()

# ---------- Live status (single line under bars) ----------
_STATUS_LOCK = threading.Lock()

def _print_status_below_bar(text: str):
    try:
        width = shutil.get_terminal_size((120, 24)).columns
    except Exception:
        width = 120
    shown = text[:max(1, width - 1)]
    with _STATUS_LOCK:
        sys.stdout.write('\x1b7')
        sys.stdout.write('\x1b[1E')
        sys.stdout.write('\x1b[2K')
        sys.stdout.write(shown)
        sys.stdout.write('\x1b8')
        sys.stdout.flush()

def make_enum_status_cb():
    def cb(host: str, share: str, path: str):
        if not path.startswith('\\'):
            path = '\\' + path
        msg = f"Enumerating: \\\\{host}\\{share}{path}"
        _print_status_below_bar(msg)
    return cb

def make_scan_status_cb():
    def cb(host: str, share: str, path: str):
        if not path.startswith('\\'):
            path = '\\' + path
        msg = f"Scanning:    \\\\{host}\\{share}{path}"
        _print_status_below_bar(msg)
    return cb

def clear_status_line():
    with _STATUS_LOCK:
        sys.stdout.write('\x1b7')
        sys.stdout.write('\x1b[1E')
        sys.stdout.write('\x1b[2K')
        sys.stdout.write('\x1b8')
        sys.stdout.flush()

# ----- Highlight helpers -----
def make_snippet_with_highlights(text: str, start_idx: int, end_idx: int, terms):
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
    out = text
    for term in sorted(set(terms), key=len, reverse=True):
        out = re.sub(re.escape(term), lambda m: f"{C.BG_RED}{m.group(0)}{C.END}", out, flags=re.I)
    return out

# ---------- Extractors ----------
def extract_text_from_office_xml(data_bytes: bytes) -> str:
    texts = []
    try:
        z = zipfile.ZipFile(io.BytesIO(data_bytes))
        try:
            for name in z.namelist():
                if name.endswith(('.xml', '.rels')):
                    try:
                        txt = z.read(name)
                        s = re.sub(rb'<[^>]+>', b' ', txt)
                        texts.append(to_text(s))
                    except Exception:
                        continue
        finally:
            z.close()
    except Exception:
        pass
    return "\n".join(texts)

def _strip_html_to_text(html: str) -> str:
    html = re.sub(r'(?is)<(script|style).*?>.*?</\1>', ' ', html)
    html = re.sub(r'(?is)<br\s*/?>', '\n', html)
    html = re.sub(r'(?is)</p\s*>', '\n', html)
    html = re.sub(r'(?is)<.*?>', ' ', html)
    html = re.sub(r'[ \t\r\f\v]+', ' ', html)
    html = re.sub(r'\n\s*\n+', '\n\n', html)
    return html.strip()

def extract_text_from_eml(data_bytes: bytes) -> str:
    try:
        msg = BytesParser(policy=policy.default).parsebytes(data_bytes)
    except Exception:
        try:
            msg = email.message_from_bytes(data_bytes)
        except Exception:
            return ""
    parts = []

    def _maybe_add(part):
        try:
            ctype = part.get_content_type()
        except Exception:
            ctype = part.get('Content-Type', '') or ''
        try:
            payload = part.get_content()
        except Exception:
            try:
                payload = part.get_payload(decode=True)
                if isinstance(payload, bytes):
                    payload = to_text(payload)
            except Exception:
                payload = None
        if not payload:
            return
        if 'text/plain' in ctype:
            parts.append(str(payload))
        elif 'text/html' in ctype:
            parts.append(_strip_html_to_text(str(payload)))

    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            _maybe_add(part)
    else:
        _maybe_add(msg)

    if not parts:
        parts.append(to_text(data_bytes))
    return "\n\n".join(p for p in parts if p).strip()

def extract_text_from_msg(data_bytes: bytes) -> str:
    if not HAS_EXTRACT_MSG:
        return ""
    import tempfile
    text = ""
    try:
        with tempfile.NamedTemporaryFile(delete=True, suffix=".msg") as tf:
            tf.write(data_bytes)
            tf.flush()
            with quiet_stderr():
                m = extract_msg.Message(tf.name)
            plain = getattr(m, 'body', None)
            html = getattr(m, 'htmlBody', None)
            if html and not plain:
                plain = _strip_html_to_text(html)
            elif html:
                plain = (plain or "") + "\n\n" + _strip_html_to_text(html)
            text = (plain or "").strip()
    except Exception:
        return ""
    return text

def extract_text_from_pdf(data_bytes: bytes) -> str:
    texts = []
    total_pages = 0
    pypdf_pages_with_text = 0

    if HAS_PYPDF2:
        try:
            with quiet_stderr():
                reader = PyPDF2.PdfReader(io.BytesIO(data_bytes))
                total_pages = len(reader.pages)
                for p in reader.pages:
                    try:
                        t = p.extract_text() or ""
                        if t.strip():
                            pypdf_pages_with_text += 1
                            texts.append(t)
                    except Exception:
                        continue
        except Exception:
            pass

    joined = "\n".join(texts)

    need_fallback = False
    if HAS_PDFMINER:
        if len(joined) < 200:
            need_fallback = True
        else:
            if total_pages:
                coverage = pypdf_pages_with_text / total_pages
                if coverage < 0.8:
                    need_fallback = True

    if need_fallback and pdfminer_extract_text:
        try:
            with quiet_stderr():
                pm_text = pdfminer_extract_text(io.BytesIO(data_bytes)) or ""
            if pm_text:
                joined = pm_text if not joined else f"{joined}\n{pm_text}"
        except Exception:
            pass

    return joined

def extract_text_from_ole(data_bytes: bytes) -> str:
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

# ---------- Scanners ----------
def scan_text_for_keywords(text: str, keywords_lower):
    results = []
    lower = text.lower()
    for kw in keywords_lower:
        for m in re.finditer(re.escape(kw), lower):
            results.append(make_snippet_with_highlights(text, m.start(), m.end(), [kw]))
    return results

def scan_bytes_for_patterns(bdata: bytes, keywords_lower):
    results = []
    text = to_text(bdata)
    results.extend(scan_text_for_keywords(text, keywords_lower))
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
    seen = set(); out = []
    for r in results:
        if r not in seen:
            seen.add(r); out.append(r)
    return out

# ---------- SMB helpers ----------
def _is_dir_entry(e):
    for attr in ("isDirectory", "is_directory"):
        try:
            return bool(getattr(e, attr)())
        except Exception:
            pass
    for attr_getter in ("get_attributes", "getAttributes", "get_attr"):
        try:
            attrs = getattr(e, attr_getter)()
            if isinstance(attrs, int):
                return bool(attrs & 0x10)
        except Exception:
            pass
    try:
        return bool(getattr(e, "is_directory"))
    except Exception:
        return False

def share_is_excluded(name: str) -> bool:
    if not name:
        return True
    up = name.upper()
    if up in EXCLUDE_SHARES:
        return True
    if EXCLUDE_SHARE_REGEX.match(up):
        return True
    return False

def build_remote_name(host: str, target_name: str | None, kerberos: bool) -> str:
    if target_name:
        return target_name
    if kerberos:
        try:
            fqdn = socket.getfqdn(host)
            if fqdn and fqdn != host and '.' in fqdn:
                return fqdn
        except Exception:
            pass
    return host

def new_conn(host, auth):
    kerberos = (auth.get('mode') == 'kerberos')
    remote_name = build_remote_name(host, auth.get('target_name'), kerberos)

    conn = SMBConnection(remote_name, host, sess_port=445, timeout=auth.get('smb_connect_timeout', SMB_CONNECT_TIMEOUT))
    try:
        conn.setTimeout(auth.get('smb_op_timeout', SMB_OP_TIMEOUT))
    except Exception:
        pass

    user = auth.get('username') or ''
    domain = auth.get('domain') or ''
    password = auth.get('password') or ''
    lmhash = auth.get('lmhash') or ''
    nthash = auth.get('nthash') or ''
    kdc = auth.get('kdc')
    use_cache = bool(auth.get('use_cache', False))

    try:
        if kerberos:
            conn.kerberosLogin(user, password, domain,
                               lmhash, nthash,
                               aesKey='',
                               TGT=None, TGS=None,
                               useCache=use_cache,
                               kdcHost=kdc)
        else:
            if nthash and len(nthash) == 32:
                conn.login(user, '', domain, lmhash=lmhash, nthash=nthash)
            else:
                conn.login(user, password, domain)
        return conn, None
    except Exception as e:
        try:
            conn.close()
        except Exception:
            pass
        return None, str(e)

def test_kerberos(auth, test_host):
    conn, err = new_conn(test_host, auth)
    if err or not conn:
        return False, f"{err}"
    try:
        conn.listShares()
        return True, None
    except Exception as e:
        return False, str(e)
    finally:
        try:
            conn.logoff()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass

def download_file_smb_by_conn(host, auth, share, path, max_bytes=MAX_FILE_BYTES) -> bytes:
    buf = io.BytesIO()
    got = 0
    conn = None
    try:
        conn, err = new_conn(host, auth)
        if err or not conn:
            return b''
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

def enumerate_files_on_host(host, auth, keywords_lower, include_unknown=True, status_cb=None):
    tasks = []
    if not port_open(host, 445, timeout=auth.get('port_probe_timeout', PORT_PROBE_TIMEOUT)):
        return tasks

    conn, err = new_conn(host, auth)
    if err or not conn:
        return tasks

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
            if not name or share_is_excluded(name):
                continue
            shares.append(name)
    except Exception:
        pass

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

                if cur in ('\\', ''):
                    pattern = '\\*'
                    current_dir = '\\'
                else:
                    p = cur.replace('/', '\\').lstrip('\\')
                    pattern = p + '\\*'
                    current_dir = '\\' + p if not p.startswith('\\') else p

                if status_cb:
                    try:
                        status_cb(host, share, current_dir)
                    except Exception:
                        pass

                try:
                    entries = conn.listPath(share, pattern)
                except Exception:
                    continue

                for e in entries:
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

                    if current_dir in ('\\', ''):
                        full = '\\' + fname
                    else:
                        full = current_dir.rstrip('\\') + '\\' + fname

                    if status_cb:
                        try:
                            status_cb(host, share, full)
                        except Exception:
                            pass

                    if _is_dir_entry(e):
                        max_depth = auth.get('max_dir_depth', MAX_DIR_DEPTH)
                        if max_depth is not None:
                            depth = full.count('\\') - 1
                            if depth > max_depth:
                                continue
                        stack.append(full)
                        continue

                    name_l = fname.lower()
                    ext = os.path.splitext(name_l)[1]
                    interesting_name = any(kw in name_l for kw in ["pass", "pwd", "secret", "cred", "token", "key"])
                    if ext in SUPPORTED_EXTS:
                        tasks.append((host, share, full))
                    elif include_unknown and (ext == "" or ext not in SUPPORTED_EXTS):
                        if interesting_name:
                            cap = auth.get('max_unknown_bytes', MAX_UNKNOWN_BYTES)
                            tasks.append((host, share, full + f"|unknown<{cap}>"))
    finally:
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
def process_file_task_reconnect(task, auth, keywords_lower, status_cb=None):
    host, share, filepath = task
    if status_cb:
        try:
            status_cb(host, share, filepath if "|unknown<" not in filepath else filepath.split("|unknown<",1)[0])
        except Exception:
            pass

    limit = auth.get('max_file_bytes', MAX_FILE_BYTES)
    if "|unknown<" in filepath:
        path_only, marker = filepath.split("|unknown<", 1)
        filepath = path_only
        try:
            limit = min(limit, int(marker.rstrip(">").strip()))
        except Exception:
            limit = min(limit, auth.get('max_unknown_bytes', MAX_UNKNOWN_BYTES))

    try:
        b = download_file_smb_by_conn(host, auth, share, filepath, max_bytes=limit)
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
            matches.extend(scan_bytes_for_patterns(b, keywords_lower))

        elif ext in EXTS_EMAIL:
            if ext == '.eml':
                text = extract_text_from_eml(b)
            else:
                text = extract_text_from_msg(b)
            if text:
                matches.extend(scan_text_for_keywords(text, keywords_lower))
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
            seen = set(); uniq = []
            for m in matches:
                if m not in seen:
                    seen.add(m); uniq.append(m)
            return {"host": host, "share": share, "path": filepath, "matches": uniq}
    except Exception:
        return None
    return None

# ---------- Pretty table rendering (for optional stdout) ----------
def wrap_ansi_lines(s: str, width: int):
    if width <= 0:
        return [s or ""]
    s = s or ""
    out = []
    line = []
    last_space_idx = -1
    i = 0
    while i < len(s):
        if s[i] == '\x1b':
            m = ANSI_RE_FULL.match(s, i)
            if m:
                line.append(m.group(0))
                i = m.end()
                continue
        ch = s[i]; i += 1
        line.append(ch)
        if ch == ' ':
            last_space_idx = len(line) - 1
        vis = visible_len(''.join(line))
        if vis > width:
            break_at = last_space_idx if last_space_idx != -1 else len(line) - 1
            cur = ''.join(line[:break_at]).rstrip()
            out.append(cur)
            rem = line[break_at + 1:] if break_at == last_space_idx else line[break_at:]
            line = rem
            last_space_idx = -1
    out.append(''.join(line))
    return [seg if seg != "" else "" for seg in out] or [""]

def compute_widths(headers, rows, term_w):
    cols = len(headers)
    if cols == 2:
        minw = [12, 20]
        caps = [24, 9999]
    else:
        minw = [15, 14, 30, 28]
        caps = [24, 22, 60, 9999]

    desired = [max(minw[i], visible_len(headers[i])) for i in range(cols)]
    for r in rows[:400]:
        for i in range(cols):
            desired[i] = max(desired[i], min(caps[i], visible_len(str(r[i]))))

    overhead = (cols + 1) + 2 * cols
    max_line = max(60, term_w)
    widths = minw[:]
    available = max_line - overhead
    min_sum = sum(widths)

    if min_sum > available:
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
    rows = []
    for item in found:
        host = item['host']; share = item['share']; path = item['path']
        if item['matches']:
            for m in item['matches']:
                rows.append([host, share, path, m])
        else:
            rows.append([host, share, path, ""])
    return rows

def print_results_table(found):
    if not found:
        print(f"{C.WARNING}No secrets found.{C.END}", flush=True)
        return
    headers_scr = [f"{C.BOLD}Host{C.END}", f"{C.BOLD}Share{C.END}", f"{C.BOLD}Path{C.END}", f"{C.BOLD}Match{C.END}"]
    print("\n" + render_table(format_screen_rows(found), headers_scr) + "\n", flush=True)

# ---------- Streaming Output (neu) ----------
_OUT_LOCK = threading.Lock()
_out_fh = None
_output_path = None
_write_header_once = True

def open_output_file(base_path: str):
    """
    Öffnet die Ergebnisdatei im Append-Modus (TSV) und schreibt einmalig den Header.
    """
    global _out_fh, _output_path, _write_header_once
    _output_path = base_path
    # Append + line buffering: buffering=1 (Textmodus) => zeilenweise Flush
    _out_fh = open(_output_path, "a", encoding="utf-8", buffering=1)
    with _OUT_LOCK:
        if _write_header_once:
            _out_fh.write(f"# Secrets Find0r results (TSV) - {datetime.now().isoformat()}\n")
            _out_fh.write("host\tshare\tpath\tmatch\n")
            _out_fh.flush()
            _write_header_once = False

def append_findings(item: dict, also_stdout: bool = False):
    """
    Hängt alle Treffer eines Items (host/share/path, jede Match-Zeile) an die Datei an.
    Thread-sicher und sofort flush.
    Optional: Live-Ausgabe auf stdout.
    """
    if _out_fh is None:
        return
    host = item.get("host", "")
    share = item.get("share", "")
    path = item.get("path", "")
    matches = item.get("matches") or [""]

    with _OUT_LOCK:
        for m in matches:
            line = f"{host}\t{share}\t{path}\t{strip_ansi(m)}\n"
            _out_fh.write(line)
        _out_fh.flush()

    if also_stdout:
        # Schlanke stdout-Zeilen, kein großes Table-Rendering während des Scans
        for m in matches:
            print(f"[FOUND] {host}\\{share}{path} :: {strip_ansi(m)}", flush=True)

def close_output_file():
    global _out_fh
    try:
        if _out_fh:
            _out_fh.flush()
            _out_fh.close()
    except Exception:
        pass
    _out_fh = None

# ---------- CLI parsing ----------
def build_arg_parser():
    p = argparse.ArgumentParser(description="Secrets Find0r - SMB secret scanner (NTLM/Kerberos)")
    p.add_argument("cidr", nargs="?", help="CIDR to scan, e.g. 192.168.1.0/24")

    # Auth mode
    g_auth = p.add_argument_group("Authentication")
    g_auth.add_argument("--kerberos", action="store_true", help="Use Kerberos instead of NTLM")
    g_auth.add_argument("--domain", help="Domain/realm for authentication (required for Kerberos)")
    g_auth.add_argument("--kdc", help="KDC/Domain Controller IP or FQDN (Kerberos)")
    g_auth.add_argument("--use-cache", action="store_true", help="Use Kerberos credential cache (kinit)")
    g_auth.add_argument("--target-name", help="SPN remote name (hostname/FQDN) for Kerberos SPN, e.g. filesrv01.domain.tld")

    g_ntlm = p.add_argument_group("NTLM credentials")
    g_ntlm.add_argument("--username", help="Username (DOMAIN\\user or user)")
    g_ntlm.add_argument("--password", help="Password (if not using NTLM hash)")
    g_ntlm.add_argument("--hash", help="NTLM hash (NT or LM:NT)")

    # Behavior/limits
    g_cfg = p.add_argument_group("Performance & Limits")
    g_cfg.add_argument("--threads-enum", type=int, help=f"Enumeration workers (default {THREADS_ENUM})")
    g_cfg.add_argument("--threads-files", type=int, help=f"Download/scan workers (default {THREADS_FILES})")
    g_cfg.add_argument("--max-file-bytes", type=int, help=f"Max bytes per file (default {MAX_FILE_BYTES})")
    g_cfg.add_argument("--max-unknown-bytes", type=int, help=f"Max bytes for unknown files (default {MAX_UNKNOWN_BYTES})")
    g_cfg.add_argument("--max-dir-depth", type=int, help=f"Max directory depth (default {MAX_DIR_DEPTH})")
    g_cfg.add_argument("--port-probe-timeout", type=float, help=f"TCP connect timeout (default {PORT_PROBE_TIMEOUT})")
    g_cfg.add_argument("--smb-connect-timeout", type=float, help=f"SMB connect timeout (default {SMB_CONNECT_TIMEOUT})")
    g_cfg.add_argument("--smb-op-timeout", type=float, help=f"SMB op timeout (default {SMB_OP_TIMEOUT})")

    # Include unknown & keywords control
    g_scan = p.add_argument_group("Scanning options")
    g_scan.add_argument("--include-unknown", action="store_true", help="Include unknown/no-extension files if names look sensitive")
    g_scan.add_argument("--no-include-unknown", action="store_true", help="Do NOT include unknown/no-extension files")
    g_scan.add_argument("--use-default-keywords", action="store_true", help="Use built-in default keywords (no prompt)")
    g_scan.add_argument("--keywords", help="Comma-separated custom keywords (overrides default keywords)")

    # Optional stdout live
    p.add_argument("--stdout", action="store_true", help="Live-Findings zusätzlich auf stdout ausgeben (Standard: nein)")

    return p

# ---------- Main ----------
def main():
    clear_screen()
    print(C.OKCYAN + BANNER + C.END)
    print(C.OKBLUE + imprint + C.END)
    sys.stdout.flush()

    parser = build_arg_parser()
    args = parser.parse_args()

    interactive = False

    # Resolve CIDR
    if not args.cidr:
        interactive = True
        while True:
            cidr = input("CIDR to scan (e.g. 192.168.1.0/24): ").strip()
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                break
            except Exception:
                print(f"{C.FAIL}Invalid CIDR, try again.{C.END}", flush=True)
    else:
        try:
            network = ipaddress.ip_network(args.cidr, strict=False)
        except Exception:
            print(f"{C.FAIL}Invalid CIDR provided on CLI.{C.END}", flush=True)
            sys.exit(1)

    # ---- Authentication mode selection (interactive prompt) ----
    if args.kerberos:
        auth_mode = 'kerberos'
    else:
        interactive = True
        mode_choice = input("Auth mode: [1] NTLM (default)  [2] Kerberos: ").strip()
        auth_mode = 'kerberos' if mode_choice == '2' else 'ntlm'

    auth = {
        'mode': auth_mode,
        'username': args.username,
        'password': args.password,
        'lmhash': None,
        'nthash': None,
        'domain': args.domain,
        'kdc': args.kdc,
        'use_cache': bool(args.use_cache),
        'target_name': args.target_name,
        'smb_connect_timeout': args.smb_connect_timeout or SMB_CONNECT_TIMEOUT,
        'smb_op_timeout': args.smb_op_timeout or SMB_OP_TIMEOUT,
        'port_probe_timeout': args.port_probe_timeout or PORT_PROBE_TIMEOUT,
        'max_dir_depth': args.max_dir_depth if args.max_dir_depth is not None else MAX_DIR_DEPTH,
        'max_file_bytes': args.max_file_bytes or MAX_FILE_BYTES,
        'max_unknown_bytes': args.max_unknown_bytes or MAX_UNKNOWN_BYTES,
    }

    # Include unknown?
    include_unknown = None
    if args.include_unknown and args.no_include_unknown:
        print(f"{C.WARNING}Both --include-unknown and --no-include-unknown specified; ignoring both and prompting.{C.END}", flush=True)
    elif args.include_unknown:
        include_unknown = True
    elif args.no_include_unknown:
        include_unknown = False

    if include_unknown is None:
        interactive = True
        choice = input("Include unknown/no-extension files if name looks sensitive? [Y/n]: ").strip().lower()
        include_unknown = (choice in ("", "y", "yes"))

    # Keywords selection
    if args.keywords:
        keywords_lower = [k.strip().lower() for k in args.keywords.split(',') if k.strip()]
    elif args.use_default_keywords:
        keywords_lower = [k.lower() for k in KEYWORDS_DEFAULT]
    else:
        interactive = True
        choice = input("Use default keyword list? [Y/n]: ").strip().lower()
        if choice in ("", "y", "yes"):
            keywords_lower = [k.lower() for k in KEYWORDS_DEFAULT]
        else:
            kws = input("Enter comma-separated keywords (e.g. password,secret,token): ").strip()
            keywords_lower = [k.strip().lower() for k in kws.split(",") if k.strip()]
            if not keywords_lower:
                keywords_lower = [k.lower() for k in KEYWORDS_DEFAULT]

    # Threads
    enum_threads = args.threads_enum or THREADS_ENUM
    file_threads = args.threads_files or THREADS_FILES

    # ---- Collect auth details per mode ----
    if auth['mode'] == 'kerberos':
        if not auth['domain']:
            interactive = True
            while True:
                auth['domain'] = input("Kerberos Domain (e.g. CONTOSO or CONTOSO.LOCAL - mus be DNS-resolvable or in /etc/hosts): ").strip()
                if auth['domain']:
                    break
                print(f"{C.FAIL}Domain is required for Kerberos.{C.END}", flush=True)

        if not auth['username']:
            interactive = True
            auth['username'] = input("Username (user only, not DOMAIN\\user): ").strip()

        if not auth['password'] and not auth['use_cache'] and not args.password and not args.hash:
            interactive = True
            use_cache = input("Use Kerberos credential cache (kinit)? [y/N]: ").strip().lower() in ("y", "yes")
            auth['use_cache'] = use_cache

        if not auth['use_cache'] and not auth['password'] and not args.password and not args.hash:
            interactive = True
            use_hash = input("Use NTLM hash instead of password? [y/N]: ").strip().lower() in ("y", "yes")
            if use_hash:
                h = input("NTLM hash (NT or LM:NT): ").strip()
                lm, nt = parse_ntlm_hash(h)
                if not nt:
                    print(f"{C.FAIL}Invalid NTLM hash format.{C.END}", flush=True)
                    sys.exit(1)
                auth['lmhash'], auth['nthash'] = lm, nt
            else:
                auth['password'] = getpass.getpass("Password: ")

        if args.password and not auth['password']:
            auth['password'] = args.password

        if args.hash:
            lm, nt = parse_ntlm_hash(args.hash)
            if not nt:
                print(f"{C.FAIL}Invalid NTLM hash format on CLI.{C.END}", flush=True)
                sys.exit(1)
            auth['lmhash'], auth['nthash'] = lm, nt

        if not auth['kdc']:
            interactive = True
            auth['kdc'] = input("KDC / Domain Controller (FQDN - mus be DNS-resolvable or in /etc/hosts): ").strip()

        if not auth['target_name']:
            interactive = True
            tn = input("Target SPN name (hostname/FQDN used for SPN cifs/<name>) [usually the Domaincontroller's FQDN]: ").strip()
            auth['target_name'] = tn or None

        test_host = first_network_host_str(network)
        if test_host:
            ok, reason = test_kerberos(auth, test_host)
            if not ok:
                if interactive:
                    print(f"{C.FAIL}Kerberos authentication failed: {reason}{C.END}", flush=True)
                    while True:
                        print("\nAdjust Kerberos parameters (press Enter to keep current):", flush=True)
                        new_domain = input(f"Domain [{auth['domain']}]: ").strip() or auth['domain']
                        new_kdc = input(f"KDC/DC [{auth['kdc']}]: ").strip() or auth['kdc']
                        new_tn = input(f"Target SPN name [{auth.get('target_name') or 'auto'}]: ").strip()
                        auth['domain'] = new_domain
                        auth['kdc'] = new_kdc
                        auth['target_name'] = new_tn or auth['target_name']
                        ok, reason = test_kerberos(auth, test_host)
                        if ok:
                            print(f"{C.OKGREEN}Kerberos test OK. Continuing...{C.END}", flush=True)
                            break
                        print(f"{C.FAIL}Still failing: {reason}{C.END}", flush=True)
                        again = input("Try again? [Y/n]: ").strip().lower()
                        if again in ('n', 'no'):
                            sys.exit(1)
                else:
                    print(f"{C.FAIL}Kerberos authentication failed: {reason}{C.END}", flush=True)
                    print("Hint: verify --domain, --username, --password/--hash/--use-cache, --kdc, and --target-name (SPN).", flush=True)
                    sys.exit(1)
        else:
            print(f"{C.WARNING}No usable host in the provided CIDR to test Kerberos; continuing without pre-test.{C.END}", flush=True)

    else:
        if not auth['username']:
            interactive = True
            auth['username'] = input("Username (DOMAIN\\user or user): ").strip()

        if not auth['password'] and not args.hash:
            interactive = True
            use_hash = input("Use NTLM hash instead of password? [y/N]: ").strip().lower() in ("y", "yes")
            if use_hash:
                h = input("NTLM hash (NT or LM:NT): ").strip()
                lm, nt = parse_ntlm_hash(h)
                if not nt:
                    print(f"{C.FAIL}Invalid NTLM hash format.{C.END}", flush=True)
                    sys.exit(1)
                auth['lmhash'], auth['nthash'] = lm, nt
            else:
                auth['password'] = getpass.getpass("Password: ")

        if args.hash:
            lm, nt = parse_ntlm_hash(args.hash)
            if not nt:
                print(f"{C.FAIL}Invalid NTLM hash format on CLI.{C.END}", flush=True)
                sys.exit(1)
            auth['lmhash'], auth['nthash'] = lm, nt

        if auth['username'] and '\\' in auth['username']:
            auth['domain'], auth['username'] = auth['username'].split('\\', 1)

    # Stdout-Live-Ausgabe?
    stdout_live = bool(args.stdout)
    if not args.stdout:
        interactive = True
        ans = input("Findings zusätzlich live auf dem Bildschirm ausgeben? [n/N = nein, y/Y = ja]: ").strip().lower()
        stdout_live = ans in ("y", "yes", "j", "ja")

    # Hosts & output
    hosts = [str(h) for h in network.hosts()]
    prefix = (auth.get('domain') + '_' if auth.get('domain') else '') + (auth.get('username') or 'anon')
    output_file = f"{prefix}_secrets_found_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    open_output_file(output_file)  # Datei direkt öffnen (Append + Header)
    print(f"Output-Datei (TSV, Append): {output_file}", flush=True)

    print(f"Enumerating shares and candidate files on {len(hosts)} hosts (enum threads={enum_threads})...", flush=True)

    # Stage 1: enumerate files per host
    file_tasks = []
    enum_workers = min(enum_threads, max(4, len(hosts)))
    auth_for_enum = auth.copy()
    enum_status_cb = make_enum_status_cb()

    with ThreadPoolExecutor(max_workers=enum_workers) as ex:
        futures = {ex.submit(enumerate_files_on_host, host, auth_for_enum, keywords_lower, include_unknown, enum_status_cb): host
                   for host in hosts}
        pbar = tqdm(as_completed(futures), total=len(futures), desc="Enumerating shares (this may take a while)", unit="host")
        for fut in pbar:
            try:
                tasks = fut.result()
                if tasks:
                    file_tasks.extend(tasks)
            except Exception:
                continue
        clear_status_line()

    if not file_tasks:
        print("No candidate files found (no shares with supported/selected file types).", flush=True)
        # Abschlusszeile in Datei schreiben, damit sie nicht leer bleibt
        with _OUT_LOCK:
            _out_fh.write("# No candidate files found.\n")
            _out_fh.flush()
        close_output_file()
        return

    print(f"Found {len(file_tasks)} candidate files. Scanning files for secrets (file threads={file_threads})...", flush=True)

    # Stage 2: scan files (live Append in Datei)
    found_count = 0
    auth_for_files = auth.copy()
    scan_status_cb = make_scan_status_cb()

    with ThreadPoolExecutor(max_workers=file_threads) as ex:
        futures = {ex.submit(process_file_task_reconnect, task, auth_for_files, keywords_lower, scan_status_cb): task
                   for task in file_tasks}
        pbar2 = tqdm(as_completed(futures), total=len(futures), desc="Scanning files", unit="file")
        for fut in pbar2:
            try:
                res = fut.result()
                if res:
                    found_count += 1
                    append_findings(res, also_stdout=stdout_live)  # Sofort in Datei + optional stdout
            except Exception:
                continue
        clear_status_line()

    # Zusammenfassung
    print(f"\nScan abgeschlossen. Treffer-Datei: {output_file}", flush=True)
    print(f"Anzahl Dateien mit Treffern: {found_count}", flush=True)
    if stdout_live is False:
        print("(Hinweis: Live-stdout war deaktiviert. Verwenden Sie --stdout oder bestätigen Sie die Nachfrage, um Live-Ausgaben zu sehen.)", flush=True)

    # Abschlusszeile
    with _OUT_LOCK:
        _out_fh.write(f"# Scan finished at {datetime.now().isoformat()}, files_with_matches={found_count}\n")
        _out_fh.flush()
    close_output_file()

if __name__ == "__main__":
    main()
