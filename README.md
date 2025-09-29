# Secrets Find0r

A powerful multi-threaded SMB-share explorer & credential/secret discovery tool. Search across SMB shares for exposed credentials, tokens, connection strings etc., with highlights in output and clean ASCII table exports.

---

## Features

* Recursive SMB share scanning with depth limit (configurable)
* File type filtering & keyword + regex-based secret detection (supports text, Office documents, PDFs, unknown/no-extension with name hints)
* Token-level highlighting in console, plain ASCII export to file
* Multithreading: separate pools for enumeration and file scanning
* Proper closing of connections to avoid resource leaks
* Configurable parameters: threads, timeouts, max directory depth

---

## Installation

1. Clone the repo:

   ```
   git clone https://github.com/YourUsername/secrets_find0r.git
   cd secrets_find0r
   ```
2. Install dependencies:

   ```
   pip install -r requirements.txt
   ```
   
3. Make script executable if needed:

   ```
   chmod +x secrets_find0r.py
   ```

---

## Usage

```
./secrets_find0r.py
```

* On start it will prompt for:
  – Username (leave blank for anonymous)
  – Password (if username entered)
  – CIDR to scan (e.g. `192.168.1.0/24`)
  – Whether to include unknown or no-extension files
  – Optionally custom keywords
* The script will enumerate accessible shares, then scan candidate files, showing a progress bar
* Results are shown onscreen in a colored, aligned table, and saved to a file prefixed with the username (or `anon_`)

---

## Screenshot of Secrets Find0r in action
![Secrets Find0r in action](secrets_find0r_scanning.png)

---

## Output

* Console output: aligned ASCII table, matched tokens highlighted with red background
* File output: plain ASCII table, no color codes
* Example filename:

  ```
  userX_secrets_found_20250917_123456.txt
  ```
* Contents: columns: `Host | Share | Path | Match`
![Secrets Find0r in Demo-Output](secrets_find0r_output.png)

---

## Notes

* SMB shares that deny listPath or have tight permissions may hide files; may need sufficient permissions
* Deep directory trees may be large; `MAX_DIR_DEPTH` setting helps prevent runaway recursion.
* Large files truncated by `MAX_FILE_BYTES` setting
* Parser availability (PDF, legacy Office) depends on installed optional libraries (`PyPDF2`, `olefile`)

---

## Modification

* To change number of threads: adjust `THREADS_ENUM` and `THREADS_FILES` in the configuration section
* To adjust timeouts, file size caps, directory depth: modify corresponding constants at top of script
* To add new keywords or extensions: edit `KEYWORDS`, `SUPPORTED_EXTS`, `REGEX_PATTERNS`

---

## Disclaimer

Use only in environments where you have explicit authorization. The author is not responsible for misuse.

---
