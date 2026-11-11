# Mini Vulnerability Scanner

A simple Python script that scans a host for open ports, identifies risky services and outdated software versions, checks basic web server configuration, and generates a vulnerability report.

Built as an internship mini project to learn the fundamentals of vulnerability assessment and penetration testing.

> **Legal and ethical notice:** Only scan systems you own or have explicit written permission to test. Unauthorized scanning may be illegal. Safe practice targets: `127.0.0.1`, your own virtual machine, or `scanme.nmap.org` (light scanning permitted by the Nmap project).

---

## Features

| Feature | What it does |
|---|---|
| **Open port scan** | Multithreaded TCP connect scan of common ports or a custom range |
| **Banner grabbing** | Reads service banners to identify software and version |
| **Risky service detection** | Flags exposed services such as Telnet, FTP, SMB, RDP, Redis, MongoDB and databases |
| **Outdated version detection** | Compares detected versions (OpenSSH, Apache, nginx, vsftpd, ProFTPD) against a minimum-version table |
| **Weak HTTP configuration checks** | Missing security headers (CSP, X-Frame-Options, X-Content-Type-Options, HSTS), version disclosure, `X-Powered-By` exposure, plain HTTP |
| **Report generation** | Saves a Markdown report and a JSON report, sorted by severity (High, Medium, Low) |

---

## Requirements

- Python 3.8 or newer
- No third-party packages (standard library only)

---

## Usage

```bash
# Scan common ports on localhost
python3 vuln_scanner.py 127.0.0.1

# Scan a custom list or range of ports
python3 vuln_scanner.py 127.0.0.1 --ports 22,80,443,8080
python3 vuln_scanner.py scanme.nmap.org --ports 1-1024

# Choose the report file name
python3 vuln_scanner.py 127.0.0.1 --out my_report
```

### Options

| Option | Description | Default |
|---|---|---|
| `target` | IP address or hostname to scan | required |
| `--ports` | Ports, e.g. `22,80,443` or `1-1024` | common ports |
| `--timeout` | Connection timeout in seconds | `1.0` |
| `--threads` | Number of concurrent threads | `100` |
| `--out` | Output file prefix | `scan_report` |

---

## Example Output

Console:

```
[*] Scanning 127.0.0.1 (127.0.0.1) - 4 ports...
[+]  8080/tcp open  HTTP-Alt

[*] 5 finding(s). Reports saved: scan_report.md, scan_report.json
    [Medium] port 8080: Service served over plain HTTP
    [Low] port 8080: Missing security header: Content-Security-Policy
    [Low] port 8080: Missing security header: X-Frame-Options
    [Low] port 8080: Missing security header: X-Content-Type-Options
    [Low] port 8080: Server version disclosed: SimpleHTTP/0.6 Python/3.12.3
```

Generated report (`scan_report.md`):

```markdown
# Vulnerability Scan Report

- **Target:** 127.0.0.1
- **Open ports:** 1
- **Findings:** 0 High, 1 Medium, 4 Low

## Findings

### [Medium] Port 8080: Service served over plain HTTP
**Recommendation:** Redirect traffic to HTTPS.
```

---

## How It Works

1. **Port scan:** Opens a TCP connection to each port using a thread pool. A successful connection means the port is open.
2. **Banner grab:** Reads the service's greeting. For HTTP ports it sends a `HEAD` request first.
3. **Analysis:**
   - Checks open ports against a list of risky services.
   - Extracts software name and version from the banner with a regex and compares it to `MIN_VERSIONS`.
   - For HTTP/HTTPS ports, requests `/` and inspects the response headers.
4. **Report:** Sorts findings by severity and writes `.md` and `.json` files.

---

## Project Structure

```
.
├── vuln_scanner.py   # the scanner
└── README.md
```

---

## Testing It Yourself

To see the outdated-version detection in action, scan a deliberately vulnerable target in an **isolated** environment, for example:

- A VM running an older Apache, vsftpd or OpenSSH release
- [Metasploitable](https://sourceforge.net/projects/metasploitable/) or [DVWA](https://github.com/digininja/DVWA) on a host-only network

Quick local test with a simple web server:

```bash
python3 -m http.server 8080 --bind 127.0.0.1 &
python3 vuln_scanner.py 127.0.0.1 --ports 8080
```

---

## Limitations

- **Version table is illustrative.** `MIN_VERSIONS` should be updated from vendor advisories or the [NVD](https://nvd.nist.gov/) before relying on results.
- **Banner-based detection can be wrong.** Banners can be hidden or spoofed, and distributions often backport security patches without changing the version number, which causes false positives and false negatives.
- **No CVE matching.** The scanner compares versions only; it does not look up specific CVEs.
- **TCP only.** UDP services are not scanned.
- **No exploitation.** The tool only detects and reports; it never attempts to exploit anything.
- A clean report does **not** mean a system is secure.

---

## Future Improvements

- CVE lookup for detected versions using the NVD API
- TLS certificate expiry and weak cipher checks
- HTML report output
- Service detection beyond banner matching
- Configurable minimum-version file (JSON/YAML)

---

## What I Learned

- How TCP connect scanning and banner grabbing work
- How exposed services and weak HTTP headers increase attack surface
- The difference between vulnerability assessment (finding and reporting) and penetration testing (exploiting)
- Why scan results need manual verification

---

## Disclaimer

This project is for educational purposes only. The author is not responsible for misuse. Always obtain permission before scanning any system.
