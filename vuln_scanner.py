#!/usr/bin/env python3
"""
Mini Vulnerability Scanner (educational project)

Features:
  1. Scan for open ports and flag risky services / weak HTTP configuration
  2. Identify outdated software versions from service banners
  3. Generate a simple vulnerability report (Markdown + JSON)

ONLY scan systems you own or have explicit written permission to test.
Safe practice targets: 127.0.0.1, your own VM, or scanme.nmap.org
(Nmap allows light scanning of that host).

Usage:
  python3 vuln_scanner.py 127.0.0.1
  python3 vuln_scanner.py scanme.nmap.org --ports 1-1024
  python3 vuln_scanner.py 127.0.0.1 --ports 22,80,443,8080 --out my_report
"""
import argparse
import datetime
import http.client
import json
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor

# ----------------------------- Configuration ------------------------------

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}

# port -> (severity, explanation)
RISKY_PORTS = {
    21: ("Medium", "FTP sends credentials in plaintext. Use SFTP/FTPS instead."),
    23: ("High", "Telnet is unencrypted and obsolete. Use SSH instead."),
    445: ("High", "SMB exposed. Restrict to internal networks / firewall it."),
    3306: ("Medium", "MySQL reachable over the network. Bind to localhost or firewall it."),
    3389: ("Medium", "RDP exposed. Put it behind a VPN and enable NLA."),
    5432: ("Medium", "PostgreSQL reachable over the network. Restrict access."),
    6379: ("High", "Redis often runs without authentication. Restrict and set a password."),
    27017: ("High", "MongoDB exposed. Make sure authentication is enabled and restrict access."),
}

# Minimum "acceptable" versions. These are ILLUSTRATIVE: update them from
# vendor advisories / CVE databases (nvd.nist.gov) before relying on them.
MIN_VERSIONS = {
    "OpenSSH": (9, 0),
    "Apache": (2, 4, 58),
    "nginx": (1, 24, 0),
    "vsftpd": (3, 0, 3),
    "ProFTPD": (1, 3, 8),
}

SECURITY_HEADERS = {
    "Content-Security-Policy": "Helps prevent XSS and data injection.",
    "X-Frame-Options": "Protects against clickjacking.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing.",
}

BANNER_RE = re.compile(
    r"(OpenSSH|Apache|nginx|vsftpd|ProFTPD)[_/ ](\d+(?:\.\d+)*)", re.IGNORECASE
)

# ------------------------------- Scanning ---------------------------------


def parse_ports(spec):
    """Turn '22,80,100-200' into a sorted list of ints."""
    if not spec:
        return sorted(COMMON_PORTS)
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-")
            ports.update(range(int(a), int(b) + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


def grab_banner(host, port, timeout):
    """Connect and try to read a service banner."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in (80, 8080, 8000):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            try:
                return s.recv(1024).decode(errors="ignore").strip()
            except (socket.timeout, OSError):
                return ""
    except OSError:
        return None  # None = port closed / unreachable


def scan_port(host, port, timeout):
    banner = grab_banner(host, port, timeout)
    if banner is None:
        return None
    return {"port": port, "service": COMMON_PORTS.get(port, "unknown"), "banner": banner}


def version_tuple(text):
    return tuple(int(x) for x in text.split("."))


def check_outdated(banner):
    """Return (software, found_version, minimum) if the banner shows an old version."""
    m = BANNER_RE.search(banner or "")
    if not m:
        return None
    name = next((k for k in MIN_VERSIONS if k.lower() == m.group(1).lower()), None)
    if not name:
        return None
    found = version_tuple(m.group(2))
    if found < MIN_VERSIONS[name]:
        return name, m.group(2), ".".join(map(str, MIN_VERSIONS[name]))
    return None


def check_http(host, port, timeout, use_ssl):
    """Inspect an HTTP(S) service for weak configuration."""
    findings = []
    try:
        if use_ssl:
            ctx = ssl._create_unverified_context()  # we only inspect headers
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("GET", "/")
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
    except Exception:
        return findings

    for h, why in SECURITY_HEADERS.items():
        if h.lower() not in headers:
            findings.append(("Low", port, f"Missing security header: {h}", why))
    if use_ssl and "strict-transport-security" not in headers:
        findings.append(("Low", port, "Missing security header: Strict-Transport-Security",
                         "Forces browsers to use HTTPS."))
    server = headers.get("server", "")
    if re.search(r"\d+\.\d+", server):
        findings.append(("Low", port, f"Server version disclosed: {server}",
                         "Hide version info to make fingerprinting harder."))
    if "x-powered-by" in headers:
        findings.append(("Low", port, f"X-Powered-By header exposed: {headers['x-powered-by']}",
                         "Remove this header."))
    if not use_ssl:
        findings.append(("Medium", port, "Service served over plain HTTP",
                         "Redirect traffic to HTTPS."))
    return findings


def analyse(host, open_ports, timeout):
    """Turn raw scan results into a list of findings."""
    findings = []  # (severity, port, issue, recommendation)
    for p in open_ports:
        port = p["port"]
        if port in RISKY_PORTS:
            sev, msg = RISKY_PORTS[port]
            findings.append((sev, port, f"Risky service exposed: {p['service']}", msg))

        old = check_outdated(p["banner"])
        if old:
            name, found, minimum = old
            findings.append(("High", port, f"Outdated {name} {found} (recommended >= {minimum})",
                             f"Upgrade {name} and review its CVEs."))

        if port in (80, 8080, 8000):
            findings += check_http(host, port, timeout, use_ssl=False)
        elif port in (443, 8443):
            findings += check_http(host, port, timeout, use_ssl=True)

    order = {"High": 0, "Medium": 1, "Low": 2}
    return sorted(findings, key=lambda f: (order[f[0]], f[1]))


# ------------------------------- Reporting --------------------------------


def build_report(host, open_ports, findings):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    counts = {s: sum(1 for f in findings if f[0] == s) for s in ("High", "Medium", "Low")}

    md = [f"# Vulnerability Scan Report", "",
          f"- **Target:** {host}", f"- **Date:** {now}",
          f"- **Open ports:** {len(open_ports)}",
          f"- **Findings:** {counts['High']} High, {counts['Medium']} Medium, {counts['Low']} Low",
          "", "## Open Ports", "", "| Port | Service | Banner |", "|---|---|---|"]
    for p in open_ports:
        banner = p["banner"].splitlines()[0][:60] if p["banner"] else "-"
        md.append(f"| {p['port']} | {p['service']} | {banner} |")

    md += ["", "## Findings", ""]
    if not findings:
        md.append("No issues detected by this basic scan (this does not mean the target is secure).")
    for sev, port, issue, rec in findings:
        md += [f"### [{sev}] Port {port}: {issue}", f"**Recommendation:** {rec}", ""]
    md += ["---", "*Basic educational scan. Results can include false positives/negatives.*"]

    data = {
        "target": host, "date": now, "open_ports": open_ports,
        "summary": counts,
        "findings": [{"severity": s, "port": p, "issue": i, "recommendation": r}
                     for s, p, i, r in findings],
    }
    return "\n".join(md), data


# --------------------------------- Main -----------------------------------


def main():
    ap = argparse.ArgumentParser(description="Mini vulnerability scanner (authorized use only)")
    ap.add_argument("target", help="IP or hostname you are allowed to scan")
    ap.add_argument("--ports", help="e.g. 22,80,443 or 1-1024 (default: common ports)")
    ap.add_argument("--timeout", type=float, default=1.0)
    ap.add_argument("--threads", type=int, default=100)
    ap.add_argument("--out", default="scan_report", help="output file prefix")
    args = ap.parse_args()

    try:
        host = socket.gethostbyname(args.target)
    except socket.gaierror:
        raise SystemExit(f"Cannot resolve {args.target}")

    ports = parse_ports(args.ports)
    print(f"[*] Scanning {args.target} ({host}) - {len(ports)} ports...")

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        results = pool.map(lambda p: scan_port(host, p, args.timeout), ports)
        open_ports = [r for r in results if r]

    for p in open_ports:
        print(f"[+] {p['port']:>5}/tcp open  {p['service']}")

    findings = analyse(host, open_ports, args.timeout)
    markdown, data = build_report(args.target, open_ports, findings)

    with open(f"{args.out}.md", "w") as f:
        f.write(markdown)
    with open(f"{args.out}.json", "w") as f:
        json.dump(data, f, indent=2)

    print(f"\n[*] {len(findings)} finding(s). Reports saved: {args.out}.md, {args.out}.json")
    for sev, port, issue, _ in findings:
        print(f"    [{sev}] port {port}: {issue}")


if __name__ == "__main__":
    main()
