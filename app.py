#!/usr/bin/env python3
"""Security Scan Dashboard.

A small Flask web app that runs a TCP port scan and basic web security
header checks against a target, then presents everything on one dashboard
page.

Only point this at systems you own or have explicit permission to test.
"""

import socket
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import requests
from flask import Flask, redirect, render_template_string, request, url_for

app = Flask(__name__)

# Top 100 most commonly seen TCP ports.
TOP_PORTS = [
    21, 22, 23, 25, 53, 69, 79, 80, 88, 110, 111, 119, 123, 135, 137,
    138, 139, 143, 161, 162, 179, 194, 220, 389, 443, 445, 465, 514,
    515, 548, 554, 587, 593, 636, 646, 691, 873, 993, 995, 1080, 1433,
    1434, 1521, 1723, 1755, 1900, 2049, 2082, 2083, 2086, 2087, 2095,
    2096, 2100, 2222, 2375, 2376, 2483, 2484, 3000, 3128, 3268, 3306,
    3389, 3443, 3632, 4369, 5060, 5061, 5432, 5672, 5900, 5901, 5985,
    5986, 6379, 6443, 6660, 6667, 8000, 8008, 8010, 8022, 8080, 8081,
    8088, 8090, 8181, 8443, 8888, 9000, 9001, 9090, 9100, 9200, 9300,
    11211, 27017, 27018, 50000,
]

SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    69: "tftp", 79: "finger", 80: "http", 88: "kerberos", 110: "pop3",
    111: "rpcbind", 119: "nntp", 123: "ntp", 135: "msrpc",
    137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 162: "snmptrap", 179: "bgp", 194: "irc",
    220: "imap3", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    514: "syslog", 515: "printer", 548: "afp", 554: "rtsp",
    587: "submission", 593: "http-rpc", 636: "ldaps", 646: "ldp",
    691: "resvc", 873: "rsync", 993: "imaps", 995: "pop3s",
    1080: "socks", 1433: "mssql", 1434: "mssql-monitor", 1521: "oracle",
    1723: "pptp", 1755: "ms-streaming", 1900: "upnp", 2049: "nfs",
    2082: "cpanel", 2083: "cpanel-ssl", 2086: "whm", 2087: "whm-ssl",
    2095: "webmail", 2096: "webmail-ssl", 2100: "amiganetfs",
    2222: "ssh-alt", 2375: "docker", 2376: "docker-ssl",
    2483: "oracle-ssl", 2484: "oracle-ssl", 3000: "dev-server",
    3128: "squid", 3268: "ad-global-catalog", 3306: "mysql",
    3389: "rdp", 3443: "https-alt", 3632: "distcc", 4369: "epmd",
    5060: "sip", 5061: "sip-tls", 5432: "postgres", 5672: "rabbitmq",
    5900: "vnc", 5901: "vnc-1", 5985: "winrm", 5986: "winrm-ssl",
    6379: "redis", 6443: "k8s-api", 6660: "irc", 6667: "irc",
    8000: "http-alt", 8008: "http-alt", 8010: "http-alt",
    8022: "http-alt", 8080: "http-proxy", 8081: "http-alt",
    8088: "http-alt", 8090: "http-alt", 8181: "http-alt",
    8443: "https-alt", 8888: "http-alt", 9000: "http-alt",
    9001: "http-alt", 9090: "http-alt", 9100: "printer",
    9200: "elasticsearch", 9300: "elasticsearch", 11211: "memcached",
    27017: "mongodb", 27018: "mongodb", 50000: "db2",
}

# In-memory scan store. Fine for a demo; a real app would use a database.
scans = {}


def check_port(ip, port, timeout=1.0):
    """Try one TCP connect. Returns a dict if open, None if closed."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return None
    banner = ""
    try:
        # Short separate read timeout: some services wait for us to speak first.
        sock.settimeout(1.5)
        chunk = sock.recv(1024)
        if chunk:
            banner = chunk.decode("utf-8", errors="replace").strip().splitlines()[0][:120]
    except OSError:
        pass
    finally:
        sock.close()
    return {
        "port": port,
        "service": SERVICE_NAMES.get(port, "unknown"),
        "banner": banner,
    }


def header_finding(severity, title, detail, why):
    return {"severity": severity, "title": title, "detail": detail, "why": why}


def check_web(host, port):
    """Fetch the site and check security headers and cookie flags.

    Returns (findings, scanned_url). findings is a list of dicts.
    """
    findings = []
    scanned_url = None
    response = None

    if port:
        candidates = [("https", port)] if port == 443 else [("http", port)]
    else:
        candidates = [("https", 443), ("http", 80)]

    for scheme, p in candidates:
        url = "%s://%s:%d" % (scheme, host, p)
        try:
            response = requests.get(
                url, timeout=8, headers={"User-Agent": "security-dashboard/1.0"}
            )
            scanned_url = url
            break
        except requests.RequestException:
            continue

    if response is None:
        findings.append(header_finding(
            "info", "No web server responded",
            "Neither HTTPS nor HTTP answered on %s." % host,
            "Nothing to check on the web side. The port scan results above are still valid.",
        ))
        return findings, scanned_url

    scheme = scanned_url.split("://")[0]
    headers = response.headers

    checks = [
        ("Content-Security-Policy", "medium",
         "The main defense against cross-site scripting. It controls which sources "
         "can load scripts and other resources. Without it, a single injected "
         "script can run with full page privileges."),
        ("X-Frame-Options", "low",
         "Keeps the page out of other sites' iframes. Without it, an attacker can "
         "embed the page invisibly and trick users into clicking things they "
         "cannot see, which is called clickjacking."),
        ("X-Content-Type-Options", "low",
         "The nosniff directive stops browsers from guessing content types. That "
         "blocks a class of attacks that smuggle scripts inside innocent-looking files."),
        ("Referrer-Policy", "info",
         "Controls how much of the URL leaks into the Referer header on outgoing "
         "links. Without it, tokens or IDs sitting in URLs can leak to third parties."),
    ]
    for name, severity, why in checks:
        if name not in headers:
            findings.append(header_finding(
                severity, "Missing %s header" % name,
                "Response from %s does not include this header." % scanned_url,
                why,
            ))

    if scheme == "https":
        if "Strict-Transport-Security" not in headers:
            findings.append(header_finding(
                "medium", "Missing Strict-Transport-Security header",
                "Response from %s does not include this header." % scanned_url,
                "HSTS tells browsers to only ever use HTTPS for this site, which "
                "blocks SSL stripping attacks.",
            ))
    else:
        findings.append(header_finding(
            "info", "Site served over plain HTTP",
            "The scan reached %s over unencrypted HTTP." % scanned_url,
            "HSTS and the Secure cookie flag only apply once HTTPS is in place. "
            "Anything sensitive on this site is traveling in the clear.",
        ))

    try:
        set_cookies = response.raw.headers.getlist("Set-Cookie")
    except Exception:
        set_cookies = []

    if not set_cookies:
        findings.append(header_finding(
            "info", "No cookies set",
            "The response did not set any cookies.",
            "Nothing to audit here. If the app sets cookies on other pages, check those too.",
        ))
    else:
        for sc in set_cookies:
            name = sc.split("=", 1)[0].strip()[:40] or "(unnamed)"
            lowered = sc.lower()
            if "httponly" not in lowered:
                findings.append(header_finding(
                    "low", "Cookie without HttpOnly flag: %s" % name,
                    "The Set-Cookie header for '%s' is missing the HttpOnly flag." % name,
                    "HttpOnly keeps JavaScript from reading the cookie, which limits "
                    "what a cross-site scripting attack can steal.",
                ))
            if "samesite" not in lowered:
                findings.append(header_finding(
                    "info", "Cookie without SameSite attribute: %s" % name,
                    "The Set-Cookie header for '%s' does not set SameSite." % name,
                    "SameSite controls whether the cookie is sent on cross-site "
                    "requests, which is the main lever against cross-site request forgery.",
                ))
            if scheme == "https" and "secure" not in lowered:
                findings.append(header_finding(
                    "medium", "Cookie without Secure flag: %s" % name,
                    "The Set-Cookie header for '%s' is missing the Secure flag." % name,
                    "Without Secure, the browser may send this cookie over plain HTTP, "
                    "where anyone on the network can read it.",
                ))

    return findings, scanned_url


def do_scan(scan_id, host, ip, web_port):
    """Run the full scan in a background thread and store the result."""
    entry = scans[scan_id]
    try:
        open_ports = []
        with ThreadPoolExecutor(max_workers=50) as pool:
            futures = [pool.submit(check_port, ip, p) for p in TOP_PORTS]
            for future in futures:
                result = future.result()
                if result:
                    open_ports.append(result)
        open_ports.sort(key=lambda r: r["port"])
        entry["open_ports"] = open_ports

        findings, scanned_url = check_web(host, web_port)
        entry["findings"] = findings
        entry["scanned_url"] = scanned_url or "n/a"
        entry["status"] = "done"
    except Exception as exc:  # never leave the UI hanging on "scanning..."
        entry["status"] = "error"
        entry["error"] = str(exc)
    entry["finished"] = time.time()


def parse_target(raw):
    """Accept 'host' or 'host:port'. Returns (host, port_or_None, error_or_None)."""
    raw = (raw or "").strip()
    if not raw:
        return None, None, "Enter a target first."
    if "://" in raw:
        return None, None, "Just the hostname or IP, no http:// prefix needed."
    if raw.count(":") == 1 and not raw.startswith("["):
        host, port_s = raw.rsplit(":", 1)
        try:
            port = int(port_s)
        except ValueError:
            return None, None, "That port does not look like a number."
        if not 1 <= port <= 65535:
            return None, None, "Port must be between 1 and 65535."
        if not host:
            return None, None, "Enter a hostname or IP before the colon."
        return host, port, None
    return raw, None, None


CSS = """
body { background: #0d1117; color: #e6edf3;
       font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
       margin: 0; }
.wrap { max-width: 920px; margin: 0 auto; padding: 32px 20px 60px; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
        padding: 20px; margin-bottom: 20px; }
h1 { font-size: 28px; margin: 0 0 8px; }
h2 { font-size: 20px; margin: 0 0 12px; }
.sub { color: #8b949e; margin-top: 0; }
input[type=text] { width: 100%; box-sizing: border-box; padding: 12px;
                   background: #0d1117; color: #e6edf3;
                   border: 1px solid #30363d; border-radius: 6px; font-size: 15px; }
button { background: #1f6feb; color: #fff; border: none; padding: 12px 24px;
         border-radius: 6px; font-size: 15px; cursor: pointer; margin-top: 12px; }
button:hover { background: #388bfd; }
.warning { background: #3a2c00; border: 1px solid #9e6a03; color: #ffdf5d;
           border-radius: 6px; padding: 12px 16px; margin-bottom: 20px; font-size: 14px; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #30363d; }
th { color: #8b949e; font-weight: 600; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.stats { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 20px; }
.stat { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
        padding: 14px 18px; min-width: 110px; }
.stat .num { font-size: 26px; }
.stat .lbl { color: #8b949e; font-size: 13px; }
.finding { border-left: 4px solid #30363d; padding: 10px 14px; margin-bottom: 12px;
           background: #0d1117; border-radius: 0 6px 6px 0; }
.finding.high { border-color: #f85149; }
.finding.medium { border-color: #d29922; }
.finding.low { border-color: #a371f7; }
.finding.info { border-color: #388bfd; }
.pill { display: inline-block; padding: 2px 10px; border-radius: 12px;
        font-size: 12px; margin-right: 8px; vertical-align: middle; }
.pill.high { background: #5a1f1f; color: #ff7b72; }
.pill.medium { background: #5a3d1a; color: #e3b341; }
.pill.low { background: #3d2f5a; color: #bc8cff; }
.pill.info { background: #1a3a5a; color: #79c0ff; }
.finding .title { font-size: 15px; }
.finding .detail { color: #8b949e; font-size: 13px; margin: 6px 0; }
.finding .why { font-size: 13px; margin: 0; }
a { color: #58a6ff; }
.foot { color: #8b949e; font-size: 13px; margin-top: 30px; }
"""

HOME_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Security Scan Dashboard</title>
<style>{{ css }}</style></head>
<body><div class="wrap">
<h1>Security Scan Dashboard</h1>
<p class="sub">Enter a target to scan its common ports and check its web security headers.</p>
<div class="warning">Only scan systems you own or have explicit permission to test.
Scanning someone else's systems without permission can get you in real legal trouble.</div>
<div class="card">
<form method="post" action="/scan">
<input type="text" name="target" placeholder="example.com  or  192.168.1.10  or  example.com:8080" autofocus>
<button type="submit">Start scan</button>
</form>
</div>
<p class="foot">Runs a TCP connect scan across the top 100 ports plus checks for
Content-Security-Policy, HSTS, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, and cookie flags. Built as a portfolio project.</p>
</div></body></html>
"""

SCANNING_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><meta http-equiv="refresh" content="2">
<title>Scanning...</title><style>{{ css }}</style></head>
<body><div class="wrap">
<h1>Scanning {{ target }} ...</h1>
<p class="sub">The port scan and header checks are running in the background.
This page refreshes automatically.</p>
</div></body></html>
"""

RESULTS_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Results for {{ target }}</title>
<style>{{ css }}</style></head>
<body><div class="wrap">
<h1>Scan results: {{ target }}</h1>
<p class="sub">Finished in {{ elapsed }} seconds.
<a href="/">Scan again</a></p>

<div class="stats">
<div class="stat"><div class="num">{{ open_ports|length }}</div><div class="lbl">open ports</div></div>
<div class="stat"><div class="num">{{ counts.high }}</div><div class="lbl">high</div></div>
<div class="stat"><div class="num">{{ counts.medium }}</div><div class="lbl">medium</div></div>
<div class="stat"><div class="num">{{ counts.low }}</div><div class="lbl">low</div></div>
<div class="stat"><div class="num">{{ counts.info }}</div><div class="lbl">info</div></div>
</div>

<div class="card">
<h2>Open ports</h2>
{% if open_ports %}
<table><tr><th>Port</th><th>Service</th><th>Banner</th></tr>
{% for p in open_ports %}
<tr><td class="mono">{{ p.port }}</td><td class="mono">{{ p.service }}</td>
<td class="mono">{{ p.banner }}</td></tr>
{% endfor %}
</table>
{% else %}
<p class="sub">No open ports found in the top 100.</p>
{% endif %}
</div>

<div class="card">
<h2>Web findings{% if scanned_url != "n/a" %} <span class="sub mono" style="font-size:13px">{{ scanned_url }}</span>{% endif %}</h2>
{% for f in findings %}
<div class="finding {{ f.severity }}">
<span class="pill {{ f.severity }}">{{ f.severity }}</span>
<span class="title">{{ f.title }}</span>
<p class="detail">{{ f.detail }}</p>
<p class="why">{{ f.why }}</p>
</div>
{% endfor %}
</div>

<p class="foot"><a href="/">Scan again</a></p>
</div></body></html>
"""

ERROR_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Error</title><style>{{ css }}</style></head>
<body><div class="wrap">
<h1>Something went wrong</h1>
<p>{{ message }}</p>
<p><a href="/">Back</a></p>
</div></body></html>
"""


@app.route("/", methods=["GET"])
def index():
    return render_template_string(HOME_PAGE, css=CSS)


@app.route("/scan", methods=["POST"])
def start_scan():
    raw = request.form.get("target", "")
    host, web_port, error = parse_target(raw)
    if error:
        return render_template_string(ERROR_PAGE, css=CSS, message=error)
    try:
        ip = socket.gethostbyname(host)
    except OSError:
        return render_template_string(
            ERROR_PAGE, css=CSS, message="Could not resolve host: %s" % host
        )
    scan_id = uuid.uuid4().hex[:8]
    scans[scan_id] = {
        "status": "running",
        "target": raw.strip(),
        "started": time.time(),
    }
    thread = threading.Thread(
        target=do_scan, args=(scan_id, host, ip, web_port), daemon=True
    )
    thread.start()
    return redirect(url_for("scanning", scan_id=scan_id))


@app.route("/scanning/<scan_id>")
def scanning(scan_id):
    entry = scans.get(scan_id)
    if not entry:
        return render_template_string(ERROR_PAGE, css=CSS, message="Unknown scan.")
    if entry["status"] == "done":
        return redirect(url_for("results", scan_id=scan_id))
    if entry["status"] == "error":
        return render_template_string(
            ERROR_PAGE, css=CSS, message="Scan failed: %s" % entry.get("error", "?")
        )
    return render_template_string(SCANNING_PAGE, css=CSS, target=entry["target"])


@app.route("/results/<scan_id>")
def results(scan_id):
    entry = scans.get(scan_id)
    if not entry or entry["status"] != "done":
        return redirect(url_for("scanning", scan_id=scan_id))
    findings = entry["findings"]
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        counts[finding["severity"]] += 1
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings_sorted = sorted(findings, key=lambda f: order[f["severity"]])
    elapsed = round(entry["finished"] - entry["started"], 1)
    return render_template_string(
        RESULTS_PAGE,
        css=CSS,
        target=entry["target"],
        elapsed=elapsed,
        open_ports=entry["open_ports"],
        findings=findings_sorted,
        counts=counts,
        scanned_url=entry["scanned_url"],
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
