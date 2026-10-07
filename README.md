# security-dashboard

A Flask web app that puts a dashboard on top of network scanning. Type in a
target, get back open ports and web security findings on one page, with
severity labels and plain-English explanations for each finding.

## Why I built this

My other scanner projects are all command line, which is fine for me, but I
wanted to build something another person could actually use without touching
a terminal. A dashboard also demos better. If someone clicks one link from
my portfolio, I would rather it be this than a terminal screenshot.

It also forced me to learn Flask basics: routes, templates, and how to keep
a web request from hanging while a scan runs in the background.

## What it does

- Takes a hostname or IP, with an optional port (like example.com:8080),
  and runs two checks against it
- Threaded TCP connect scan across the top 100 common ports, with banner
  grabbing where the service talks first
- Web security header checks: Content-Security-Policy, Strict-Transport-
  Security, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
  plus cookie flag checks (HttpOnly, Secure, SameSite)
- Results dashboard with summary counts, an open-ports table, and findings
  grouped by severity, each with a plain-English explanation
- Scans run in a background thread so the page never hangs. The scanning
  page auto-refreshes until the results are ready
- Big warning banner on the front page: only scan what you are allowed to scan

## How to run it

```bash
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000 in a browser, type in a target, and hit
Start scan.

## What tripped me up

Getting cookie flags out of requests, again. I hit this same wall on the
web security scanner: the flags live on the raw urllib3 response, not on
the nice cookie objects requests gives you. This time I went straight for
response.raw.headers.getlist("Set-Cookie") instead of losing another hour.

The other thing was the background thread. My first version ran the whole
scan inside the request handler, so Flask just sat there until the scan
finished and the browser timed out on slower targets. Moving the scan to a
thread with a status page that refreshes itself was not hard once I stopped
overthinking it. The scan results live in an in-memory dict keyed by a scan
ID, which is fine for a demo and would be the first thing to replace in a
real deployment.

## What I'd do differently

- A real database instead of an in-memory dict, so scan history survives a
  restart and multiple workers can share it
- Authentication and rate limiting. Right now anyone who can reach the app
  can point it at anything, which is why the warning banner is there, but a
  banner is not a control
- Charts. Counts are fine, but a timeline showing how a target's open ports
  change across repeated scans would be more useful
- Smarter service detection instead of just banner grabbing. Right now a
  weird banner means "unknown," and that is honest but not helpful

## A note on using this

Only scan systems you own or have explicit permission to test. I built this
to learn Flask and to scan my own lab. Pointing it at someone else's network
without permission can get you in real legal trouble, and it is just not
worth it.
