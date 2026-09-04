# RECOONGAN

**ReCoongan** is an evidence-driven HTTP security reconnaissance scanner for pentesters, security engineers, and learners.

It helps you quickly understand the public security posture of a web target by collecting observable evidence from HTTP, TLS, DNS, cookies, public files, and lightweight service signals.

ReCoongan does **not** exploit targets.
It only inspects externally visible security information and reports what is missing, weak, or worth reviewing.

---

## Current Status

| Item              | Value                                        |
| ----------------- | -------------------------------------------- |
| Version           | `0.2.1`                                      |
| Package           | `recoongan`                                  |
| CLI command       | `recoongan`                                  |
| Language          | Python 3.10+                                 |
| Main dependencies | `httpx`, `rich`, `cryptography`, `dnspython` |

---

## What ReCoongan Can Do

ReCoongan helps you inspect a web target from multiple reconnaissance angles.

### HTTP Security Headers

ReCoongan checks important browser security headers and grades the target from **A to F**.

It reviews headers such as:

* `Strict-Transport-Security`
* `Content-Security-Policy`
* `X-Frame-Options`
* `X-Content-Type-Options`
* `Referrer-Policy`
* `Permissions-Policy`

The goal is to identify missing, weak, or misconfigured security controls.

---

### Web Reconnaissance

ReCoongan can inspect common public web signals, including:

* Redirect behavior
* Cookie attributes
* `robots.txt`
* `sitemap.xml`
* `security.txt`
* Public URL candidates

This helps you understand what the target exposes before deeper manual testing.

---

### Content Discovery

ReCoongan supports controlled content discovery using a custom wordlist.

It can probe common paths and extensions while respecting configured limits such as rate, concurrency, and wordlist size.

Example use cases:

* Find exposed directories
* Identify interesting files
* Discover common application paths
* Review unexpected public resources

---

### TLS Intelligence

ReCoongan can inspect TLS and certificate information, including:

* TLS version
* Cipher information
* ALPN
* Certificate metadata
* Validity period
* Subject Alternative Names
* Hostname matching

This helps reveal certificate issues, exposed hostnames, and TLS configuration details.

---

### DNS and Hostname Reconnaissance

ReCoongan can collect DNS-related evidence, including:

* Hostname candidates from certificate data
* DNS resolution results
* DNS records
* Lightweight service checks

This provides a broader view of the target’s externally visible infrastructure.

---

### JSON Reporting

Scan results can be saved as JSON for later review, automation, or reporting.

This makes ReCoongan useful not only as a terminal tool, but also as a data source for security notes, audit logs, and future reporting workflows.

---

## Why Use ReCoongan?

ReCoongan is designed for defensive reconnaissance.

It helps answer practical questions such as:

* Is the target using important HTTP security headers?
* Are there obvious HTTP, TLS, DNS, or cookie issues?
* What public files are exposed?
* What URL candidates are visible?
* What hostnames can be discovered from certificate data?
* What evidence should be reviewed before manual testing?

ReCoongan focuses on **evidence**, not assumptions.

---

## Installation

```bash
git clone https://github.com/quarrcyber/ReCoongan.git
cd ReCoongan
python3 -m pip install -e .
```

---

## Usage

Run a basic scan:

```bash
recoongan https://example.com
```

Run all available checks:

```bash
recoongan https://example.com --all
```

Run selected modules:

```bash
recoongan https://example.com \
  --check-tls \
  --dns \
  --dns-records \
  --known-files
```

Run content discovery with a wordlist:

```bash
recoongan https://example.com \
  --discover-paths wordlist-congan/wordlist.txt \
  --wordlist-limit 200 \
  -x php,html
```

Save results as JSON:

```bash
recoongan https://example.com --all --save-report report.json
```

---

## Output

ReCoongan prints a clear terminal report containing:

* Overall security grade
* Passed and failed checks
* Collected evidence
* Security findings
* Reconnaissance results
* Optional JSON report output

The output is designed to be readable, reviewable, and useful during authorized security assessment.

---

## Future Work

The current project is complete up to the planned **14 modules**.

Future improvements may include:

### WAF / CDN / Edge Intelligence

Detect whether a target is protected by providers such as:

* Cloudflare
* Akamai
* Fastly
* AWS CloudFront
* Other CDN or edge platforms

---

### Scope / Budget Engine

Add stricter scan controls for safer reconnaissance, including:

* Request budgets
* Per-module limits
* Stronger rate boundaries
* Clearer scan scope enforcement

---

### Better Reports

Improve exported reports with:

* Richer summaries
* Remediation notes
* Cleaner JSON structure
* Possible HTML report output

---

### Rule / Plugin System

Allow checks to be extended without changing the core scanner logic.

This would make ReCoongan easier to grow over time as new checks, headers, and reconnaissance techniques are added.

---

## Ethical Use

ReCoongan is intended for:

* Education
* Defensive security review
* Authorized penetration testing
* Security learning and research

Only scan targets that you own or have explicit permission to test.

You are responsible for ensuring that every target is within your legal and contractual scope.

---

## License

No license file is included yet.

Add a license before accepting external contributions or publishing the project as reusable open-source software.
