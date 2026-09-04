ReCoongan

ReCoongan is an evidence-driven HTTP security reconnaissance scanner for pentesters, security engineers, and learners who want to quickly understand the public security posture of a web target.

It does not exploit targets. It collects observable evidence, analyzes common web security signals, and reports what is missing, weak, or worth reviewing.

 ____  _____  ____   ___ ====___  _   _   ____      _     _   _
|  _ \| ____|/ ___| /  _ \__/ _ \| \ | | / ___|    / \   | \ | |
| |_) |  _| | |    |  / \ || / \ |  \| || |  _    / _ \  |  \| |
|  _ <| |___| |___ |  \_/ || \_/ | |\  || |_| |  / ___ \ | |\  |
|_| \_\_____|\____| \____/==\___/|_| \_| \____| /_/   \_\|_| \_|

Current status

Version: 0.2.1

Package name: recoongan

CLI command: recoongan

Language: Python 3.10+

Main dependencies: httpx, rich, cryptography, dnspython

What ReCoongan Can Do

ReCoongan helps you inspect a target from multiple external reconnaissance angles:

Analyze HTTP security headers and grade the target from A to F

Detect missing or weak headers such as:

Strict-Transport-Security

Content-Security-Policy

X-Frame-Options

X-Content-Type-Options

Referrer-Policy

Permissions-Policy

Review redirects, cookies, and basic HTTP behavior

Check known web files such as:

robots.txt

sitemap.xml

security.txt

Discover URL candidates from public web resources

Probe common paths and extensions with a controlled wordlist

Inspect TLS configuration, certificate metadata, SAN entries, validity, and hostname matching

Discover hostname candidates from certificate data

Resolve DNS information and DNS records

Perform lightweight service checks

Save scan results as JSON for later review or reporting

Why This Tool Exists

ReCoongan is built for defensive reconnaissance.

It is useful when you want to answer questions like:

Is this web target using important browser security headers?

Are there obvious HTTP, TLS, DNS, or cookie issues?

What public files and URL candidates are exposed?

What hostnames or services are visible from outside?

What evidence should be reviewed before deeper manual testing?

Installation

git clone https://github.com/quarrcyber/ReCoongan.git
cd ReCoongan
python3 -m pip install -e .

Usage

Run a basic scan:

recoongan https://example.com

Run all available checks:

recoongan https://example.com --all

Run selected reconnaissance modules:

recoongan https://example.com --check-tls --dns --dns-records --known-files

Run content discovery with a wordlist:

recoongan https://example.com \
  --discover-paths wordlist-congan/wordlist.txt \
  --wordlist-limit 200 \
  -x php,html

Save the result as JSON:

recoongan https://example.com --all --save-report report.json

Output

ReCoongan prints a terminal report containing:

Overall security grade

Passed and failed checks

Evidence collected from the target

Security findings

Reconnaissance results

Optional JSON report output

The goal is to provide clear evidence, not guesswork.

Future Work

The current project is complete up to the planned 14 modules. Future improvements may include:

WAF / CDN / Edge Intelligence
Detect whether a target is protected by providers such as Cloudflare, Akamai, Fastly, AWS CloudFront, or similar edge platforms.

Scope / Budget Engine
Add stricter scan limits for safer reconnaissance, including request budgets, per-module caps, and clearer scope boundaries.

Better Reports
Improve exported reports with richer summaries, remediation notes, and possibly HTML output.

Rule / Plugin System
Allow checks to be extended without changing the core scanner logic.

Disclaimer

ReCoongan is intended for education, defensive security review, and authorized penetration testing. You are responsible for ensuring that every target you scan is within your legal and contractual scope.

License

No license file is included yet. Add a license before accepting external contributions or publishing the project as reusable open-source software.
