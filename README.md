# Recon Pipeline

A staged Python orchestrator for **authorized** penetration tests and bug-bounty scopes. It uses installed best-of-breed tools, normalizes their output into SQLite, preserves raw evidence, shows live stage progress, and produces a self-contained dark-mode HTML report.

After crawling, the pipeline inspects in-scope HTML, JavaScript, JSON, XML, source maps and other text resources for exposed credentials. Provider-specific formats, private keys, JWTs, database URLs and secret assignments are detected with regex plus entropy/context checks. Evidence is fingerprinted and redacted before it is written to disk. Likely Base64, URL-encoded, hexadecimal, JWT, and hash artifacts are classified with bundled `bin/ducky-ana`; encodings receive bounded decoded analysis while hashes are identified but never cracked.

WHOIS and structured RDAP registration data are normalized into the report. Recon-ng enriches hosts through a bounded, no-key module set (certificate transparency, HackerTarget, ThreatMiner, MX/SPF) using an isolated per-run workspace. The deep profile ranks and deduplicates parameterized endpoints before bounded XSS checks with Dalfox and XSStrike and conservative SQL injection detection with sqlmap. HTML forms are inventoried; only idempotent in-scope GET fields receive automatic inert reflection canaries. Password, token, file, checkout, and state-changing inputs are excluded.

## Quick start

Clone the repository and run the idempotent bootstrap. It creates the Python
environment, downloads pinned third-party repositories into ignored `tools/`,
and builds the supported Go tools into `tools/bin/`:

```bash
python3 setup.py
```

The installer never deletes or replaces `results/`, `instance/`, or an existing
`.env`. It does not use `sudo`; install any OS commands reported by
`python3 setup.py status` with the system package manager. Re-running the
installer is safe and skips existing clones and binaries.

It also skips Python package installation when the requirements and tool source
have not changed. To deliberately repair or rebuild everything, run
`python3 setup.py --force`.

```bash
venv/bin/python recon_pipeline.py example.com --i-have-authorization --profile standard
```

For deeper, noisier enumeration (top 1,000 ports, Nuclei and recursive `ffuf`):

```bash
venv/bin/python recon_pipeline.py example.com --i-have-authorization --profile deep \
  --rate 50 --concurrency 30 --depth 4
```

Results are written to `results/<domain>-<timestamp>/` with `report.html`, `recon.sqlite3`, `summary.json`, raw tool output, and exact command metadata. A failed optional tool is recorded and the rest of the run continues.

## Web application

The included web console adds authenticated target management, persistent scan queues, live log progress, and result pages backed by each scan's SQLite database.

1. Edit `.env` and replace `ADMIN_PASSWORD` and `FLASK_SECRET_KEY`. Keep `WEB_HOST=127.0.0.1` unless the application is placed behind an authenticated HTTPS reverse proxy.
2. Start the console with the same virtual environment used by the scanner:

```bash
venv/bin/python webapp.py
```

3. Open `http://127.0.0.1:8080` and sign in with the credentials from `.env`.

Adding one or more targets automatically creates background scan jobs. Jobs are processed one at a time to avoid multiplying load against target infrastructure; browser requests remain responsive while scans run. Once a scan completes, its target page offers a downloadable Markdown report containing the complete normalized recon inventory. Control data is stored in `instance/control.sqlite3`, logs in `instance/logs/`, and per-job evidence under `results/web/`. A service restart preserves queued jobs and marks an interrupted running job as failed so it can be deliberately requeued.

Every submission requires confirmation of written authorization. The default binding is local-only, sessions are HTTP-only and same-site, POST requests use CSRF tokens, scanner commands never invoke a shell, and web credentials are removed from scanner subprocess environments. For remote deployment, keep exactly one background worker (or move it into a dedicated service), place the web process behind an HTTPS reverse proxy, and set `SESSION_COOKIE_SECURE=true`.

## Profiles

- `passive`: passive `ducky-subs` sources plus DNS resolution; it sends no HTTP requests to the target.
- `standard`: adds WHOIS/Recon-ng OSINT, active Gobuster DNS enumeration, a restrained top-100 port scan, service fingerprinting, crawling, FFUF content discovery and exposure analysis.
- `deep`: active Gobuster DNS enumeration, full-range TCP scanning, detailed service fingerprinting, historical host/URL recovery, JavaScript endpoint mining, layered takeover checks, Nuclei, recursive content discovery, and bounded XSS/SQLi detection. Use only where the engagement explicitly permits active vulnerability testing.

Useful controls include `--skip nuclei,ffuf`, `--wordlist PATH`, `--max-urls`, `--rate`, `--concurrency`, and `--timeout`. The bundled web-discovery wordlist is selected automatically.

Standard and deep scans use the bundled `bin/ffuf` and `wordlists/web-discovery-common.txt` first. Content discovery runs sequentially against every distinct live in-scope HTTP origin found across the apex domain and its active subdomains, so `--rate` remains the exact per-target FFUF request ceiling. Recursion follows `--depth`; per-host auto-calibration suppresses wildcard/error-page noise, and only 2xx, useful redirects, authentication/authorization responses, and HTTP 405 results are added to the endpoint inventory. Every service receives a separate raw FFUF output file.

Before bulk DNS resolution, standard and deep scans run bundled `bin/gobuster` against `wordlists/subdomains-top1million-5000.txt`. Gobuster validates each candidate through DNS and checks CNAMEs; valid hosts and their A, AAAA and CNAME answers are normalized into the shared inventory before takeover, port and HTTP stages. Worker count and per-worker delay are derived from `--concurrency` and `--rate` to keep aggregate DNS pressure bounded. Wildcard DNS is not forced, preventing wildcard zones from filling the report with false subdomains.

Deep scans pass every resolved IPv4 and IPv6 address to Nmap with `-p-`, covering TCP ports 1–65535. A non-privileged connect scan performs version-intensity 7 service detection and bounded default scripts; `--max-rate` follows the configured scan rate, retries are limited, and each host has a 45-minute ceiling. Nmap-only port discoveries are inserted rather than discarded. State/reason, product, version, extra information, CPE identifiers, and script evidence are normalized into SQLite and displayed by IP in the target page's **Infrastructure** tab. Full-range scans can take substantially longer at low request rates.

Exposure scanning is bounded by `--secret-max-files` (default 2,000) and `--secret-max-bytes` (default 2 MB per resource). Findings are leads: confirm validity without attempting to use discovered credentials, then revoke/rotate confirmed secrets.

Deep active checks are bounded by `--active-max-urls` (default 25) and `--active-delay` (default 0.5 seconds). Candidate URLs are collapsed by host, path and parameter signature; secret-bearing query strings are excluded. sqlmap is restricted to detection-only `level=1`, `risk=1`, one thread, and does not enumerate or extract database contents. Disable modules with `--skip`, for example `--skip gobuster,waybackurls,jsminer,subjack,dalfox,xsstrike,sqlmap`.

The deep profile runs bundled WaybackURLs before DNS resolution so historical in-scope hosts re-enter the live resolution and HTTP-probing flow. Archived JavaScript, source maps, structured files, and parameterized URLs are prioritized within a bounded archive budget, leaving inventory capacity for live crawling. After Katana, GAU and FFUF contribute current endpoints, bundled JSMiner analyzes up to 1,000 discovered JavaScript files for additional in-scope endpoints. Browser rendering, external imports and insecure TLS are disabled to keep that stage bounded and scope-safe.

Technology analysis combines HTTPX's Wappalyzer fingerprints, web-server headers, CDN/WAF detection and WhatWeb. Deep scans use WhatWeb aggression level 3 with one rate-delayed worker for stronger version and framework detection without unbounded request bursts. The target page's **Tech stacks** tab normalizes these signals, removes metadata-only plugins, and groups technologies, versions and services by apex domain or subdomain.

Before deep vulnerability checks, the pipeline explicitly checks for the latest released Nuclei community templates. It then runs both the general safe template set and a second Wappalyzer-driven automatic scan that selects technology-relevant templates. The **Tech stacks** tab correlates medium-or-higher host findings, CVE identifiers and product-specific template matches with detected versions. A version without a matching finding is deliberately labeled **Version detected**, never “safe” or “up to date”; automated matches still require validation.

Takeover analysis combines bundled Subjack with SubOver and Nuclei. Subjack checks HTTP fingerprints, CNAME chains, SRV records, nameserver delegations, SPF includes and MX targets using bounded concurrency; only positive, in-scope JSON results become findings. All takeover matches remain leads requiring manual DNS/provider confirmation.

The deep profile also runs Arjun parameter discovery, bounded Nikto checks, linked GitHub repository secret scanning with Gitleaks and TruffleHog, and TLS analysis with SSLyze, SSLScan, and testssl.sh. Mantra supplements the built-in web/JavaScript detector; its raw matches are immediately confidence-filtered, fingerprinted, redacted, and overwritten. TruffleHog verification is deliberately disabled so discovered credentials are never used.

Setup shallow-clones SecLists and PayloadsAllTheThings under `tools/wordlists/`. FFUF defaults to the repository's `wordlists/web-discovery-common.txt`, with managed and system SecLists paths as fallbacks. PayloadsAllTheThings is installed as analyst reference material and is not sprayed automatically. Override content discovery with `--wordlist PATH`.

## Multiple targets

Put one authorized apex domain per line in `targets.txt` and run:

```bash
venv/bin/python recon_pipeline.py --targets-file targets.txt \
  --i-have-authorization --profile deep --active-delay 1
```

Passing `targets.txt` as the positional argument also works. Targets run sequentially to preserve per-host rate limits, and each receives an independent timestamped database, artifact tree, and HTML report. Live progress includes a rolling ETA based on completed stages.

## Installer-managed tools

Third-party source and binaries are deliberately excluded from Git. `setup.py`
downloads tested revisions of theHarvester, SpiderFoot, Recon-ng, XSStrike,
sqlmap, testssl.sh, dnsenum, SubOver, Mantra, Gitleaks, and TruffleHog. Python
tools with conflicting dependency sets use isolated environments. dnsenum still
requires upstream Perl modules and degrades cleanly when they are absent.

## Design notes

The pipeline passes argument arrays directly to subprocesses (never a shell), accepts only apex domains, filters crawled URLs back to that domain, rate-limits active tools, applies timeouts, deduplicates normalized URLs, and requires an explicit authorization acknowledgement. Scanner observations are leads, not confirmed vulnerabilities; validate them manually.

Run tests with:

```bash
python3 -m unittest discover -v
```
