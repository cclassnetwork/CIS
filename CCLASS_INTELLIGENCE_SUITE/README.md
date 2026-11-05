# CCLASS INTELLIGENCE SUITE — Professional Edition 1.0

A local-first, modular **OSINT and cyber-threat-intelligence** platform for Kali Linux, Debian and Ubuntu.
It correlates **public-source data, authorised datasets and evidence you provide** into investigations with
entity graphs, timelines, maps, confidence scoring and exportable reports.

It is an original implementation. It takes inspiration from the *idea* of publicly described analyst tooling
(unified selector search, metadata dashboards) but **does not intercept communications, access private
accounts, bypass authentication or track individuals covertly**. See [Legal and ethical limits](#legal-and-ethical-limits).

---

## 1. Quick start

```bash
unzip CCLASS_INTELLIGENCE_SUITE.zip
cd CCLASS_INTELLIGENCE_SUITE
chmod +x install.sh
./install.sh
python3 cclass.py            # or: python3 cclass.py --dashboard
```

Open **http://127.0.0.1:8000** and press **Load offline demo data** on the Overview page.
No API keys, accounts or paid services are required.

## 2. Detailed installation guide

### Requirements

| Item | Requirement |
|---|---|
| OS | Kali Linux, Debian 11+, Ubuntu 20.04+ (any Linux with Python 3.9+ works) |
| Python | 3.9 or newer |
| RAM | 8 GB target (typical use is well under 500 MB) |
| Disk | ~300 MB including dependencies |
| Network | Needed only for online lookups and for the CDN front-end libraries (see below) |

### What `install.sh` does

1. Checks for Python ≥ 3.9 and installs `python3-venv`, `python3-pip` and `iputils-ping` with `apt` if missing
   (uses `sudo` when you are not root; skip with `--no-apt`).
2. Creates a virtual environment in `./.venv` — required on current Kali/Debian, whose system Python is
   "externally managed" (PEP 668), so nothing is installed system-wide.
3. Installs `requirements.txt` into the virtualenv.
4. Initialises the SQLite database and applies migrations.
5. Runs the automated tests (skip with `--no-tests`).

`python3 cclass.py` automatically relaunches itself inside `./.venv`, so you do not need to activate it.

### Options

```text
./install.sh --vendor     also download Bootstrap, Leaflet, Chart.js and Cytoscape into
                          cclass_suite/web/static/vendor so the dashboard works with no Internet
./install.sh --no-tests   skip the self-test run
./install.sh --no-apt     do not call apt (packages already installed)
```

### Front-end libraries and the map

The dashboard uses Bootstrap 5, Leaflet, Chart.js and Cytoscape.js. By default they are loaded from the jsDelivr CDN.
Run `./install.sh --vendor` once while online to serve them locally. **Map tiles** always come from OpenStreetMap
and therefore need Internet access; markers still render on a blank map when offline.

### Manual installation

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python3 cclass.py init
python3 -m pytest -q tests
python3 cclass.py
```

### Troubleshooting

| Symptom | Fix |
|---|---|
| `externally-managed-environment` | Use `./install.sh` (virtualenv) instead of `pip install` on the system Python. |
| `ensurepip is not available` | `sudo apt install python3-venv python3-pip` |
| Dashboard charts/map blank | CDN blocked or offline → `./install.sh --vendor` while online. |
| Many "unavailable" warnings | You are offline or behind a filtering proxy; use **Offline mode** (Settings) to work with bundled sample data. |
| Port already in use | `python3 cclass.py --port 8081` |
| PDF reports fail | `.venv/bin/pip install reportlab` |
| DNS lookups fail | `.venv/bin/pip install dnspython`; check your resolver |

## 3. Using the platform

### Dashboard (`python3 cclass.py --dashboard`)

| View | Purpose |
|---|---|
| **Overview** | Counters, severity charts, entity mix, recent alerts and activity, cross-investigation overlaps |
| **Intelligence Search** | *Search* stored data or *Investigate* a selector (auto-detects e-mail, IP, domain, URL, username, CVE, coordinates, place, keyword) |
| **Modules** | Run any module directly |
| **Threat Alerts** | CISA KEV / NVD / CISA advisories, watchlists, scheduled monitoring |
| **Investigations** | Create, triage, attach **evidence** (hashed, duplicate-detected), correlate, delete |
| **Geographic Map** | Leaflet map of located entities and findings, confidence-sized markers |
| **Entity Graph** | Cytoscape relationship graph: mouse-wheel / pinch zoom, **+ / - / %** buttons, Fit, four layouts, node/edge details |
| **Timeline** | Chronology of findings, evidence and activity |
| **Reports** | HTML, PDF, CSV, JSON, TXT |
| **Settings** | Offline mode, timeouts, scan limits, scheduler, **source reliability ratings** |

### Command line

```bash
python3 cclass.py demo                              # load the offline demonstration investigation
python3 cclass.py investigate admin@demo-corp.example
python3 cclass.py --offline investigate "Lagos | London"   # distance and bearing
python3 cclass.py investigate CVE-2021-44228
python3 cclass.py globalwatch -c Nigeria -s Kano --days 3 --max 5 --min-severity LOW --links
python3 cclass.py --offline globalwatch              # bundled sample headlines (marked 'Sample Wire')
python3 cclass.py feeds                             # refresh public threat feeds  (--sample for bundled data)
python3 cclass.py watch add keyword Citrix
python3 cclass.py alerts --matched
python3 cclass.py metadata ./report.pdf -i 1        # analyse a file and store it as evidence
python3 cclass.py report 1 -f pdf
python3 cclass.py netscan 192.168.1.0/24 --i-am-authorized
python3 cclass.py monitor                           # run scheduled tasks without the dashboard
```

Global flags: `--offline`, `--host`, `--port`, `--data-dir`. Environment: `CCLASS_HOME`, `CCLASS_OFFLINE=1`,
`CCLASS_NVD_API_KEY` (optional, raises NVD rate limits; never stored on disk).

## 4. The modules (the ten required ones plus GLOBALWATCH)

| Module | What it does | Sources |
|---|---|---|
| **XKEYSEARCH** | Detects the selector type, runs matching modules, pivots (e-mail → domain → IPs, max depth 2 / 8 steps), then correlates. Searches all stored data. | local DB |
| **EMAILINTEL** | RFC syntax, role/free/disposable checks, MX, SPF (policy and lookup count), DMARC, DKIM at common selectors, public Gravatar profile | DNS, Gravatar |
| **IPINTEL** | Classification, reverse DNS, ASN/prefix, RDAP allocation and holder, approximate geolocation | Team Cymru DNS, RDAP, ipwho.is |
| **DOMAININTEL** | A/AAAA/NS/MX/TXT/CAA/SOA, RDAP registration (age, expiry), certificate-transparency sub-domains, passive resolution | DNS, RDAP, crt.sh |
| **SOCIALINTEL** | Whether a handle has a *public* profile on open platforms (GitHub, GitLab, Codeberg, HN, Dev.to, Docker Hub, Keybase, Lichess, Mastodon, Bluesky, Wikipedia, PyPI) | public APIs |
| **GEOINT** | Gazetteer lookup, nearest cities, great-circle distance and bearing, bounding boxes, optional OSM geocoding | bundled data, Nominatim |
| **THREATMONITOR** | CISA KEV, NVD, CISA advisories; CVE/keyword lookup; watchlist matching | public feeds |
| **METADATA** | PDF, DOCX/XLSX/PPTX and image metadata: authors, software, dates, macros, external links, embedded objects, EXIF device and GPS, hashes | your files |
| **NETWORKINTEL** | Authorised inventory: live hosts, common open ports, reverse DNS, MAC/vendor from the ARP cache | your network |
| **GLOBALWATCH** | International news watch for security, military readiness, cyber and conflict headlines. Classifies each by severity, country and region; ranks, de-duplicates and caps per category. Query: `Nigeria`, `Nigeria \| Kano` or `global`. Headline keywords only, so confidence is low; always verify at the linked source. | Google News RSS (keyless) |
| **REPORTGEN** | HTML, PDF, CSV (formula-injection safe), JSON, TXT | local DB |

### Intelligence features

* **Correlation engine** — shared infrastructure, shared ASN, username reuse, pivot candidates, cross-investigation overlaps.
* **Confidence scoring** — `source reliability (A–F) × evidence quality × age decay`; independent sources combine as `1 − Π(1 − cᵢ)`.
  Reliability ratings are editable in Settings, and the effect shows up immediately in new findings.
* **Duplicate detection** — findings (fingerprint), entities (normalised value), evidence (SHA-256), alerts (feed + id).
* **Watchlists and scheduling** — keyword/product/vendor/CVE/domain watchlists matched against alerts; scheduled feed refresh and watchlist re-checks.
* **Database** — SQLite, WAL mode, foreign keys, indexes, versioned migrations (`schema_migrations`). Tables: investigations, entities,
  relationships, findings, evidence, sources, threat_alerts, watchlists, activity_logs, scheduled_tasks, reports.

## 5. Offline mode and sample data

`--offline` (or Settings → Offline mode) makes **zero network requests** and answers from `sample_data/`:
DNS, RDAP, IP/ASN/geolocation, certificate transparency, social profiles, a threat feed, a world-city gazetteer.
The sample data uses reserved documentation domains and IP ranges (`*.example`, `203.0.113.0/24`, `198.51.100.0/24`,
`192.0.2.0/24`) — **nothing refers to a real organisation or person**. Findings from sample data carry source
reliability `F`, so their confidence is deliberately low.

## Graph Lab (Maltego-style link analysis)

A web canvas where you place entities and **right-click -> transform** to expand them into linked results (DNS, ASN,
owners, locations, news, CVEs ...). Open **Graph Lab** in the dashboard menu or `/graphlab`. Graphs are saved, shareable
as JSON, exportable to CSV/GraphML/PNG, and fully audited. See **docs/GRAPH_LAB.md**.

## 6. Security model

* Binds to **127.0.0.1** by default. **Sign-in is on by default** with three roles (viewer, analyst, admin), scrypt
  password hashing, lockout, optional TOTP two-factor authentication and server-side sessions.
* Every sign-in, denial, user/case/evidence/report/backup/settings action goes to a **tamper-evident, hash-chained audit
  log** (`python3 cclass.py audit verify`).
* HTTPS deployment (Docker + Caddy, or systemd + nginx), backups with checksums, restore and retention, and case
  management (assignee, tags, due date, TLP, comments) are included. See **docs/ADMIN_GUIDE.md** and **docs/SECURITY.md**.
* Host-header allow-list (DNS-rebinding defence) and same-origin check on every state-changing request.
* All SQL is parameterised; all output rendered in the browser is HTML-escaped; reports use auto-escaping; CSV cells that
  start with `= + - @` are neutralised; HTML reports are served with `Content-Security-Policy: sandbox`.
* Uploaded evidence is size-limited, stored under hashed names with mode `0600`, never executed. Office/PDF parsing refuses
  XML entities (XXE) and decompression bombs.
* **No secrets in code or settings files.** The optional NVD key is read only from `CCLASS_NVD_API_KEY`.
* Every external call has a timeout and response-size cap and fails soft: an unavailable service produces a warning,
  never a crash. A crashing module is contained and reported as a failed result.

## 7. Legal and ethical limits

Not implemented, by design: interception of private communications, credential theft, password cracking, authentication
bypass, access to private social accounts, covert tracking of individuals, exploitation of networks.

* **NETWORKINTEL** needs an explicit authorisation confirmation, is limited to private/loopback/link-local ranges by
  default, and uses only TCP connect probes, ICMP echo and reverse DNS — no banner grabbing, credential testing or exploits.
  Scanning networks you do not own or have written permission to test may be illegal.
* **IP geolocation** is statistical (usually city/region level) and never identifies a person or a precise site.
* **A matching username is a lead, not proof of identity.** Confidence for such links is intentionally low.
* Findings may contain personal data (e.g. EXIF GPS, author names). Handle it under the law that applies to you
  (GDPR, NDPR, etc.), keep only what you need, and respect the terms of service of each public source.

## 8. Project layout

```text
cclass.py                  entry point (dashboard + CLI)
install.sh  requirements.txt
cclass_suite/
  config.py db.py models.py scoring.py utils.py dnsutil.py     core
  ingest.py correlation.py xkeysearch.py context.py scheduler.py demo.py
  modules/                 emailintel ipintel domainintel socialintel geoint threatmonitor
                           metadata networkintel globalwatch reportgen rdap base
  graphlab/                store, transforms, engine, routes for Graph Lab
web/                     app.py (FastAPI), auth.py, ops.py, templates/, static/ (cclass.js, cclass.css)
docs/                    ADMIN_GUIDE, SECURITY, ANALYST_QUICKSTART, GRAPH_LAB
deploy/                  Caddyfile, nginx.conf, cclass.service (plus Dockerfile and docker-compose.yml)
sample_data/               offline demonstration datasets
tests/                     pytest suite
data/                      created at first run: cclass.db, evidence/, reports/, logs/, settings.json
```

## 9. Testing

```bash
.venv/bin/python -m pytest -q tests
```

Covers validation, settings, database/migrations/constraints/cascades, scoring, every module in offline mode and its parsers,
metadata extraction (generated DOCX, PDF and EXIF/GPS images, XXE and zip-bomb guards), network authorisation and
loopback scanning, correlation, orchestration and pivoting, evidence handling, all report formats, the scheduler and
accounts, RBAC, the audit chain, backup/restore, case management and the authentication layer, and (when FastAPI is installed) the REST API.

## 10. Known limitations

* Online integrations depend on third-party services whose formats and rate limits can change; they degrade to warnings.
* SOCIALINTEL covers a short list of open APIs; platforms that require login or block automation are intentionally excluded.
* NETWORKINTEL is IPv4-only and reads MAC addresses from the local ARP cache (same-subnet hosts only).
* Accounts are local (no SSO/LDAP yet) and the application is designed as a single instance.
* The full FastAPI app under uvicorn, the Docker build and live TLS were not executed in the build environment; see docs/SECURITY.md.
* Not a substitute for legal advice or for formal evidence-handling procedures.
