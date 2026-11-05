# Graph Lab - link analysis (Maltego-style)

Open it from the dashboard menu (**Graph Lab**) or go to `http://127.0.0.1:8000/graphlab`. It uses the same sign-in,
roles, audit log and backups as the rest of the suite.

## The idea

1. Put an **entity** on the canvas (email, domain, IP, URL, username, place, CVE, person, organisation, note...).
2. **Right-click** it and run a **transform**. The results appear as new entities, already linked to the one you expanded.
3. Keep expanding, rearrange, add your own links and notes, then export.

## Working with the canvas

| Action | How |
|---|---|
| Add an entity | Type it in the top box (the type is detected), drag one from the palette, or click a palette item |
| Run a transform | Right-click an entity (or a multi-selection), or use the list in the right-hand panel. Double-click runs the main lookup |
| Select several | Shift+drag a box, Ctrl+A, or Shift+click |
| Draw your own link | Link mode (click source, then target), or select two entities and press "Link them..." |
| Move / arrange | Drag; positions are saved. Arrange menu: Organic, Concentric, Circle, Hierarchy, Grid |
| Find | "Find in graph" dims everything that does not match |
| Delete | Select and press Delete |
| Export | JSON (re-importable), CSV (entities or links), GraphML, PNG |

Duplicate entities merge automatically (`Demo-Corp.example` and `demo-corp.example.` are the same domain). Limits: 2,000
entities and 6,000 links per graph, 150 results per transform run, 25 entities per run.

## Transforms included

| Transform | Works on | Uses |
|---|---|---|
| To DNS, name servers & registration | domain, hostname | DNS, RDAP, certificate transparency |
| To ASN, network, owner & location | IP | reverse DNS, ASN, geolocation |
| To domain & mail servers | email | DNS MX |
| To public profiles | username | a short list of open public APIs |
| To coordinates & country | place, country | bundled gazetteer / coordinates |
| To news & security events | place, country | public news RSS (GLOBALWATCH) |
| To CVE details & exploitation status | CVE | public vulnerability data |
| Profile URL to handle | URL, social profile | no network; recognises 20+ public profile URL formats (X, Instagram, Facebook, LinkedIn, TikTok, YouTube, Telegram, GitHub, Reddit ...) |
| To social profiles the site links to | domain, hostname | the public home page the site itself publishes (fetched through an SSRF guard) |
| To public Gravatar profile | email | the name, linked accounts and websites the address owner chose to publish |
| To possible handle variants | username | no network; results are marked unverified |
| Phone to numbering-plan country | phone | no network; country of the calling-code prefix only |
| Email to domain, URL to host, Subdomain to parent domain, IP to enclosing network, Extract entities from text | various | no network at all |

In **offline mode** every module transform answers from the bundled sample data (reserved documentation domains and
IP ranges), so you can learn the tool without touching the Internet.

## Social transforms: scope

These work like the social-media transforms of commercial link-analysis tools, but only from **public, no-login** sources.
A handle or link found this way is a *lead*, not proof that accounts belong to the same person.

Not included, by design: logging into any platform, reading private or friends-only content, scraping follower lists,
looking up who owns a phone number, contact-sync tricks, or tracking a person's activity over time. Fetching a website
refuses internal addresses, odd ports and redirects into private networks.

## What is deliberately not here

Active network scanning is not a transform. No transform reads private communications, logs into accounts, bypasses
authentication or tracks individuals covertly. Run transforms only on subjects you are entitled to research, and treat
personal data under the law that applies to you.

## Roles

*viewer* can open and export graphs; *analyst* and *admin* can create and change them. Every change, and every transform
run, is recorded in the audit log.

## Adding your own transform

Add a `Transform(...)` to `cclass_suite/graphlab/transforms.py`. A transform is a function `(node, ctx) -> Output` that
calls `out.ent(type, value)` for each result and `out.link(src, dst, label)` for each relationship; the engine handles
merging, placement, limits, history and auditing.
