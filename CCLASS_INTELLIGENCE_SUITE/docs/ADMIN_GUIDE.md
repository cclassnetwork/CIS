# Administrator guide

## 1. First start

```bash
python3 cclass.py users add admin --role admin     # prompts for a password (12+ characters, 3 character classes)
python3 cclass.py                                   # then open http://127.0.0.1:8000 and sign in
```

If you open the dashboard before any account exists, the sign-in page offers one-time **first administrator setup**.
From any non-local address it asks for a setup token that is printed in the server log, so a stranger who reaches
the page first cannot claim the system.

`--no-auth` / `CCLASS_AUTH=off` disables sign-in for a single-user, localhost-only workstation. The program prints a
warning, and refuses to start on a non-loopback address with sign-in off unless you set `CCLASS_ALLOW_INSECURE=1`.
Never use that on a shared server.

## 2. Roles

| Role | Can do |
|---|---|
| **viewer** | Read everything: investigations, findings, graph, map, timeline, reports, alerts. Cannot change anything. |
| **analyst** | Everything a viewer can, plus run modules and investigations, upload evidence, create/edit cases, comment, manage watchlists and scheduled tasks, generate reports. |
| **admin** | Everything, plus users, settings, sources, demo data, audit log, backups and retention. |

Access is enforced on the server by one rule table (`cclass_suite/security.py`). Any route that is not matched is
**admin-only** (default deny). A test fails if a new route is added without a deliberate role.

## 3. Users

Dashboard → **Users**, or the CLI:

```bash
python3 cclass.py users list
python3 cclass.py users add jane --role analyst --must-change
python3 cclass.py users set-role jane viewer
python3 cclass.py users set-password jane        # also signs jane out everywhere
python3 cclass.py users disable jane             # ends her sessions immediately
python3 cclass.py users unlock jane              # after 5 failed sign-ins an account locks for 15 minutes
python3 cclass.py users reset-2fa jane           # lost phone
```

The last active administrator cannot be demoted, disabled or deleted. Prefer **disable** over **delete** so that
the audit log still names the person.

### Two-factor authentication

Each user can enable authenticator-app TOTP (Google Authenticator, Aegis, 1Password, etc.) from the user menu. Codes
cannot be replayed. Require it for every administrator.

### Sessions

Server-side, stored only as a SHA-256 hash. Idle timeout 60 minutes, absolute limit 12 hours, cookie
`HttpOnly; SameSite=Strict` (plus `Secure` over HTTPS). Changing a password signs out the user's other sessions.

## 4. HTTPS deployment

### Docker (recommended)

```bash
cp .env.example .env            # set CCLASS_DOMAIN
docker compose up -d --build
docker compose exec cclass python cclass.py users add admin --role admin
```

Caddy terminates TLS and the application port is never published to the host. For a public DNS name, certificates
are issued and renewed automatically (ports 80 and 443 must be reachable). For an internal LAN name, uncomment
`tls internal` in `deploy/Caddyfile` and install Caddy's root CA on staff machines.

### Without Docker

Use `deploy/cclass.service` (hardened systemd unit) with either `deploy/Caddyfile` or `deploy/nginx.conf`.

### Environment switches

These come from the environment only, so the settings API cannot weaken them.

| Variable | Meaning |
|---|---|
| `CCLASS_ALLOWED_HOSTS` | Comma-separated host names the dashboard may be served under |
| `CCLASS_COOKIE_SECURE=1` | Cookie only over HTTPS; sends HSTS |
| `CCLASS_TRUST_PROXY=1` | Use the reverse proxy's client IP (only when the app port is not reachable except through the proxy) |
| `CCLASS_AUTH=off` | Disable sign-in (single-user localhost only) |
| `CCLASS_NVD_API_KEY` | Optional NVD key. Environment only; never stored or returned by the API |

## 5. Backup, restore and retention

```bash
python3 cclass.py backup --prune                  # database + evidence + reports + settings -> data/backups/*.zip
python3 cclass.py backup --verify FILE.zip        # recompute every checksum
python3 cclass.py restore FILE.zip                # stop the dashboard first; asks for confirmation
python3 cclass.py retention                       # dry-run preview
python3 cclass.py retention --apply
```

* Backups carry a manifest with a SHA-256 for every file and are verified after creation. Restore refuses unsafe
  paths and oversized archives, and takes a safety copy of the current data first.
* **A backup contains case data and password hashes. Store it encrypted** (for example `gpg -c`) and off the server.
* Schedule backups from the dashboard (scheduled tasks on the Threat Monitor page, admin-only task types `backup` and `retention`) and keep the newest
  `backup_keep` (default 14).
* Retention (`retention_alert_days`, `retention_activity_days` in Settings; 0 = keep forever) removes only
  *acknowledged* threat alerts and old activity rows, plus expired sessions. It never touches cases, findings,
  evidence or the audit log.
* **Test a restore on a spare machine at least once.** An untested backup is a hope, not a backup.

## 6. Audit log

Every sign-in (success and failure), permission denial, user change, case change, evidence action, report, backup and
settings change is appended to a hash-chained, append-only log (database triggers refuse UPDATE and DELETE).

```bash
python3 cclass.py audit verify         # recompute the chain; exit code 3 on tampering
python3 cclass.py audit tail -n 50
python3 cclass.py audit export --format csv --out audit.csv
```

**Limit:** someone who can edit the database *file* could rebuild the whole chain. Once a day, record the printed
**head hash** somewhere the server cannot alter (a ticket, a signed email, write-once storage). Removing the newest
entries is then detectable.

## 7. Upgrading

1. `python3 cclass.py backup`
2. Replace the program files, keep `data/`.
3. `python3 cclass.py init` applies database migrations in a transaction.
