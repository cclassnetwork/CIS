# Security overview

## What is built in

| Area | Control |
|---|---|
| Passwords | scrypt (N=2^15), per-user salt, 12+ characters with 3 character classes, no username inside; constant-time compare; dummy hash for unknown users so timing does not reveal valid names |
| Brute force | 5 failures lock the account for 15 minutes; the login endpoint is also rate-limited per IP |
| 2FA | RFC 6238 TOTP (verified against the RFC test vectors), replay of a used code rejected |
| Sessions | Random 256-bit token, only its SHA-256 stored; HttpOnly, SameSite=Strict, Secure over HTTPS; idle and absolute expiry; revoked on disable, role change and password change |
| CSRF | SameSite=Strict, Origin check, and a required custom header on every state-changing request |
| Authorisation | Server-side role table, default-deny, plus a test that every route has an intentional role |
| Audit | Append-only, hash-chained, verifiable, exportable; failures and denials are logged |
| Transport | HTTPS through Caddy/nginx, HSTS when `CCLASS_COOKIE_SECURE=1`, Host allow-list |
| Data | Parameterised SQL, HTML escaping, CSV formula neutralisation, sandboxed HTML reports, upload size limits, XXE and zip-bomb guards |
| Secrets | Only from the environment; never persisted or returned by the API |
| Container | Non-root, read-only filesystem, all capabilities dropped, app port not published |

## Verified here, and not

Verified by automated tests in the build environment: password hashing and policy, TOTP, accounts, lockout,
sessions, RBAC table, audit chain and tamper detection, backup/restore/retention, case management, the
authentication middleware and routes (via Starlette's test client), and the route-policy check.

**Not executed in the build environment** (no network access to install FastAPI there): the complete FastAPI
application under uvicorn, the Docker image build, and a live TLS handshake through Caddy. Their configuration is
standard, but run `docker compose up` and `pytest` on your own machine and confirm before relying on them.

## Known limits

* The audit chain proves *internal consistency*; see the head-hash advice in the Admin Guide.
* Backups are not encrypted by the program. Encrypt them.
* No single sign-on / LDAP yet. Accounts are local.
* Sessions are in the local SQLite database, so the app is designed as a single instance.
* The program does not replace a penetration test. Commission one before exposing it to the Internet.

## Reporting a vulnerability

Describe it privately to the system owner of your deployment; do not post details publicly until fixed.
