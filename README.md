# openhost-nextcloud

Nextcloud (files / calendar / contacts / etc.) packaged as an OpenHost
app, with single sign-on via the OpenHost zone's `zone_auth` cookie.

## What you get

- The official upstream `nextcloud:33-apache` image, augmented with:
  - PostgreSQL 17 (private to the container, listens on loopback only)
  - Redis 7 (private to the container, loopback only, used for file
    locking + memory cache)
  - A small Python auth-sidecar in front of Apache that bridges
    OpenHost's `zone_auth` JWT cookie to Nextcloud's `user_saml` app
    in environment-variable mode
  - tini as PID 1 to reap zombies and forward signals
- Persistent state under `$OPENHOST_APP_DATA_DIR`:
  - `pgdata/` — PostgreSQL cluster
  - `redis/` — Redis dump (currently disabled; `appendonly no`)
  - The Nextcloud upstream image's standard volumes
    (`/var/www/html/data`, `/var/www/html/config`, custom apps, etc.)
    are bind-mounted under the upstream image's own paths, which are
    inside the container filesystem
  - `.postgres_password` — chmod 644.  Regenerated only when the
    file is missing OR present-but-empty/corrupt (truncated to zero
    bytes, all-whitespace, etc.).  An operator who hand-edits this
    file should make sure the new value is on a single non-blank
    line so the boot-time loader doesn't treat it as corrupt and
    silently overwrite it.  If you change the password by hand, the
    boot following will also issue an ``ALTER ROLE`` to keep
    Postgres' role password in sync.
  - `admin_password.txt` — chmod 644, the bootstrap admin
    Nextcloud account's password.  Same regeneration rules as
    `.postgres_password`.
- `[runtime.container]` requests 1.5 GiB / 1.5 cores. Bump
  `memory_mb` in `openhost.toml` if you run heavy workloads (Talk,
  OnlyOffice, large preview backlogs).

## Authentication architecture

There are TWO authentication rails because Nextcloud's native sync
clients (Desktop / Android / iOS / WebDAV CLIs) do not carry the
`zone_auth` cookie:

### Rail 1: web UI (browser)

1. The browser arrives at `nextcloud.<zone-domain>` carrying
   `zone_auth` (set by the OpenHost router after the owner logs in
   to the zone).
2. The OpenHost router treats every path under this app as
   "public" (`public_paths = ["/"]` in `openhost.toml`) so the
   request reaches the auth-sidecar inside the container regardless
   of `zone_auth`'s validity.
3. The auth-sidecar verifies the `zone_auth` JWT against the router's
   JWKS (`<router>/.well-known/jwks.json`, RS256). If the claim
   `sub == "owner"` the sidecar **strips any client-supplied
   `X-Openhost-User` header** and stamps `X-Openhost-User: admin`
   (or `$NEXTCLOUD_ADMIN_USER`).
4. Nextcloud's `user_saml` app, configured in `environment-variable`
   mode with `general-uid_mapping=HTTP_X_OPENHOST_USER`, treats the
   stamped header as the authenticated user. On first login
   user_saml auto-creates the `admin` user.

If the JWT is missing or invalid, the sidecar forwards the request
WITHOUT stamping the SSO header, and Nextcloud falls through to its
own login page. This is the right fallback: the operator can always
log in via the bootstrap admin password (saved to
`admin_password.txt` — read it via the file-browser app).

### Rail 2: native sync clients

1. The user opens the Nextcloud Desktop / Android / iOS app and
   chooses "log in" with the URL `https://nextcloud.<zone-domain>`.
2. The client opens Login Flow v2 in the system browser. The system
   browser already carries `zone_auth`, so the auth-sidecar
   recognises the owner and the Login Flow v2 pages SSO straight
   through.
3. Nextcloud mints an **app password** scoped to that client and
   returns it to the client process.
4. From then on the client uses HTTP Basic Auth (`username:app-password`)
   against any path listed in `auth_proxy.py`'s `PUBLIC_PATH_PATTERNS`.
   The full list (kept current in code, summarised here) covers:
   `/remote.php/dav/*`, `/remote.php/webdav/*`, `/ocs/*`,
   the legacy `/caldav` and `/carddav` aliases, `/status.php`,
   `/.well-known/*`, `/login/v2*` and `/index.php/login/v2*` (the
   pairing flow itself), public file shares (`/s/<id>`,
   `/index.php/s/<id>`, `/public.php`, `/index.php/public.php`),
   and the CSRF-token bootstrap (`/csrftoken`, `/index.php/csrftoken`).
   Requests on these paths pass through with the `Authorization`
   header intact and **no** `X-Openhost-User` stamped — Nextcloud
   authenticates them via the app password (or share token, or
   anonymous public access) directly.

The result is that revoking a client (Settings → Security → revoke
the app password) immediately disconnects that one device without
affecting other clients or the web session. App passwords also
support per-app permissions (e.g. read-only).

### Why `public_paths = ["/"]` is safe

`public_paths = ["/"]` tells the **OpenHost router** that no path
under this app requires `zone_auth` at the router layer. A
consequence is that the router ALSO does not strip
client-supplied `X-OpenHost-Is-Owner` headers on those paths
(the router only overwrites that header for authenticated owners).
On the surface this looks like a privilege-escalation vector: a
hostile client could simply send `X-OpenHost-Is-Owner: true` and
have it propagate untouched through the router.

The auth-sidecar closes that gap: it **unconditionally strips
`X-Openhost-Is-Owner` AND `X-Openhost-User` from every incoming
request before any other processing**, including on the bypass
("public") paths. Owner status is then redetermined inside the
sidecar by verifying the `zone_auth` JWT against the router's
JWKS. A request that bypasses `zone_auth` entirely therefore
cannot trick the sidecar into stamping owner identity, regardless
of which paths are listed as router-public.

## First boot / installation

OpenHost will pull the image and start the container. The upstream
Nextcloud entrypoint detects an empty `/var/www/html` and runs
`occ maintenance:install`, creating the database schema, the admin
user (with the password from `$NEXTCLOUD_ADMIN_PASSWORD`), and
seeding `config/config.php`. After that completes successfully the
post-installation hook (`hooks/post-installation/01-openhost-sso.sh`)
runs, installs the `user_saml` app, configures environment-variable
mode, sets a few hardening flags (`upgrade.disable-web=true`,
`default_phone_region`, ajax background mode), and then Apache
starts.

To retrieve the admin password:

```
curl -fsS "https://file-browser.<zone-domain>/app_data/nextcloud/admin_password.txt" \
    -H "Authorization: Bearer <zone-token>"
```

The first time you visit `https://nextcloud.<zone-domain>` as the
zone owner, user_saml auto-provisions the SAML-authenticated `admin`
user. From then on you don't need the password for normal web use —
it's there as a break-glass credential.

## Backup

Persistent state lives under `$OPENHOST_APP_DATA_DIR`:

- `pgdata/` — Postgres cluster. Use
  `pg_dump -h /run/postgresql -U nextcloud nextcloud` from inside
  the container, or copy the entire dir while Postgres is stopped.
- `redis/` — In-memory cache; safe to skip (regenerated on demand).
- The Nextcloud upstream image's `data/` and `config/` directories
  live inside the container's `/var/www/html/`. They're persisted
  by OpenHost via the upstream image's volume declarations on the
  base image.
- `.postgres_password` — needed to read the database back; do NOT
  lose this when restoring.
- `admin_password.txt` — convenience copy of the bootstrap admin
  password.

## Upgrades

Nextcloud only supports upgrading **one major version at a time**.
This image pins `nextcloud:33-apache`; bumping to `34-apache`
requires a follow-up release that pins `34-apache`, then `35-apache`,
etc. — never skip majors.

The web-based updater is disabled at install time
(`upgrade.disable-web=true` set by the post-installation hook).
Upgrades happen only by rebuilding the image with a newer base.

## Environment variables

| Var | Default | Purpose |
| --- | --- | --- |
| `NEXTCLOUD_ADMIN_USER` | `admin` | The local Nextcloud user that the auth-sidecar's `X-Openhost-User` stamp identifies. user_saml auto-creates this account on first SSO login. |
| `NEXTCLOUD_DOMAIN` | `${OPENHOST_APP_NAME}.${OPENHOST_ZONE_DOMAIN}` | The public hostname the app is served at; used for `trusted_domains` and `overwrite.*`. |
| `AUTH_PROXY_LISTEN_PORT` | `8080` | The port the auth-sidecar binds. Must match `[runtime.container].port` in `openhost.toml`. |
| `APACHE_PORT` | `8081` | The port Apache binds inside the container. The auth-sidecar proxies to `127.0.0.1:$APACHE_PORT`. |
| `APACHE_READY_TIMEOUT` | `90` | Seconds to wait for Apache to bind its listening port before declaring startup failed. |
| `REDIS_READY_TIMEOUT` | `30` | Seconds to wait for Redis to respond to PING before declaring startup failed. |
| `PG_WATCHDOG_INTERVAL` | `15` | Seconds between Postgres `pg_isready` probes. Three consecutive failures terminate the container so OpenHost restarts it. |
| `AUTH_PROXY_LOG_LEVEL` | `INFO` | Python logging level for the sidecar. Set to `DEBUG` to log per-token JWT verification failures (helpful for diagnosing "I can't log in"). |

The following variables are set by OpenHost itself and consumed
internally by `start.sh`, the auth-sidecar, and the hooks; they're
listed here so you don't have to read the source to understand
what's happening:

| Var | Source | Purpose |
| --- | --- | --- |
| `OPENHOST_ROUTER_URL` | OpenHost runtime | The internal URL of the OpenHost router (used by the auth-sidecar to fetch the JWKS). The sidecar refuses to start without this. |
| `OPENHOST_ZONE_DOMAIN` | OpenHost runtime | The zone's public domain. Used to derive `NEXTCLOUD_DOMAIN`. |
| `OPENHOST_APP_NAME` | OpenHost runtime | This app's name (`nextcloud`). Used to derive `NEXTCLOUD_DOMAIN`. |
| `OPENHOST_APP_DATA_DIR` | OpenHost runtime | The persistent-data directory. Defaults to `/var/lib/openhost-nextcloud` if unset (which only happens in standalone testing). |
| `OPENHOST_APP_TEMP_DATA_DIR` | OpenHost runtime | Per-boot scratch directory; redis.conf is written here. |
| `OPENHOST_NEXTCLOUD_DOMAIN` | exported by `start.sh` | The resolved public hostname. The before-starting hook reads this to re-stamp `trusted_*` and `overwrite.*`. |

The Nextcloud image's standard env vars (`POSTGRES_*`, `REDIS_*`,
`NEXTCLOUD_TRUSTED_DOMAINS`, `TRUSTED_PROXIES`, `OVERWRITEHOST`,
`OVERWRITEPROTOCOL`, `OVERWRITECLIURL`) are set automatically by
`start.sh`. Do not override them through the OpenHost UI unless you
also know how Nextcloud's first-install flow consumes them.

## Caveats

- **One major upgrade at a time** (Nextcloud rule, not OpenHost).
- **App passwords for sync clients can't be revoked from outside
  Nextcloud.** If you revoke the zone owner's `zone_auth`, the web
  UI logs them out immediately, but app passwords minted earlier
  remain valid until manually revoked via Settings → Security.
  This is the architectural reason this app maxes out at integration
  score 3 instead of 4 — there's no central revocation rail that
  reaches Nextcloud's app-password DB.
- **No bundled cron daemon.** Background jobs run via the ajax mode
  on page loads, so a Nextcloud session that's idle for hours won't
  process its background queue. The web UI's "background jobs"
  status page may warn about this; ignore the warning unless you
  have a specific reason to want strict cron timing.
- **PostgreSQL data integrity on shutdown.** OpenHost sends SIGTERM
  on stop; the supervisor traps it and runs `pg_ctl stop -m fast`.
  A SIGKILL (e.g. ungraceful host crash) skips that and Postgres
  recovers from WAL on next boot — no data loss but the first
  boot after such a crash takes a few extra seconds.
- **Memory.** 1.5 GiB is comfortable for a personal/family setup of
  5-10 users and a few TB of storage. Heavy preview-generation
  backlogs (e.g. uploading a 100k-photo library all at once) can
  push past that; bump `memory_mb` in `openhost.toml` if you see
  OOM kills.

## File layout

```
.
├── Dockerfile                        # FROM nextcloud:33-apache + Postgres + Redis + Python + tini
├── auth_proxy.py                     # Streaming HTTP proxy on :8080 -> 127.0.0.1:8081
├── start.sh                          # Boots Postgres, Redis, Apache (via upstream entrypoint), auth-sidecar
├── openhost.toml                     # OpenHost manifest
├── hooks/
│   ├── post-installation/
│   │   └── 01-openhost-sso.sh        # Install + configure user_saml on first boot
│   └── before-starting/
│       └── 00-openhost-overwrite.sh  # Re-stamp trusted_*/overwrite.* every boot
└── README.md                         # This file.
```
