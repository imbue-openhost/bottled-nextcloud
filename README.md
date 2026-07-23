# openhost-nextcloud

Nextcloud (files / calendar / contacts / etc.) packaged as an OpenHost
app, with single sign-on driven by the OpenHost router's
`X-OpenHost-Is-Owner` trusted header.

## What you get

- The official upstream `nextcloud:33-apache` image, augmented with:
  - PostgreSQL (whatever the upstream image's Debian release ships;
    currently PostgreSQL 17 on Trixie), private to the container,
    listens on 127.0.0.1 only over TCP and unix-socket
  - Redis (currently 8.x on Trixie), private to the container,
    reachable ONLY over the unix socket `/run/redis/redis.sock` (TCP
    disabled). Wired in as Nextcloud's distributed cache AND
    transactional file-locking backend (`memcache.distributed` +
    `memcache.locking`); APCu is the local cache (`memcache.local`).
    Apache/PHP (running as `www-data`) is added to the `redis` group
    so it can open the 0770 socket.
  - A small Python auth-sidecar in front of Apache that bridges
    OpenHost's owner signal (the `X-OpenHost-Is-Owner` header) to
    Nextcloud's `user_saml` app in environment-variable mode
  - tini as PID 1 to reap zombies and forward signals
- Persistent state under `$OPENHOST_APP_DATA_DIR`:
  - `pgdata/` — PostgreSQL cluster
  - `redis/` — Redis on-disk dump directory.  Both AOF
    (`appendonly no`) AND RDB snapshots (`save ""`) are disabled in
    the generated redis.conf, so this directory typically stays
    empty — Redis is used as a non-persistent cache + file lock
    backend only.
  - `html/` — Nextcloud's persisted application state.  The upstream
    image mounts `/var/www/html` as an anonymous podman VOLUME, which
    OpenHost does NOT persist across container rebuilds, so we keep
    the pieces that must survive a rebuild here instead:
    `html/config.php` (config.php with DB creds, instanceid, secret,
    the user_saml settings), `html/version.php` (drives the upstream
    entrypoint's install-vs-upgrade decision), `html/data/` (user
    uploads + `nextcloud.log`, via `NEXTCLOUD_DATA_DIR`), and
    `html/custom_apps/` + `html/themes/`.  On each boot `start.sh`
    copies this state into the fresh volume before the upstream
    entrypoint runs and copies it back out once Apache is up.  Without
    this a rebuild would re-run `maintenance:install` against the
    still-populated Postgres DB and wedge on "The Login is already
    being used".
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
- `[resources]` in `openhost.toml` requests 1.5 GiB / 1.5 cores.
  Bump `memory_mb` if you run heavy workloads (Talk, OnlyOffice,
  large preview backlogs).

## Authentication architecture

There are TWO authentication rails because Nextcloud's native sync
clients (Desktop / Android / iOS / WebDAV CLIs) do not carry the
OpenHost owner session:

### Rail 1: web UI (browser)

1. The owner arrives at `nextcloud.<zone-domain>`. The OpenHost router
   authenticates the owner via their zone `session_token` cookie and,
   on success, stamps `X-OpenHost-Is-Owner: true` on the request it
   forwards to the container.
2. The OpenHost router treats every path under this app as
   "public" (`public_paths = ["/"]` in `openhost.toml`) so the
   request reaches the auth-sidecar inside the container even when the
   visitor is not the owner (needed for native-sync and public-share
   traffic — see Rail 2). The router still runs owner authentication
   and stamps the header when the owner is signed in.
3. The auth-sidecar reads `X-OpenHost-Is-Owner`. Because the router is
   the sole authority for that header — it strips any client-supplied
   `X-OpenHost-*` header before adding its own — a value of `true` is
   trustworthy. On owner requests the sidecar **strips any
   client-supplied `X-Openhost-User` header** and stamps
   `X-Openhost-User: admin` (or `$NEXTCLOUD_ADMIN_USER`).
4. Nextcloud's `user_saml` app, configured in `environment-variable`
   mode with `general-uid_mapping=HTTP_X_OPENHOST_USER`, treats the
   stamped header as the authenticated user. On first login
   user_saml auto-creates the `admin` user.

If `X-OpenHost-Is-Owner` is absent, the sidecar forwards the request
WITHOUT stamping the SSO header, and Nextcloud falls through to its
own login page. This is the right fallback: the operator can always
log in via the bootstrap admin password (saved to
`admin_password.txt` — read it via the file-browser app).

> **Note on the previous JWT approach.** Earlier revisions verified a
> router-signed `zone_auth` JWT cookie against the router's JWKS
> endpoint. Current OpenHost does not mint a `zone_auth` cookie for
> apps at all — the trusted `X-OpenHost-Is-Owner` header is the only
> owner signal — so relying on the (nonexistent) JWT left the owner
> permanently unable to sign in ("Account not provisioned"). The
> sidecar now consumes the header directly and no longer needs
> `OPENHOST_ROUTER_URL` or any JWT/JWKS dependency.

### Rail 2: native sync clients

1. The user opens the Nextcloud Desktop / Android / iOS app and
   chooses "log in" with the URL `https://nextcloud.<zone-domain>`.
2. The client opens Login Flow v2 in the system browser. The system
   browser already carries the owner's OpenHost session, so the
   router stamps `X-OpenHost-Is-Owner: true`, the auth-sidecar
   recognises the owner, and the Login Flow v2 pages SSO straight
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
under this app requires an authenticated owner at the router layer —
so anonymous native-sync clients and public-share visitors are not
bounced to the OpenHost `/login` page and can reach Nextcloud
directly.

Trusting the `X-OpenHost-Is-Owner` header is safe because the router
is the sole authority for it: on EVERY request (public or not) the
router strips any client-supplied `X-OpenHost-*` header before adding
its own, and only adds `X-OpenHost-Is-Owner: true` after it has
authenticated the owner's `session_token` cookie. A hostile client
that sends its own `X-OpenHost-Is-Owner: true` has that header
removed at the router before the sidecar ever sees it.

As defence-in-depth against a misconfigured router, the auth-sidecar
ALSO strips any inbound `X-Openhost-Is-Owner` and `X-Openhost-User`
from the request before forwarding it upstream to Apache, and only
stamps `X-Openhost-User` on protected (non-public) paths — so a
public-share visitor is never auto-logged-in as the owner.

## First boot / installation

OpenHost will pull the image and start the container. On first boot
`start.sh` seeds the Nextcloud core code into the fresh
`/var/www/html` volume and finds no persisted `config.php`/`version.php`
in `$OPENHOST_APP_DATA_DIR/html`, so the upstream entrypoint runs
`occ maintenance:install`, creating the database schema, the admin
user (with the password from `$NEXTCLOUD_ADMIN_PASSWORD`), and
seeding `config/config.php` (with `datadirectory` pointed at
`$OPENHOST_APP_DATA_DIR/html/data` via `NEXTCLOUD_DATA_DIR`). After
that completes successfully the post-installation hooks run:
`01-openhost-sso.sh` installs the `user_saml` app, configures
environment-variable mode, and sets a few hardening flags
(`upgrade.disable-web=true`, `default_phone_region`, ajax background
mode); then `02-openhost-extensions.sh` installs the pre-configured
extensions (see below). Apache then starts. Once Apache is
listening `start.sh` copies `config.php` + `version.php` + the
installed extensions (`custom_apps/`) out to
`$OPENHOST_APP_DATA_DIR/html` so the next rebuild restores them and
takes the upstream entrypoint's upgrade path instead of reinstalling.

To retrieve the admin password:

```
curl -fsS "https://file-browser.<zone-domain>/app_data/nextcloud/admin_password.txt" \
    -H "Authorization: Bearer <zone-token>"
```

The first time you visit `https://nextcloud.<zone-domain>` as the
zone owner, user_saml auto-provisions the SAML-authenticated `admin`
user. From then on you don't need the password for normal web use —
it's there as a break-glass credential.

## Pre-configured extensions

A fresh install ships with the common "Nextcloud Hub" productivity
extensions already installed and enabled, so the instance is useful
out of the box instead of a bare Files-only server. The default set
(installed on first boot by
`hooks/post-installation/02-openhost-extensions.sh`) is:

| App | What it adds |
| --- | --- |
| `calendar` | CalDAV calendar UI |
| `contacts` | CardDAV address-book UI |
| `notes` | Markdown notes (also powers the mobile Notes app) |
| `tasks` | CalDAV task lists (VTODO), pairs with calendar |
| `deck` | Kanban boards |

These are official, actively-maintained apps that install cleanly on
`nextcloud:33-apache` with no extra system packages. They install into
`custom_apps/` and are persisted to `$OPENHOST_APP_DATA_DIR/html` by
the same copy-out that persists `config.php`, so they survive rebuilds.

Customise the set with the `NEXTCLOUD_PRECONFIGURED_APPS` env var
(space- or comma-separated app-store IDs), e.g.
`calendar contacts mail forms`. Set it to `none` to deploy a bare
Files-only install. The installs are **best-effort**: a store outage,
rate-limit, or a single incompatible app is logged and skipped — it
never blocks the boot, because the instance is fully usable without
the extras. Any extension you install later from the web UI also
persists across rebuilds: it lands in `custom_apps/`, which is copied
out to `$OPENHOST_APP_DATA_DIR/html` both once per boot (after Apache
starts) and again on graceful shutdown (the `SIGTERM` teardown path in
`start.sh`), so a normal OpenHost stop/redeploy captures it. A hard
kill (ungraceful host crash) between installing an app and the next
graceful stop is the only case where a freshly-installed extension
could be lost on the following rebuild.

## Backup

Persistent state lives under `$OPENHOST_APP_DATA_DIR`:

- `pgdata/` — Postgres cluster. Use
  `pg_dump -h /run/postgresql -U nextcloud nextcloud` from inside
  the container, or copy the entire dir while Postgres is stopped.
- `redis/` — In-memory cache; safe to skip (regenerated on demand).
- `html/` — Nextcloud's persisted application state:
  `html/data/` (user uploads + `nextcloud.log`), `html/config.php`,
  `html/version.php`, `html/custom_apps/`, `html/themes/`. Back up
  `html/data/` and `html/config.php` together with `pgdata/` — they
  are consistent only as a set. (The `/var/www/html` volume itself is
  ephemeral and reconstructed from `html/` + the image on each boot,
  so there is nothing to back up there.)
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
| `NEXTCLOUD_PRECONFIGURED_APPS` | `calendar contacts notes tasks deck` | Space- or comma-separated list of Nextcloud app-store IDs to install + enable on first boot (see "Pre-configured extensions" below). Set to `none` (or `-`/`off`/`false`) to deploy a bare Files-only install. Installs are best-effort: an app-store outage or a single failing app is logged and skipped, never fatal. |
| `NEXTCLOUD_DOMAIN` | `${OPENHOST_APP_NAME}.${OPENHOST_ZONE_DOMAIN}` | The public hostname the app is served at; used for `trusted_domains` and `overwrite.*`. |
| `AUTH_PROXY_LISTEN_PORT` | `8080` | The port the auth-sidecar binds. Must match `[runtime.container].port` in `openhost.toml`. |
| `APACHE_PORT` | `8081` | The port Apache binds inside the container; the auth-sidecar proxies to `127.0.0.1:$APACHE_PORT`. The value is baked into Apache's `ports.conf` and the default vhost at build time via `sed`, AND read at runtime by `start.sh` (for the readiness probe) and `auth_proxy.py` (for the upstream target). Setting this at runtime changes only the readiness probe and proxy target — Apache itself is still bound to the build-time value, so a runtime override would point the proxy at a port nothing is listening on. **Effectively build-time only.** Operators wanting a different port must rebuild the image. |
| `APACHE_READY_TIMEOUT` | `90` | Seconds to wait for Apache to bind its listening port before declaring startup failed. |
| `REDIS_READY_TIMEOUT` | `30` | Seconds to wait for Redis to respond to PING before declaring startup failed. |
| `PG_WATCHDOG_INTERVAL` | `15` | Seconds between Postgres `pg_isready` probes. Three consecutive failures terminate the container so OpenHost restarts it. |
| `AUTH_PROXY_LOG_LEVEL` | `INFO` | Python logging level for the sidecar. Set to `DEBUG` for verbose per-request logging (helpful for diagnosing routing/SSO issues). |

The following variables are set by OpenHost itself and consumed
internally by `start.sh`, the auth-sidecar, and the hooks; they're
listed here so you don't have to read the source to understand
what's happening:

| Var | Source | Purpose |
| --- | --- | --- |
| `OPENHOST_ZONE_DOMAIN` | OpenHost runtime | The zone's public domain. Used to derive `NEXTCLOUD_DOMAIN`. |
| `OPENHOST_APP_NAME` | OpenHost runtime | This app's name (`nextcloud`). Used to derive `NEXTCLOUD_DOMAIN`. |
| `OPENHOST_APP_DATA_DIR` | OpenHost runtime | The persistent-data directory. Defaults to `/var/lib/openhost-nextcloud` if unset (which only happens in standalone testing). |
| `OPENHOST_APP_TEMP_DIR` | OpenHost runtime | Per-boot scratch directory; redis.conf is written here. (The legacy name `OPENHOST_APP_TEMP_DATA_DIR` is also accepted as a fallback.) |
| `OPENHOST_NEXTCLOUD_DOMAIN` | exported by `start.sh` | The resolved public hostname. The before-starting hook reads this to re-stamp `trusted_*` and `overwrite.*`. |

The Nextcloud image's standard env vars (`POSTGRES_*`, `REDIS_*`,
`NEXTCLOUD_TRUSTED_DOMAINS`, `TRUSTED_PROXIES`, `OVERWRITEHOST`,
`OVERWRITEPROTOCOL`, `OVERWRITECLIURL`) are set automatically by
`start.sh`. Do not override them through the OpenHost UI unless you
also know how Nextcloud's first-install flow consumes them.

## Caveats

- **One major upgrade at a time** (Nextcloud rule, not OpenHost).
- **App passwords for sync clients can't be revoked from outside
  Nextcloud.** If you end the zone owner's OpenHost session, the web
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
│       └── 00-openhost-overwrite.sh  # Re-stamp trusted_*/overwrite.* AND user_saml SSO settings every boot
└── README.md                         # This file.
```
