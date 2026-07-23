#!/bin/bash
# Entrypoint for openhost-nextcloud.
#
# We need /bin/bash (not /bin/sh) because we use ``wait -n`` to
# supervise multiple background children: Apache (via the upstream
# Nextcloud entrypoint), the Python auth-sidecar, Redis, and a small
# pg_isready watchdog.  PostgreSQL itself is started via ``pg_ctl
# start`` so it forks into the background; it is NOT a direct child
# of this shell — the watchdog detects its death by polling and exits
# non-zero, which trips the ``wait -n`` cleanup path.  ``wait -n`` is
# a bashism not available in the Debian ``dash``-based /bin/sh.
#
# What this script does on every boot:
#   1. Resolve the public domain (<APP>.<ZONE>) and a few env vars the
#      upstream Nextcloud entrypoint uses to drive the Apache/PHP
#      install or upgrade flow.
#   2. Initialise PostgreSQL on first boot under
#      ``$OPENHOST_APP_DATA_DIR/pgdata`` (idempotent: skips if
#      ``PG_VERSION`` is already there), then start the cluster.
#   3. Start a private Redis on 127.0.0.1:6379.
#   4. Provision the ``nextcloud`` Postgres role + database with a
#      generated password (persisted to ``$DATA_DIR/.postgres_password``
#      chmod 644 so the operator can read via the file-browser).
#   5. Generate the Nextcloud admin password (persisted to
#      ``$DATA_DIR/admin_password.txt`` chmod 644 same reason).
#   6. Run the upstream ``/entrypoint.sh apache2-foreground`` as a
#      backgrounded child — that runs install/upgrade hooks then
#      Apache.  (It's NOT ``exec``'d — the trailing ``&`` makes it a
#      child so ``wait -n`` can supervise it.)
#   7. Start the auth_proxy.py sidecar on :8080 and a pg_isready
#      watchdog as further backgrounded children.
#   8. ``wait -n`` on Apache, the proxy, Redis, and the pg watchdog;
#      if any dies, tear the rest down (via the EXIT trap) and exit
#      so OpenHost restarts the container.
#
# All persistent secrets live under $OPENHOST_APP_DATA_DIR.  Under
# rootless podman the container's ``root`` is mapped to a random
# host uid, so we tolerate chown failures with ``|| true`` rather
# than aborting the whole boot.

set -euo pipefail

log() { printf '[start.sh] %s\n' "$*" >&2; }

DATA_DIR="${OPENHOST_APP_DATA_DIR:-/var/lib/openhost-nextcloud}"
# OpenHost exposes the per-boot scratch mount as OPENHOST_APP_TEMP_DIR.
# (An earlier revision read OPENHOST_APP_TEMP_DATA_DIR, which OpenHost
# never sets — so TMP_DIR always fell back to a non-persistent /tmp
# path.  Accept both names for backwards compatibility, preferring the
# one OpenHost actually provides.)
TMP_DIR="${OPENHOST_APP_TEMP_DIR:-${OPENHOST_APP_TEMP_DATA_DIR:-/tmp/openhost-nextcloud}}"
PG_DATA="$DATA_DIR/pgdata"
REDIS_DIR="$DATA_DIR/redis"
PG_PASSWORD_FILE="$DATA_DIR/.postgres_password"
ADMIN_PASSWORD_FILE="$DATA_DIR/admin_password.txt"
# Archive tier: S3-backed (JuiceFS) storage the operator configures once
# per zone from the OpenHost dashboard.  We put Nextcloud's user-file
# data directory here so uploads scale elastically to object storage
# instead of being capped by (and bloating backups of) the local
# app_data disk.  OpenHost exposes it in-container via
# OPENHOST_APP_ARCHIVE_DIR (mounted at /data/app_archive/<app>).  This
# app declares ``app_archive = true`` in openhost.toml, so OpenHost will
# refuse to install/reload it until the operator has configured the S3
# backend — the archive dir is therefore always present at boot.
ARCHIVE_DIR="${OPENHOST_APP_ARCHIVE_DIR:-/data/app_archive/${OPENHOST_APP_NAME:-nextcloud}}"
# Nextcloud keeps its whole application tree (core code, installed
# apps, the config/ dir with config.php, and — by default — the data/
# uploads dir) under /var/www/html.  The upstream image declares that
# path as an anonymous VOLUME, but OpenHost does NOT persist
# container volumes across rebuilds: every ``update`` reload gives the
# container a fresh empty /var/www/html.  With an empty tree the
# upstream entrypoint sees no version.php, decides the instance is
# uninstalled, and runs ``maintenance:install`` again — which then
# collides with the STILL-persistent Postgres database
# ("The Login is already being used") and wedges the container in a
# retry loop.
#
# We therefore keep the state that must survive a rebuild on the
# persistent app_data mount (HTML_PERSIST) and, on each boot, copy it
# INTO the fresh /var/www/html volume before the upstream entrypoint
# runs and copy it back OUT once Apache is up — so config.php and
# version.php survive rebuilds and the upstream entrypoint takes its
# ``upgrade`` path instead of ``install``.  A bind mount would be
# simpler but is denied under rootless podman.  See
# persist_html_state_in / persist_html_state_out below.
HTML_DIR="/var/www/html"
HTML_PERSIST="$DATA_DIR/html"
# Nextcloud's scratch dir (chunked-upload assembly, file conversions,
# zip-download staging).  Lives on LOCAL temp disk — never on the
# S3-backed archive that holds the data dir.  Created + chowned here
# in start.sh (which runs as root) because the before-starting hook
# runs as the unprivileged www-data and can't mkdir under the
# root-owned temp mount.  Exported so the hook can point Nextcloud's
# ``tempdirectory`` config at it.
export NEXTCLOUD_TMP_DIR="$TMP_DIR/nextcloud-tmp"

mkdir -p "$DATA_DIR" "$TMP_DIR" "$REDIS_DIR" "$NEXTCLOUD_TMP_DIR" /run/postgresql /run/redis
chown postgres:postgres /run/postgresql 2>/dev/null || true
# www-data (Apache+PHP) must be able to write scratch files here.
chown www-data:www-data "$NEXTCLOUD_TMP_DIR" 2>/dev/null || true

# ---------------------------------------------------------------------
# Resolve the externally-facing host so Nextcloud's overwrite.* values
# are right and ``trusted_domains`` accepts the host header arriving
# from the OpenHost router.
# ---------------------------------------------------------------------
resolve_domain() {
    if [[ -n "${NEXTCLOUD_DOMAIN:-}" ]]; then
        printf '%s' "$NEXTCLOUD_DOMAIN"
        return
    fi
    if [[ -n "${OPENHOST_ZONE_DOMAIN:-}" ]]; then
        printf '%s.%s' "${OPENHOST_APP_NAME:-nextcloud}" "$OPENHOST_ZONE_DOMAIN"
        return
    fi
    # No useful env at all — fall back to localhost so first-boot
    # ``occ maintenance:install`` doesn't fail validating
    # ``trusted_domains``.  In production the OpenHost env vars are
    # always set; this is just a safe default for ad-hoc local use.
    printf 'localhost'
}

DOMAIN="$(resolve_domain)"
log "DOMAIN=$DOMAIN"
log "DATA_DIR=$DATA_DIR"

# ---------------------------------------------------------------------
# Persist Nextcloud's state across container rebuilds.
#
# /var/www/html is an ephemeral podman volume under OpenHost.  We keep
# the pieces of Nextcloud state that MUST survive a rebuild on the
# persistent app_data mount:
#
#   * config/config.php — DB creds, instanceid, secret, trusted_domains,
#                         the user_saml settings, ...  Without it a
#                         rebuild re-runs ``maintenance:install`` and
#                         collides with the persistent Postgres DB
#                         ("The Login is already being used").
#   * version.php       — the upstream entrypoint reads this to decide
#                         install-vs-upgrade; persisting it makes a
#                         rebuild take the ``upgrade`` path.
#   * custom_apps/      — apps installed after image build.
#   * themes/           — custom themes.
#
# User files (the ``datadirectory``: every user's uploads, plus
# nextcloud.log and the preview appdata) do NOT live on app_data — they
# live on the S3-backed ARCHIVE tier (see PERSIST_DATA_DIR / ARCHIVE_DIR
# below and the env block).  They are therefore NOT part of this
# copy-in/copy-out set: the archive is its own durable store and is
# mounted directly into the container, so nothing about it needs
# rebuild-time copying.
#
# We use a COPY-IN / COPY-OUT scheme rather than symlinks.  Symlinks
# do not survive the upstream entrypoint: its top-level
# ``rsync --delete --exclude-from=/upgrade.exclude`` removes a
# destination ``config`` symlink (the ``/config/`` exclude protects
# the contents from transfer but not the symlink from --delete), and
# its ``rsync --include /version.php`` replaces a dangling
# version.php symlink with a real file.  Both were verified
# empirically.  Copy-in before the entrypoint runs, copy-out after
# it has settled (persist_html_state_out, called once Apache is up).
# Nextcloud's user-file data directory lives on the ARCHIVE tier
# (S3-backed), NOT on local app_data.  This is the whole point of this
# app declaring ``app_archive = true``: user uploads scale to object
# storage and don't bloat the local disk or the restic backup.  We give
# Nextcloud its own subdirectory of the archive mount so a future
# co-tenant of the same archive namespace can't collide.
PERSIST_DATA_DIR="$ARCHIVE_DIR/data"
PERSIST_DIRS=(custom_apps themes)

# Copy persistent state INTO the fresh volume before the upstream
# entrypoint runs, so it sees an existing install (version.php +
# config.php present) and takes the upgrade path instead of
# reinstalling.
persist_html_state_in() {
    mkdir -p "$HTML_PERSIST" "$PERSIST_DATA_DIR"
    # The app_data mount is created owned by the container's root
    # (uid 0), but the upstream install and Apache run as www-data
    # (uid 33) and must be able to create/write the data dir and the
    # persisted tree.  chown the whole persistent tree up front.  This
    # may fail under rootless podman's uid remapping (hence ``|| true``
    # elsewhere) but on OpenHost the container is root-in-userns so it
    # succeeds and is required for the install to proceed
    # ("Cannot create or write into the data directory ...").
    chown -R www-data:www-data "$HTML_PERSIST" 2>/dev/null || true
    # The user-file data dir lives on the archive mount (a separate mount
    # from HTML_PERSIST).  www-data must own it AND its contents — not just
    # for uploads under ``<user>/files`` but also for Nextcloud's own
    # ``appdata_<instanceid>`` (JS/preview caches it writes on the fly, e.g.
    # when rendering a public share page).  Shallow-chown the parent dirs
    # first so provisioning can create children.  Then, ONLY when the tree
    # is not already www-data-owned, chown it recursively: this repairs the
    # 0:0 ownership left by a platform-side ``local``->S3 migration (whose
    # copy runs as namespace-root), while avoiding a slow deep -R over the
    # S3-backed FS on every normal boot (where ownership is already right).
    chown www-data:www-data "$ARCHIVE_DIR" "$PERSIST_DATA_DIR" 2>/dev/null || true
    if [[ -d "$PERSIST_DATA_DIR" ]]; then
        # ``find -not -user www-data -print -quit`` returns a line iff at
        # least one entry has the wrong owner — a cheap early-exit probe
        # that doesn't walk the whole tree when everything is already fine.
        if [[ -n "$(find "$PERSIST_DATA_DIR" -not -user www-data -print -quit 2>/dev/null)" ]]; then
            log "archive data dir has non-www-data entries (e.g. after a local->S3 migration); chowning recursively"
            chown -R www-data:www-data "$PERSIST_DATA_DIR" 2>/dev/null || true
        fi
    fi

    # Populate the Nextcloud CORE CODE into the fresh volume ourselves.
    #
    # The upstream entrypoint only rsyncs /usr/src/nextcloud into
    # /var/www/html when it decides the on-disk version is OLDER than
    # the image version.  Once we restore a persisted version.php (so a
    # rebuild takes the upgrade path instead of reinstalling), the
    # on-disk version EQUALS the image version, so the entrypoint skips
    # that rsync entirely — leaving a fresh volume with NO index.php or
    # core code and Apache serving 403.  We therefore seed the code
    # ourselves whenever the volume is missing it, mirroring the
    # entrypoint's own rsync but WITHOUT --delete (we must not wipe the
    # config/version.php we are about to restore) and excluding the
    # state paths we manage.  The ``! -f index.php`` guard means this
    # only runs on a fresh/empty volume, so the (rare) boot where code
    # is already present skips it entirely.
    if [[ ! -f "$HTML_DIR/index.php" ]]; then
        log "seeding Nextcloud core code into fresh volume"
        # Copy everything EXCEPT version.php and data (we manage those).
        # We DO let the image's config/ defaults (redis.config.php,
        # reverse-proxy.config.php, apcu.config.php, ...) through — the
        # persisted config.php is layered on top afterwards.  No
        # --delete: we must not wipe state we're about to restore.
        rsync -rlD \
            --exclude '/data/***' \
            --exclude '/version.php' \
            /usr/src/nextcloud/ "$HTML_DIR/" \
            || log "warning: core code seed rsync returned non-zero"
        chown -R www-data:www-data "$HTML_DIR" 2>/dev/null || true
    fi
    if [[ -f "$HTML_PERSIST/config.php" ]]; then
        log "restoring persisted config.php into volume"
        mkdir -p "$HTML_DIR/config"
        cp -a "$HTML_PERSIST/config.php" "$HTML_DIR/config/config.php"
    fi
    if [[ -f "$HTML_PERSIST/version.php" ]]; then
        log "restoring persisted version.php into volume"
        cp -a "$HTML_PERSIST/version.php" "$HTML_DIR/version.php"
    fi
    local d
    for d in "${PERSIST_DIRS[@]}"; do
        if [[ -d "$HTML_PERSIST/$d" ]] && [[ -n "$(ls -A "$HTML_PERSIST/$d" 2>/dev/null)" ]]; then
            log "restoring persisted $d into volume"
            mkdir -p "$HTML_DIR/$d"
            cp -a "$HTML_PERSIST/$d/." "$HTML_DIR/$d/"
        fi
    done
    chown -R www-data:www-data "$HTML_DIR/config" "$HTML_DIR/version.php" 2>/dev/null || true
}

# Copy state BACK OUT to persistent storage after the entrypoint has
# installed/upgraded.  Called once Apache is confirmed listening, so
# config.php (written by maintenance:install) and the current
# version.php exist.  Idempotent: safe to run on every boot.
persist_html_state_out() {
    if [[ -f "$HTML_DIR/config/config.php" ]]; then
        cp -a "$HTML_DIR/config/config.php" "$HTML_PERSIST/config.php.partial" \
            && mv "$HTML_PERSIST/config.php.partial" "$HTML_PERSIST/config.php" \
            && log "persisted config.php to app_data" \
            || log "warning: failed to persist config.php"
    fi
    if [[ -f "$HTML_DIR/version.php" ]]; then
        cp -a "$HTML_DIR/version.php" "$HTML_PERSIST/version.php.partial" \
            && mv "$HTML_PERSIST/version.php.partial" "$HTML_PERSIST/version.php" \
            && log "persisted version.php to app_data" \
            || log "warning: failed to persist version.php"
    fi
    local d
    for d in "${PERSIST_DIRS[@]}"; do
        if [[ -d "$HTML_DIR/$d" ]] && [[ -n "$(ls -A "$HTML_DIR/$d" 2>/dev/null)" ]]; then
            mkdir -p "$HTML_PERSIST/$d"
            cp -a "$HTML_DIR/$d/." "$HTML_PERSIST/$d/" 2>/dev/null \
                && log "persisted $d to app_data" \
                || log "warning: failed to persist $d"
        fi
    done
    chown -R www-data:www-data "$HTML_PERSIST" 2>/dev/null || true
}
mkdir -p "$HTML_PERSIST"
persist_html_state_in

# ---------------------------------------------------------------------
# Generate / load the postgres password.  We keep it in a side file
# (chmod 644) so the file-browser app can read it; the postgres role
# uses ``md5`` auth so an attacker with read access still needs to
# reach 127.0.0.1:5432 from inside the container — outside the
# container the postgres port is not exposed.
# ---------------------------------------------------------------------
load_or_generate() {
    local file="$1"
    local current head_rc
    if [[ -s "$file" ]]; then
        # Strip any trailing newline that openssl adds.  Don't read
        # multi-line files: a corrupted password file with embedded
        # newlines would otherwise feed garbage into postgres.
        #
        # We capture head's exit code separately so a permission /
        # read failure surfaces as a FATAL error rather than silently
        # producing an empty ``current`` and unsafely regenerating
        # the password (which would de-sync our file from postgres'
        # role password and break every subsequent connection).
        #
        # Append ``|| head_rc=$?`` to the substitution so a failed
        # ``head`` doesn't trip ``set -e`` and exit the script
        # before our diagnostic log line runs.  Without this guard,
        # under bash 5.x the failed command-substitution can abort
        # before ``head_rc=$?`` is evaluated, and the operator gets
        # only a generic shell-error exit instead of our FATAL
        # message.
        head_rc=0
        current=$(head -n1 "$file" 2>/dev/null) || head_rc=$?
        if [[ "$head_rc" -ne 0 ]]; then
            log "FATAL: failed to read $file (head exit $head_rc); not regenerating to avoid file/db drift"
            log "  if the file is genuinely corrupt, delete it and re-run; otherwise check permissions"
            exit 1
        fi
        # Detect "all-whitespace" content (including only spaces /
        # tabs / CR / LF) as corrupt.  Use a separate check that
        # doesn't mangle the actual returned password — we want to
        # preserve any internal characters the operator might have
        # set.  Trim trailing whitespace (newline / CR from openssl,
        # plus any operator-added trailing space) but leave the
        # body alone.
        local stripped_check
        stripped_check=$(printf '%s' "$current" | tr -d '[:space:]')
        if [[ -z "$stripped_check" ]]; then
            log "warning: $file present but empty/whitespace-only; regenerating"
        else
            # Trim trailing whitespace only; the password itself
            # must not have internal whitespace under our own
            # generator (openssl rand -hex 16) but operator edits
            # might inadvertently add it, so we don't fully strip.
            current="${current%"${current##*[![:space:]]}"}"
            printf '%s' "$current"
            return
        fi
    fi
    local fresh
    if ! fresh=$(openssl rand -hex 16); then
        log "FATAL: openssl rand -hex 16 failed (cannot generate password)"
        exit 1
    fi
    if [[ ${#fresh} -ne 32 ]]; then
        log "FATAL: openssl rand produced unexpected output (len=${#fresh})"
        exit 1
    fi
    # Atomic write via .partial + mv so a SIGKILL between truncate and
    # write can't leave an empty password file behind.
    local partial="$file.partial"
    if ! printf '%s\n' "$fresh" > "$partial"; then
        log "FATAL: failed to write $partial"
        rm -f "$partial" 2>/dev/null || true
        exit 1
    fi
    if ! mv "$partial" "$file"; then
        log "FATAL: failed to mv $partial -> $file"
        rm -f "$partial" 2>/dev/null || true
        exit 1
    fi
    # 644 not 600: under rootless podman, the file-browser app
    # (which the operator uses to retrieve these passwords via the
    # OpenHost data API) runs in a different container with a
    # different UID and ACL set.  600 would block the legitimate
    # operator-readback path.
    #
    # Tradeoff: any process inside THIS container running as
    # ``www-data`` (Apache+PHP), ``redis``, or otherwise non-root
    # can also read these files.  We mitigate this for the postgres
    # password via pg_hba.conf — see the ``local all all reject``
    # entry there: PHP can read the password file but its postgres
    # connection must still go through TCP+md5 with the same
    # password it already needs to know to do its job.  The
    # admin password is an emergency credential whose disclosure
    # to PHP is horizontal (PHP already has equivalent privilege
    # via SSO when properly authenticated).
    chmod 644 "$file"
    printf '%s' "$fresh"
}

POSTGRES_PASSWORD="$(load_or_generate "$PG_PASSWORD_FILE")"
NEXTCLOUD_ADMIN_PASSWORD="$(load_or_generate "$ADMIN_PASSWORD_FILE")"

# ---------------------------------------------------------------------
# Initialise PostgreSQL on first boot
# ---------------------------------------------------------------------
PG_BIN=""
for d in /usr/lib/postgresql/*/bin; do
    if [[ -x "$d/postgres" ]]; then
        PG_BIN="$d"
        break
    fi
done
if [[ -z "$PG_BIN" ]]; then
    log "FATAL: no PostgreSQL binaries found under /usr/lib/postgresql/*/bin"
    exit 1
fi
log "using postgres at $PG_BIN"

if [[ ! -f "$PG_DATA/PG_VERSION" ]]; then
    log "initialising PostgreSQL cluster at $PG_DATA"
    mkdir -p "$PG_DATA"
    chown postgres:postgres "$PG_DATA" 2>/dev/null || true
    # ``--auth=trust`` for the bootstrap superuser only; the nextcloud
    # role we'll create later uses md5 auth via pg_hba below.
    su postgres -c "$PG_BIN/initdb -D '$PG_DATA' --auth-local=trust --auth-host=md5 --encoding=UTF8 --locale=C.UTF-8"

    # Listen on 127.0.0.1 over TCP because the upstream Nextcloud
    # image's php-pgsql can't easily be persuaded to use the unix
    # socket from PHP (it can technically, but the env-var driven
    # upstream entrypoint passes ``host=`` rather than the socket
    # path).  pg_hba below uses ``peer`` auth on the unix socket so
    # the OS user identity is checked at the kernel level: the
    # ``postgres`` OS user can authenticate as the ``postgres``
    # role (used for bootstrap by start.sh + provision_db); any
    # other OS user (including ``www-data`` running PHP) is
    # rejected at the socket layer and MUST go through TCP + md5
    # with the generated password.  ``trust`` would have allowed
    # ``www-data`` (or any other OS user) to claim the postgres
    # role passwordlessly — a real privilege-escalation gap.
    cat > "$PG_DATA/pg_hba.conf" <<'EOF'
# OpenHost-managed: peer auth ties the postgres role to the
# postgres OS user; reject all other socket connections.
local   all postgres                  peer
local   all all                       reject
host    all all      127.0.0.1/32     md5
host    all all      ::1/128          md5
host    all all      0.0.0.0/0        reject
host    all all      ::/0             reject
EOF

    # Tune for a small container.
    cat >> "$PG_DATA/postgresql.conf" <<'EOF'

# OpenHost tuning
listen_addresses = '127.0.0.1'
unix_socket_directories = '/run/postgresql'
shared_buffers = 128MB
work_mem = 8MB
maintenance_work_mem = 32MB
max_connections = 50
log_min_messages = warning
EOF
fi

chown -R postgres:postgres "$PG_DATA" 2>/dev/null || true

# Clear any stale postmaster.pid from an unclean shutdown.  Postgres
# is conservative and refuses to start if it sees a .pid file; we know
# only one postgres is running per container, so removing it here is
# safe.
rm -f "$PG_DATA/postmaster.pid"

PG_LOG="$PG_DATA/postgresql.log"

# Initialise the supervisor PIDs and the cleanup machinery BEFORE
# starting Postgres.  Postgres is started via ``pg_ctl`` so it
# forks into the background and is not a direct child of this
# shell — without an EXIT-trap-driven cleanup, an exit before the
# main supervisor section (e.g. provision_db failure) would leave
# Postgres running as an orphan tied to the now-dead container.
REDIS_PID=""
APACHE_PID=""
PROXY_PID=""
PG_WATCHDOG_PID=""
TERMINATING=0
cleanup() {
    if [[ "$TERMINATING" == "1" ]]; then
        return
    fi
    TERMINATING=1
    log "tearing down"
    # Capture any state written since this boot's post-Apache copy-out
    # (e.g. an extension the operator installed from the web UI, or a
    # config.php change) so it survives the rebuild.  Guarded on
    # index.php so we never copy out a half-populated volume, and
    # ``|| true`` so a copy failure never blocks teardown.  Runs before
    # we stop Apache/Postgres so the on-disk files are quiescent copies
    # of what the running instance was using.
    if [[ -f "$HTML_DIR/index.php" ]]; then
        persist_html_state_out || true
    fi
    kill -TERM ${APACHE_PID:-} ${PROXY_PID:-} ${REDIS_PID:-} \
              ${PG_WATCHDOG_PID:-} 2>/dev/null || true
    # Postgres is not a direct child; stop it via pg_ctl.
    su postgres -c "$PG_BIN/pg_ctl stop -D '$PG_DATA' -m fast" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup TERM INT EXIT

log "starting postgres"
# We use ``pg_ctl start`` (not ``postgres -D``) so postgres forks into
# the background and we can wait for it to be ready before continuing
# (the ``-w`` flag).  The tradeoff: postgres' PID is not a direct
# child of our shell, so ``wait -n`` won't see it die.  We compensate
# with the pg_isready watchdog later in the supervisor section, and
# the EXIT trap above guarantees we tear it down on any exit path.
#
# pg_ctl directs Postgres' own startup messages to ``$PG_LOG`` (a
# file in the data dir), not to the supervisor's stderr.  If pg_ctl
# fails, we'd otherwise see only a generic bash error.  Catch the
# failure and tail the log into our stderr so the operator sees
# the cause from container logs alone.
if ! su postgres -c "$PG_BIN/pg_ctl start -D '$PG_DATA' -l '$PG_LOG' -w -t 60 -o '-k /run/postgresql'"; then
    log "FATAL: pg_ctl start failed; recent postgres log lines follow:"
    if [[ -r "$PG_LOG" ]]; then
        # ``tail -n 50`` captures plenty of context without
        # overwhelming the log; postgres errors are usually within
        # the last few lines.
        while IFS= read -r line; do
            log "  pg: $line"
        done < <(tail -n 50 "$PG_LOG" 2>/dev/null || echo "(could not read $PG_LOG)")
    else
        log "  (postgres log file at $PG_LOG is not readable)"
    fi
    exit 1
fi

# ---------------------------------------------------------------------
# Provision nextcloud role + database
# ---------------------------------------------------------------------
provision_db() {
    local db_exists role_exists
    db_exists=$(su postgres -c "psql -h /run/postgresql -tAc \"SELECT 1 FROM pg_database WHERE datname='nextcloud'\"" 2>/dev/null || true)
    role_exists=$(su postgres -c "psql -h /run/postgresql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='nextcloud'\"" 2>/dev/null || true)

    # Send the SQL (which carries the plaintext password) via stdin
    # instead of the ``-c`` argument so the password never appears in
    # ``/proc/<pid>/cmdline``.  ``psql -f -`` reads SQL from stdin.
    # We escape any single-quote in the password by doubling it (the
    # standard SQL literal escape).  ``ON_ERROR_STOP=1`` ensures
    # psql exits non-zero on any SQL error.
    local escaped_pw="${POSTGRES_PASSWORD//\'/\'\'}"

    if [[ "$role_exists" != "1" ]]; then
        log "creating nextcloud role"
        if ! printf "CREATE ROLE nextcloud LOGIN PASSWORD '%s';\n" "$escaped_pw" \
                | su postgres -c "psql -h /run/postgresql -v ON_ERROR_STOP=1 -f -" >/dev/null; then
            log "FATAL: failed to create nextcloud role"
            return 1
        fi
    else
        # Role exists: re-set the password to the file's value so a
        # password rotation (operator hand-edits the side file)
        # propagates on next boot.  The check above means we always
        # reach this branch when the role already exists.
        #
        # If ALTER fails we abort the boot — continuing would leave
        # the password file out of sync with the database role, and
        # every subsequent Nextcloud connection would 500 with an
        # authentication error.  Better to fail loudly here so the
        # operator can investigate.
        if ! printf "ALTER ROLE nextcloud WITH PASSWORD '%s';\n" "$escaped_pw" \
                | su postgres -c "psql -h /run/postgresql -v ON_ERROR_STOP=1 -f -" >/dev/null; then
            log "FATAL: failed to ALTER nextcloud role password — file/db now out of sync; aborting boot"
            return 1
        fi
    fi

    if [[ "$db_exists" != "1" ]]; then
        log "creating nextcloud database"
        if ! su postgres -c "createdb -h /run/postgresql -O nextcloud nextcloud" >/dev/null; then
            log "FATAL: failed to create nextcloud database"
            return 1
        fi
    fi
    return 0
}
if ! provision_db; then
    log "FATAL: database provisioning failed"
    exit 1
fi

# ---------------------------------------------------------------------
# Start Redis (foreground child of our shell)
# ---------------------------------------------------------------------
REDIS_CONF="$TMP_DIR/redis.conf"
# Prefer the unix socket for Nextcloud <-> Redis traffic: it's faster
# than the TCP loopback and needs no port.  We disable TCP entirely
# (``port 0``) so Redis is reachable ONLY via the socket — nothing
# outside this container can reach it, and even in-container processes
# must be in the ``redis`` group (``unixsocketperm 770``) to connect.
# Nextcloud (Apache+PHP running as www-data) is added to the ``redis``
# group in the Dockerfile so it can open the socket.
cat > "$REDIS_CONF" <<EOF
port 0
unixsocket /run/redis/redis.sock
unixsocketperm 770
dir $REDIS_DIR
appendonly no
save ""
daemonize no
loglevel notice
maxmemory 128mb
maxmemory-policy allkeys-lru
EOF
chmod 644 "$REDIS_CONF"
chown -R redis:redis "$REDIS_DIR" /run/redis 2>/dev/null || true

# Cleanup machinery + trap were registered earlier, before the
# pg_ctl call.  See the block above the postgres startup for
# details.

log "starting redis"
# Drop redis to its dedicated ``redis`` user (the Debian package
# creates the user + group) so it doesn't run as root.  Running
# Redis as root triggers a startup warning and is a defense-in-
# depth gap — a Redis RCE would otherwise have full container-root
# privileges instead of being scoped to the redis user.  ``su`` is
# used (rather than ``runuser``) for portability across the
# multiple base images we may be derived from.
if id redis >/dev/null 2>&1; then
    su redis -s /bin/sh -c "redis-server '$REDIS_CONF'" &
else
    log "warning: 'redis' user not found; falling back to running redis-server as root"
    redis-server "$REDIS_CONF" &
fi
REDIS_PID=$!

# Wait for redis to be READY (responding to PING), not just alive.
# A slow-starting Redis would otherwise pass a kill -0 liveness check
# while still rejecting connections, causing Nextcloud's first cache
# / file-locking calls to fail.  Apache's readiness loop uses the
# same flag-based pattern.
REDIS_READY_TIMEOUT="${REDIS_READY_TIMEOUT:-30}"
# Sanity-clamp: 0 (or non-positive) would produce no loop iterations
# and immediately fail with a misleading "did not respond within 0s"
# log line.  Force a minimum of 1 second.
if ! [[ "$REDIS_READY_TIMEOUT" =~ ^[0-9]+$ ]] || (( REDIS_READY_TIMEOUT < 1 )); then
    log "warning: REDIS_READY_TIMEOUT='$REDIS_READY_TIMEOUT' is not a positive integer; using default 30"
    REDIS_READY_TIMEOUT=30
fi
redis_ready=0
for _ in $(seq 1 "$REDIS_READY_TIMEOUT"); do
    if redis-cli -s /run/redis/redis.sock ping 2>/dev/null | grep -q PONG; then
        redis_ready=1
        break
    fi
    if ! kill -0 "$REDIS_PID" 2>/dev/null; then
        log "FATAL: redis died during startup"
        wait "$REDIS_PID" || true
        exit 1
    fi
    sleep 1
done
if [[ "$redis_ready" != "1" ]]; then
    log "FATAL: redis did not respond to PING within ${REDIS_READY_TIMEOUT}s"
    kill -TERM "$REDIS_PID" 2>/dev/null || true
    wait "$REDIS_PID" || true
    exit 1
fi
log "redis is ready"

# ---------------------------------------------------------------------
# Configure Nextcloud env so the upstream entrypoint runs install/upgrade
# correctly.  See https://hub.docker.com/_/nextcloud for the full list.
# ---------------------------------------------------------------------
export POSTGRES_HOST="127.0.0.1"
export POSTGRES_DB="nextcloud"
export POSTGRES_USER="nextcloud"
export POSTGRES_PASSWORD
# Point Nextcloud at the Redis UNIX SOCKET.  The upstream image's
# redis.config.php treats a REDIS_HOST beginning with "/" as a socket
# path and, in that case, omits the port entirely (see the base
# image's config/redis.config.php).  Redis itself has TCP disabled
# (``port 0`` in the generated redis.conf above), so the socket is the
# only transport.  This wires Redis in as Nextcloud's distributed
# cache AND file-locking backend (memcache.distributed +
# memcache.locking), which redis.config.php sets whenever REDIS_HOST
# is present; APCu (apcu.config.php) remains the local cache.
export REDIS_HOST="/run/redis/redis.sock"
# REDIS_HOST_PORT intentionally unset: redis.config.php skips the port
# for a socket-path host.  Leaving a stale "6379" here would make the
# config include ``'port' => 6379`` alongside a socket host, which the
# phpredis client rejects.
unset REDIS_HOST_PORT
export NEXTCLOUD_ADMIN_USER="${NEXTCLOUD_ADMIN_USER:-admin}"
export NEXTCLOUD_ADMIN_PASSWORD
# User-file data dir lives on the S3-backed ARCHIVE tier (see
# PERSIST_DATA_DIR / ARCHIVE_DIR above), NOT on the ephemeral
# /var/www/html volume or local app_data.  The upstream entrypoint
# passes this to ``occ maintenance:install --data-dir`` on first boot
# and, once config.php records ``datadirectory``, Nextcloud keeps using
# it on every subsequent boot regardless of this env var — but we keep
# exporting it so a from-scratch reinstall lands in the right place too.
export NEXTCLOUD_DATA_DIR="$PERSIST_DATA_DIR"
# trusted_domains: the public hostname.  We add 127.0.0.1 too so
# health-check probes from inside the container don't get rejected.
export NEXTCLOUD_TRUSTED_DOMAINS="$DOMAIN 127.0.0.1 localhost"
# trusted_proxies: the auth-sidecar at 127.0.0.1 is the only entity
# allowed to set the X-Openhost-User header that user_saml will read.
export TRUSTED_PROXIES="127.0.0.1/32"
# overwrite.* tells Nextcloud the request URL it would have received
# directly even though it actually got it from a reverse proxy.
export OVERWRITEHOST="$DOMAIN"
case "${OPENHOST_ZONE_DOMAIN:-}" in
    lvh.me|*.lvh.me|localhost|*.localhost)
        export OVERWRITEPROTOCOL="http"
        export OVERWRITECLIURL="http://$DOMAIN"
        ;;
    *)
        export OVERWRITEPROTOCOL="https"
        export OVERWRITECLIURL="https://$DOMAIN"
        ;;
esac
# Disable the entrypoint's Apache helpful X-Forwarded-* parsing — we
# inject our own trusted-proxy setup via ``trusted_proxies`` above.
export APACHE_DISABLE_REWRITE_IP="1"
# Surface the domain to before-starting hooks so they can re-stamp
# overwrite.* idempotently on every boot.
export OPENHOST_NEXTCLOUD_DOMAIN="$DOMAIN"

# ---------------------------------------------------------------------
# Start the auth-proxy FIRST, before the (slow) Nextcloud first-boot
# install.  The proxy is what listens on the OpenHost-routed port
# (:8080), and OpenHost's readiness probe polls that port with only a
# ~60s deadline.  Nextcloud's first boot (Postgres init + install + SSO
# config + pre-installing the Hub extensions) runs well past 60s, so if
# the proxy only started AFTER Apache was ready the app would be marked
# "error: App started but not responding to HTTP" every first boot even
# though it comes up fine minutes later.
#
# The proxy serves /_healthz and a cold-start placeholder on "/" while
# Apache (127.0.0.1:$APACHE_PORT) is still unreachable, so the readiness
# probe passes immediately; once Apache binds, real traffic flows
# through.  The proxy has no start-time dependency on Apache being up.
log "starting auth-proxy on :${AUTH_PROXY_LISTEN_PORT:-8080} (before nextcloud install)"
python3 /usr/local/bin/auth_proxy.py &
PROXY_PID=$!

log "starting nextcloud (apache2-foreground via upstream entrypoint)"
# The upstream ENTRYPOINT script runs install/upgrade hooks (which
# includes our /docker-entrypoint-hooks.d/post-installation/01-openhost-sso.sh)
# and then exec's the supplied command.  We pass ``apache2-foreground``
# so apache stays attached to our shell and ``wait -n`` sees it.
/entrypoint.sh apache2-foreground &
APACHE_PID=$!

# Wait for Apache to bind 127.0.0.1:8081 before starting the sidecar
# so the very first request doesn't 502.  We try ``APACHE_READY_TIMEOUT``
# times at 1s intervals.  If Apache stays alive but never binds the
# port (e.g. a misconfigured vhost that aborts during ServerName
# resolution), we treat that as a fatal startup error rather than
# silently letting the sidecar serve 502s indefinitely.
APACHE_READY_TIMEOUT="${APACHE_READY_TIMEOUT:-90}"
if ! [[ "$APACHE_READY_TIMEOUT" =~ ^[0-9]+$ ]] || (( APACHE_READY_TIMEOUT < 1 )); then
    log "warning: APACHE_READY_TIMEOUT='$APACHE_READY_TIMEOUT' is not a positive integer; using default 90"
    APACHE_READY_TIMEOUT=90
fi
apache_ready=0
for _ in $(seq 1 "$APACHE_READY_TIMEOUT"); do
    if APACHE_PORT="${APACHE_PORT:-8081}" python3 -c '
import os, socket, sys
with socket.socket() as s:
    s.settimeout(0.5)
    sys.exit(0 if s.connect_ex(("127.0.0.1", int(os.environ["APACHE_PORT"]))) == 0 else 1)
' 2>/dev/null; then
        log "apache is listening"
        apache_ready=1
        break
    fi
    if ! kill -0 "$APACHE_PID" 2>/dev/null; then
        log "FATAL: apache died during startup"
        wait "$APACHE_PID" || true
        exit 1
    fi
    sleep 1
done
if [[ "$apache_ready" != "1" ]]; then
    log "FATAL: apache did not bind 127.0.0.1:${APACHE_PORT:-8081} within ${APACHE_READY_TIMEOUT}s"
    kill -TERM "$APACHE_PID" 2>/dev/null || true
    wait "$APACHE_PID" || true
    exit 1
fi

# Apache is up, which means the upstream entrypoint has finished its
# install/upgrade and written config.php + version.php.  Copy that
# state back out to app_data so the next rebuild restores it.  This
# is the second half of the copy-in / copy-out persistence scheme
# (see persist_html_state_in at the top of this script).
persist_html_state_out

# (The auth-proxy was already started above, before the Nextcloud
# install, so it could answer OpenHost's readiness probe during the
# slow first boot.  It is now transparently forwarding to the
# now-ready Apache.)

# Postgres was started via ``pg_ctl start`` so it's NOT a direct child
# of this shell — ``wait -n`` cannot see it die.  Without intervention,
# a postgres crash would leave Apache running and serving 500s
# indefinitely.  Run a small watchdog as a real child of this shell:
# every ``PG_WATCHDOG_INTERVAL`` seconds it pings postgres via
# ``pg_isready``; on three consecutive failures it exits non-zero,
# which trips the ``wait -n`` cleanup path and tears the container
# down so OpenHost restarts it.  Three strikes (not one) avoids
# false positives during, e.g., a brief WAL replay or a momentary
# socket-unavailability blip from postgres rotating its log.
PG_WATCHDOG_INTERVAL="${PG_WATCHDOG_INTERVAL:-15}"
if ! [[ "$PG_WATCHDOG_INTERVAL" =~ ^[0-9]+$ ]] || (( PG_WATCHDOG_INTERVAL < 1 )); then
    log "warning: PG_WATCHDOG_INTERVAL='$PG_WATCHDOG_INTERVAL' is not a positive integer; using default 15"
    PG_WATCHDOG_INTERVAL=15
fi
(
    set +e
    fails=0
    while :; do
        sleep "$PG_WATCHDOG_INTERVAL"
        if "$PG_BIN/pg_isready" -h /run/postgresql -q; then
            fails=0
        else
            fails=$((fails + 1))
            log "postgres watchdog: pg_isready failed ($fails consecutive)"
            if [[ $fails -ge 3 ]]; then
                log "postgres watchdog: 3 consecutive failures, exiting"
                exit 1
            fi
        fi
    done
) &
PG_WATCHDOG_PID=$!

# ---------------------------------------------------------------------
# Supervise the children.  ``wait -n`` returns when any one exits.
# ``set -e`` is suppressed around it so a non-zero child exit doesn't
# bypass our cleanup.
# ---------------------------------------------------------------------
set +e
wait -n "$APACHE_PID" "$PROXY_PID" "$REDIS_PID" "$PG_WATCHDOG_PID"
EXIT_CODE=$?
set -e

log "child exited (code=$EXIT_CODE); stopping container"
# The EXIT trap handles teardown; just exit with the right code.
exit "$EXIT_CODE"
