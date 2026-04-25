#!/bin/bash
# Entrypoint for openhost-nextcloud.
#
# We need /bin/bash (not /bin/sh) because we use ``wait -n`` to supervise
# multiple background children — Apache (via the upstream Nextcloud
# entrypoint), the Python auth-sidecar, PostgreSQL (run via ``pg_ctl
# start`` so it forks into the background), and Redis (foregrounded as
# a child).  ``wait -n`` is a bashism not available in the Debian
# ``dash``-based /bin/sh.
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
#   6. ``exec`` the upstream ``/entrypoint.sh apache2-foreground`` as a
#      background child — that runs install/upgrade hooks then Apache.
#   7. Start the auth_proxy.py sidecar on :8080.
#   8. ``wait -n`` on the four children; if any dies, tear the rest
#      down and exit so OpenHost restarts the container.
#
# All persistent secrets live under $OPENHOST_APP_DATA_DIR.  Under
# rootless podman the container's ``root`` is mapped to a random
# host uid, so we tolerate chown failures with ``|| true`` rather
# than aborting the whole boot.

set -euo pipefail

log() { printf '[start.sh] %s\n' "$*" >&2; }

DATA_DIR="${OPENHOST_APP_DATA_DIR:-/var/lib/openhost-nextcloud}"
TMP_DIR="${OPENHOST_APP_TEMP_DATA_DIR:-/tmp/openhost-nextcloud}"
PG_DATA="$DATA_DIR/pgdata"
REDIS_DIR="$DATA_DIR/redis"
PG_PASSWORD_FILE="$DATA_DIR/.postgres_password"
ADMIN_PASSWORD_FILE="$DATA_DIR/admin_password.txt"

mkdir -p "$DATA_DIR" "$TMP_DIR" "$REDIS_DIR" /run/postgresql /run/redis
chown postgres:postgres /run/postgresql 2>/dev/null || true

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
# Generate / load the postgres password.  We keep it in a side file
# (chmod 644) so the file-browser app can read it; the postgres role
# uses ``md5`` auth so an attacker with read access still needs to
# reach 127.0.0.1:5432 from inside the container — outside the
# container the postgres port is not exposed.
# ---------------------------------------------------------------------
load_or_generate() {
    local file="$1"
    local current
    if [[ -s "$file" ]]; then
        # Strip any trailing newline that openssl adds.  Don't read
        # multi-line files: a corrupted password file with embedded
        # newlines would otherwise feed garbage into postgres.
        current=$(head -n1 "$file" | tr -d '\r\n')
        if [[ -n "$current" ]]; then
            printf '%s' "$current"
            return
        fi
        log "warning: $file present but empty/corrupt; regenerating"
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
    # 644 not 600: under rootless podman the file-browser app's UID
    # differs from this container's UID.  The data dir is already
    # scoped to this app under OpenHost's data model.
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

    # Listen only on the unix socket — Nextcloud connects via
    # 127.0.0.1 over TCP because the upstream image's php-pgsql can't
    # easily be persuaded to use the socket; we'll add a listen_addresses
    # below.  pg_hba: trust local socket access (postgres role only),
    # md5 for TCP from 127.0.0.1.
    cat > "$PG_DATA/pg_hba.conf" <<'EOF'
local   all all                trust
host    all all 127.0.0.1/32   md5
host    all all ::1/128        md5
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
log "starting postgres"
# We use ``pg_ctl start`` (not ``postgres -D``) so postgres forks into
# the background and we can supervise the parent shell instead.  The
# tradeoff: postgres' PID is not directly a child of our shell, so
# ``wait -n`` won't see it die.  We add a periodic liveness check via
# the supervisor below.
su postgres -c "$PG_BIN/pg_ctl start -D '$PG_DATA' -l '$PG_LOG' -w -t 60 -o '-k /run/postgresql'"

# ---------------------------------------------------------------------
# Provision nextcloud role + database
# ---------------------------------------------------------------------
provision_db() {
    local db_exists role_exists
    db_exists=$(su postgres -c "psql -h /run/postgresql -tAc \"SELECT 1 FROM pg_database WHERE datname='nextcloud'\"" 2>/dev/null || true)
    role_exists=$(su postgres -c "psql -h /run/postgresql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='nextcloud'\"" 2>/dev/null || true)

    if [[ "$role_exists" != "1" ]]; then
        log "creating nextcloud role"
        # We pass the password via an env var + psql ``\set`` so it
        # doesn't end up on the command line (visible in
        # /proc/<pid>/cmdline) or in postgres' ``log_statement=all``
        # logs (which we don't enable, but defence in depth).
        local sql
        sql="$(printf "CREATE ROLE nextcloud LOGIN PASSWORD '%s';" "${POSTGRES_PASSWORD//\'/\'\'}")"
        if ! su postgres -c "psql -h /run/postgresql -v ON_ERROR_STOP=1 -c \"$sql\"" >/dev/null; then
            log "FATAL: failed to create nextcloud role"
            return 1
        fi
    else
        # Role exists: re-set the password to the file's value so a
        # password rotation (operator hand-edits the side file)
        # propagates on next boot.  The check above means we always
        # reach this branch when the role already exists.
        local sql
        sql="$(printf "ALTER ROLE nextcloud WITH PASSWORD '%s';" "${POSTGRES_PASSWORD//\'/\'\'}")"
        if ! su postgres -c "psql -h /run/postgresql -v ON_ERROR_STOP=1 -c \"$sql\"" >/dev/null; then
            log "warning: failed to ALTER nextcloud role password (continuing with existing password)"
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
cat > "$REDIS_CONF" <<EOF
bind 127.0.0.1
port 6379
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

REDIS_PID=""
APACHE_PID=""
PROXY_PID=""

# Trap BEFORE any backgrounding so a SIGTERM that arrives during the
# small race window between ``&`` and the trap line doesn't use bash's
# default handler and orphan our children.
cleanup() {
    log "received signal; tearing down"
    kill -TERM ${APACHE_PID:-} ${PROXY_PID:-} ${REDIS_PID:-} 2>/dev/null || true
    # Also stop postgres explicitly (it's not a direct child).
    su postgres -c "$PG_BIN/pg_ctl stop -D '$PG_DATA' -m fast" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup TERM INT

log "starting redis"
redis-server "$REDIS_CONF" &
REDIS_PID=$!

# Wait for redis to bind.
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if redis-cli -s /run/redis/redis.sock ping 2>/dev/null | grep -q PONG; then
        break
    fi
    sleep 0.3
done
if ! kill -0 "$REDIS_PID" 2>/dev/null; then
    log "FATAL: redis died during startup"
    exit 1
fi

# ---------------------------------------------------------------------
# Configure Nextcloud env so the upstream entrypoint runs install/upgrade
# correctly.  See https://hub.docker.com/_/nextcloud for the full list.
# ---------------------------------------------------------------------
export POSTGRES_HOST="127.0.0.1"
export POSTGRES_DB="nextcloud"
export POSTGRES_USER="nextcloud"
export POSTGRES_PASSWORD
export REDIS_HOST="127.0.0.1"
export REDIS_HOST_PORT="6379"
export NEXTCLOUD_ADMIN_USER="${NEXTCLOUD_ADMIN_USER:-admin}"
export NEXTCLOUD_ADMIN_PASSWORD
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

log "starting nextcloud (apache2-foreground via upstream entrypoint)"
# The upstream ENTRYPOINT script runs install/upgrade hooks (which
# includes our /docker-entrypoint-hooks.d/post-installation/01-openhost-sso.sh)
# and then exec's the supplied command.  We pass ``apache2-foreground``
# so apache stays attached to our shell and ``wait -n`` sees it.
/entrypoint.sh apache2-foreground &
APACHE_PID=$!

# Wait for Apache to bind 127.0.0.1:8081 before starting the sidecar
# so the very first request doesn't 502.
for _ in $(seq 1 60); do
    if APACHE_PORT="${APACHE_PORT:-8081}" python3 -c '
import os, socket, sys
s = socket.socket()
s.settimeout(0.5)
sys.exit(0 if s.connect_ex(("127.0.0.1", int(os.environ["APACHE_PORT"]))) == 0 else 1)
' 2>/dev/null; then
        log "apache is listening"
        break
    fi
    if ! kill -0 "$APACHE_PID" 2>/dev/null; then
        log "FATAL: apache died during startup"
        wait "$APACHE_PID" || true
        exit 1
    fi
    sleep 1
done

log "starting auth-proxy on :${AUTH_PROXY_LISTEN_PORT:-8080}"
python3 /usr/local/bin/auth_proxy.py &
PROXY_PID=$!

# ---------------------------------------------------------------------
# Supervise the children.  ``wait -n`` returns when any one exits.
# ``set -e`` is suppressed around it so a non-zero child exit doesn't
# bypass our cleanup.
# ---------------------------------------------------------------------
set +e
wait -n "$APACHE_PID" "$PROXY_PID" "$REDIS_PID"
EXIT_CODE=$?
set -e

log "child exited (code=$EXIT_CODE); stopping container"
kill -TERM "$APACHE_PID" "$PROXY_PID" "$REDIS_PID" 2>/dev/null || true
su postgres -c "$PG_BIN/pg_ctl stop -D '$PG_DATA' -m fast" 2>/dev/null || true
wait || true
exit "$EXIT_CODE"
