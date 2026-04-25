#!/bin/bash
# Runs on every container start, AFTER the upstream entrypoint has
# determined the install/upgrade state and before Apache starts.
#
# Purpose: keep the few config.php settings that depend on the
# container env (trusted_proxies, trusted_domains, overwrite.* URLs)
# in sync with whatever start.sh set the env vars to this boot.
# Without this, a domain change between deploys would leave
# Nextcloud generating absolute URLs from the previous install.
#
# Why not just lean on the upstream image's NEXTCLOUD_TRUSTED_DOMAINS
# / TRUSTED_PROXIES / OVERWRITEHOST handling?  Those env vars only
# apply on first install — once config.php exists the upstream
# entrypoint doesn't touch them again.  We re-stamp them every
# boot so they track operator changes.

# Note: we deliberately do NOT use ``set -e`` here.  Failures in this
# hook (transient occ command issues, db not yet ready, …) would
# otherwise crash apache's startup and put the container into a
# restart loop.  A failure to re-stamp these settings is recoverable
# (the previous values stay in place) so we log+continue rather than
# abort.
set -uo pipefail

log() { printf '[before-starting] %s\n' "$*" >&2; }

# Always succeed — we never want a re-stamp failure to keep apache
# from starting.  Operators monitoring the container log will see
# the [before-starting] FAILED line.
trap 'log "exited with code $? (continuing anyway)"; exit 0' EXIT

# If Nextcloud isn't installed yet, the post-installation hook hasn't
# run and we have no config to update.  Bail silently — the
# post-installation hook will run later this boot and pick up the
# env-driven overrides itself via the upstream entrypoint.
if [[ ! -f /var/www/html/config/config.php ]]; then
    log "config.php absent; skipping (first install)"
    exit 0
fi

# The upstream Nextcloud entrypoint already runs hooks as the
# ``www-data`` user (see /entrypoint.sh `run_as` / `run_path`).  We
# therefore invoke ``php`` directly without an extra user switch — a
# ``runuser`` here would fail with "may not be used by non-root
# users".  Some upstream image variants do run hooks as root, so to
# be portable we detect the current uid and elide the user switch
# only when we're already www-data.
occ() {
    if [[ "$(id -u)" == "0" ]]; then
        runuser -u www-data -- php /var/www/html/occ "$@"
    else
        php /var/www/html/occ "$@"
    fi
}

DOMAIN="${OPENHOST_NEXTCLOUD_DOMAIN:-}"
if [[ -z "$DOMAIN" ]]; then
    log "OPENHOST_NEXTCLOUD_DOMAIN not set; nothing to do"
    exit 0
fi

log "re-stamping overwrite.* and trusted_* for $DOMAIN"

# Helper that wraps an ``occ`` invocation and surfaces failures via
# our log so a misconfigured database / occ flag drift is visible
# instead of silently leaving stale config in place.  We don't abort
# on a single failure (``set -e`` is intentionally off) — partial
# re-stamp is preferable to a crashed Apache.
occ_or_warn() {
    local desc="$1"
    shift
    if ! occ --no-warnings "$@" >/dev/null 2>&1; then
        log "warning: $desc failed (continuing with previous value)"
        return 1
    fi
    return 0
}

# trusted_domains is an indexed array.  Stale higher indices left
# from a previous deploy with a different domain would otherwise
# remain trusted forever — Nextcloud has no built-in TTL.  Delete
# the whole key first, then re-set the indices we want.  The
# window between delete and re-set is small (~ms) and runs before
# Apache binds its listening port, so there are no concurrent
# requests during it.
occ_or_warn "config:system:delete trusted_domains" \
    config:system:delete trusted_domains
occ_or_warn "config:system:set trusted_domains[0]=$DOMAIN" \
    config:system:set trusted_domains 0 --value="$DOMAIN"
occ_or_warn "config:system:set trusted_domains[1]=localhost" \
    config:system:set trusted_domains 1 --value="localhost"
occ_or_warn "config:system:set trusted_domains[2]=127.0.0.1" \
    config:system:set trusted_domains 2 --value="127.0.0.1"

# trusted_proxies: only the auth-sidecar at 127.0.0.1.  Setting more
# than one here would let any of those addresses inject the
# X-Openhost-User header — the sidecar is on loopback only.  Same
# delete-then-set pattern to clear any stale entries.
occ_or_warn "config:system:delete trusted_proxies" \
    config:system:delete trusted_proxies
occ_or_warn "config:system:set trusted_proxies[0]=127.0.0.1" \
    config:system:set trusted_proxies 0 --value="127.0.0.1"

# overwrite.cli.url drives URL generation for occ commands and
# emails.  Prefer ``$OVERWRITEPROTOCOL`` (set by start.sh from the
# same case statement) over re-deriving the scheme here, so a future
# change to the dev-domain list lives in one place.
SCHEME="${OVERWRITEPROTOCOL:-https}"
occ_or_warn "config:system:set overwrite.cli.url" \
    config:system:set overwrite.cli.url --value="${SCHEME}://${DOMAIN}"
occ_or_warn "config:system:set overwriteprotocol" \
    config:system:set overwriteprotocol --value="${SCHEME}"
occ_or_warn "config:system:set overwritehost" \
    config:system:set overwritehost --value="$DOMAIN"

# user_saml's environment-variable mode reads $_SERVER['HTTP_X_OPENHOST_USER'].
# Re-affirm the mapping every boot in case a future user_saml upgrade
# resets it.  Slot 1 is what the post-installation hook created.
#
# We log warnings on failure (rather than ``|| true`` silently) so a
# user_saml drift — e.g. an upgrade that renamed a CLI flag — is
# visible in the container log instead of producing a silently
# misconfigured SSO.  We still don't abort the boot: the previous
# config still in config.php remains in place and a working SSO is
# preferred over a crashing container.
if occ --no-warnings app:list --output=json 2>/dev/null \
        | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if "user_saml" in (d.get("enabled") or {}) else 1)'; then
    if ! occ --no-warnings saml:config:set --general-uid_mapping "HTTP_X_OPENHOST_USER" 1 >/dev/null 2>&1; then
        log "warning: failed to re-stamp user_saml general-uid_mapping (continuing)"
    fi
    # ``type`` is an app-wide config value (not a per-provider one);
    # see the post-installation hook for context.
    if ! occ --no-warnings config:app:set user_saml type --value="environment-variable" >/dev/null 2>&1; then
        log "warning: failed to re-stamp user_saml type=environment-variable (continuing)"
    fi
fi

log "before-starting hook complete"
