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

set -euo pipefail

log() { printf '[before-starting] %s\n' "$*" >&2; }

# If Nextcloud isn't installed yet, the post-installation hook hasn't
# run and we have no config to update.  Bail silently — the
# post-installation hook will run later this boot and pick up the
# env-driven overrides itself via the upstream entrypoint.
if [[ ! -f /var/www/html/config/config.php ]]; then
    log "config.php absent; skipping (first install)"
    exit 0
fi

occ() {
    runuser -u www-data -- php /var/www/html/occ "$@"
}

DOMAIN="${OPENHOST_NEXTCLOUD_DOMAIN:-}"
if [[ -z "$DOMAIN" ]]; then
    log "OPENHOST_NEXTCLOUD_DOMAIN not set; nothing to do"
    exit 0
fi

log "re-stamping overwrite.* and trusted_* for $DOMAIN"

# trusted_domains is an indexed list.  We always set index 0 to the
# public domain and index 1 to ``localhost`` for in-container
# health-check probes.
occ --no-warnings config:system:set trusted_domains 0 --value="$DOMAIN"
occ --no-warnings config:system:set trusted_domains 1 --value="localhost"
occ --no-warnings config:system:set trusted_domains 2 --value="127.0.0.1"

# trusted_proxies: only the auth-sidecar at 127.0.0.1.  Setting more
# than one here would let any of those addresses inject the
# X-Openhost-User header — the sidecar is on loopback only.
occ --no-warnings config:system:set trusted_proxies 0 --value="127.0.0.1"

# overwrite.cli.url drives URL generation for occ commands and
# emails.  Match the protocol to the OpenHost zone style.
case "${OPENHOST_ZONE_DOMAIN:-}" in
    lvh.me|*.lvh.me|localhost|*.localhost)
        SCHEME="http"
        ;;
    *)
        SCHEME="https"
        ;;
esac
occ --no-warnings config:system:set overwrite.cli.url --value="${SCHEME}://${DOMAIN}"
occ --no-warnings config:system:set overwriteprotocol --value="${SCHEME}"
occ --no-warnings config:system:set overwritehost --value="$DOMAIN"

# user_saml's environment-variable mode reads $_SERVER['HTTP_X_OPENHOST_USER'].
# Re-affirm the mapping every boot in case a future user_saml upgrade
# resets it.  Slot 1 is what the post-installation hook created.
if occ --no-warnings app:list --output=json 2>/dev/null \
        | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if "user_saml" in (d.get("enabled") or {}) else 1)'; then
    occ --no-warnings saml:config:set --general-uid_mapping "HTTP_X_OPENHOST_USER" 1 || true
    occ --no-warnings saml:config:set --type "environment-variable" 1 || true
fi

log "before-starting hook complete"
