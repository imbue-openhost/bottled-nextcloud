#!/bin/bash
# Runs once, on first install (post-installation), AFTER the SSO hook.
#
# Pre-installs a curated set of common Nextcloud "Hub" extensions so a
# freshly-deployed OpenHost instance arrives with the productivity apps
# most people expect (Calendar, Contacts, Notes, Tasks, Deck) already
# present and enabled — instead of a bare Files-only install.
#
# Design notes:
#
#   * NON-FATAL.  Unlike the SSO hook (which fails loudly because a
#     broken SSO is worse than a restart loop), extension installs
#     depend on OUTBOUND connectivity to the Nextcloud app store
#     (apps.nextcloud.com).  A store outage, a rate-limit, or a single
#     incompatible app must NOT crash the boot — the instance is fully
#     usable without these extras.  So we log failures and continue,
#     and we do NOT use ``set -e`` around the install loop.
#
#   * PERSISTENT.  App-store apps install into
#     /var/www/html/custom_apps (the writable apps path).  start.sh's
#     persistence scheme copies custom_apps out to app_data after
#     Apache comes up, and back in on rebuilds — so pre-installed
#     extensions survive container rebuilds.  Because this hook runs
#     during first-boot BEFORE that copy-out, the apps it installs are
#     captured on the very first persist cycle.
#
#   * IDEMPOTENT.  ``occ app:install`` is a no-op-with-nonzero-exit for
#     an already-present app; we probe ``app:list`` first and skip
#     anything already enabled, so a re-run (e.g. an operator deletes
#     the install marker and re-bootstraps) does not error-spam.
#
#   * CONFIGURABLE.  Operators can override the list via the
#     NEXTCLOUD_PRECONFIGURED_APPS env var (space- or comma-separated
#     app IDs), or set it to "-" / "none" to disable pre-installation
#     entirely.  The default list is deliberately conservative: only
#     official, actively-maintained, dependency-light apps that need no
#     extra system packages or external services.

# Intentionally NOT ``set -e``: a failed app install must not abort the
# boot.  We still want ``-u`` (catch typos) and ``-o pipefail``.
set -uo pipefail

log() { printf '[post-installation:extensions] %s\n' "$*" >&2; }

occ() {
    if [[ "$(id -u)" == "0" ]]; then
        runuser -u www-data -- php /var/www/html/occ "$@"
    else
        php /var/www/html/occ "$@"
    fi
}

# Default curated set.  All are official Nextcloud apps that install
# cleanly from the app store with no extra binaries/PHP extensions
# (verified on nextcloud:33-apache):
#   calendar  — CalDAV calendar UI
#   contacts  — CardDAV address-book UI
#   notes     — Markdown notes (also powers the mobile Notes app)
#   tasks     — CalDAV VTODO task lists (pairs with calendar)
#   deck      — Kanban boards
DEFAULT_APPS="calendar contacts notes tasks deck"

RAW_APPS="${NEXTCLOUD_PRECONFIGURED_APPS:-$DEFAULT_APPS}"

# Allow disabling entirely.
case "${RAW_APPS,,}" in
    "-"|"none"|"off"|"false"|"")
        log "pre-configured extensions disabled (NEXTCLOUD_PRECONFIGURED_APPS=$RAW_APPS)"
        exit 0
        ;;
esac

# Normalise commas to spaces so both "a,b,c" and "a b c" work.
RAW_APPS="${RAW_APPS//,/ }"

# Snapshot the currently-enabled apps once so we can skip no-ops
# without an occ round-trip per app.  If the probe fails we fall back
# to attempting every install (occ app:install is itself idempotent).
ENABLED_APPS=""
if APP_LIST_JSON=$(occ --no-warnings app:list --output=json 2>/dev/null); then
    ENABLED_APPS=$(printf '%s' "$APP_LIST_JSON" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
if isinstance(data, dict):
    print(" ".join((data.get("enabled") or {}).keys()))
' 2>/dev/null || true)
fi

installed=0
failed=0
skipped=0
for app in $RAW_APPS; do
    # Ignore stray whitespace-only tokens.
    [[ -z "$app" ]] && continue
    # Basic sanity on the app id (Nextcloud app ids are lowercase
    # alphanumerics + underscore).  Reject anything else so a
    # malformed env var can't turn into an arbitrary occ argument.
    if [[ ! "$app" =~ ^[a-z0-9_]+$ ]]; then
        log "skipping invalid app id: '$app'"
        failed=$((failed + 1))
        continue
    fi
    if [[ " $ENABLED_APPS " == *" $app "* ]]; then
        log "$app already enabled; skipping"
        skipped=$((skipped + 1))
        continue
    fi
    log "installing $app"
    if occ --no-warnings app:install "$app" 2>&1 | sed 's/^/[post-installation:extensions]   /' >&2; then
        installed=$((installed + 1))
    else
        # app:install exits non-zero if the app is already present
        # (race with the probe) or genuinely failed.  Re-check the
        # enabled state to tell the two apart for the log summary.
        if occ --no-warnings app:list --output=json 2>/dev/null \
                | python3 -c 'import json,sys
try:
    d=json.load(sys.stdin)
except Exception:
    sys.exit(1)
sys.exit(0 if sys.argv[1] in (d.get("enabled") or {}) else 1)' "$app" 2>/dev/null; then
            log "$app ended up enabled despite non-zero exit; counting as installed"
            installed=$((installed + 1))
        else
            log "WARNING: failed to install $app (continuing; instance remains usable)"
            failed=$((failed + 1))
        fi
    fi
done

log "extension pre-configuration complete: installed=$installed skipped=$skipped failed=$failed"
# Always succeed — a failed extra app is not a boot-blocking condition.
exit 0
