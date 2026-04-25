#!/bin/bash
# Runs once, immediately after Nextcloud's first-boot
# ``occ maintenance:install`` succeeds.  We use this single shot to
# install + configure the user_saml app in environment-variable mode
# so the auth-sidecar's stamped X-Openhost-User header is treated as
# the authenticated user, plus a few hardening tweaks (disable web
# updater, set core defaults).
#
# Idempotency: this hook only ever runs once per Nextcloud install
# (``post-installation`` per the upstream image's entrypoint
# documentation).  Re-runs after a container restart go through
# ``before-starting`` only.  Even so we use ``--allow-already-active``
# / ``IF NOT EXISTS``-style guards so that if the operator deletes
# the install marker and re-bootstraps, we don't error out.
#
# All ``occ`` invocations use ``--no-warnings`` to keep the install
# log clean and ``set -e`` so a failure aborts the boot — a partial
# SSO setup would manifest as users mysteriously bypassing user_saml,
# better to fail loudly.

set -euo pipefail

log() { printf '[post-installation] %s\n' "$*" >&2; }

# Run occ as the www-data user under which Apache + PHP run.  We use
# ``runuser`` rather than ``su`` so the environment is preserved
# (NEXTCLOUD_ADMIN_USER, etc).  ``--`` separates runuser args from
# the command's args.
# The upstream Nextcloud entrypoint already runs hooks as the
# ``www-data`` user (see /entrypoint.sh `run_as` / `run_path`); a
# ``runuser`` here would error with "may not be used by non-root
# users".  Detect the current uid and only switch user when we're
# running as root.  This makes the script portable to upstream
# image variants that run hooks as root.
occ() {
    if [[ "$(id -u)" == "0" ]]; then
        runuser -u www-data -- php /var/www/html/occ "$@"
    else
        php /var/www/html/occ "$@"
    fi
}

ADMIN_USER="${NEXTCLOUD_ADMIN_USER:-admin}"

log "installing user_saml app"
# ``app:install`` errors if the app is already installed.  Detect the
# state first via ``app:list``.
if occ --no-warnings app:list --output=json 2>/dev/null \
        | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if "user_saml" in (d.get("enabled") or {}) or "user_saml" in (d.get("disabled") or {}) else 1)'; then
    log "user_saml already present; skipping install"
else
    occ --no-warnings app:install user_saml || {
        # Fall back to enabling if install reports already-installed.
        log "app:install user_saml failed; trying app:enable"
        occ --no-warnings app:enable user_saml
    }
fi
occ --no-warnings app:enable user_saml

# user_saml stores configs in indexed slots starting at 1.  We always
# operate on slot 1 since this is a single-IdP deployment.  ``saml:config:create``
# is idempotent in the sense that calling it twice creates two configs;
# guard by checking for an existing one.
log "configuring user_saml environment-variable mode"
SAML_CONFIG_ID=""
# saml:config:list is added in user_saml >= 5.x.  Older versions
# require querying the config table directly.  Try the modern path
# first; fall back to creating fresh.
if occ --no-warnings saml:config:list --output=json 2>/dev/null > /tmp/saml_configs.json; then
    SAML_CONFIG_ID=$(python3 -c '
import json, sys
try:
    data = json.load(open("/tmp/saml_configs.json"))
except Exception:
    sys.exit(0)
if isinstance(data, dict) and data:
    print(next(iter(data.keys())))
elif isinstance(data, list) and data:
    # Some versions return [{"id": 1}, ...]
    print(data[0].get("id", ""))
' 2>/dev/null || true)
    rm -f /tmp/saml_configs.json
fi
if [[ -z "$SAML_CONFIG_ID" ]]; then
    log "creating fresh user_saml config"
    occ --no-warnings saml:config:create
    SAML_CONFIG_ID="1"
fi
log "using user_saml config id=$SAML_CONFIG_ID"

# Environment-variable mode: user_saml reads the NCASE-mangled
# ``HTTP_<header>`` env var that PHP receives from Apache.  The
# auth-sidecar sets ``X-Openhost-User`` so the env var is
# ``HTTP_X_OPENHOST_USER``.  We also set a friendly display-name
# mapping (also from the same header — the auto-provisioned user's
# display name will be the username, which is fine for a
# single-owner deployment).
occ --no-warnings saml:config:set --general-uid_mapping "HTTP_X_OPENHOST_USER" "$SAML_CONFIG_ID"
occ --no-warnings saml:config:set --type "environment-variable" "$SAML_CONFIG_ID"
occ --no-warnings saml:config:set --general-idp0_display_name "OpenHost SSO" "$SAML_CONFIG_ID"

# Allow the local password-form login as well.  We need this for two
# reasons:
#   (a) the auto-provisioned ``admin`` Nextcloud account from the
#       upstream entrypoint's ``occ maintenance:install`` exists with
#       the password we generated in start.sh.  The operator can fall
#       back to that account if SSO ever breaks.
#   (b) Nextcloud's CLI tools (occ, system cron) authenticate as
#       admin via the local backend regardless.
occ --no-warnings config:app:set user_saml general-allow_multiple_user_back_ends --value=1

# Disable the web-based upgrader.  Container-managed deployments
# upgrade by rebuilding the image, not by clicking the in-app
# updater button — running both would leave the on-disk state out
# of sync with the image.
log "disabling web-based updater"
occ --no-warnings config:system:set upgrade.disable-web --type=boolean --value=true

# Default phone region (used by the ``user_phone_provisioning`` flow,
# search by phone number, etc.).  Only set if not already configured.
if ! occ --no-warnings config:system:get default_phone_region 2>/dev/null | grep -q .; then
    occ --no-warnings config:system:set default_phone_region --value="US"
fi

# Maintenance window (3-5am local time) — Nextcloud cron runs heavy
# tasks like preview generation during this window, freeing daytime
# CPU for interactive use.
occ --no-warnings config:system:set maintenance_window_start --type=integer --value=3

# Set the cron mode to ajax by default.  The container doesn't run
# its own cron daemon (we have one less moving piece) so we let
# Nextcloud trigger background jobs from page loads.  Operators who
# want better timing accuracy can switch to ``cron`` mode and add a
# host-side cron entry that hits the container — but that's an
# ad-hoc opt-in.
occ --no-warnings background:ajax

log "post-installation hook complete"
