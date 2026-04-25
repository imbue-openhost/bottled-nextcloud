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

# Run occ either as ``www-data`` (when the hook itself runs as
# root) or as the current user (when the hook is already running
# as ``www-data``, which is what the upstream Nextcloud entrypoint
# does in its standard runtime).  Detect the uid because some
# upstream image variants run hooks as root; we want this hook to
# work both ways without extra configuration.  We prefer
# ``runuser`` over ``su`` because it preserves the environment
# (which the upstream entrypoint sets up with NEXTCLOUD_*
# variables).
occ() {
    if [[ "$(id -u)" == "0" ]]; then
        runuser -u www-data -- php /var/www/html/occ "$@"
    else
        php /var/www/html/occ "$@"
    fi
}

log "installing user_saml app"
# Probe the current state of user_saml first.  Three cases:
#   * already enabled  → nothing to do for the install/enable phase
#   * installed but disabled  → just ``app:enable``
#   * not present  → ``app:install`` (which auto-enables in v33)
#
# Without this probe, calling ``app:enable`` unconditionally on an
# already-enabled app raises a non-zero exit on Nextcloud >= 25
# without ``--force``, which under ``set -e`` would abort the whole
# hook before any saml:config:set calls run.
SAML_STATE=""
SAML_LIST_JSON=$(occ --no-warnings app:list --output=json 2>/dev/null || echo '{}')
SAML_STATE=$(printf '%s' "$SAML_LIST_JSON" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
if isinstance(data, dict):
    if "user_saml" in (data.get("enabled") or {}):
        print("enabled")
    elif "user_saml" in (data.get("disabled") or {}):
        print("disabled")
' 2>/dev/null || true)

case "$SAML_STATE" in
    enabled)
        log "user_saml already enabled; skipping install/enable"
        ;;
    disabled)
        log "user_saml disabled; enabling"
        occ --no-warnings app:enable user_saml
        ;;
    *)
        log "user_saml not present; installing"
        occ --no-warnings app:install user_saml
        ;;
esac

# user_saml stores configs in indexed slots starting at 1.  We need
# the slot ID for the saml:config:set calls below.  In user_saml v8
# the discovery API is ``saml:config:get --output=json`` (with NO
# ``-p`` flag), which returns a JSON dict keyed by provider ID
# containing every existing config.  Note the asymmetry: there is
# NO ``saml:config:list`` command in v8 — only ``get``, ``create``,
# ``set``, and ``delete``.  ``saml:config:create`` echoes the new
# provider ID on stdout, which we capture if we have to create one
# (rather than assuming the new slot is always 1).
log "configuring user_saml environment-variable mode"
SAML_CONFIG_ID=""
# Stage to a tempfile we own and clean up on script exit so a crash
# mid-script doesn't leave files behind in /tmp.
SAML_TMP=""
if SAML_TMP=$(mktemp 2>/dev/null) && [[ -n "$SAML_TMP" ]]; then
    trap 'rm -f "$SAML_TMP" 2>/dev/null || true' EXIT
fi
if [[ -n "$SAML_TMP" ]] \
        && occ --no-warnings saml:config:get --output=json > "$SAML_TMP" 2>/dev/null; then
    PARSE_OUT=$(python3 -c '
import json, sys
try:
    data = json.load(open(sys.argv[1]))
except Exception as exc:
    sys.stderr.write(f"PARSE_ERROR:{exc}\n")
    sys.exit(0)
# saml:config:get with no -p returns a {provider_id: provider_config}
# dict.  Pick the lowest numeric ID for stability.
if isinstance(data, dict) and data:
    keys = []
    for k in data.keys():
        try:
            keys.append((int(k), k))
        except (TypeError, ValueError):
            keys.append((float("inf"), k))
    keys.sort()
    print(keys[0][1])
' "$SAML_TMP" 2>&1 || true)
    if printf '%s' "$PARSE_OUT" | grep -q "^PARSE_ERROR:"; then
        log "warning: saml:config:get output unparseable; falling back to fresh config"
        log "  $PARSE_OUT"
    else
        SAML_CONFIG_ID=$(printf '%s' "$PARSE_OUT" | tr -d '\n')
    fi
fi
if [[ -z "$SAML_CONFIG_ID" ]]; then
    log "creating fresh user_saml config"
    # ``saml:config:create`` echoes the new provider ID as the
    # entirety of stdout (just a number, no decoration).  Capture
    # both stdout and stderr separately so that a failure (DB
    # error, missing user_saml app, ...) shows up in the log as a
    # diagnostic line.  We treat a non-numeric output as a hard
    # failure (exit 1) rather than silently falling back to slot
    # 1 — the design intent of this hook (top-of-file comment) is
    # to fail loudly so an operator can fix the cause; a partial
    # SSO setup that quietly bypasses user_saml is worse than a
    # restart loop the operator can investigate.
    CREATE_ERR=""
    CREATE_ERR=$(mktemp 2>/dev/null) || CREATE_ERR=""
    # Register the new tempfile with the EXIT trap so it's cleaned
    # up on any abnormal termination, matching the SAML_TMP pattern
    # above.  We update the trap rather than installing a second
    # one because bash only supports one EXIT trap.
    if [[ -n "$CREATE_ERR" ]]; then
        trap 'rm -f "$SAML_TMP" "$CREATE_ERR" 2>/dev/null || true' EXIT
        NEW_ID=$(occ --no-warnings saml:config:create 2>"$CREATE_ERR" | tr -d '\r\n[:space:]' || true)
    else
        NEW_ID=$(occ --no-warnings saml:config:create 2>/dev/null | tr -d '\r\n[:space:]' || true)
    fi
    if [[ "$NEW_ID" =~ ^[0-9]+$ ]]; then
        SAML_CONFIG_ID="$NEW_ID"
    else
        log "FATAL: saml:config:create returned non-numeric output ($NEW_ID)"
        if [[ -n "$CREATE_ERR" && -s "$CREATE_ERR" ]]; then
            while IFS= read -r line; do
                log "  saml:config:create stderr: $line"
            done < "$CREATE_ERR"
        fi
        log "  refusing to silently default to slot 1; aborting post-installation"
        exit 1
    fi
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
occ --no-warnings saml:config:set --general-idp0_display_name "OpenHost SSO" "$SAML_CONFIG_ID"
# The "type" field is not exposed via saml:config:set (which only
# handles per-provider config keys).  user_saml reads its type from
# a single app-wide config value via
# ``$appConfig->getAppValueString('type')`` — see the v8 source
# under apps/user_saml/lib/AppInfo/Application.php.  So we set
# ``type=environment-variable`` on the user_saml app itself, which
# is what tells the bootstrap (lib/base.php's
# ``OC_User::handleApacheAuth()``) and the Sabre/WebDAV plugin
# (DavPlugin.php) to honour the HTTP_X_OPENHOST_USER env var.
occ --no-warnings config:app:set user_saml type --value="environment-variable"

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
# Check whether ``default_phone_region`` is already set, then set
# the default if not.  We use ``--default-value=__UNSET__`` so that
# an unset key returns the sentinel and exit 0 — without the
# default-value flag, ``config:system:get`` returns exit 1 for an
# unset key, which is indistinguishable from a real occ failure
# under ``set -e``.
PHONE_REGION=$(occ --no-warnings config:system:get default_phone_region --default-value=__UNSET__ 2>/dev/null || true)
if [[ "$PHONE_REGION" == "__UNSET__" ]]; then
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
