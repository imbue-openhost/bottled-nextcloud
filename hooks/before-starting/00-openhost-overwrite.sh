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
#
# We DO enable ``-u`` (unset variable use) so a typo in a variable
# name surfaces as an error instead of silently expanding to empty,
# and ``-o pipefail`` so the exit status of a pipeline reflects the
# leftmost failed command (helpful for the ``occ ... | python3 ...``
# chains below).  The unconditional EXIT trap below remaps any
# non-zero exit to 0 so neither flag actually aborts the boot.
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

# Run occ either as ``www-data`` (when the hook itself runs as
# root) or as the current user (when the hook is already running
# as ``www-data``, which is what the upstream Nextcloud entrypoint
# does in its standard runtime).  Detect the uid because some
# upstream image variants run hooks as root; we want this hook to
# work both ways without extra configuration.  ``runuser`` errors
# with "may not be used by non-root users" if we used it
# unconditionally on non-root, hence the conditional.
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
#
# We capture stderr to a tempfile so the log line includes the
# actual diagnostic from occ (DB connection error, unknown config
# key, PHP fatal, …) rather than a generic "X failed" message.
# If mktemp itself fails we fall back to discarding stderr — the
# warning still fires, just without the diagnostic body.
occ_or_warn() {
    local desc="$1"
    shift
    local err
    err=$(mktemp 2>/dev/null) || err=""
    local rc
    if [[ -n "$err" ]]; then
        occ --no-warnings "$@" >/dev/null 2>"$err"
        rc=$?
    else
        occ --no-warnings "$@" >/dev/null 2>&1
        rc=$?
    fi
    if [[ "$rc" -ne 0 ]]; then
        log "warning: $desc failed (continuing with previous value)"
        if [[ -n "$err" && -s "$err" ]]; then
            # Surface the error output, prefixed so it's visually
            # nested under the warning line.
            while IFS= read -r line; do
                log "  occ: $line"
            done < "$err"
        fi
        rm -f "$err" 2>/dev/null || true
        return 1
    fi
    rm -f "$err" 2>/dev/null || true
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
# resets it.
#
# We log warnings on failure (rather than ``|| true`` silently) so a
# user_saml drift — e.g. an upgrade that renamed a CLI flag — is
# visible in the container log instead of producing a silently
# misconfigured SSO.  We still don't abort the boot: the previous
# config still in config.php remains in place and a working SSO is
# preferred over a crashing container.
APP_LIST=$(occ --no-warnings app:list --output=json 2>/dev/null || true)
if printf '%s' "$APP_LIST" | python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(2)
sys.exit(0 if "user_saml" in (d.get("enabled") or {}) else 1)'; then
    # Discover the active user_saml config slot the same way the
    # post-installation hook does, so a deployment with a non-1 slot
    # (e.g. an upgrade-style flow that recreated slots) gets its
    # current slot re-stamped instead of an unrelated slot 1.
    # ``saml:config:get --output=json`` (no -p flag) returns a dict
    # keyed by provider ID in user_saml v8.  Note: there is NO
    # ``saml:config:list`` command in v8 — only ``get``, ``create``,
    # ``set``, and ``delete``.
    SAML_SLOT=""
    SAML_SLOT_OUT=$(occ --no-warnings saml:config:get --output=json 2>/dev/null || true)
    if [[ -n "$SAML_SLOT_OUT" ]]; then
        # The python script tags JSON parse failures with a
        # ``PARSE_ERROR:`` prefix on stderr (matching the post-install
        # hook's pattern) so a corrupted occ output is distinguishable
        # from a genuine 'no slots configured' state.
        SAML_PARSE_OUT=$(printf '%s' "$SAML_SLOT_OUT" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception as exc:
    sys.stderr.write(f"PARSE_ERROR:{exc}\n")
    sys.exit(0)
if isinstance(data, dict) and data:
    keys = []
    for k in data.keys():
        try:
            keys.append((int(k), k))
        except (TypeError, ValueError):
            keys.append((float("inf"), k))
    keys.sort()
    print(keys[0][1])
' 2>&1 || true)
        if printf '%s' "$SAML_PARSE_OUT" | grep -q "^PARSE_ERROR:"; then
            log "warning: saml:config:get output unparseable; falling back to slot 1"
            log "  $SAML_PARSE_OUT"
        else
            SAML_SLOT=$(printf '%s' "$SAML_PARSE_OUT" | tr -d '\n')
        fi
    fi
    if [[ -z "$SAML_SLOT" ]]; then
        log "warning: could not discover user_saml config slot; defaulting to 1"
        SAML_SLOT="1"
    fi

    # user_saml >= 8 (ConfigurationsMapper::set) REJECTS a
    # ``general-uid_mapping`` value that starts with ``HTTP_`` while
    # ``type == environment-variable`` — it throws
    # "Environment var starting with HTTP_ are not allowed...".  The
    # post-installation hook sidesteps this by setting the mapping
    # BEFORE flipping type to environment-variable.  On a re-stamp,
    # though, type is already environment-variable, so a naive
    # ``saml:config:set --general-uid_mapping HTTP_X_OPENHOST_USER``
    # fails every boot and (worse) can never repair genuine drift.
    #
    # Only re-stamp when the current mapping actually differs from the
    # desired value — the common case (no drift) then issues no
    # blocked command at all.  When we DO need to write it, briefly
    # unset the app-wide ``type`` so the mapper's guard doesn't fire,
    # write the mapping, then restore ``type``.  The window is a few
    # milliseconds and runs before Apache binds its port, so no
    # request observes the transient state.
    DESIRED_UID_MAPPING="HTTP_X_OPENHOST_USER"
    CURRENT_UID_MAPPING=$(printf '%s' "$SAML_SLOT_OUT" | SAML_SLOT="$SAML_SLOT" python3 -c '
import json, os, sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
slot = os.environ.get("SAML_SLOT", "")
if isinstance(data, dict):
    cfg = data.get(slot) or {}
    if isinstance(cfg, dict):
        v = cfg.get("general-uid_mapping")
        if isinstance(v, str):
            print(v)
' 2>/dev/null || true)

    if [[ "$CURRENT_UID_MAPPING" == "$DESIRED_UID_MAPPING" ]]; then
        log "user_saml[$SAML_SLOT] general-uid_mapping already correct; not re-stamping"
    else
        log "user_saml[$SAML_SLOT] general-uid_mapping is '$CURRENT_UID_MAPPING'; re-stamping to '$DESIRED_UID_MAPPING'"
        # Temporarily clear the type guard so the HTTP_-prefixed value
        # is accepted, then restore it.  If clearing fails we still
        # attempt the set (it will just warn), and we always restore
        # type at the end regardless.
        occ_or_warn "config:app:delete user_saml type (transient)" \
            config:app:delete user_saml type
        occ_or_warn "saml:config:set user_saml[$SAML_SLOT] general-uid_mapping" \
            saml:config:set --general-uid_mapping "$DESIRED_UID_MAPPING" "$SAML_SLOT"
    fi

    # ``type`` is an app-wide config value (not a per-provider one);
    # see the post-installation hook for context.  We (re-)assert it
    # unconditionally — this is both the normal per-boot re-affirm and
    # the restore step for the transient-unset path above.  It never
    # trips the mapper guard because that guard only applies to
    # ``saml:config:set``, not to ``config:app:set``.
    occ_or_warn "config:app:set user_saml type=environment-variable" \
        config:app:set user_saml type --value="environment-variable"
elif [[ -z "$APP_LIST" ]]; then
    # ``occ app:list`` itself failed (DB not ready, occ binary moved,
    # PHP error).  Surface this distinctly from the silent
    # "user_saml not enabled" case so an operator investigating a
    # silent SSO failure has a hint to look at the database.
    log "warning: occ app:list returned no output; cannot re-stamp user_saml settings"
else
    # APP_LIST is non-empty but the python check exited non-zero —
    # either the JSON is unparseable (a future Nextcloud version
    # that prepends warnings to JSON output, or a PHP fatal that
    # leaked through ``--no-warnings``), or user_saml is genuinely
    # not enabled.  Log a warning so an operator investigating a
    # silent SSO failure has a hint that the parse may have failed
    # — they can re-run the app:list command manually to confirm.
    log "warning: user_saml not in app:list output, or app:list output unparseable; skipping re-stamp"
fi

log "before-starting hook complete"
