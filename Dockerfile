# Nextcloud as an OpenHost app — single-container deployment.
#
# OpenHost runs one container per app, so this image bundles four
# things that would normally be separate containers in a docker-compose
# deployment: the Nextcloud Apache + PHP stack, PostgreSQL, Redis, and
# a small Python auth-sidecar that fronts Apache and bridges OpenHost's
# owner signal (the router-stamped X-OpenHost-Is-Owner header) to
# Nextcloud's user_saml app.
#
# The Nextcloud upstream image's entrypoint (which handles install,
# upgrade, and hooks) is preserved verbatim — we just call it from a
# wrapper that boots Postgres and Redis first.

FROM nextcloud:33-apache

# The official Nextcloud entrypoint runs Apache on port 80.  We move
# it to 8081 so our auth-sidecar can be the only thing listening on
# the OpenHost-router-facing port (8080).  This value is BAKED IN to
# the Apache config below via ``sed`` and is NOT runtime-configurable
# — the auth-sidecar reads ``$APACHE_PORT`` to know where to proxy
# to, so the env var and the Apache config must always agree.  We
# therefore set the env var here at build time only.  Operators
# wanting a different port must rebuild the image.
ENV APACHE_PORT=8081

# Layer PostgreSQL + Redis + Python onto the upstream image (which
# is currently based on Debian Trixie 13 — that ships PostgreSQL
# 17 and Redis 8, which are what we get from the unversioned apt
# package names below).  Operators reading this if/when the
# upstream image rebases onto a newer Debian: ``cat /etc/os-release``
# inside the running container to see the actual current value.
#
# postgresql-client is included so our supervisor shell can probe
# Postgres readiness with ``pg_isready`` before launching Apache;
# without it Nextcloud's first-boot ``occ maintenance:install`` would
# flap if Postgres is still starting.
#
# python3 is needed for the auth-sidecar.  The sidecar uses only the
# Python standard library (http.server, socket, re) — owner status is
# read from the trusted ``X-OpenHost-Is-Owner`` header the router
# stamps, so no JWT/JWKS/HTTP-client dependencies are required.
#
# tini gives us a real PID 1 that reaps zombies and forwards signals,
# matching the supervisor pattern used by openhost-miniflux.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        postgresql \
        postgresql-client \
        redis-server \
        python3 \
        tini; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*; \
    # The Debian postgresql package creates /var/lib/postgresql owned
    # by the ``postgres`` user.  We don't run initdb here — that has
    # to happen against the persistent OPENHOST_APP_DATA_DIR mount
    # path on first boot, in start.sh.  Just make sure the runtime
    # directories exist with the right ownership so the ``postgres``
    # user can write into them.
    mkdir -p /run/postgresql; \
    chown postgres:postgres /run/postgresql

# Tell Apache to listen on $APACHE_PORT instead of the default 80.
# Apache's default ``Listen 80`` is configured in
# /etc/apache2/ports.conf, and the default vhost in
# 000-default.conf uses :80.  We use ``sed`` rather than rewriting
# the file so future image upgrades that change the stock Apache
# config keep working.  Both ports are derived from $APACHE_PORT
# (which is set above to 8081) so the Apache config and the
# auth-sidecar's upstream target agree.
RUN sed -i "s/^Listen 80$/Listen ${APACHE_PORT}/" /etc/apache2/ports.conf \
    && sed -i "s/<VirtualHost \*:80>/<VirtualHost *:${APACHE_PORT}>/" /etc/apache2/sites-available/000-default.conf

# Hook scripts: dropped into the directory the upstream entrypoint
# scans for /docker-entrypoint-hooks.d/{pre,post}-installation/*.sh.
# We use post-installation (runs only on first install) for the
# Nextcloud-side SSO setup, and before-starting (runs on every boot)
# for trusted_proxies / overwrite settings that need to stay in sync
# with current container env.
COPY hooks/ /docker-entrypoint-hooks.d/
RUN find /docker-entrypoint-hooks.d -type f -name '*.sh' -exec chmod +x {} \;

# Our supervisor + auth-sidecar.
COPY start.sh /usr/local/bin/openhost-start.sh
COPY auth_proxy.py /usr/local/bin/auth_proxy.py
RUN chmod +x /usr/local/bin/openhost-start.sh /usr/local/bin/auth_proxy.py

# Document the OpenHost-router-facing port.  EXPOSE doesn't actually
# publish anything; OpenHost's [[ports]] (none here, since Nextcloud
# is HTTP-only via the router) and ``port`` in openhost.toml control
# what's reachable from outside.
EXPOSE 8080

# Override the upstream ENTRYPOINT.  We still want the upstream
# entrypoint's installation/upgrade machinery; openhost-start.sh
# calls it explicitly with ``apache2-foreground`` after Postgres and
# Redis are up.  tini becomes PID 1 so SIGTERM from podman cleanly
# tears down the whole tree.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/openhost-start.sh"]
