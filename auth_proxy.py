"""OpenHost auth proxy sidecar for Nextcloud.

Sits between the OpenHost router and Apache+Nextcloud.  Two distinct rails:

1. Web UI (browser) — every request that ISN'T on a known native-sync
   client path is treated as "owner web request": we verify the
   ``zone_auth`` JWT cookie (RS256 signed by the OpenHost router,
   key set published at /.well-known/jwks.json).  If the claim
   ``sub == "owner"`` we strip any client-supplied
   ``X-Openhost-User`` header and stamp our own
   ``X-Openhost-User: admin`` (or ``$NEXTCLOUD_ADMIN_USER``).
   Nextcloud's ``user_saml`` app, configured in ``environment-variable``
   mode with ``general-uid_mapping=HTTP_X_OPENHOST_USER``, treats that
   header as the authenticated user — auto-creating the account on
   first login.

2. Native sync clients (Desktop / Android / iOS / WebDAV CLIs) and a
   handful of anonymous / Basic-Auth endpoints — pair through Login
   Flow v2 in the system browser, mint an ``app password``, then
   carry that as HTTP Basic Auth on subsequent requests.  The
   authoritative bypass list is ``PUBLIC_PATH_PATTERNS`` below;
   it covers WebDAV (``/remote.php/dav/*``, ``/remote.php/webdav/*``,
   plus the legacy ``/caldav`` and ``/carddav`` aliases), OCS
   (``/ocs/*``), Login Flow v2 (``/login/v2*`` and
   ``/index.php/login/v2*``), well-known service endpoints
   (``/.well-known/*``, ``/status.php``), public file shares
   (``/s/<id>``, ``/index.php/s/<id>``, ``/public.php``,
   ``/index.php/public.php``), and the CSRF-token bootstrap
   endpoints (``/csrftoken``, ``/index.php/csrftoken``).
   Requests on any of these paths pass through with their
   ``Authorization`` header intact and NO ``X-Openhost-User`` header
   stamped — Nextcloud authenticates them via the app-password (or
   share token / anonymous public access) directly.  Refer to
   ``PUBLIC_PATH_PATTERNS`` as the source of truth; this docstring
   is a summary that may drift.

Why public_paths = ["/"] in openhost.toml then?  Because the OpenHost
router treats public_paths as "no zone_auth required AND don't strip
client-supplied X-Openhost-Is-Owner header".  We want the router to
let ALL requests reach us so we can enforce the two-rail logic in
this sidecar instead.  See the openhost.toml comments and the README.

We deliberately strip any client-supplied X-Openhost-User AND
X-OpenHost-Is-Owner headers on EVERY request — including public
paths — so a hostile request can't inject an identity the JWT
didn't authorise.  The ``user_saml`` env-variable authenticator
will only see the value WE stamp.

Streaming:  Nextcloud serves and accepts files of arbitrary size,
so unlike miniflux's auth-proxy we MUST stream bodies in both
directions rather than buffer them in memory.  We use raw sockets
plus the ``socket.makefile`` API to copy bytes block-by-block; the
``http.client`` library is intentionally NOT used for upstream I/O
because its response-buffering model would defeat the streaming
goal.
"""

from __future__ import annotations

import logging
import os
import re
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import AbstractSet, Iterable

import jwt
import requests

AUTH_HEADER_NAME = "X-Openhost-User"
OWNER_HEADER_NAME = "X-OpenHost-Is-Owner"
ZONE_COOKIE = "zone_auth"
JWKS_PATH = "/.well-known/jwks.json"
JWKS_REFRESH_INTERVAL_SEC = 600  # 10 minutes
# Maximum number of bytes to copy in a single chunk between client and
# upstream.  64 KiB is comfortably below typical socket buffer sizes
# and small enough that an idle connection releases its slot reasonably
# quickly under the per-read timeout.
STREAM_CHUNK_BYTES = 64 * 1024
# Total time we'll spend reading/writing a single request, beyond which
# the connection is torn down.  Generous because Nextcloud uploads can
# legitimately take many minutes for large files on slow networks.
STREAM_TIMEOUT_SECONDS = 30 * 60
# Maximum size we'll readline() for an upstream response status line
# or response header.  Sits at module scope alongside the other
# protocol-shape constants.  64 KiB is well above any realistic
# legitimate header (a JWT in a Set-Cookie or a Link rel=preload
# can run a few KiB) while keeping a single readline from buffering
# unbounded bytes if the upstream sends a runaway line.
HEADER_LINE_CAP = 64 * 1024
# Hop-by-hop headers (RFC 9110 §7.6.1) plus a few entries we rewrite
# ourselves at the proxy seam.  We forward neither direction.
HOP_BY_HOP_HEADERS = frozenset(
    h.lower()
    for h in (
        "Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade",
        # Host is rewritten by us in the request-line emission code
        # (see ``_stream_inner``) based on the upstream target.
        "Host",
        # Content-Length / Transfer-Encoding determine framing — we
        # strip the original here and re-stamp the right framing
        # header in ``_stream_inner`` based on the body mode we
        # actually transmit.  Forwarding both verbatim (which the
        # client's headers might be inconsistent with after we
        # buffered or re-framed the body) would corrupt parse on
        # the upstream side.
        "Content-Length",
    )
)

# Path prefixes that bypass SSO entirely — Nextcloud's native sync
# clients use these with their own app-password Basic Auth.  We MUST
# NOT stamp X-Openhost-User on these requests because user_saml in
# env-variable mode would then over-authenticate them as the owner,
# and the auto-generated app-password (which can be revoked) would be
# bypassed.  These patterns are anchored at the start of the path
# only — query strings are ignored because the raw path is matched
# before path/query splitting.
PUBLIC_PATH_PATTERNS = [
    re.compile(r"^/remote\.php/(dav|webdav)(/|$)"),
    re.compile(r"^/ocs(/|$)"),
    re.compile(r"^/status\.php(\?|$)"),
    re.compile(r"^/\.well-known(/|$)"),
    re.compile(r"^/login/v2(/|$)"),
    re.compile(r"^/index\.php/login/v2(/|$)"),
    # CalDAV / CardDAV well-known redirects from the bare /caldav
    # path go through the dav handler, which is already covered, but
    # some clients try ``/caldav`` or ``/carddav`` directly.
    re.compile(r"^/caldav(/|$)"),
    re.compile(r"^/carddav(/|$)"),
    # Public file shares — anonymous users access these.
    re.compile(r"^/s/[^/]+(/|$)"),
    re.compile(r"^/index\.php/s/[^/]+(/|$)"),
    # OpenCloudMesh federated sharing.
    re.compile(r"^/public\.php(/|$)"),
    re.compile(r"^/index\.php/public\.php(/|$)"),
    # CSRF / capability requests Nextcloud's JS makes before the
    # session cookie is established.  These are intentionally
    # unauthenticated.
    re.compile(r"^/csrftoken$"),
    re.compile(r"^/index\.php/csrftoken$"),
]


def _is_public_path(path: str) -> bool:
    """Return True if ``path`` matches one of the SSO-bypass patterns.

    The argument is the raw HTTP request-target as ``BaseHTTPRequestHandler``
    receives it — including any query string.  Strip the query string
    before matching so that, e.g., ``/csrftoken?foo=bar`` matches
    ``^/csrftoken$``.  Also strip a fragment defensively (clients
    don't send fragments to servers per RFC 9110, but be liberal).
    """
    # ``str.split(sep, 1)[0]`` is faster than parsing a full URL and
    # handles the simple "is there a ? or # in the path" case fine.
    path_only = path.split("?", 1)[0].split("#", 1)[0]
    return any(p.match(path_only) for p in PUBLIC_PATH_PATTERNS)


logging.basicConfig(
    level=os.environ.get("AUTH_PROXY_LOG_LEVEL", "INFO"),
    format="[auth-proxy] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("auth_proxy")


class JwksCache:
    """Fetches the OpenHost router's JWKS and caches it with stale fallback.

    On a successful fetch, keys are cached for JWKS_REFRESH_INTERVAL_SEC.
    On a failed refresh we keep serving the previously-cached keys
    rather than failing closed, so a transient router blip doesn't
    lock the owner out of their own files.
    """

    def __init__(self, router_url: str) -> None:
        self._router_url = router_url.rstrip("/")
        self._keys: list = []
        self._fetched_at: float = 0.0
        self._cache_lock = threading.Lock()
        self._fetch_lock = threading.Lock()

    def _fetch(self) -> list:
        url = f"{self._router_url}{JWKS_PATH}"
        with requests.get(url, timeout=5) as resp:
            resp.raise_for_status()
            jwks = resp.json()
        keys = []
        skipped = 0
        for jwk in jwks.get("keys", []):
            try:
                key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
            except Exception as exc:  # noqa: BLE001
                skipped += 1
                kid = jwk.get("kid") if isinstance(jwk, dict) else None
                log.warning("skipping malformed JWK (kid=%s): %s", kid, exc)
                continue
            keys.append(key)
        if not keys:
            raise RuntimeError(
                f"router JWKS contains no usable keys (skipped {skipped})"
            )
        return keys

    def get(self) -> list:
        with self._cache_lock:
            cached_keys = self._keys
            cached_at = self._fetched_at
        if cached_keys and (time.time() - cached_at) < JWKS_REFRESH_INTERVAL_SEC:
            return cached_keys

        with self._fetch_lock:
            with self._cache_lock:
                cached_keys = self._keys
                cached_at = self._fetched_at
            if cached_keys and (time.time() - cached_at) < JWKS_REFRESH_INTERVAL_SEC:
                return cached_keys

            try:
                keys = self._fetch()
            except Exception as exc:  # noqa: BLE001 - log+fallback
                if cached_keys:
                    log.warning(
                        "JWKS refresh failed, using cached keys: %s", exc
                    )
                    return cached_keys
                log.warning("JWKS fetch failed and no cache: %s", exc)
                raise

            # Update both fields under the cache lock.  All readers
            # of ``_keys`` and ``_fetched_at`` also acquire
            # ``_cache_lock`` (see ``get`` and the early-return at
            # the top of ``_fetch_lock``), so they observe the two
            # writes as a single atomic update — no torn reads.
            now = time.time()
            with self._cache_lock:
                self._fetched_at = now
                self._keys = keys
            log.info("refreshed JWKS (%d key(s))", len(keys))
            return keys

    def prefetch(self) -> None:
        try:
            self.get()
        except Exception as exc:  # noqa: BLE001
            log.warning("initial JWKS prefetch failed (will retry on demand): %s", exc)


def _parse_cookie_header(cookie_header: str | None) -> dict[str, str]:
    """Parse an RFC6265 Cookie header into {name: value} (first-wins).

    Browsers send most-specific-path / most-specific-domain cookies
    first, so the first occurrence is what the site "meant" to set.
    Also prevents a hostile client from appending a duplicate
    ``zone_auth=garbage`` to invalidate an otherwise valid token.
    """
    if not cookie_header:
        return {}
    result: dict[str, str] = {}
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        result.setdefault(name.strip(), value.strip())
    return result


def _verify_owner(token: str, jwks: JwksCache) -> bool:
    """Return True if the JWT is a valid router-signed owner token."""
    if not token:
        return False
    try:
        keys = jwks.get()
    except Exception as exc:  # noqa: BLE001
        log.warning("JWKS unavailable; denying owner check: %s", exc)
        return False
    last_error: jwt.PyJWTError | None = None
    last_non_owner_sub: str | None = None
    for key in keys:
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                options={
                    "require": ["exp"],
                    "verify_aud": False,
                },
            )
        except jwt.PyJWTError as exc:
            # Capture for diagnostic logging if every key fails.  We
            # still have to try every key because a JWKS rotation
            # window can have a token signed under the previous key
            # while the new key is also published.
            last_error = exc
            continue
        if claims.get("sub") == "owner":
            return True
        # Cryptographically valid token, but the claim isn't
        # ``owner`` — record the actual subject for diagnostic
        # logging.  We continue to the next key in case the JWKS
        # rotation window has multiple valid keys, but the very
        # first key that decoded successfully will already have
        # told us the right answer (sub doesn't change with key
        # rotation), so this loop will terminate quickly in
        # practice.
        last_non_owner_sub = claims.get("sub")
    if last_error is not None or last_non_owner_sub is not None:
        # Log at DEBUG (not INFO/WARNING) because failed JWT
        # verifications are common and noisy: any anonymous request
        # without zone_auth, an expired session, or a third-party
        # request reaches this path.  Operators investigating "why
        # can't I log in?" can crank AUTH_PROXY_LOG_LEVEL=DEBUG to
        # see the per-token failure type (ExpiredSignatureError,
        # InvalidSignatureError, MissingRequiredClaimError, or
        # "valid token but sub=foo not owner").
        if last_non_owner_sub is not None:
            log.debug(
                "JWT verified but sub=%r != 'owner'; denying owner check",
                last_non_owner_sub,
            )
        elif last_error is not None:
            log.debug(
                "JWT verification failed against all %d JWKS key(s): %s: %s",
                len(keys), type(last_error).__name__, last_error,
            )
    return False


def _strip_headers(
    headers: Iterable[tuple[str, str]], drop: AbstractSet[str]
) -> list[tuple[str, str]]:
    drop_lower = {h.lower() for h in drop}
    return [(k, v) for k, v in headers if k.lower() not in drop_lower]


class _CappedReader:
    """Wraps a file-like ``.read(n)`` that knows a maximum total length.

    Used when forwarding a Content-Length-framed request body: we
    must read at most ``length`` bytes from the client (a malicious
    client could keep sending after the declared length, and we'd
    happily forward extra bytes interpreted by Apache as a second
    pipelined request — request smuggling).  ``read(-1)`` or
    ``read()`` returns up to remaining bytes.
    """

    def __init__(self, src, length: int) -> None:
        self._src = src
        self._remaining = int(length)

    def read(self, n: int = -1) -> bytes:
        if self._remaining <= 0:
            return b""
        if n is None or n < 0 or n > self._remaining:
            n = self._remaining
        chunk = self._src.read(n)
        if not chunk:
            # EOF reached before we got the promised number of bytes.
            self._remaining = 0
            return b""
        self._remaining -= len(chunk)
        return chunk

    @property
    def remaining(self) -> int:
        return self._remaining


def _copy_stream(src, dst, max_bytes: int | None = None) -> int:
    """Copy bytes from src.read() to dst.write(); return total copied.

    ``max_bytes`` caps the total — if the source produces more, we
    stop reading.  Returning the count lets the caller decide how
    to react (e.g., emit a 502 if the upstream lied about its
    Content-Length).
    """
    copied = 0
    while True:
        if max_bytes is not None and copied >= max_bytes:
            return copied
        want = STREAM_CHUNK_BYTES
        if max_bytes is not None:
            want = min(want, max_bytes - copied)
        chunk = src.read(want)
        if not chunk:
            return copied
        dst.write(chunk)
        copied += len(chunk)


class AuthProxyHandler(BaseHTTPRequestHandler):
    # HTTP/1.1 for the response side: chunked transfer encoding (which
    # we use for streaming responses whose size we don't know up front)
    # is illegal in HTTP/1.0, and BaseHTTPRequestHandler's default of
    # HTTP/1.0 would cause the client (the OpenHost router) to reject
    # the response.  We use Connection: close anyway (see below), so we
    # get none of the keep-alive complexity that HTTP/1.1 normally
    # requires us to handle.
    protocol_version = "HTTP/1.1"

    # Close the client connection after every response so that
    # request-body framing across requests can never get out of sync.
    # The OpenHost router doesn't pipeline so we lose nothing in
    # practice and gain a much simpler invariant: every connection
    # carries exactly one request/response pair.
    close_connection = True

    # Class-level configuration set by main() before serve_forever().
    jwks: JwksCache | None = None
    upstream_host: str = "127.0.0.1"
    upstream_port: int = 8081
    admin_user: str = "admin"

    # Disable the default per-request log line; route through our
    # logger so entries get the [auth-proxy] prefix and skip
    # health-check probes which would otherwise spam the log.
    def log_message(self, format: str, *args) -> None:  # noqa: A002, N802
        path = getattr(self, "path", "")
        if path.startswith("/status.php"):
            return
        log.info("%s - " + format, self.address_string(), *args)

    # We override every standard verb (and a couple of WebDAV-specific
    # ones).  Using a single ``do_*`` for each keeps the dispatch
    # behaviour deterministic — BaseHTTPRequestHandler matches by
    # method-name attribute.
    def do_GET(self) -> None:  # noqa: N802
        self._proxy()

    def do_HEAD(self) -> None:  # noqa: N802
        self._proxy()

    def do_POST(self) -> None:  # noqa: N802
        self._proxy()

    def do_PUT(self) -> None:  # noqa: N802
        self._proxy()

    def do_DELETE(self) -> None:  # noqa: N802
        self._proxy()

    def do_PATCH(self) -> None:  # noqa: N802
        self._proxy()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._proxy()

    # WebDAV verbs.  BaseHTTPRequestHandler doesn't know about these
    # but it dispatches to ``do_<METHOD>`` by attribute lookup, so
    # adding the methods below is enough to handle them.
    def do_PROPFIND(self) -> None:  # noqa: N802
        self._proxy()

    def do_PROPPATCH(self) -> None:  # noqa: N802
        self._proxy()

    def do_MKCOL(self) -> None:  # noqa: N802
        self._proxy()

    def do_COPY(self) -> None:  # noqa: N802
        self._proxy()

    def do_MOVE(self) -> None:  # noqa: N802
        self._proxy()

    def do_LOCK(self) -> None:  # noqa: N802
        self._proxy()

    def do_UNLOCK(self) -> None:  # noqa: N802
        self._proxy()

    def do_REPORT(self) -> None:  # noqa: N802
        self._proxy()

    def do_SEARCH(self) -> None:  # noqa: N802
        self._proxy()

    def _safe_send_error(self, code: int, message: str) -> None:
        try:
            self.send_error(code, message)
        except OSError as exc:
            log.debug("client disconnected before error response: %s", exc)

    def _proxy(self) -> None:
        # Apply a generous read timeout to the client socket — large
        # uploads on slow networks legitimately take many minutes.
        # If the call fails (very unlikely; the socket should be in
        # a healthy state at this point), continue without a timeout
        # but log so an operator investigating "request stalls
        # forever" has a hint.  log.debug because this is rare and
        # noisy in production logs at higher levels.
        try:
            self.connection.settimeout(STREAM_TIMEOUT_SECONDS)
        except OSError as exc:
            log.debug("settimeout on client socket failed: %s", exc)

        # Ensure the JWKS cache is available before we make policy
        # decisions.  This is set in main() before the server starts;
        # a None here implies a construction-order bug.
        if self.jwks is None:
            log.error("auth-proxy JWKS not initialised; refusing request")
            self._safe_send_error(503, "auth-proxy not initialised")
            return

        # Decide if this path should bypass SSO.  Public paths get
        # forwarded with the ORIGINAL Authorization header preserved
        # (Basic Auth from sync clients) and with NO X-Openhost-User
        # stamped — Nextcloud authenticates them via the app password.
        public = _is_public_path(self.path)

        # For protected paths, decide owner status.  We always strip
        # client-supplied auth headers so a hostile request can't
        # inject identity even on a bypassed path.
        is_owner = False
        if not public:
            cookies = _parse_cookie_header(self.headers.get("Cookie"))
            token = cookies.get(ZONE_COOKIE, "")
            is_owner = _verify_owner(token, self.jwks)

        # Headers we must always strip before forwarding upstream.
        # ``X-Openhost-User`` and ``X-OpenHost-Is-Owner`` are the
        # SSO-trust headers — never let a client supply them.
        always_drop = {
            AUTH_HEADER_NAME.lower(),
            OWNER_HEADER_NAME.lower(),
        }
        cleaned_headers = _strip_headers(
            self.headers.items(),
            HOP_BY_HOP_HEADERS | always_drop,
        )

        # Stamp the SSO header only on protected paths AND only when
        # we successfully verified an owner JWT.  Public paths reach
        # Nextcloud with no SSO header; user_saml's env-var auth then
        # leaves them alone and the request falls through to
        # Nextcloud's regular Basic Auth handling.
        if not public and is_owner:
            cleaned_headers.append((AUTH_HEADER_NAME, self.admin_user))

        # Determine framing of the request body.  Three cases:
        #   * Content-Length: forward exactly that many bytes.
        #   * Transfer-Encoding: chunked: forward as chunked.
        #   * Neither: no body.  (The client may have a body for POST
        #     etc. with no length, but RFC 9110 §6.3 says servers MAY
        #     reject; we forward an empty body, which is what the
        #     client effectively sent.)
        transfer_encoding = self.headers.get("Transfer-Encoding", "").lower().strip()
        content_length_header = self.headers.get("Content-Length")
        body_mode: str
        body_length: int = 0
        if transfer_encoding and transfer_encoding != "identity":
            # We support the ONE chunked transfer encoding.  Any
            # combination of multiple codings ("gzip, chunked")
            # would require us to decode them — beyond scope.
            if transfer_encoding != "chunked":
                self._safe_send_error(501, "Transfer-Encoding not supported")
                return
            body_mode = "chunked"
        elif content_length_header is not None:
            try:
                body_length = int(content_length_header)
            except ValueError:
                self._safe_send_error(400, "invalid Content-Length")
                return
            if body_length < 0:
                self._safe_send_error(400, "negative Content-Length")
                return
            body_mode = "fixed"
        else:
            body_mode = "none"

        # Open the upstream connection.  We use a longish timeout
        # because Nextcloud's PHP can stall briefly during request
        # processing (e.g. previewing a video, rendering a thumbnail).
        try:
            upstream_sock = socket.create_connection(
                (self.upstream_host, self.upstream_port),
                timeout=STREAM_TIMEOUT_SECONDS,
            )
        except OSError as exc:
            log.warning("upstream connect failed: %s", exc)
            self._safe_send_error(502, "Bad Gateway")
            return

        try:
            self._stream(
                upstream_sock,
                cleaned_headers,
                body_mode,
                body_length,
            )
        finally:
            try:
                upstream_sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                upstream_sock.close()
            except OSError:
                pass

    def _stream(
        self,
        upstream_sock: socket.socket,
        cleaned_headers: list[tuple[str, str]],
        body_mode: str,
        body_length: int,
    ) -> None:
        """Write the request to upstream and copy the response back.

        We talk raw HTTP/1.1 to upstream and stream the response body
        without buffering it.  The response framing (chunked vs
        Content-Length vs connection-close) is detected from the
        upstream's headers and copied to the client verbatim.
        """
        upstream_sock.settimeout(STREAM_TIMEOUT_SECONDS)
        # Initialise to None so the finally block can clean up
        # whichever file objects were successfully created — without
        # the explicit ``None`` defaults a failure in the second
        # ``makefile`` call (e.g., FD-limit hit) would raise
        # NameError when the finally tried to close the unbound
        # ``upstream_reader`` and skip closing ``upstream_writer``.
        upstream_writer = None
        upstream_reader = None
        try:
            # ``buffering=-1`` (default) wraps the raw SocketIO in a
            # BufferedWriter, whose ``.write(b)`` is GUARANTEED to
            # write every byte (or raise) — unlike SocketIO.write
            # which can return short on a partial send().  We MUST
            # have full-write semantics because none of the call
            # sites in _stream_inner check the return value, and a
            # short write of an HTTP header line would corrupt the
            # request mid-flight.  We then ``flush()`` after the
            # framing block before reading the response so the
            # upstream sees the complete request before we look
            # for status bytes.
            upstream_writer = upstream_sock.makefile("wb")
            upstream_reader = upstream_sock.makefile("rb", buffering=STREAM_CHUNK_BYTES)
            self._stream_inner(
                upstream_sock,
                upstream_writer,
                upstream_reader,
                cleaned_headers,
                body_mode,
                body_length,
            )
        finally:
            # ``socket.makefile()`` duplicates the FD via ``socket.dup()``
            # internally, so closing the raw socket alone leaks the
            # duplicates.  Close both file objects here and let the
            # caller's finally close the underlying socket.
            for f in (upstream_writer, upstream_reader):
                if f is None:
                    continue
                try:
                    f.close()
                except OSError:
                    pass

    @staticmethod
    def _encode_header_bytes(value: str) -> bytes:
        """Encode a header line value to bytes for the wire.

        HTTP headers are octets; ``latin-1`` is the canonical encoding
        for Python strings ↔ HTTP header bytes round-tripping (the
        same encoding ``http.server`` and ``http.client`` use).
        Non-latin-1 code points (e.g. a UTF-8 cookie set by a buggy
        client) would otherwise raise ``UnicodeEncodeError`` and tear
        down the connection.  We replace such code points with ``?``
        so the request still goes through, log a warning, and let
        Apache decide how to react.
        """
        try:
            return value.encode("latin-1")
        except UnicodeEncodeError:
            log.warning("non-latin-1 header value, replacing offending bytes")
            return value.encode("latin-1", errors="replace")

    def _stream_inner(
        self,
        upstream_sock: socket.socket,
        upstream_writer,
        upstream_reader,
        cleaned_headers: list[tuple[str, str]],
        body_mode: str,
        body_length: int,
    ) -> None:
        # ---- write request line + headers ----
        # The request-target is exactly what the client sent, including
        # query string.  ``self.path`` already has it.  Per RFC 9110
        # §3.2 the request-target on an origin-form URL is the
        # ``absolute-path [ "?" query ]`` part.
        try:
            request_line = f"{self.command} {self.path} HTTP/1.1\r\n"
            upstream_writer.write(self._encode_header_bytes(request_line))
            # Always send a Host header.
            upstream_writer.write(
                self._encode_header_bytes(
                    f"Host: {self.upstream_host}:{self.upstream_port}\r\n"
                )
            )
            for key, value in cleaned_headers:
                upstream_writer.write(
                    self._encode_header_bytes(f"{key}: {value}\r\n")
                )
        except OSError as exc:
            # Apache restarted mid-write, or the upstream socket
            # closed before we finished the headers.  Don't let the
            # exception propagate as a dropped connection — return a
            # proper 502.
            log.warning("upstream write failed during request headers: %s", exc)
            self._safe_send_error(502, "Bad Gateway")
            return
        # Re-state the framing.  We dropped the original
        # Content-Length / Transfer-Encoding via HOP_BY_HOP_HEADERS
        # so re-add the right one for the upstream.
        try:
            if body_mode == "chunked":
                upstream_writer.write(b"Transfer-Encoding: chunked\r\n")
            elif body_mode == "fixed":
                upstream_writer.write(
                    f"Content-Length: {body_length}\r\n".encode("latin-1")
                )
            elif body_mode == "none":
                # Methods that traditionally have a body (POST/PUT/PATCH)
                # without explicit framing get a Content-Length: 0 so
                # Apache doesn't wait for EOF.  Methods without bodies
                # (GET/HEAD/DELETE) don't strictly need it but it doesn't
                # hurt — and is more deterministic than relying on Apache
                # inferring from the verb.
                upstream_writer.write(b"Content-Length: 0\r\n")
            # We only speak HTTP/1.1 to upstream.  Force ``Connection: close``
            # so the upstream signals end-of-response cleanly and we don't
            # have to track keep-alive state across the proxy.
            upstream_writer.write(b"Connection: close\r\n")
            upstream_writer.write(b"\r\n")
        except OSError as exc:
            log.warning("upstream write failed during framing headers: %s", exc)
            self._safe_send_error(502, "Bad Gateway")
            return

        # ---- write request body ----
        try:
            if body_mode == "fixed" and body_length > 0:
                reader = _CappedReader(self.rfile, body_length)
                copied = _copy_stream(reader, upstream_writer)
                if copied != body_length:
                    log.info(
                        "short request body: declared=%d actual=%d",
                        body_length, copied,
                    )
                    # Half-close the write side so upstream sees EOF
                    # promptly and replies (typically 400) rather than
                    # waiting for the full STREAM_TIMEOUT_SECONDS for
                    # the missing bytes.  Errors here are best-effort:
                    # the socket may already be in an unusual state.
                    try:
                        upstream_sock.shutdown(socket.SHUT_WR)
                    except OSError as exc:
                        log.debug("upstream half-close failed: %s", exc)
            elif body_mode == "chunked":
                # The standard library's
                # http.server.BaseHTTPRequestHandler does NOT decode
                # the chunked encoding for us when handing us
                # ``self.rfile`` — it gives us the raw bytes after the
                # request-line + headers.  So we can copy the chunked
                # stream byte-for-byte to the upstream.  We stop when
                # we see the terminating ``0\r\n\r\n`` chunk-end.
                if not self._copy_chunked(self.rfile, upstream_writer):
                    log.warning(
                        "chunked request body forwarded with truncation; "
                        "upstream may see a malformed request"
                    )
                    # Half-close the write side so Apache sees EOF
                    # promptly and replies with 400 (matching the
                    # behaviour of the fixed-length truncation path
                    # above).  Without this, Apache would wait for
                    # more chunk data and pin the handler thread for
                    # the full STREAM_TIMEOUT_SECONDS.
                    try:
                        upstream_writer.flush()
                    except OSError as exc:
                        log.debug("upstream flush before half-close failed: %s", exc)
                    try:
                        upstream_sock.shutdown(socket.SHUT_WR)
                    except OSError as exc:
                        log.debug("upstream half-close failed: %s", exc)
        except (OSError, TimeoutError) as exc:
            log.info("client/upstream IO error during request body: %s", exc)
            self._safe_send_error(502, "Bad Gateway")
            return

        # Flush the request-side bytes.
        try:
            upstream_writer.flush()
        except OSError as exc:
            log.warning("upstream flush failed: %s", exc)
            self._safe_send_error(502, "Bad Gateway")
            return

        # ---- read response status + headers ----
        #
        # We loop over status lines so that an upstream that emits an
        # interim 1xx response (most notably ``HTTP/1.1 100 Continue``
        # in answer to ``Expect: 100-continue`` from the client) is
        # silently consumed and discarded — RFC 9110 §15.2 says
        # interim responses are followed by zero-or-more headers and
        # then a final response, and that intermediaries should not
        # forward 100 to a client that didn't send Expect.  The
        # OpenHost router can't be assumed to add Expect support, so
        # the safe behaviour is to absorb interim responses and only
        # forward the final status to the client.
        #
        # ``HEADER_LINE_CAP`` is defined at module scope.
        status_code: int = 0
        reason: str = ""
        resp_headers: list[list[str]] = []
        # Hard cap on the number of interim responses we accept before
        # giving up — a runaway upstream emitting nothing but 100s
        # would otherwise wedge the proxy here.  Eight is far more
        # than any sensible upstream produces.
        MAX_INTERIM = 8
        interim_seen = 0
        while True:
            try:
                status_line = upstream_reader.readline(HEADER_LINE_CAP)
            except OSError as exc:
                log.warning("upstream read status failed: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                return
            if not status_line:
                log.warning("upstream closed before sending status line")
                self._safe_send_error(502, "Bad Gateway")
                return
            if not status_line.endswith((b"\n",)):
                log.warning(
                    "upstream status line exceeds %d bytes", HEADER_LINE_CAP
                )
                self._safe_send_error(502, "upstream status line too long")
                return

            try:
                parts = status_line.decode("latin-1").rstrip("\r\n").split(" ", 2)
            except UnicodeDecodeError:
                log.warning("upstream status line not latin-1")
                self._safe_send_error(502, "Bad Gateway")
                return
            if len(parts) < 2 or not parts[0].startswith("HTTP/"):
                log.warning("malformed upstream status line: %r", status_line)
                self._safe_send_error(502, "Bad Gateway")
                return
            try:
                status_code = int(parts[1])
            except ValueError:
                log.warning("non-numeric status code: %r", parts[1])
                self._safe_send_error(502, "Bad Gateway")
                return
            reason = parts[2] if len(parts) > 2 else ""

            # Read response headers until blank line.  We store
            # entries as mutable two-element lists so RFC 9110 §5.2
            # obsolete line-folding can update the entry in-place via
            # the ``resp_headers[-1]`` reference.
            resp_headers = []
            while True:
                try:
                    line = upstream_reader.readline(HEADER_LINE_CAP)
                except OSError as exc:
                    log.warning("upstream read header failed: %s", exc)
                    self._safe_send_error(502, "Bad Gateway")
                    return
                if not line or line in (b"\r\n", b"\n"):
                    break
                if not line.endswith((b"\n",)):
                    log.warning(
                        "upstream header line exceeds %d bytes",
                        HEADER_LINE_CAP,
                    )
                    self._safe_send_error(502, "upstream header too long")
                    return
                try:
                    decoded = line.decode("latin-1").rstrip("\r\n")
                except UnicodeDecodeError:
                    log.warning("upstream header not latin-1")
                    self._safe_send_error(502, "Bad Gateway")
                    return
                # Continuation lines start with whitespace; append to
                # the previous header's value (mutating the entry in
                # ``resp_headers`` because we hold a reference).
                if line[:1] in (b" ", b"\t") and resp_headers:
                    resp_headers[-1][1] = (
                        resp_headers[-1][1] + " " + decoded.strip()
                    )
                    continue
                if ":" not in decoded:
                    # Skip malformed lines silently.
                    continue
                name, _, value = decoded.partition(":")
                resp_headers.append([name.strip(), value.strip()])

            # 1xx status codes are interim per RFC 9110 §15.2.  Loop
            # back to read the next status line.  Anything else
            # (including the 101 Switching Protocols which SHOULD be
            # handled differently — we treat it as final and forward
            # to the client; the OpenHost router doesn't support
            # WebSocket upgrades through this proxy anyway).
            if 100 <= status_code < 200 and status_code != 101:
                interim_seen += 1
                if interim_seen > MAX_INTERIM:
                    log.warning(
                        "upstream sent more than %d interim responses; aborting",
                        MAX_INTERIM,
                    )
                    self._safe_send_error(502, "too many interim responses")
                    return
                log.debug(
                    "skipping interim response %d %s", status_code, reason
                )
                continue
            break

        # Detect response framing.  We're defensive about
        # negative or non-integer Content-Length values: a malicious
        # or buggy upstream could otherwise corrupt our framing
        # (negative ``_CappedReader`` has remaining=0 and reads
        # nothing, while we'd echo the negative number to the
        # client as an invalid header).
        resp_te = ""
        resp_cl: int | None = None
        for k, v in resp_headers:
            kl = k.lower()
            if kl == "transfer-encoding":
                resp_te = v.lower().strip()
            elif kl == "content-length":
                try:
                    parsed_cl = int(v.strip())
                except ValueError:
                    resp_cl = None
                    continue
                if parsed_cl < 0:
                    log.warning(
                        "upstream sent negative Content-Length %d; ignoring",
                        parsed_cl,
                    )
                    resp_cl = None
                    continue
                resp_cl = parsed_cl

        # ---- write status + headers to client ----
        try:
            self.send_response_only(status_code, reason)
            for k, v in resp_headers:
                if k.lower() in HOP_BY_HOP_HEADERS:
                    # We dropped the upstream's TE/CL; re-add the
                    # right framing below based on what we'll
                    # actually send.
                    continue
                self.send_header(k, v)
            # Mirror the upstream's framing back to the client.
            if status_code in (204, 304):
                # 204/304 MUST NOT have a body and have no Content-Length
                # (RFC 9110 §15.3.5 / §15.4.5).  Skip framing entirely.
                pass
            elif self.command == "HEAD":
                # HEAD responses MUST NOT include a message body, but
                # MUST include the same Content-Length the equivalent
                # GET would (RFC 9110 §9.3.2).  We dropped the
                # upstream's Content-Length above as a hop-by-hop
                # header so we have to re-add it here.  If upstream
                # used chunked, we report nothing (HEAD bodies aren't
                # chunked-framed and there's no Content-Length to
                # propagate).
                if resp_cl is not None:
                    self.send_header("Content-Length", str(resp_cl))
            elif resp_te == "chunked":
                self.send_header("Transfer-Encoding", "chunked")
            elif resp_cl is not None:
                self.send_header("Content-Length", str(resp_cl))
            # We always send Connection: close — see the
            # ``close_connection = True`` class attribute above for
            # why.  We add it unconditionally so even chunked or
            # CL-framed responses tell the client to disconnect.
            self.send_header("Connection", "close")
            self.end_headers()
        except OSError as exc:
            log.debug("client disconnected before response headers: %s", exc)
            return

        # ---- stream response body ----
        if status_code in (204, 304) or self.command == "HEAD":
            # No body to stream.
            return

        try:
            if resp_te == "chunked":
                if not self._copy_chunked(upstream_reader, self.wfile):
                    # The headers are already on their way out — we
                    # can't change the response code at this point.
                    # Logging at WARNING is the best we can do; the
                    # client may still see a partial chunked stream
                    # that ends without a zero-chunk.
                    log.warning(
                        "chunked response body delivered with truncation"
                    )
            elif resp_cl is not None:
                reader = _CappedReader(upstream_reader, resp_cl)
                copied = _copy_stream(reader, self.wfile)
                if copied != resp_cl:
                    log.warning(
                        "Content-Length mismatch: declared=%d delivered=%d",
                        resp_cl, copied,
                    )
            else:
                # Connection-close framing: read until upstream EOF.
                _copy_stream(upstream_reader, self.wfile)
        except OSError as exc:
            # Log at INFO so a mid-response upstream crash or client
            # disconnect is visible at the default log level.  The
            # response headers are already on the wire and we can no
            # longer change the status code.
            log.info("IO error streaming response body: %s", exc)
            return

    # Limits used by ``_copy_chunked`` to bound abuse.  An attacker or
    # buggy peer that streams nothing but blank/trailer lines can pin
    # a handler thread for ``STREAM_TIMEOUT_SECONDS`` (30 minutes)
    # without these caps.  The values are generous enough that real
    # traffic will never trip them.
    _CHUNKED_MAX_BLANK_LINES = 8
    _CHUNKED_MAX_TRAILER_LINES = 64
    # Cap the chunk-size header line.  RFC 9110 doesn't strictly bound
    # it, but in practice it's <20 bytes (a hex size + optional
    # extensions).  An 8 KiB cap is far above any legitimate value
    # and keeps a single readline from buffering megabytes of input.
    _CHUNKED_LINE_CAP = 8192

    def _copy_chunked(self, src, dst) -> bool:
        """Copy a chunked transfer body verbatim from src to dst.

        Returns ``True`` if the body terminated cleanly (zero-chunk +
        terminating blank trailer), ``False`` if we aborted partway
        through (truncated stream, malformed chunk size, blank-line
        flood, etc.).  The caller can use the return value to log a
        warning when the proxy delivers a truncated body, which would
        otherwise be invisible.

        Validation strategy: parse each chunk-size line BEFORE
        forwarding it.  If the line is malformed (not hex, no
        terminating newline, etc.), abort without writing the bad
        bytes — that way the caller sees a clean truncation rather
        than a corrupted partial chunk header in the stream.
        """
        blank_lines_seen = 0
        while True:
            size_line = src.readline(self._CHUNKED_LINE_CAP)
            if not size_line:
                # Source closed mid-stream.
                log.info("chunked stream truncated: EOF before chunk-size line")
                return False
            # readline() returns up to N bytes; an N-byte return
            # without a terminating newline means the line was
            # truncated and we don't know whether the next bytes are
            # a continuation or a fresh chunk.  Bail rather than
            # forwarding garbage.
            if not size_line.endswith((b"\n",)):
                log.warning(
                    "chunk-size line exceeds %d bytes; aborting stream",
                    self._CHUNKED_LINE_CAP,
                )
                return False
            decoded = size_line.split(b";", 1)[0].strip()
            if not decoded:
                # Stray blank line.  Cap so an infinite stream of
                # blank lines can't spin forever.  We DO forward
                # the blank line — it's a tolerated byte sequence,
                # not a corrupted one.
                blank_lines_seen += 1
                if blank_lines_seen > self._CHUNKED_MAX_BLANK_LINES:
                    log.warning(
                        "too many blank chunk-size lines (%d); aborting stream",
                        blank_lines_seen,
                    )
                    return False
                dst.write(size_line)
                continue
            try:
                size = int(decoded, 16)
            except ValueError:
                log.warning("malformed chunk size: %r", size_line)
                return False
            blank_lines_seen = 0
            # Validated: now safe to forward the size line.
            dst.write(size_line)
            if size == 0:
                # Read trailers until empty line, write through.
                # Cap the number of trailer lines so an unterminated
                # trailer stream can't pin the thread.
                trailers_seen = 0
                while True:
                    trailer = src.readline(self._CHUNKED_LINE_CAP)
                    if not trailer:
                        log.info(
                            "chunked stream truncated: EOF in trailer block"
                        )
                        return False
                    if not trailer.endswith((b"\n",)):
                        log.warning(
                            "trailer line exceeds %d bytes; aborting stream",
                            self._CHUNKED_LINE_CAP,
                        )
                        return False
                    # Forward the line BEFORE counting it so that
                    # the terminating blank line, which is the 65th
                    # line in a max-trailers response, isn't dropped
                    # by the cap.  A correctly-formed response with
                    # exactly _CHUNKED_MAX_TRAILER_LINES (64) actual
                    # trailer headers + a blank terminator would
                    # otherwise have its terminator silently
                    # discarded.
                    dst.write(trailer)
                    if trailer in (b"\r\n", b"\n"):
                        # Clean termination: zero-chunk + blank
                        # trailer line.
                        return True
                    trailers_seen += 1
                    # Use ``>`` not ``>=`` so the cap allows exactly
                    # ``_CHUNKED_MAX_TRAILER_LINES`` non-blank
                    # trailer headers + the terminating blank line.
                    # ``>=`` would make trailers_seen=64 abort right
                    # before reading the (legitimate) blank line on
                    # the next iteration.
                    if trailers_seen > self._CHUNKED_MAX_TRAILER_LINES:
                        log.warning(
                            "too many trailer lines (%d); aborting stream",
                            trailers_seen,
                        )
                        return False
                # unreachable
            # Copy ``size`` bytes plus the trailing CRLF.
            remaining = size
            while remaining > 0:
                chunk = src.read(min(STREAM_CHUNK_BYTES, remaining))
                if not chunk:
                    log.info(
                        "chunked stream truncated: EOF mid-chunk (declared %d bytes, %d remaining)",
                        size, remaining,
                    )
                    return False
                dst.write(chunk)
                remaining -= len(chunk)
            # CRLF after each chunk.  ``read(2)`` on a buffered
            # socket file is NOT guaranteed to return exactly 2
            # bytes — it can return 1 if the TCP segment splits at
            # the boundary.  Loop until we have both bytes (or EOF).
            crlf = b""
            while len(crlf) < 2:
                more = src.read(2 - len(crlf))
                if not more:
                    log.info(
                        "chunked stream truncated: EOF in inter-chunk CRLF"
                    )
                    return False
                crlf += more
            dst.write(crlf)


class IPv4ThreadingServer(ThreadingHTTPServer):
    address_family = socket.AF_INET
    allow_reuse_address = True
    daemon_threads = True


def _port_from_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name}={raw!r} is not an integer: {exc}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"{name}={raw!r} is out of range (1-65535)")
    return port


def main() -> int:
    router_url = os.environ.get("OPENHOST_ROUTER_URL", "").strip()
    if not router_url:
        log.error("OPENHOST_ROUTER_URL is not set; refusing to start")
        return 1

    try:
        listen_port = _port_from_env("AUTH_PROXY_LISTEN_PORT", 8080)
        upstream_port = _port_from_env("APACHE_PORT", 8081)
    except ValueError as exc:
        log.error("invalid port configuration: %s", exc)
        return 1

    admin_user = os.environ.get("NEXTCLOUD_ADMIN_USER", "admin").strip() or "admin"

    jwks = JwksCache(router_url)
    jwks.prefetch()

    AuthProxyHandler.jwks = jwks
    AuthProxyHandler.upstream_port = upstream_port
    AuthProxyHandler.admin_user = admin_user

    try:
        server = IPv4ThreadingServer(("0.0.0.0", listen_port), AuthProxyHandler)
    except OSError as exc:
        log.error(
            "failed to bind auth-proxy listener on 0.0.0.0:%d: %s",
            listen_port,
            exc,
        )
        return 1
    log.info(
        "listening on 0.0.0.0:%d -> 127.0.0.1:%d (router=%s, admin_user=%s)",
        listen_port,
        upstream_port,
        router_url,
        admin_user,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
