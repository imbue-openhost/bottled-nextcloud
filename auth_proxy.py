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

2. Native sync clients (Desktop / Android / iOS / WebDAV CLIs) —
   pair through Login Flow v2 in the system browser, mint an
   ``app password``, then carry that as HTTP Basic Auth on
   subsequent WebDAV / OCS requests.  Those requests do NOT carry
   zone_auth (the system browser session is separate from the sync
   client's process) so we cannot SSO them.  Instead we let any
   request to ``/remote.php/dav/*``, ``/remote.php/webdav/*``,
   ``/ocs/*``, ``/status.php``, ``/.well-known/*``,
   ``/login/v2*``, ``/index.php/login/v2*`` pass through with the
   ``Authorization`` header intact and NO ``X-Openhost-User`` header
   stamped — Nextcloud authenticates them via the app-password
   directly.

Why public_paths = ["/"] in openhost.toml then?  Because the OpenHost
router treats public_paths as "no zone_auth required AND don't strip
client-supplied X-Openhost-Is-Owner header".  We want the router to
let ALL requests reach us so we can enforce the two-rail logic in
this sidecar instead.  See the openhost.toml comments and the README.

We deliberately strip any client-supplied X-Openhost-User header
on protected paths so a hostile request can't inject an identity
the JWT didn't authorise.  The ``user_saml`` env-variable
authenticator will only see the value WE stamp.

Streaming:  Nextcloud serves and accepts files of arbitrary size,
so unlike miniflux's auth-proxy we MUST stream bodies in both
directions rather than buffer them in memory.  We use raw sockets +
http.client for the upstream side and copy bytes block-by-block.
"""

from __future__ import annotations

import http.client
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
        # Host is rewritten by http.client based on the target host.
        "Host",
        # Content-Length / Transfer-Encoding determine framing — we
        # forward the original framing exactly via the raw stream;
        # http.client must not insert its own.
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
    return any(p.match(path) for p in PUBLIC_PATH_PATTERNS)


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

            with self._cache_lock:
                self._keys = keys
                self._fetched_at = time.time()
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
        except jwt.PyJWTError:
            continue
        if claims.get("sub") == "owner":
            return True
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
        try:
            self.connection.settimeout(STREAM_TIMEOUT_SECONDS)
        except OSError:
            pass

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

        We talk raw HTTP/1.1 to upstream rather than going through
        http.client so we can stream the response body without
        forcing http.client to buffer it.  The response framing
        (chunked vs Content-Length vs connection-close) is detected
        from the upstream's headers and copied to the client
        verbatim.
        """
        upstream_sock.settimeout(STREAM_TIMEOUT_SECONDS)
        upstream_writer = upstream_sock.makefile("wb", buffering=0)
        upstream_reader = upstream_sock.makefile("rb", buffering=STREAM_CHUNK_BYTES)

        # ---- write request line + headers ----
        # The request-target is exactly what the client sent, including
        # query string.  ``self.path`` already has it.  Per RFC 9110
        # §3.2 the request-target on an origin-form URL is the
        # ``absolute-path [ "?" query ]`` part.
        request_line = f"{self.command} {self.path} HTTP/1.1\r\n"
        upstream_writer.write(request_line.encode("latin-1"))
        # Always send a Host header — http.client would have done
        # this for us but we're talking raw bytes now.
        upstream_writer.write(
            f"Host: {self.upstream_host}:{self.upstream_port}\r\n".encode("latin-1")
        )
        for key, value in cleaned_headers:
            # Latin-1 is HTTP/1.1's header byte encoding.  PyJWT and
            # parsers reject non-ASCII anyway, so we won't see any
            # input that latin-1 can't represent in practice — and if
            # we did, we'd have already corrupted the data on the way
            # in.
            upstream_writer.write(f"{key}: {value}\r\n".encode("latin-1"))
        # Re-state the framing.  We dropped the original
        # Content-Length / Transfer-Encoding via HOP_BY_HOP_HEADERS
        # so re-add the right one for the upstream.
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
                self._copy_chunked(self.rfile, upstream_writer)
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
        try:
            status_line = upstream_reader.readline(8192)
        except OSError as exc:
            log.warning("upstream read status failed: %s", exc)
            self._safe_send_error(502, "Bad Gateway")
            return
        if not status_line:
            log.warning("upstream closed before sending status line")
            self._safe_send_error(502, "Bad Gateway")
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

        # Read response headers until blank line.
        resp_headers: list[tuple[str, str]] = []
        last_header: list[str] | None = None
        while True:
            try:
                line = upstream_reader.readline(8192)
            except OSError as exc:
                log.warning("upstream read header failed: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                return
            if not line or line in (b"\r\n", b"\n"):
                break
            try:
                decoded = line.decode("latin-1").rstrip("\r\n")
            except UnicodeDecodeError:
                log.warning("upstream header not latin-1")
                self._safe_send_error(502, "Bad Gateway")
                return
            # RFC 9110 §5.2 obsolete line-folding: continuation lines
            # start with whitespace and append to the previous header.
            # Apache won't send these but be defensive.
            if line[:1] in (b" ", b"\t") and last_header is not None:
                last_header[1] = last_header[1] + " " + decoded.strip()
                continue
            if ":" not in decoded:
                # Skip malformed lines silently — http.client does the
                # same.
                continue
            name, _, value = decoded.partition(":")
            entry = [name.strip(), value.strip()]
            resp_headers.append((entry[0], entry[1]))
            last_header = entry

        # Detect response framing.
        resp_te = ""
        resp_cl: int | None = None
        for k, v in resp_headers:
            kl = k.lower()
            if kl == "transfer-encoding":
                resp_te = v.lower().strip()
            elif kl == "content-length":
                try:
                    resp_cl = int(v.strip())
                except ValueError:
                    resp_cl = None

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
            if status_code in (204, 304) or self.command == "HEAD":
                # No response body; framing-irrelevant per RFC 9110.
                # Do NOT send Content-Length (HEAD's CL is the size
                # of the body a GET would return — we already
                # forwarded it from the upstream above).
                pass
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
                self._copy_chunked(upstream_reader, self.wfile)
            elif resp_cl is not None:
                reader = _CappedReader(upstream_reader, resp_cl)
                _copy_stream(reader, self.wfile)
            else:
                # Connection-close framing: read until upstream EOF.
                _copy_stream(upstream_reader, self.wfile)
        except OSError as exc:
            log.debug("IO error streaming response body: %s", exc)
            return

    def _copy_chunked(self, src, dst) -> None:
        """Copy a chunked transfer body verbatim from src to dst.

        We don't decode the chunks — the encoding is preserved
        end-to-end — but we DO need to detect the terminating
        ``0\\r\\n\\r\\n`` chunk so we know when the body ends.

        This is necessary because our caller multiplexes multiple
        request bodies on the same connection in principle; in
        practice we use Connection: close upstream, but the same
        helper handles the response side too where Apache may keep
        the connection open across responses if we let it.
        """
        # Read the chunk-size line, write it through, read that
        # many bytes plus the trailing CRLF, write through, repeat
        # until size is 0; then read trailers (zero or more header
        # lines terminated by blank line) and write through.
        while True:
            size_line = src.readline(8192)
            if not size_line:
                # Source closed mid-stream — propagate and let caller
                # detect the truncated stream.
                return
            dst.write(size_line)
            # Strip any chunk-extensions after a ``;``.
            decoded = size_line.split(b";", 1)[0].strip()
            if not decoded:
                # Tolerate a stray blank line at the start (Apache
                # doesn't send these but be defensive).
                continue
            try:
                size = int(decoded, 16)
            except ValueError:
                log.warning("malformed chunk size: %r", size_line)
                return
            if size == 0:
                # Read trailers until empty line, write through.
                while True:
                    trailer = src.readline(8192)
                    if not trailer:
                        return
                    dst.write(trailer)
                    if trailer in (b"\r\n", b"\n"):
                        return
                # unreachable
            # Copy ``size`` bytes plus the trailing CRLF.
            remaining = size
            while remaining > 0:
                chunk = src.read(min(STREAM_CHUNK_BYTES, remaining))
                if not chunk:
                    return
                dst.write(chunk)
                remaining -= len(chunk)
            # CRLF after each chunk.
            crlf = src.read(2)
            if not crlf:
                return
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
