"""OpenHost auto-login auth-proxy for Mealie.

Sits between the OpenHost router and Mealie. When an authenticated
zone owner visits the app for the first time on a device, this proxy
logs them in to Mealie automatically using the persisted admin
credentials and sets the resulting ``mealie.access_token`` cookie on
the browser. After the cookie is set the proxy is a near
pass-through; subsequent requests carry the cookie and reach Mealie
with no further proxy involvement.

This is Pattern B1 (HTTP login dance) from the OpenHost SSO
playbook. We chose B1 over OIDC (Pattern D) because OpenHost's web
service exposes only ``/.well-known/jwks.json`` — there is no
``openid-configuration`` discovery document for Mealie's OIDC client
to consume, so a Pattern D implementation would require running a
small in-container OIDC IdP. That's tractable but materially more
code; for an app like Mealie where the JWT login dance is a single
form-encoded POST, B1 is the simpler and more reliable path.

Mealie's login dance is:

  POST /api/auth/token  (Content-Type: application/x-www-form-urlencoded)
    body: username=<email>&password=<pw>&remember_me=false
    response: {"access_token": "<jwt>", "token_type": "bearer"}

The Nuxt frontend stores ``access_token`` in a cookie named
``mealie.access_token`` and includes it on subsequent requests; the
backend reads it from the cookie or from an Authorization header
(see mealie/core/dependencies/dependencies.py). So minting the cookie
on the proxy 302 is sufficient — the SPA will read it on the next
navigation and consider the user logged in.

Auth model summary:

  * Anonymous (no zone_auth)        → router 302's to /login on
                                       parent zone before the request
                                       reaches us.  Public paths (see
                                       PUBLIC_PATH_PREFIXES) are
                                       routed through unauthenticated.
  * Owner, has mealie cookie         → forward unchanged.
  * Owner, no cookie, HTML nav,
    not on a public path             → mint a JWT via /api/auth/token
                                       with persisted credentials,
                                       redirect with Set-Cookie.
  * Owner, no cookie, public path    → forward unchanged. Anonymous
                                       readers of the same page get
                                       the same view as the owner does.
  * /api/                            → forward unchanged. Mobile and
                                       integration clients use Bearer
                                       tokens.

Defense in depth: ALWAYS strip any client-supplied
``X-OpenHost-Is-Owner`` / ``X-OpenHost-User`` before forwarding
upstream.

Implementation modelled on openhost-memos/auth_proxy.py; kept
deliberately structurally close to make security review by diff easy.
"""

from __future__ import annotations

import http.client
import json
import logging
import os
import re
import selectors
import socket
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import AbstractSet, Iterable

OWNER_HEADER_NAME = "X-OpenHost-Is-Owner"
USER_HEADER_NAME = "X-OpenHost-User"

# Mealie sets this cookie via the Nuxt frontend after a successful
# /api/auth/token. The backend also reads it from
# request.cookies["mealie.access_token"] (see
# mealie/core/dependencies/dependencies.py:93). We mint it directly on
# our 302 to skip the SPA round-trip.
MEALIE_SESSION_COOKIE = "mealie.access_token"

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
        "Host",
        "Content-Length",
    )
)

ALWAYS_STRIP_HEADERS = frozenset(
    h.lower() for h in (OWNER_HEADER_NAME, USER_HEADER_NAME)
)

# Public paths a non-authenticated visitor can reach without
# auto-login. These MUST mirror ``routing.public_paths`` in
# openhost.toml — both layers need to agree to let anonymous traffic
# end-to-end through.
#
# Categories (see README for rationale):
#   /g/                       — group-scoped pages. Mealie has two
#                              FastAPI handlers under this prefix
#                              that explicitly serve public content
#                              (``/g/{slug}/r/{recipe}`` and
#                              ``/g/{slug}/shared/r/{token}``); other
#                              ``/g/...`` paths fall through to the
#                              Nuxt SPA static index, which then
#                              renders an auth-gated client-side
#                              page. So anonymous traffic on a
#                              non-public ``/g/...`` URL gets the
#                              SPA's "log in" view rather than the
#                              data behind it. We deliberately use
#                              the broad ``/g/`` prefix here because
#                              OpenHost's public_paths matcher is a
#                              simple string-prefix check; narrower
#                              regex matching isn't supported.
#   /explore/                 — public group exploration UI
#   /api/explore/             — public-explore JSON API
#   /api/recipes/shared/      — share-token JSON API
#   /api/app/about            — anonymous "about" data the SPA polls
#   /api/media/               — recipe images referenced by public pages
#   /_nuxt/, /assets/, /icons/, /favicon.ico, /manifest.webmanifest
#                             — static assets the SPA loads
#   /_healthz                 — proxy-served liveness probe (200)
PUBLIC_PATH_PREFIXES = (
    "/g/",
    "/explore/",
    "/api/explore/",
    "/api/recipes/shared/",
    "/api/app/about",
    "/api/media/",
    "/_nuxt/",
    "/assets/",
    "/icons/",
    "/favicon.ico",
    "/manifest.webmanifest",
    "/_healthz",
)

CLIENT_READ_TIMEOUT_SECONDS = 60

# Mealie accepts recipe-image uploads (jpg/webp). 100 MiB cap is
# generous; Mealie itself caps via uvicorn's default body size.
MAX_BODY_BYTES = 100 * 1024 * 1024

# WebSocket support: Mealie's current backend doesn't open WS
# connections, but the Nuxt dev mode (and any future hot-reload /
# server-sent-events feature) needs streaming. We forward the
# upgrade transparently.
STREAM_CHUNK_BYTES = 64 * 1024
STREAM_TIMEOUT_SECONDS = 6 * 60 * 60
HEADER_LINE_CAP = 64 * 1024

MEALIE_TOKEN_PATH = "/api/auth/token"

logging.basicConfig(
    level=os.environ.get("AUTH_PROXY_LOG_LEVEL", "INFO"),
    format="[auth-proxy] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("auth_proxy")


def _parse_cookie_header(cookie_header: str | None) -> dict[str, str]:
    if not cookie_header:
        return {}
    result: dict[str, str] = {}
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        result.setdefault(name.strip(), value.strip())
    return result


def _strip_headers(
    headers: Iterable[tuple[str, str]], drop: AbstractSet[str]
) -> list[tuple[str, str]]:
    drop_lower = {h.lower() for h in drop}
    return [(k, v) for k, v in headers if k.lower() not in drop_lower]


def _read_credentials(cred_file: str) -> tuple[str | None, str | None]:
    """Read MEALIE_USERNAME + MEALIE_PASSWORD from bootstrap's persisted file."""
    try:
        with open(cred_file, encoding="utf-8") as fh:
            content = fh.read()
    except FileNotFoundError:
        return None, None
    except OSError as exc:
        log.warning("could not read credentials file %s: %s", cred_file, exc)
        return None, None
    username: str | None = None
    password: str | None = None
    for line in content.splitlines():
        m = re.match(
            r"^\s*(?:export\s+)?(MEALIE_USERNAME|MEALIE_PASSWORD)\s*=\s*(.*?)\s*$",
            line,
        )
        if not m:
            continue
        key = m.group(1)
        val = m.group(2)
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        if key == "MEALIE_USERNAME":
            username = val
        elif key == "MEALIE_PASSWORD":
            password = val
    return username, password


def _login_to_mealie(
    upstream_host: str,
    upstream_port: int,
    username: str,
    password: str,
) -> str | None:
    """POST credentials to Mealie's /api/auth/token and return the JWT.

    Returns None on failure — auto-login is best-effort; on failure the
    proxy falls through and the operator sees Mealie's own login form.
    """
    payload = urllib.parse.urlencode({
        "username": username,
        "password": password,
        "remember_me": "false",
    }).encode("utf-8")
    conn = http.client.HTTPConnection(upstream_host, upstream_port, timeout=15)
    try:
        conn.request(
            "POST",
            MEALIE_TOKEN_PATH,
            body=payload,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "Content-Length": str(len(payload)),
            },
        )
        resp = conn.getresponse()
        body = b""
        try:
            body = resp.read()
        except (OSError, http.client.HTTPException) as read_exc:
            # Don't bail entirely — we may still have a usable status
            # code from getresponse(). But log so debugging an
            # auto-login failure doesn't surface as a confusing
            # "body was not JSON" downstream message.
            log.warning(
                "auto-login: read of /api/auth/token response body failed: %s",
                read_exc,
            )
    except (OSError, http.client.HTTPException) as exc:
        log.warning("auto-login: upstream POST %s failed: %s", MEALIE_TOKEN_PATH, exc)
        return None
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass

    if resp.status != 200:
        snippet = body[:200].decode("utf-8", errors="replace")
        log.warning(
            "auto-login: mealie returned %d to /api/auth/token: %s",
            resp.status,
            snippet,
        )
        return None
    try:
        data = json.loads(body)
    except (ValueError, json.JSONDecodeError):
        log.warning("auto-login: /api/auth/token body was not JSON: %r", body[:200])
        return None
    token = data.get("access_token")
    if not isinstance(token, str) or not token:
        log.warning("auto-login: /api/auth/token response missing access_token")
        return None
    return token


def _safe_redirect_target(path: str) -> str:
    """Sanitise the ``self.path`` we're about to use as a redirect Location.

    We must NEVER allow a path-from-client to redirect to a different host
    (open-redirect), and we must reject anything that isn't a same-origin
    path-and-query. ``self.path`` from BaseHTTPRequestHandler is the raw
    request-URI; we re-parse it and reconstruct only the path + query.
    """
    if not path:
        return "/"
    parsed = urllib.parse.urlparse(path)
    # Reject absolute URIs (scheme/netloc set) — these would let a
    # client-controlled Host header send the owner to another origin.
    if parsed.scheme or parsed.netloc:
        return "/"
    safe_path = parsed.path or "/"
    # Don't bounce the owner back to /login; we just minted a session
    # for them and a /login navigation would clear it.
    if safe_path.rstrip("/") in ("/login",):
        safe_path = "/"
    if parsed.query:
        return f"{safe_path}?{parsed.query}"
    return safe_path


class AuthProxyHandler(BaseHTTPRequestHandler):
    # HTTP/1.1 lets us forward Transfer-Encoding: chunked from upstream
    # untouched and supports Range responses (206) for image streaming.
    protocol_version = "HTTP/1.1"

    upstream_host: str = "127.0.0.1"
    upstream_port: int = 9000
    cred_file: str = "/data/app_data/mealie/admin-credentials.txt"

    def log_message(self, format: str, *args) -> None:  # noqa: A002, N802
        path = getattr(self, "path", "")
        # Suppress noisy probes.
        if path == "/_healthz" and self.command == "GET":
            return
        log.info("%s - " + format, self.address_string(), *args)

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PUT(self) -> None:  # noqa: N802
        self._dispatch()

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PATCH(self) -> None:  # noqa: N802
        self._dispatch()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._dispatch()

    def _safe_send_error(self, code: int, message: str) -> None:
        try:
            self.send_error(code, message)
        except OSError as exc:
            log.debug("client disconnected before error response: %s", exc)

    def _is_public_path(self) -> bool:
        path_only = urllib.parse.urlparse(self.path or "/").path or "/"
        return any(path_only.startswith(p) for p in PUBLIC_PATH_PREFIXES)

    def _dispatch(self) -> None:
        try:
            self.connection.settimeout(CLIENT_READ_TIMEOUT_SECONDS)
        except OSError:
            pass

        # Static health endpoint, served by us regardless of upstream
        # health. Lets OpenHost's liveness probe stay green during
        # mealie's cold-start (DB migrations can take ~15s).
        if self.command == "GET" and self.path == "/_healthz":
            self._send_static_ok()
            return

        if self._is_websocket_upgrade():
            self._proxy_websocket()
            return

        is_owner = self.headers.get(OWNER_HEADER_NAME, "").lower() == "true"
        cookies = _parse_cookie_header(self.headers.get("Cookie"))
        has_session = MEALIE_SESSION_COOKIE in cookies

        accept = self.headers.get("Accept", "")
        is_html_navigation = (
            self.command == "GET" and "text/html" in accept.lower()
        )

        # Explicit /api/ exclusion. Mobile / integration / native
        # clients hit /api/* with their own Bearer tokens and don't
        # want a 302+Set-Cookie response — even when their Accept
        # header includes text/html (e.g. browsers exploring docs).
        # is_html_navigation alone isn't enough because a curl-style
        # client can still send `Accept: */*, text/html`.
        path_only = urllib.parse.urlparse(self.path or "/").path or "/"
        is_api_path = path_only.startswith("/api/") or path_only == "/api"
        # Mealie also serves OpenAPI docs under /docs and /redoc;
        # those should pass through without auto-login so anyone with
        # a Bearer token can read them.
        is_doc_path = path_only.startswith(("/docs", "/redoc", "/openapi"))

        # Owner-bounce: only on top-level HTML navigations that aren't
        # already on a public-share / API / docs path. Public paths are
        # served the same content to anonymous and owner visitors.
        if (
            is_owner
            and not has_session
            and is_html_navigation
            and not is_api_path
            and not is_doc_path
            and not self._is_public_path()
        ):
            if self._maybe_auto_login():
                return

        self._proxy()

    def _send_static_ok(self) -> None:
        try:
            self.send_response(200, "OK")
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            body = b"ok\n"
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.close_connection = True
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except OSError as exc:
            log.debug("client disconnected during /_healthz: %s", exc)

    def _is_websocket_upgrade(self) -> bool:
        upgrade = self.headers.get("Upgrade", "").lower().strip()
        connection = self.headers.get("Connection", "").lower()
        connection_tokens = {t.strip() for t in connection.split(",")}
        return upgrade == "websocket" and "upgrade" in connection_tokens

    def _proxy_websocket(self) -> None:
        # Once we hijack the connection for a WebSocket upgrade we
        # MUST mark close_connection so the framework doesn't try to
        # parse another HTTP request after we're done. Set it
        # eagerly: even a failed handshake leaves the stream in an
        # ambiguous state because we may have already forwarded
        # bytes to the client.
        self.close_connection = True

        ws_drop = ALWAYS_STRIP_HEADERS | frozenset({"host"})
        cleaned = _strip_headers(self.headers.items(), ws_drop)
        forwarded_host = self.headers.get("X-Forwarded-Host", "").strip()

        try:
            upstream_sock = socket.create_connection(
                (self.upstream_host, self.upstream_port),
                timeout=STREAM_TIMEOUT_SECONDS,
            )
        except OSError as exc:
            log.warning("upstream connect failed (websocket): %s", exc)
            self._safe_send_error(502, "Bad Gateway")
            return

        try:
            upstream_sock.settimeout(STREAM_TIMEOUT_SECONDS)
            host_header = forwarded_host or f"{self.upstream_host}:{self.upstream_port}"
            request_bytes = bytearray()
            request_bytes.extend(
                self._encode_header_bytes(
                    f"{self.command} {self.path} HTTP/1.1\r\n"
                )
            )
            request_bytes.extend(
                self._encode_header_bytes(f"Host: {host_header}\r\n")
            )
            for k, v in cleaned:
                request_bytes.extend(
                    self._encode_header_bytes(f"{k}: {v}\r\n")
                )
            request_bytes.extend(b"\r\n")
            try:
                upstream_sock.sendall(bytes(request_bytes))
            except OSError as exc:
                log.warning("websocket request send failed: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                return

            response_buf = self._read_until_double_crlf(
                upstream_sock, max_bytes=HEADER_LINE_CAP
            )
            if response_buf is None:
                self._safe_send_error(502, "Bad Gateway")
                return
            head_bytes, tail_bytes = response_buf

            try:
                self.wfile.write(head_bytes)
                if tail_bytes:
                    self.wfile.write(tail_bytes)
                self.wfile.flush()
            except OSError as exc:
                log.debug("client disconnected during ws handshake: %s", exc)
                return

            if not head_bytes.startswith(b"HTTP/1.1 101"):
                first_line = head_bytes.split(b"\r\n", 1)[0].decode(
                    "latin-1", errors="replace"
                )
                log.info("upstream rejected websocket upgrade: %s", first_line)
                return

            self._websocket_pump(self.connection, upstream_sock)
        finally:
            try:
                upstream_sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                upstream_sock.close()
            except OSError:
                pass

    @staticmethod
    def _read_until_double_crlf(
        sock: socket.socket, max_bytes: int
    ) -> tuple[bytes, bytes] | None:
        buf = bytearray()
        while True:
            try:
                chunk = sock.recv(4096)
            except OSError as exc:
                log.info("websocket handshake recv failed: %s", exc)
                return None
            if not chunk:
                return None
            buf.extend(chunk)
            idx = buf.find(b"\r\n\r\n")
            if idx >= 0:
                head = bytes(buf[: idx + 4])
                tail = bytes(buf[idx + 4 :])
                return head, tail
            if len(buf) >= max_bytes:
                log.warning(
                    "websocket response head exceeds %d bytes; aborting",
                    max_bytes,
                )
                return None

    @staticmethod
    def _websocket_pump(
        client_sock: socket.socket, upstream_sock: socket.socket
    ) -> None:
        for s in (client_sock, upstream_sock):
            try:
                s.settimeout(None)
            except OSError:
                pass

        sel = selectors.DefaultSelector()
        try:
            sel.register(client_sock, selectors.EVENT_READ, "client")
            sel.register(upstream_sock, selectors.EVENT_READ, "upstream")
            while True:
                events = sel.select(timeout=STREAM_TIMEOUT_SECONDS)
                if not events:
                    log.info("websocket idle timeout; closing")
                    return
                for key, _ in events:
                    if key.data == "client":
                        src, dst = client_sock, upstream_sock
                        direction = "client->upstream"
                    else:
                        src, dst = upstream_sock, client_sock
                        direction = "upstream->client"
                    try:
                        chunk = src.recv(STREAM_CHUNK_BYTES)
                    except OSError as exc:
                        log.info("websocket %s recv failed: %s", direction, exc)
                        return
                    if not chunk:
                        log.debug("websocket %s EOF; closing", direction)
                        return
                    try:
                        dst.sendall(chunk)
                    except OSError as exc:
                        log.info("websocket %s sendall failed: %s", direction, exc)
                        return
        finally:
            try:
                sel.close()
            except Exception as exc:  # noqa: BLE001
                log.debug("websocket selector close failed: %s", exc)

    @staticmethod
    def _encode_header_bytes(value: str) -> bytes:
        try:
            return value.encode("latin-1")
        except UnicodeEncodeError:
            log.warning("non-latin-1 header value, replacing offending bytes")
            return value.encode("latin-1", errors="replace")

    def _maybe_auto_login(self) -> bool:
        username, password = _read_credentials(self.cred_file)
        if not username or not password:
            log.info(
                "auto-login skipped: credentials file missing or unreadable at %s "
                "(bootstrap may not have completed yet)",
                self.cred_file,
            )
            return False

        token = _login_to_mealie(
            self.upstream_host, self.upstream_port, username, password
        )
        if not token:
            return False

        target_path = _safe_redirect_target(self.path or "/")

        # Mealie's frontend stores the token in a cookie via Nuxt's
        # ``useCookie``. We reproduce its attributes (Path=/, HttpOnly
        # OFF — the SPA reads it via document.cookie via useCookie,
        # which mints a non-HttpOnly cookie). We also set Secure +
        # SameSite=Lax because the OpenHost outer Caddy terminates TLS.
        # Max-Age matches mealie's TOKEN_TIME default (48 hours);
        # if the operator has overridden it, the cookie will be
        # refreshed on the next /api/auth/refresh call.
        cookie_value = (
            f"{MEALIE_SESSION_COOKIE}={token}; "
            "Path=/; Secure; SameSite=Lax; "
            "Max-Age=172800"
        )

        try:
            self.send_response(302)
            self.send_header("Location", target_path)
            self.send_header("Set-Cookie", cookie_value)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.close_connection = True
            self.end_headers()
        except OSError as exc:
            log.debug("client disconnected during auto-login redirect: %s", exc)
            return False

        log.info(
            "auto-login: minted mealie session for owner; redirected to %s",
            target_path,
        )
        return True

    def _proxy(self) -> None:
        """Forward an HTTP request to the upstream and stream the response back.

        We deliberately stream both directions in chunks rather than buffer
        the body — recipe-image uploads / archive exports would otherwise
        OOM the proxy or trip a body-size cap and 502 the request.
        """
        cleaned_headers = _strip_headers(
            self.headers.items(),
            HOP_BY_HOP_HEADERS | ALWAYS_STRIP_HEADERS,
        )

        # Mealie validates Host against BASE_URL only for OIDC /
        # callback URL generation; for general requests it doesn't
        # care. We do still set X-Forwarded-* so audit logs show the
        # real client IP and so the SPA's BASE_URL detection works
        # when an operator hasn't set BASE_URL explicitly.
        forwarded_host = next(
            (v for k, v in cleaned_headers if k.lower() == "x-forwarded-host"),
            None,
        )
        if forwarded_host:
            cleaned_headers.append(("Host", forwarded_host))
        else:
            cleaned_headers.append(("Host", f"{self.upstream_host}:{self.upstream_port}"))
        # Always assert HTTPS upstream so mealie generates https://
        # links in OG tags / share URLs even though the inner hop is
        # plain HTTP.
        if not any(k.lower() == "x-forwarded-proto" for k, _ in cleaned_headers):
            cleaned_headers.append(("X-Forwarded-Proto", "https"))

        body: bytes | None = None
        client_te = self.headers.get("Transfer-Encoding", "").lower().strip()
        if client_te and client_te != "identity":
            self._safe_send_error(501, "Transfer-Encoding not supported on requests")
            return

        content_length_header = self.headers.get("Content-Length")
        if content_length_header:
            try:
                length = int(content_length_header)
            except ValueError:
                self._safe_send_error(400, "invalid Content-Length")
                return
            if length < 0:
                self._safe_send_error(400, "negative Content-Length")
                return
            if length > MAX_BODY_BYTES:
                self._safe_send_error(413, "request body too large")
                return
            if length > 0:
                try:
                    body = self.rfile.read(length)
                except (OSError, TimeoutError) as exc:
                    log.info("client read error: %s", exc)
                    self._safe_send_error(400, "request body read failed")
                    return
                if len(body) != length:
                    self._safe_send_error(400, "incomplete request body")
                    return
            else:
                body = b""
        elif self.command in ("POST", "PUT", "PATCH", "DELETE"):
            body = b""

        # Long timeout so multi-MiB exports / imports aren't capped at 120s.
        conn = http.client.HTTPConnection(
            self.upstream_host, self.upstream_port, timeout=STREAM_TIMEOUT_SECONDS
        )
        try:
            try:
                conn.putrequest(
                    self.command,
                    self.path,
                    skip_host=True,  # we set Host explicitly above
                    skip_accept_encoding=True,
                )
                for key, value in cleaned_headers:
                    conn.putheader(key, value)
                if body is not None:
                    conn.putheader("Content-Length", str(len(body)))
                conn.endheaders(message_body=body)
                upstream = conn.getresponse()
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream error: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                return

            reason = upstream.reason or ""
            try:
                self.send_response(upstream.status, reason)
                for key, value in upstream.getheaders():
                    if key.lower() in HOP_BY_HOP_HEADERS:
                        continue
                    self.send_header(key, value)
                # Force one-and-done so we don't have to manage
                # HTTP/1.1 keep-alive state between requests on the
                # same TCP connection.
                self.send_header("Connection", "close")
                self.close_connection = True
                self.end_headers()
            except OSError as exc:
                log.debug("client disconnected during response head: %s", exc)
                upstream.close()
                return

            if self.command != "HEAD":
                try:
                    while True:
                        chunk = upstream.read(STREAM_CHUNK_BYTES)
                        if not chunk:
                            break
                        try:
                            self.wfile.write(chunk)
                        except OSError as exc:
                            log.debug(
                                "client disconnected mid-stream after %d bytes: %s",
                                len(chunk), exc,
                            )
                            return
                except (OSError, http.client.HTTPException) as exc:
                    log.warning("upstream read error mid-stream: %s", exc)
                    return
            try:
                upstream.close()
            except Exception as exc:  # noqa: BLE001
                log.debug("upstream.close() raised (ignored): %s", exc)
        finally:
            conn.close()


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
    try:
        listen_port = _port_from_env("AUTH_PROXY_LISTEN_PORT", 8080)
        upstream_port = _port_from_env("AUTH_PROXY_UPSTREAM_PORT", 9000)
    except ValueError as exc:
        log.error("invalid port configuration: %s", exc)
        return 1

    upstream_host = os.environ.get("AUTH_PROXY_UPSTREAM_HOST", "127.0.0.1").strip()
    cred_file = os.environ.get(
        "AUTH_PROXY_CRED_FILE",
        "/data/app_data/mealie/admin-credentials.txt",
    )

    AuthProxyHandler.upstream_host = upstream_host
    AuthProxyHandler.upstream_port = upstream_port
    AuthProxyHandler.cred_file = cred_file

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
        "listening on 0.0.0.0:%d -> %s:%d (creds=%s)",
        listen_port,
        upstream_host,
        upstream_port,
        cred_file,
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
