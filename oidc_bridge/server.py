"""In-container OIDC identity provider bridging OpenHost owner auth to Mealie.

Mealie is configured with OIDC_AUTH_ENABLED + OIDC_AUTO_REDIRECT, so a browser
hitting Mealie is immediately redirected to this IdP's /authorize endpoint.
Because the whole app sits behind the OpenHost router, an authenticated zone
owner's request carries `X-OpenHost-Is-Owner: true`. When we see that header we
mint an OIDC authorization code for the owner's synthetic identity with no
password prompt; Mealie exchanges it at /token (auth-code + PKCE) and reads the
signed ID token, auto-provisioning the owner as an admin on first login.

Non-owner requests never get an auth code (403), so only the zone owner can log
in. There is no public-sharing concept in Mealie that needs anonymous access.

Endpoints (all served under /_oidc/ via nginx; issuer includes that prefix):
  GET  /_oidc/.well-known/openid-configuration   discovery
  GET  /_oidc/jwks.json                           RS256 public key
  GET  /_oidc/authorize                           owner-gated code issuance
  POST /_oidc/token                               code+PKCE -> id_token
  GET  /_oidc/userinfo                             bearer -> claims

Security model:
  - The signing key is generated on first boot and persisted under the app data
    dir. It is a private key, NOT a user credential; documented as such. Anyone
    who can read it can mint tokens for *this app only*, and only someone who
    also controls the container can use it. This is the same trust boundary as
    the app's own DB.
  - Authorization codes are single-use, short-lived, bound to the PKCE
    challenge, client_id, redirect_uri, and nonce.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any

from authlib.jose import JsonWebKey
from authlib.jose import jwt
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.responses import RedirectResponse
from starlette.responses import Response
from starlette.routing import Route

# --- Configuration from environment (set by start.sh) -----------------------

# Public origin of the app, e.g. https://mealie.andrew-2.selfhost.imbue.com
BASE_URL = os.environ["OIDC_BRIDGE_BASE_URL"].rstrip("/")
# Loopback origin Mealie's backend uses for server-side calls (token, jwks,
# userinfo, discovery). Keeping these in-container avoids hairpinning through
# the OpenHost router, which would gate an uncookied server-to-server request.
LOOPBACK_URL = os.environ.get("OIDC_BRIDGE_LOOPBACK_URL", "http://127.0.0.1:8080").rstrip("/")
# Where the RSA signing key is persisted (private key; see module docstring).
KEY_PATH = Path(os.environ.get("OIDC_BRIDGE_KEY_PATH", "/app/data/.oidc_bridge_key.json"))
# Shared expectations negotiated with Mealie's OIDC client config.
CLIENT_ID = os.environ.get("OIDC_BRIDGE_CLIENT_ID", "mealie")
CLIENT_SECRET = os.environ.get("OIDC_BRIDGE_CLIENT_SECRET", "")
# The synthetic owner identity Mealie will provision. Username comes from the
# platform; email/name are derived so Mealie has the claims it needs.
OWNER_USERNAME = os.environ.get("OPENHOST_OWNER_USERNAME", "owner")
ZONE_DOMAIN = os.environ.get("OPENHOST_ZONE_DOMAIN", "localhost")

# The issuer is the public identifier and MUST equal the id_token `iss` that
# Mealie validates against the discovery `issuer`. It is not fetched over HTTP.
ISSUER = f"{BASE_URL}/_oidc"
# Server-facing endpoint base (loopback). Mealie fetches token/jwks/userinfo
# here directly, in-container.
LOOPBACK_OIDC = f"{LOOPBACK_URL}/_oidc"
OWNER_SUB = "openhost-owner"
OWNER_EMAIL = f"{OWNER_USERNAME}@{ZONE_DOMAIN}"
OWNER_NAME = OWNER_USERNAME

CODE_TTL_SECONDS = 300
TOKEN_TTL_SECONDS = 3600

# --- Signing key -------------------------------------------------------------


def _load_or_create_key() -> Any:
    if KEY_PATH.exists():
        return JsonWebKey.import_key(json.loads(KEY_PATH.read_text()))
    key = JsonWebKey.generate_key("RSA", 2048, is_private=True)
    data = key.as_dict(is_private=True)
    data["kid"] = secrets.token_hex(8)
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    # 0600: not readable by other container users; still world-visible to
    # anyone with the app's data dir, hence documented as non-user-credential.
    KEY_PATH.write_text(json.dumps(data))
    KEY_PATH.chmod(0o600)
    return JsonWebKey.import_key(data)


_KEY = _load_or_create_key()
_KID = _KEY.as_dict().get("kid", "")

# --- In-memory authorization-code store -------------------------------------
# Single owner, single container: an in-memory dict is sufficient. Codes are
# short-lived and single-use, so nothing needs to survive a restart.
_codes: dict[str, dict[str, Any]] = {}


def _prune_codes(now: float) -> None:
    expired = [c for c, v in _codes.items() if v["exp"] < now]
    for c in expired:
        _codes.pop(c, None)


def _is_owner(request: Request) -> bool:
    return request.headers.get("x-openhost-is-owner", "").lower() == "true"


# --- Endpoints ---------------------------------------------------------------


async def discovery(_: Request) -> JSONResponse:
    return JSONResponse(
        {
            "issuer": ISSUER,
            # Browser-facing: must be the public URL the owner's browser reaches.
            "authorization_endpoint": f"{ISSUER}/authorize",
            # Server-facing: Mealie's backend fetches these over loopback.
            "token_endpoint": f"{LOOPBACK_OIDC}/token",
            "userinfo_endpoint": f"{LOOPBACK_OIDC}/userinfo",
            "jwks_uri": f"{LOOPBACK_OIDC}/jwks.json",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "profile", "email"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_post",
                "client_secret_basic",
                "none",
            ],
            "claims_supported": ["sub", "email", "email_verified", "name"],
            "code_challenge_methods_supported": ["S256"],
            "grant_types_supported": ["authorization_code"],
        }
    )


async def jwks(_: Request) -> JSONResponse:
    pub = _KEY.as_dict(is_private=False)
    pub["kid"] = _KID
    pub["use"] = "sig"
    pub["alg"] = "RS256"
    return JSONResponse({"keys": [pub]})


async def authorize(request: Request) -> Response:
    # Only the authenticated zone owner may obtain a code. Everyone else is
    # refused — Mealie has no anonymous/public content to serve.
    if not _is_owner(request):
        return Response(
            "Forbidden: this application is restricted to the zone owner.",
            status_code=403,
        )

    q = request.query_params
    if q.get("response_type") != "code":
        return _redirect_error(q, "unsupported_response_type")
    if q.get("client_id") != CLIENT_ID:
        return Response("invalid client_id", status_code=400)

    redirect_uri = q.get("redirect_uri", "")
    if not redirect_uri.startswith(f"{BASE_URL}/"):
        # Never redirect to an origin other than our own app.
        return Response("invalid redirect_uri", status_code=400)

    state = q.get("state", "")
    nonce = q.get("nonce", "")
    challenge = q.get("code_challenge", "")
    challenge_method = q.get("code_challenge_method", "")
    if not challenge or challenge_method != "S256":
        return _redirect_error(q, "invalid_request", state)

    now = time.time()
    _prune_codes(now)
    code = secrets.token_urlsafe(32)
    _codes[code] = {
        "exp": now + CODE_TTL_SECONDS,
        "redirect_uri": redirect_uri,
        "nonce": nonce,
        "challenge": challenge,
        "client_id": CLIENT_ID,
    }

    sep = "&" if "?" in redirect_uri else "?"
    location = f"{redirect_uri}{sep}code={code}"
    if state:
        location += f"&state={state}"
    return RedirectResponse(location, status_code=302)


def _redirect_error(q: Any, error: str, state: str = "") -> Response:
    redirect_uri = q.get("redirect_uri", "")
    if not redirect_uri.startswith(f"{BASE_URL}/"):
        return Response(error, status_code=400)
    sep = "&" if "?" in redirect_uri else "?"
    location = f"{redirect_uri}{sep}error={error}"
    if state:
        location += f"&state={state}"
    return RedirectResponse(location, status_code=302)


def _verify_pkce(verifier: str, challenge: str) -> bool:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return secrets.compare_digest(computed, challenge)


def _client_authenticated(request: Request, form: Any) -> bool:
    # Accept client_secret via POST body or HTTP Basic. If no secret is
    # configured (public client), accept PKCE-only.
    if not CLIENT_SECRET:
        return form.get("client_id", CLIENT_ID) == CLIENT_ID
    body_secret = form.get("client_secret")
    if body_secret is not None:
        return secrets.compare_digest(body_secret, CLIENT_SECRET)
    auth = request.headers.get("authorization", "")
    if auth.startswith("Basic "):
        try:
            raw = base64.b64decode(auth[6:]).decode("utf-8")
            _, _, secret = raw.partition(":")
            return secrets.compare_digest(secret, CLIENT_SECRET)
        except Exception:
            return False
    return False


async def token(request: Request) -> JSONResponse:
    form = await request.form()
    if form.get("grant_type") != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
    if not _client_authenticated(request, form):
        return JSONResponse({"error": "invalid_client"}, status_code=401)

    code = form.get("code", "")
    entry = _codes.pop(code, None)  # single-use
    now = time.time()
    if entry is None or entry["exp"] < now:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    if form.get("redirect_uri") != entry["redirect_uri"]:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    verifier = form.get("code_verifier", "")
    if not verifier or not _verify_pkce(verifier, entry["challenge"]):
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    claims = {
        "iss": ISSUER,
        "sub": OWNER_SUB,
        "aud": CLIENT_ID,
        "iat": int(now),
        "exp": int(now) + TOKEN_TTL_SECONDS,
        "email": OWNER_EMAIL,
        "email_verified": True,
        "name": OWNER_NAME,
        "preferred_username": OWNER_USERNAME,
    }
    if entry["nonce"]:
        claims["nonce"] = entry["nonce"]

    header = {"alg": "RS256", "kid": _KID}
    id_token = jwt.encode(header, claims, _KEY).decode("ascii")
    access_token = secrets.token_urlsafe(32)

    return JSONResponse(
        {
            "access_token": access_token,
            "id_token": id_token,
            "token_type": "Bearer",
            "expires_in": TOKEN_TTL_SECONDS,
        }
    )


async def userinfo(_: Request) -> JSONResponse:
    # Mealie primarily relies on the ID token; provide userinfo for
    # completeness. Any presented bearer maps to the single owner identity.
    return JSONResponse(
        {
            "sub": OWNER_SUB,
            "email": OWNER_EMAIL,
            "email_verified": True,
            "name": OWNER_NAME,
            "preferred_username": OWNER_USERNAME,
        }
    )


async def healthz(_: Request) -> Response:
    return Response("ok", media_type="text/plain")


app = Starlette(
    routes=[
        Route("/_oidc/.well-known/openid-configuration", discovery),
        Route("/_oidc/jwks.json", jwks),
        Route("/_oidc/authorize", authorize),
        Route("/_oidc/token", token, methods=["POST"]),
        Route("/_oidc/userinfo", userinfo),
        Route("/_oidc/healthz", healthz),
    ]
)
