"""Bootstrap the OpenHost owner as the Mealie admin on first boot.

On a brand-new database Mealie's ``init_db`` step seeds a default admin
row with email ``changeme@example.com`` and password ``MyPassword``.
That is also the row Mealie's about-page warns about as a security
issue when it remains in place.

We use those well-known seeded credentials as a one-shot bootstrap
window:

  1. Wait for the seeded admin to be reachable via ``/api/auth/token``.
  2. Login with the defaults to obtain a JWT.
  3. Generate a fresh 32-char password.
  4. PUT ``/api/users/password`` to rotate the admin's password.
  5. PUT ``/api/users/{id}`` to keep the user labelled "Owner" / "admin"
     while keeping the email unchanged so the auth-proxy's stored
     credentials line up with what the user types if they ever need
     to manually login. (Cosmetic; failure here is not fatal.)
  6. Persist the rotated credentials to ``admin-credentials.txt``
     under ``$OPENHOST_APP_DATA_DIR``, mode 0600.

Note: open self-signup is disabled separately via the
``ALLOW_SIGNUP=false`` env var exported by start.sh — see
``mealie/routes/users/registration.py`` where the env-derived
``settings.ALLOW_SIGNUP`` is checked. We don't make a defensive
admin-API call here; the env var is the single source of truth.

If the file already exists (re-deploy / restart), we verify the
persisted credentials still log in. If they don't (e.g. the password
was rotated in the UI), we leave the file in place and exit; the
operator will see Mealie's normal login form.

Idempotent and best-effort. Any failure path leaves mealie in a
working but non-SSO state rather than crashing the container.
"""

from __future__ import annotations

import http.client
import json
import logging
import os
import secrets
import string
import sys
import time
import urllib.parse

logging.basicConfig(
    level=os.environ.get("BOOTSTRAP_LOG_LEVEL", "INFO"),
    format="[bootstrap] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("bootstrap_admin")

UPSTREAM_HOST = os.environ.get("MEALIE_UPSTREAM_HOST", "127.0.0.1")


def _port_from_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        port = int(raw)
    except ValueError:
        log.warning(
            "%s=%r is not an integer; falling back to default %d",
            name,
            raw,
            default,
        )
        return default
    if not 1 <= port <= 65535:
        log.warning(
            "%s=%r is out of range (1-65535); falling back to default %d",
            name,
            raw,
            default,
        )
        return default
    return port


UPSTREAM_PORT = _port_from_env("MEALIE_UPSTREAM_PORT", 9000)
CRED_FILE = os.environ.get(
    "BOOTSTRAP_CRED_FILE", "/data/app_data/mealie/admin-credentials.txt"
)

# Mealie's seeded admin (see mealie/repos/seed/init_users.py and
# mealie/core/settings/settings.py:_DEFAULT_EMAIL/_DEFAULT_PASSWORD).
# These are private settings (underscore-prefixed in pydantic) and
# cannot be overridden via env, so we accept them as the bootstrap
# pivot.
DEFAULT_EMAIL = "changeme@example.com"
DEFAULT_PASSWORD = "MyPassword"

TOKEN_PATH = "/api/auth/token"
SELF_PATH = "/api/users/self"
PASSWORD_PATH = "/api/users/password"
USER_PATH_TMPL = "/api/users/{user_id}"

# How long to wait for mealie's first migrations + the seeded admin
# row to land before giving up. Cold start on a small VM can take
# 30-60 seconds; we allow up to 5 minutes.
READY_TIMEOUT_SECONDS = 300


def _request(
    method: str,
    path: str,
    headers: dict | None = None,
    body: bytes | None = None,
    timeout: int = 15,
) -> tuple[int, bytes, dict]:
    """Issue an HTTP request to upstream mealie and return (status, body, headers).

    Returns ``(0, b"", {})`` on transport failure. Callers should
    treat that as "try again later".
    """
    conn = http.client.HTTPConnection(UPSTREAM_HOST, UPSTREAM_PORT, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, data, dict(resp.getheaders())
    except (OSError, http.client.HTTPException) as exc:
        log.debug("upstream %s %s failed: %s", method, path, exc)
        return 0, b"", {}
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass


def _build_login_request(email: str, password: str) -> tuple[bytes, dict]:
    """Build the body + headers dict for a POST to ``/api/auth/token``.

    Mealie expects an OAuth2-style ``application/x-www-form-urlencoded``
    body with username, password, and a remember_me flag. Centralised
    here so both ``_wait_for_login`` and ``_verify_login`` (and any
    future callers) stay in lockstep when the auth contract evolves.
    """
    body = urllib.parse.urlencode({
        "username": email,
        "password": password,
        "remember_me": "false",
    }).encode("utf-8")
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "Content-Length": str(len(body)),
    }
    return body, headers


def _wait_for_login(email: str, password: str, timeout_seconds: int) -> str | None:
    """Poll /api/auth/token until it returns a JWT.

    Returns the JWT on success, None on timeout. We poll for the token
    rather than for any 200 because mealie's index serves a 200 SPA
    page well before the database migrations finish, and we need the
    DB to be ready for the auth dance to work.
    """
    deadline = time.time() + timeout_seconds
    body, headers = _build_login_request(email, password)
    last_status = -1
    while time.time() < deadline:
        status, payload, _ = _request("POST", TOKEN_PATH, headers, body, timeout=10)
        if status == 200:
            try:
                token = json.loads(payload).get("access_token")
            except (ValueError, json.JSONDecodeError):
                token = None
            if isinstance(token, str) and token:
                return token
            log.warning("auth/token returned 200 but no access_token in body: %r", payload[:200])
        elif status != last_status:
            last_status = status
            log.info(
                "auth/token poll: status=%s body=%r (still waiting)",
                status,
                payload[:200],
            )
        time.sleep(2)
    return None


def _get_self(token: str) -> dict | None:
    status, body, _ = _request(
        "GET",
        SELF_PATH,
        {"Authorization": f"Bearer {token}", "Accept": "application/json"},
        timeout=15,
    )
    if status != 200:
        log.warning("GET %s returned %d", SELF_PATH, status)
        return None
    try:
        return json.loads(body)
    except (ValueError, json.JSONDecodeError):
        return None


def _change_password(token: str, current_pw: str, new_pw: str) -> bool:
    payload = json.dumps({
        "currentPassword": current_pw,
        "newPassword": new_pw,
    }).encode("utf-8")
    status, body, _ = _request(
        "PUT",
        PASSWORD_PATH,
        {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Content-Length": str(len(payload)),
        },
        payload,
        timeout=15,
    )
    if status not in (200, 201, 204):
        log.warning(
            "PUT %s returned %d: %s",
            PASSWORD_PATH,
            status,
            body[:300].decode("utf-8", errors="replace"),
        )
        return False
    return True


def _update_user(token: str, user_id: str, fields: dict) -> bool:
    """PUT /api/users/{id} to update the user's profile fields.

    Mealie validates against the UserBase schema; unknown fields will
    cause a 422. We only ever send fields we know are in UserBase.
    """
    payload = json.dumps(fields).encode("utf-8")
    status, body, _ = _request(
        "PUT",
        USER_PATH_TMPL.format(user_id=user_id),
        {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Content-Length": str(len(payload)),
        },
        payload,
        timeout=15,
    )
    if status not in (200, 201, 204):
        log.warning(
            "PUT /api/users/%s returned %d: %s",
            user_id,
            status,
            body[:300].decode("utf-8", errors="replace"),
        )
        return False
    return True


def _generate_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(32))


def _read_persisted_credentials() -> tuple[str | None, str | None]:
    if not os.path.exists(CRED_FILE):
        return None, None
    try:
        with open(CRED_FILE, encoding="utf-8") as fh:
            content = fh.read()
    except OSError:
        return None, None
    email: str | None = None
    password: str | None = None
    for line in content.splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, _, val = line.partition("=")
        key = key.strip().removeprefix("export ").strip()
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        if key == "MEALIE_USERNAME":
            email = val
        elif key == "MEALIE_PASSWORD":
            password = val
    return email, password


def _verify_login(email: str, password: str) -> bool:
    body, headers = _build_login_request(email, password)
    status, _, _ = _request("POST", TOKEN_PATH, headers, body, timeout=10)
    return status == 200


def _write_credentials(email: str, password: str) -> bool:
    """Persist the rotated owner credentials to CRED_FILE.

    Returns True on success. Logs and returns False on any I/O
    failure; the caller should treat that as "auto-login disabled
    until next restart" rather than crashing.

    The write is atomic via os.replace on a same-directory temp file
    so the auth-proxy never reads a half-written file. On any error
    we attempt to remove the orphaned temp file so it doesn't sit
    around with a half-written copy of the credentials.
    """
    parent = os.path.dirname(CRED_FILE)
    if parent:
        try:
            os.makedirs(parent, exist_ok=True)
        except OSError as exc:
            log.error("could not create credentials parent dir %s: %s", parent, exc)
            return False
    tmp = CRED_FILE + ".tmp"
    old_umask = os.umask(0o077)
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(
                "# Mealie owner credentials, generated by bootstrap_admin.py.\n"
                "# Used by auth_proxy.py to mint owner sessions on demand.\n"
                "# Anyone who can read this file can sign in to Mealie as\n"
                "# the admin owner.\n"
                "#\n"
                "# To rotate: change the password in Mealie's UI, then update\n"
                "# this file by hand and restart the container.\n"
                f"export MEALIE_USERNAME='{email}'\n"
                f"export MEALIE_PASSWORD='{password}'\n"
            )
        os.replace(tmp, CRED_FILE)
        try:
            os.chmod(CRED_FILE, 0o600)
        except OSError as exc:
            log.warning("could not chmod %s to 0600: %s", CRED_FILE, exc)
            # Not fatal — the umask above already made it 0600 on
            # creation, and os.chmod failure on top of a successful
            # write is non-blocking.
        return True
    except OSError as exc:
        log.error("failed to persist credentials at %s: %s", CRED_FILE, exc)
        # Clean up the orphaned temp file so a half-written copy of
        # the password isn't left on disk.
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        except OSError as rm_exc:
            log.warning("could not remove orphaned temp file %s: %s", tmp, rm_exc)
        return False
    finally:
        os.umask(old_umask)


def main() -> int:
    persisted_email, persisted_pw = _read_persisted_credentials()
    if persisted_email and persisted_pw:
        # Wait briefly for mealie to come up and verify the persisted
        # credentials still log in. This handles container restart
        # cleanly (idempotent re-bootstrap is a no-op).
        for _ in range(60):
            if _verify_login(persisted_email, persisted_pw):
                log.info("persisted owner credentials still valid; nothing to do")
                return 0
            time.sleep(5)
        log.warning(
            "persisted owner credentials no longer log in; "
            "leaving file in place (operator may have rotated the password)"
        )
        return 0

    log.info("no persisted credentials; running first-boot bootstrap")
    token = _wait_for_login(DEFAULT_EMAIL, DEFAULT_PASSWORD, READY_TIMEOUT_SECONDS)
    if not token:
        log.error(
            "could not log in with seeded admin %s within %ds; "
            "auto-login is disabled until credentials land at %s",
            DEFAULT_EMAIL,
            READY_TIMEOUT_SECONDS,
            CRED_FILE,
        )
        return 1

    me = _get_self(token)
    if not me:
        log.error("could not GET /api/users/self with bootstrap token")
        return 1

    user_id = me.get("id")
    if not user_id:
        log.error("self response missing 'id': %r", me)
        return 1

    # Rotate the password to a generated 32-char value. If this
    # fails, we leave the seeded ``MyPassword`` in place — that's
    # bad for security, so we DON'T persist credentials in that
    # case (the auth-proxy will skip auto-login and the operator
    # will see Mealie's login form).
    new_password = _generate_password()
    if not _change_password(token, DEFAULT_PASSWORD, new_password):
        log.error(
            "could not rotate the seeded admin password; "
            "auto-login is disabled. You should rotate %s manually.",
            DEFAULT_EMAIL,
        )
        return 1

    # Verify the new password works before persisting.
    if not _verify_login(DEFAULT_EMAIL, new_password):
        log.error("rotated password but verify-login failed; not persisting")
        return 1

    # Best-effort: relabel the user (cosmetic). We deliberately
    # keep the email at DEFAULT_EMAIL so an operator who needs to
    # fall back to Mealie's manual login form has a predictable
    # username — the auth-proxy and the manual login both use the
    # same value. This means Mealie's about-page security warning
    # ("changeme@example.com user is still in the database",
    # admin_about.py:59) will continue to flash, which is mildly
    # annoying but doesn't reflect a real risk: the seeded
    # password has been rotated. If the warning becomes
    # operationally important we could change the email to
    # something like "owner@<zone>" and persist that — left as a
    # follow-up.
    new_email = DEFAULT_EMAIL
    # Force the cosmetic full_name to "Owner" — the seeded admin's
    # full_name is "Change Me" (see init_users.py:53), and overwriting
    # it makes the user list in Mealie's admin UI more recognisable.
    new_full_name = "Owner"
    new_username = me.get("username") or "admin"
    update_fields = {
        "id": user_id,
        "fullName": new_full_name,
        "email": new_email,
        "username": new_username,
        "admin": True,
        # Preserve group / household so we don't accidentally move
        # the admin out of their default group.
        "group": me.get("group"),
        "household": me.get("household"),
        "advanced": me.get("advanced", False),
        "canInviteUsers": me.get("canInviteUsers", True),
        "canManage": me.get("canManage", True),
        "canManageHousehold": me.get("canManageHousehold", True),
        "canOrganize": me.get("canOrganize", True),
    }
    # Remove keys with None values; mealie's UserBase pydantic
    # validator rejects unknown shapes.
    update_fields = {k: v for k, v in update_fields.items() if v is not None}
    _update_user(token, user_id, update_fields)
    # Non-fatal if this fails — the about-page warning is cosmetic.

    if not _write_credentials(new_email, new_password):
        # Password was already rotated in mealie but we couldn't
        # persist it. Auto-login is disabled; the operator can
        # recover by rotating the password in mealie's UI to a
        # known value and writing admin-credentials.txt by hand,
        # OR by deleting mealie's database and restarting the
        # container to re-bootstrap from scratch.
        log.error(
            "rotated mealie admin password but could not persist to %s; "
            "auto-login is disabled until %s is created by hand. "
            "The new password is NOT recoverable from this script.",
            CRED_FILE,
            CRED_FILE,
        )
        return 1

    log.info(
        "bootstrapped owner email='%s' and persisted credentials at %s",
        new_email,
        CRED_FILE,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
