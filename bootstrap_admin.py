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
  5. PUT ``/api/users/{id}`` to relabel the user with the OpenHost
     owner's identity — username + full name set to
     ``$OPENHOST_OWNER_USERNAME`` and email set to
     ``<owner-username>@<zone>`` (e.g.
     ``andrew@andrew-2.selfhost.imbue.com``). The email change is
     load-bearing, not cosmetic: Mealie reports ``is_first_login=True``
     for as long as a user with the seeded ``changeme@example.com``
     email exists (mealie/routes/app/app_about.py:get_startup_info),
     and while that flag is true the SPA bounces an admin into the
     ``/admin/setup`` first-time-setup wizard on every login
     (index.vue:41, login.vue:266). That wizard — which talks about
     changing the password — is the "loading screen" an OpenHost owner
     otherwise sees on each SSO login. Moving the email off the seed
     flips the flag to false. Reusing the owner's own username/email
     means the pre-filled identity matches what they set on the
     OpenHost claim/setup page. Only the email, full name, and username
     are changed (never a permission field) so we don't trip Mealie's
     "admins can't change their own permissions" 403 guard. The
     auth-proxy reads the (new) email from the persisted credentials
     file, so auto-login and manual login stay in sync. If the relabel
     fails we fall back to the seeded email so login still works (the
     owner just keeps seeing the setup wizard).
  6. Enable public group + household sharing ONCE so "publish a recipe
     and copy the link" works for anonymous visitors. Mealie seeds the
     default group/household as private, which makes public-recipe
     links dead-ends. Gated by a one-shot marker file so a later
     operator choice to re-privatise is never reverted on restart.
  7. Persist the rotated credentials to ``admin-credentials.txt``
     under ``$OPENHOST_APP_DATA_DIR``, mode 0600.

Note: open self-signup is disabled separately via the
``ALLOW_SIGNUP=false`` env var exported by start.sh — see
``mealie/routes/users/registration.py`` where the env-derived
``settings.ALLOW_SIGNUP`` is checked. We don't make a defensive
admin-API call here; the env var is the single source of truth.

If the file already exists (re-deploy / restart), we verify the
persisted credentials still log in. If they do, we additionally run a
one-shot migration for deploys bootstrapped by an older revision of
this script (relabel the seeded email if still present, enable public
sharing once). If they don't (e.g. the password was rotated in the
UI), we leave the file in place and exit; the operator will see
Mealie's normal login form.

Idempotent and best-effort. Any failure path leaves mealie in a
working but non-SSO state rather than crashing the container.
"""

from __future__ import annotations

import http.client
import json
import logging
import os
import re
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

# One-shot marker recording that the public-sharing enable + email
# relabel migration has run. Placed next to the credentials file. Its
# presence means "do not touch group/household privacy again" so an
# operator who later re-privatises their group in the UI is never
# reverted on the next container restart. This is NOT a secret — it's
# an empty sentinel file.
MIGRATION_MARKER_FILE = os.environ.get(
    "BOOTSTRAP_MIGRATION_MARKER",
    os.path.join(os.path.dirname(CRED_FILE) or ".", ".openhost-migrated"),
)

# Mealie's seeded admin (see mealie/repos/seed/init_users.py and
# mealie/core/settings/settings.py:_DEFAULT_EMAIL/_DEFAULT_PASSWORD).
# These are private settings (underscore-prefixed in pydantic) and
# cannot be overridden via env, so we accept them as the bootstrap
# pivot.
DEFAULT_EMAIL = "changeme@example.com"
DEFAULT_PASSWORD = "MyPassword"


# Fallback owner username when OpenHost doesn't hand one down. This
# mirrors the platform's own default (compute_space core.auth.auth
# DEFAULT_OWNER_USERNAME = "owner"), so a blank env var maps to the
# same identity the OpenHost dashboard shows.
DEFAULT_OWNER_USERNAME = "owner"

# Local-part of an email address per RFC 5321/5322 dot-atom, plus the
# characters Mealie's own validator tolerates. We only use this to
# decide whether the owner username is safe to drop verbatim into the
# left-hand side of an email; anything outside it gets sanitised.
_EMAIL_LOCALPART_RE = re.compile(r"^[A-Za-z0-9._%+-]+$")


def _owner_username() -> str:
    """The OpenHost owner's username, used as Mealie's username + name.

    OpenHost injects ``OPENHOST_OWNER_USERNAME`` into every app container
    (see compute_space core/data.py:provision_data). It's the name the
    owner picked on the claim/setup page (falling back to the platform
    default ``owner`` when they left it blank). We reuse it verbatim as
    the Mealie admin's username and full name so the owner sees a
    familiar identity instead of the seeded "Change Me" / "admin".

    Sanitised to what Mealie's username field accepts: we strip
    whitespace and, defensively, fall back to the platform default if
    the value is empty. We do NOT lowercase it — Mealie usernames are
    case-preserving — but the platform already constrains owner
    usernames to ``^[a-z0-9][a-z0-9._-]{0,29}$`` so this is normally a
    no-op.
    """
    raw = os.environ.get("OPENHOST_OWNER_USERNAME", "").strip()
    return raw or DEFAULT_OWNER_USERNAME


def _owner_email() -> str:
    """The email we relabel the admin to once bootstrap completes.

    We MUST move the admin off the seeded ``changeme@example.com``
    address. Mealie's ``/api/app/about/startup-info`` reports
    ``is_first_login=True`` for as long as ANY user with that exact
    email exists (see mealie/routes/app/app_about.py:get_startup_info).
    While ``is_first_login`` is true, both the SPA login page and the
    index route bounce an admin into the ``/admin/setup`` first-time
    wizard (frontend/app/pages/index.vue:41 and login.vue:266) — which
    is exactly the "loading screen that talks about changing the
    password" the OpenHost owner sees on every SSO login. Renaming the
    admin's email flips ``is_first_login`` to false and the owner lands
    straight on their group home page.

    We build the address as ``<owner-username>@<zone>`` so it matches
    the identity the owner picked on the OpenHost setup page (e.g.
    ``andrew@andrew-2.selfhost.imbue.com``). The auth-proxy reads the
    persisted email from the credentials file, so this value is the
    single source of truth for both auto-login and manual login.

    If the owner username somehow contains characters that aren't valid
    in an email local-part, we fall back to the safe ``owner`` local
    part rather than mint an address Mealie's validator would reject
    (which would fail the relabel and leave is_first_login true). If the
    zone domain is missing we fall back to a syntactically-valid
    sentinel domain so the address is still well-formed.
    """
    zone = os.environ.get("OPENHOST_ZONE_DOMAIN", "").strip().lower()
    local = _owner_username()
    if not _EMAIL_LOCALPART_RE.match(local):
        local = DEFAULT_OWNER_USERNAME
    if zone:
        return f"{local}@{zone}"
    return f"{local}@openhost.local"


TOKEN_PATH = "/api/auth/token"
SELF_PATH = "/api/users/self"
PASSWORD_PATH = "/api/users/password"
USER_PATH_TMPL = "/api/users/{user_id}"
GROUP_PREFERENCES_PATH = "/api/groups/preferences"
HOUSEHOLD_PREFERENCES_PATH = "/api/households/preferences"

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


def _build_relabel_payload(
    me: dict,
    new_email: str,
    new_full_name: str,
    new_username: str | None = None,
) -> dict:
    """Build a self-update payload that changes email + name (+ username).

    Mealie forbids an admin from changing their own permission
    attributes (mealie/routes/users/_helpers.py:assert_user_change_allowed
    raises 403 "Admins can't change their own permissions" if any of
    ``admin``/``can_invite``/``can_manage``/``can_manage_household``/
    ``can_organize`` differs between the current user and the PUT body).
    The comparison uses the values as they come back from
    ``/api/users/self``, so the ONLY safe way to relabel our own account
    is to echo every field from the ``me`` response verbatim — using the
    exact camelCase keys the API returns (e.g. ``canInvite``, NOT
    ``canInviteUsers``) — and override just the non-permission fields we
    intend to change (email, full name, and optionally username). None
    of those three are in the permission set, so changing them is
    allowed for a self-edit.

    Starting from a hand-written field list is what previously produced
    a 403: a mistyped permission key (``canInviteUsers``) fell back to
    the schema default (False) while the live admin had it True, so the
    guard saw a permission change and rejected the whole PUT.
    """
    payload = dict(me)  # copy the exact self representation
    payload["email"] = new_email
    payload["fullName"] = new_full_name
    if new_username:
        payload["username"] = new_username
    # Drop read-only / derived keys the UserBase update schema doesn't
    # accept (they're returned by /self but rejected on PUT). Keeping
    # only what UserBase defines avoids 422s while preserving every
    # permission attribute the 403-guard compares against.
    for read_only in (
        "groupId",
        "groupSlug",
        "householdId",
        "householdSlug",
        "cacheKey",
        "authMethod",
        "tokens",
        "password",
    ):
        payload.pop(read_only, None)
    # Strip Nones so pydantic doesn't choke on unexpected null shapes.
    return {k: v for k, v in payload.items() if v is not None}


def _put_preferences(token: str, path: str, fields: dict) -> bool:
    """PUT a group/household preferences object.

    Mealie's preference update endpoints accept a partial object and
    merge it (see controller_group_self_service.py:update_group_preferences
    and controller_household_self_service.py:update_household_preferences).
    We only send the keys we intend to change.

    Best-effort: on failure we log and return False. The caller treats a
    failure as "public sharing not enabled" rather than fatal.
    """
    payload = json.dumps(fields).encode("utf-8")
    status, body, _ = _request(
        "PUT",
        path,
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
            path,
            status,
            body[:300].decode("utf-8", errors="replace"),
        )
        return False
    return True


def _migration_marker_present() -> bool:
    return os.path.exists(MIGRATION_MARKER_FILE)


def _write_migration_marker() -> None:
    """Record that the one-shot public-sharing migration has run.

    Best-effort: if we can't write the marker we log and carry on. The
    only consequence of a missing marker is that the migration may run
    again on the next restart — which is safe for the email relabel
    (gated on the seeded email still being present) but would re-enable
    public sharing. To avoid silently reverting an operator's later
    re-privatisation, the caller only enables sharing when the marker
    is absent AND writes the marker in the same pass, so a marker write
    failure is the only window in which a re-enable could recur.
    """
    parent = os.path.dirname(MIGRATION_MARKER_FILE)
    if parent:
        try:
            os.makedirs(parent, exist_ok=True)
        except OSError as exc:
            log.warning("could not create marker parent dir %s: %s", parent, exc)
            return
    try:
        with open(MIGRATION_MARKER_FILE, "w", encoding="utf-8") as fh:
            fh.write(
                "# Sentinel written by bootstrap_admin.py. Its presence means the\n"
                "# one-time 'enable public sharing' migration has already run; the\n"
                "# bootstrap will NOT touch group/household privacy again. Safe to\n"
                "# delete if you want the migration to re-run on next restart.\n"
                "# NOT a secret.\n"
            )
    except OSError as exc:
        log.warning("could not write migration marker %s: %s", MIGRATION_MARKER_FILE, exc)


def _enable_public_sharing(token: str) -> None:
    """Turn off group/household privacy so public recipe links work.

    On a fresh database Mealie seeds the default group + household with
    ``private_group=True`` / ``private_household=True`` (the schema
    defaults, see mealie/schema/group/group_preferences.py:9 and
    mealie/schema/household/household_preferences.py:11). While a group
    is private, anonymous visitors hit
    ``/api/explore/groups/<slug>/recipes/<slug>`` — the endpoint the
    public-recipe page (`/g/<slug>/r/<slug>`) calls — and get a 404
    "group not found", so "make this recipe public and share the link"
    silently produces a dead link.

    Token-based share links (`/g/<slug>/shared/r/<token>`) work
    regardless of this setting because they resolve purely by share
    token (mealie/routes/recipe/shared_routes.py) — but the more common
    "publish + copy link" flow needs the group + household to be public.

    We flip both to non-private exactly ONCE, gated by the migration
    marker file (see MIGRATION_MARKER_FILE). Callers must only invoke
    this when the marker is absent, and MUST write the marker afterwards
    (via _write_migration_marker) so this never runs again — otherwise
    an operator who later re-privatises their group in the UI would have
    that choice silently reverted on the next container restart.

    Best-effort and non-fatal: a failure just leaves the operator to
    toggle "Enable public access" in Group / Household settings by hand.
    """
    if _put_preferences(token, GROUP_PREFERENCES_PATH, {"privateGroup": False}):
        log.info("enabled public group access (privateGroup=false)")
    if _put_preferences(
        token,
        HOUSEHOLD_PREFERENCES_PATH,
        {"privateHousehold": False, "recipePublic": True},
    ):
        log.info(
            "enabled public household access "
            "(privateHousehold=false, recipePublic=true)"
        )


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


def _migrate_existing_deploy(email: str, password: str) -> None:
    """Remediate deploys bootstrapped by an older version of this script.

    Earlier revisions kept the admin email at ``changeme@example.com``
    and left the default group private. That leaves two user-visible
    bugs on an already-running install: (1) the owner is bounced into
    the /admin/setup wizard on every SSO login because
    ``is_first_login`` stays true, and (2) "publish recipe + share link"
    produces dead links for anonymous visitors.

    On restart of such a deploy this migrates it in place:
      * if the admin email is still the seeded default, relabel it to
        the per-zone owner address and rewrite the persisted creds so
        the auth-proxy and manual login keep working;
      * enable public group/household sharing ONCE (gated by the
        migration marker), then write the marker so a later operator
        choice to re-privatise is never reverted.

    Everything here is best-effort and idempotent. If the migration
    marker is already present we skip entirely — a fully-migrated deploy
    makes no requests and never touches operator preferences.
    """
    # A present marker means this deploy has already been through the
    # migration; both remediations below are one-time, so there's
    # nothing to do. Crucially this prevents re-enabling public sharing
    # on a deploy where the operator has since re-privatised.
    if _migration_marker_present():
        return

    token = _wait_for_login(email, password, 60)
    if not token:
        log.info("migration: could not obtain token; skipping remediation")
        return

    me = _get_self(token)
    if not me:
        log.info("migration: could not read /api/users/self; skipping remediation")
        return

    # (1) Move the admin off the seeded email if it's still there.
    if me.get("email") == DEFAULT_EMAIL:
        user_id = me.get("id")
        new_email = _owner_email()
        new_username = _owner_username()
        update_fields = _build_relabel_payload(
            me, new_email, new_username, new_username=new_username
        )
        if (
            user_id
            and _update_user(token, user_id, update_fields)
            and _verify_login(new_email, password)
        ):
            if _write_credentials(new_email, password):
                log.info(
                    "migration: relabelled admin email %s -> %s "
                    "(fixes recurring first-time-setup screen)",
                    DEFAULT_EMAIL,
                    new_email,
                )
            else:
                log.warning(
                    "migration: relabelled email in mealie but could not "
                    "persist creds; auto-login may break until %s is fixed",
                    CRED_FILE,
                )
        else:
            log.warning("migration: admin email relabel to %s failed", new_email)

    # (2) Enable public sharing exactly once, then record the marker so
    # this never runs again (see the marker guard at the top of this
    # function). Writing the marker unconditionally after the attempt is
    # deliberate: even if _enable_public_sharing's PUTs failed, we don't
    # want to keep retrying on every restart and risk clobbering a later
    # operator choice — the operator can toggle sharing by hand, and can
    # delete the marker to force a re-run.
    _enable_public_sharing(token)
    _write_migration_marker()


def main() -> int:
    persisted_email, persisted_pw = _read_persisted_credentials()
    if persisted_email and persisted_pw:
        # Wait briefly for mealie to come up and verify the persisted
        # credentials still log in. This handles container restart
        # cleanly (idempotent re-bootstrap is a no-op).
        for _ in range(60):
            if _verify_login(persisted_email, persisted_pw):
                log.info("persisted owner credentials still valid")
                # Migrate deploys bootstrapped by an older revision that
                # left the seeded email / private group in place.
                _migrate_existing_deploy(persisted_email, persisted_pw)
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

    # Verify the new password works before continuing.
    if not _verify_login(DEFAULT_EMAIL, new_password):
        log.error("rotated password but verify-login failed; not persisting")
        return 1

    # Relabel the admin — CRITICALLY including moving the email off the
    # seeded ``changeme@example.com`` address. This is NOT cosmetic:
    # Mealie reports ``is_first_login=True`` for as long as a user with
    # that exact email exists (app_about.py:get_startup_info), and while
    # that flag is true the SPA bounces an admin into the /admin/setup
    # first-time wizard on every login (index.vue:41, login.vue:266) —
    # the "loading screen that mentions changing your password" the
    # OpenHost owner sees. Changing the email flips is_first_login to
    # false so the owner lands directly on their home page.
    new_email = _owner_email()
    # Use the OpenHost owner's username as both the Mealie username and
    # full name, and email = <username>@<zone>. This mirrors the
    # identity the owner picked on the OpenHost claim/setup page so they
    # see a familiar account instead of the seeded "admin" / "Change Me"
    # — and, critically, moves the email off changeme@example.com so
    # is_first_login flips false (see _owner_email).
    new_username = _owner_username()
    new_full_name = new_username
    # Echo the exact self representation and change only the
    # non-permission fields (email, name, username) so we don't trip
    # Mealie's "admins can't change their own permissions" 403 guard
    # (see _build_relabel_payload).
    update_fields = _build_relabel_payload(
        me, new_email, new_full_name, new_username=new_username
    )
    if not _update_user(token, user_id, update_fields):
        # The email relabel failed. Fall back to the seeded email so
        # the persisted credentials still line up with what mealie
        # believes the admin's login is — auto-login keeps working,
        # but the owner will keep seeing the first-time-setup wizard
        # (is_first_login stays true) until the email is changed by
        # hand. Better a working (if slightly annoying) login than a
        # broken one.
        log.warning(
            "could not relabel admin email to %s; falling back to %s. "
            "The owner may keep seeing Mealie's first-time-setup screen "
            "until the admin email is changed away from the default.",
            new_email,
            DEFAULT_EMAIL,
        )
        new_email = DEFAULT_EMAIL
    else:
        # Confirm the new email actually logs in before we persist it;
        # if mealie accepted the PUT but the email didn't take for some
        # reason, fall back rather than persist a credential that won't
        # authenticate.
        if not _verify_login(new_email, new_password):
            log.warning(
                "relabelled admin email to %s but verify-login failed; "
                "falling back to %s for persisted credentials",
                new_email,
                DEFAULT_EMAIL,
            )
            new_email = DEFAULT_EMAIL

    # Enable public sharing so "publish recipe + copy link" works for
    # anonymous visitors. Best-effort / non-fatal — see the function
    # docstring. We write the migration marker immediately afterwards so
    # the restart path (_migrate_existing_deploy) treats this deploy as
    # already migrated and never re-enables sharing on a later restart,
    # preserving any operator choice to re-privatise.
    _enable_public_sharing(token)
    _write_migration_marker()

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
