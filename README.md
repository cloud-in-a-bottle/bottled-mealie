# openhost-mealie

[Mealie](https://mealie.io) — a self-hosted recipe manager and meal planner —
packaged as an OpenHost app with one-click SSO and public-recipe passthrough.

## What you get

- Mealie running on `https://mealie.<zone>/` with TLS terminated by the OpenHost
  outer Caddy.
- The zone owner is auto-logged-in to the admin UI on first visit. No
  Mealie-native sign-in form ever appears for the owner.
- Public recipe-share links (`/g/<group>/shared/r/<token>`, `/g/<group>/r/<recipe>`
  for recipes flagged public, plus the `/explore/` UI for public groups) work
  for anonymous visitors without OpenHost SSO.
- Persistent state under `/data/app_data/mealie/` (sqlite + recipe images +
  generated owner credentials, mode 0600).
- Open self-signup is disabled (`ALLOW_SIGNUP=false`); the owner invites
  collaborators via Mealie's native admin UI.

## Architecture

```
browser
   │
   ▼
OpenHost outer Caddy (TLS)
   │
   ▼
OpenHost router (stamps X-OpenHost-Is-Owner: true on owner JWTs;
                 lets public-share paths through unauthenticated)
   │
   ▼
container :8080  ── auth_proxy.py ────────────────┐
                   - on first owner visit, POSTs   │
                     /api/auth/token with stored   │
                     credentials and 302's the     │
                     browser back with the         │
                     mealie.access_token cookie    │
                   - public paths bypass the       │
                     auto-login dance              │
                   - WebSocket upgrades forwarded  │
                     transparently                 │
                                                   ▼
                                       127.0.0.1:9000  (mealie)
```

`bootstrap_admin.py` runs once on cold start. Mealie seeds a default admin
(`changeme@example.com` / `MyPassword`) on first DB init; we use that to log in,
then PUT `/api/users/password` to rotate to a 32-char generated password. We
also PUT `/api/users/{id}` to move the admin's email off the seeded
`changeme@example.com` address to a per-zone `owner@<zone>` value. This email
change is load-bearing: Mealie reports `is_first_login=true` for as long as a
user with the seeded email exists, and while that flag is true the SPA bounces
an admin into the `/admin/setup` first-time-setup wizard on every login. That
wizard (which mentions changing the password) is the "loading screen" an owner
would otherwise see on each SSO login. Moving the email flips the flag to
false so the owner lands straight on their home page. The rotated password and
the new email are persisted to `admin-credentials.txt` (mode 0600) for the
auth-proxy to consume, so auto-login and any manual fallback login stay in
sync. Open self-signup is disabled via `ALLOW_SIGNUP=false` exported by
`start.sh` (Mealie's registration endpoint reads `settings.ALLOW_SIGNUP`
directly).

On first boot the bootstrap also enables public group + household sharing
once (`privateGroup=false`, `privateHousehold=false`, `recipePublic=true`) so
the "publish a recipe and copy the link" flow works for anonymous visitors —
Mealie seeds these as private, which otherwise makes public-recipe links
dead-ends. This is gated by a one-shot marker file (`.openhost-migrated` in
the data dir), so if you later re-privatise your group in the UI it is never
reverted on restart. Deploys created by an older revision of this packaging
are migrated in place on their next restart (email relabel + one-time sharing
enable).

## Auth model

| Visitor                    | Outcome                                           |
| -------------------------- | ------------------------------------------------- |
| Anonymous, public path     | Forwarded to Mealie unchanged (anonymous read).   |
| Anonymous, non-public path | OpenHost router 302's to `/login` on parent zone. |
| Owner, has cookie          | Forwarded unchanged.                              |
| Owner, no cookie, HTML     | Auto-login mints `mealie.access_token` cookie.    |
| Owner, no cookie, API/docs | Forwarded; mobile apps use Bearer tokens.         |

The auth-proxy explicitly excludes `/api/`, `/docs`, `/redoc`, and `/openapi`
paths from the auto-login bounce — even when the request includes
`Accept: text/html` — so Bearer-token clients always get a clean pass-through
and never an unexpected 302+Set-Cookie.

The auth-proxy ALWAYS strips client-supplied `X-OpenHost-Is-Owner` and
`X-OpenHost-User` headers before forwarding upstream — defence in depth.

## Public paths

The following path prefixes are allowed through the OpenHost router without
zone_auth, and the auth-proxy does NOT auto-login on them:

- `/g/` — group-scoped pages: public recipes (`/g/<group>/r/<slug>` when
  `recipe.settings.public` is set), share-token pages
  (`/g/<group>/shared/r/<token>`), and SPA-rendered fallthroughs that the
  Nuxt frontend gates client-side.
- `/explore/` — public group-exploration UI.
- `/api/` — the entire mealie REST API. Each endpoint enforces its own JWT
  auth, so this layer is just "let the request through to mealie and let
  mealie decide". Mobile clients, the recipe-import bookmarklet, n8n
  integrations, and the SPA itself all depend on this. Public
  (anonymous-allowed) endpoints inside `/api/` are `/api/auth/token`,
  `/api/explore/...`, `/api/recipes/shared/...`, `/api/app/about`, and
  `/api/media/...`.
- `/_nuxt/`, `/assets/`, `/icons/`, `/favicon.ico`, `/manifest.webmanifest`,
  `/_healthz` — static SPA assets and proxy health probe.

The lists in `openhost.toml`'s `routing.public_paths` and `auth_proxy.py`'s
`PUBLIC_PATH_PREFIXES` MUST stay in sync.

## Files

| File                  | Purpose                                                 |
| --------------------- | ------------------------------------------------------- |
| `openhost.toml`       | OpenHost manifest                                       |
| `Dockerfile`          | Wraps `ghcr.io/mealie-recipes/mealie:v3.17.0` + tini    |
| `start.sh`            | Boots Mealie on `:9000`, runs bootstrap, starts proxy   |
| `auth_proxy.py`       | OpenHost-SSO sidecar (Pattern B1)                       |
| `bootstrap_admin.py`  | First-boot owner credential rotation                    |
| `README.md`           | This file                                               |

## Resetting the owner password

If you rotate the password inside Mealie's UI, the persisted file under
`/data/app_data/mealie/admin-credentials.txt` will go stale and auto-login
will stop working (the auth-proxy logs a warning and falls through to
Mealie's login form).

To re-sync:

1. Either edit `admin-credentials.txt` to match the new password, OR
2. Delete the file. The bootstrap script on next restart will re-detect
   "no persisted credentials" and either rebootstrap (if the seeded admin
   row still exists) or leave you on the manual login form.

`Reload Router` from the OpenHost dashboard after editing.

## Why Pattern B1 (HTTP login dance) and not Pattern D (OIDC)?

Mealie supports OIDC natively (`OIDC_AUTH_ENABLED=true`,
`OIDC_CONFIGURATION_URL=...`) and Pattern D would normally be the cleaner
choice. We picked B1 because OpenHost's router currently exposes only
`/.well-known/jwks.json` — there's no `openid-configuration` discovery
document for Mealie's authlib client to consume. A Pattern D implementation
would require running an in-container OIDC IdP bridge (along the lines of
`openhost-immich/oidc-bridge`); that's tractable but materially more code
than B1, and B1 is well-trodden across openhost-memos / openhost-overleaf /
openhost-vscode. If OpenHost grows an OpenID Connect discovery endpoint in
the future, swapping in Pattern D is a one-Dockerfile-change away.

## Threat model around `admin-credentials.txt`

Files under `$OPENHOST_APP_DATA_DIR` are visible to other apps with
`access_all_data = true` (the file-browser app, by default). The
credentials file is mode 0600 and lives only inside the mealie container's
data dir — but if the operator installs file-browser with full access, it
WILL be readable. Anyone reading it can sign in to Mealie as the owner.

Mealie's session table is JWT-based (no row in the database) so Pattern B2
(direct DB INSERT of a session row) isn't applicable here without forging
JWTs. Forging would require the JWT secret, which mealie generates and
stores under `data/.secret`; we don't have a meaningfully better hiding
spot for it than the credentials file. The honest summary is: anyone who
can read `admin-credentials.txt` can also read `data/.secret` and forge
their own JWT. Don't grant `access_all_data = true` casually.
