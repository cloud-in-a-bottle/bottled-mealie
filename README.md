# openhost-mealie

[Mealie](https://mealie.io) packaged as an OpenHost app — a self-hosted recipe
manager and meal planner with a per-recipe **cooking timeline** ("I Made This"
dated entries with notes, photos, and ratings), which makes it a natural fit
for iterating on a recipe across multiple cooking attempts.

## What you get

- Recipe storage, editing, URL/image import, categories, tags, cookbooks.
- A **Timeline** on each recipe: log every time you cook it with a date, a
  note ("cut the garlic in half, she liked it more"), a photo, and a rating —
  a running journal of how a dish evolved.
- Meal planning and shopping lists.
- Single-container deployment with SQLite. No external database required.

## Authentication (zero-click owner SSO)

Access is restricted to the zone owner via OpenHost SSO. There is no login
form: when the owner opens the app, Mealie (configured with
`OIDC_AUTO_REDIRECT`) sends the browser to a tiny in-container OIDC identity
provider (`oidc_bridge/server.py`). Because the whole app sits behind the
OpenHost router, the owner's request carries `X-OpenHost-Is-Owner: true`; the
bridge trusts that header and issues an OIDC authorization code (auth-code +
PKCE). Mealie exchanges it, reads the signed ID token, and auto-provisions the
owner as an admin on first login.

Non-owner visitors receive `403` from the bridge — Mealie has no anonymous
public-sharing surface, so nothing is exposed without zone auth.

```
browser :443 ──▶ OpenHost router ──▶ nginx :8080
                                       ├─ /_healthz         → static 200
                                       ├─ /_oidc/*          → oidc_bridge :9100
                                       └─ /                 → Mealie :9000
```

## Data & credentials

All persistent state lives under `$OPENHOST_APP_DATA_DIR` (Mealie's `/app/data`
is symlinked there): the SQLite database, uploaded recipe images, and two
non-user-credential files:

- `.oidc_bridge_key.json` — the RSA key the bridge signs ID tokens with.
- `.oidc_client_secret` — the secret shared between Mealie and the bridge.

Neither is a user password. They only let a party who **already controls this
container** mint tokens for this app — the same trust boundary as the app's own
database. No plaintext user password is ever written to disk.

## Files

- `Dockerfile` — layers nginx + the OIDC bridge onto the official Mealie image.
- `start.sh` — supervisor (nginx + Mealie + bridge; exits if any dies).
- `nginx.conf.template` — front proxy on `:8080`.
- `oidc_bridge/server.py` — OpenHost owner-auth → OIDC identity provider.
- `openhost.toml` — the OpenHost app manifest.
