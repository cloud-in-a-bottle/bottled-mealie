# Mealie packaged for OpenHost with one-click SSO.
#
# Architecture:
#
#   browser
#      │
#      ▼
#   OpenHost outer Caddy (TLS)
#      │
#      ▼
#   OpenHost router (subdomain mealie.<zone>; verifies zone_auth JWT
#                    and stamps X-OpenHost-Is-Owner: true)
#      │
#      ▼
#   container :8080  (auth_proxy.py — auto-login sidecar)
#      │
#      ▼
#   127.0.0.1:9000  (mealie's own ASGI app under uvicorn)
#
# On first boot, bootstrap_admin.py:
#   1. waits for mealie's seeded "changeme@example.com" / "MyPassword"
#      admin row to exist,
#   2. logs in with those defaults,
#   3. PUT /api/users/password to rotate to a generated 32-char password,
#   4. PUT /api/users/{id} to keep the user labelled "Owner" (cosmetic),
#   5. persists the rotated credentials under
#      $OPENHOST_APP_DATA_DIR/admin-credentials.txt (mode 0600).
#
# Open self-signup is disabled separately via the ALLOW_SIGNUP=false
# env var exported by start.sh, which Mealie reads into
# settings.ALLOW_SIGNUP and the registration endpoint enforces.
#
# auth_proxy.py reads admin-credentials.txt once per cold-start of an
# owner browser, POSTs /api/auth/token to mint a JWT, and 302s the
# browser back with mealie.access_token cookie set.

# Mealie publishes a multi-arch image at ghcr.io/mealie-recipes/mealie.
# Pinning :v3.17.0 (latest stable as of 2026-05) for reproducible builds.
# Bump as needed; the OpenHost-side glue is independent of Mealie's
# minor versions.
FROM ghcr.io/mealie-recipes/mealie:v3.17.0

# Mealie's base image is python:3.12-slim, so apt + pip are available.
# We only need python3 (already present) and the small extras for the
# auth-proxy to bind on a privileged-ish port and resolve DNS reliably.
USER root
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        ca-certificates \
        tini \
    && rm -rf /var/lib/apt/lists/*

# All app files committed with mode 0755 in the git index.
COPY start.sh           /opt/openhost-mealie/start.sh
COPY auth_proxy.py      /opt/openhost-mealie/auth_proxy.py
COPY bootstrap_admin.py /opt/openhost-mealie/bootstrap_admin.py

RUN chmod 0755 /opt/openhost-mealie/start.sh \
                /opt/openhost-mealie/auth_proxy.py \
                /opt/openhost-mealie/bootstrap_admin.py

# OpenHost-routed port. Mealie's port (9000) stays loopback.
EXPOSE 8080

# tini reaps zombies and forwards SIGTERM to start.sh's child set.
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/openhost-mealie/start.sh"]
