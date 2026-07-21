#!/usr/bin/env bash
# Supervisor for the OpenHost Mealie app.
#
# Layout inside the container:
#   nginx        :8080  (the OpenHost-routed port) -> routes to Mealie / bridge
#   mealie       :9000  (upstream recipe app)
#   oidc_bridge  :9100  (OpenHost owner-auth -> OIDC IdP)
#
# We run all three and exit if any of them dies (wait -n).

set -euo pipefail

DATA_DIR="${OPENHOST_APP_DATA_DIR:-/app/data}"
ZONE_DOMAIN="${OPENHOST_ZONE_DOMAIN:-localhost}"
APP_NAME="${OPENHOST_APP_NAME:-mealie}"
PUBLIC_HOST="${APP_NAME}.${ZONE_DOMAIN}"
PUBLIC_URL="https://${PUBLIC_HOST}"

echo "[start] public URL: ${PUBLIC_URL}"

# --- Persistent data dir --------------------------------------------------
# Mealie stores its SQLite db + images under a data dir. The upstream image
# marks /app/data as a VOLUME (auto-mounted by podman), so we can't repoint
# that path. Instead, Mealie honours the DATA_DIR env var in production
# (mealie/core/config.py determine_data_dir()), so point it straight at the
# OpenHost persistent mount and make it writable by Mealie's runtime user
# (uid/gid 911, user 'abc' in the upstream image).
mkdir -p "${DATA_DIR}"
chown -R 911:911 "${DATA_DIR}" 2>/dev/null || true
export DATA_DIR="${DATA_DIR}"

# --- OIDC bridge config ---------------------------------------------------
# A stable client secret shared between Mealie and the bridge. Generated once
# and kept in the data dir; it is not a user credential (it only lets a party
# who already controls this container mint tokens for this app).
SECRET_FILE="${DATA_DIR}/.oidc_client_secret"
if [ ! -f "${SECRET_FILE}" ]; then
    head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 40 > "${SECRET_FILE}"
    chmod 600 "${SECRET_FILE}"
fi
OIDC_CLIENT_SECRET="$(cat "${SECRET_FILE}")"

export OIDC_BRIDGE_BASE_URL="${PUBLIC_URL}"
export OIDC_BRIDGE_KEY_PATH="${DATA_DIR}/.oidc_bridge_key.json"
export OIDC_BRIDGE_CLIENT_ID="mealie"
export OIDC_BRIDGE_CLIENT_SECRET="${OIDC_CLIENT_SECRET}"
export OPENHOST_OWNER_USERNAME="${OPENHOST_OWNER_USERNAME:-owner}"
export OPENHOST_ZONE_DOMAIN="${ZONE_DOMAIN}"

# --- Mealie config --------------------------------------------------------
export BASE_URL="${PUBLIC_URL}"
export API_PORT=9000
export API_HOST=127.0.0.1
export DB_ENGINE=sqlite
export ALLOW_SIGNUP=false
# Pure-SSO: users never see a password form; the owner is auto-redirected to
# our in-container IdP, which trusts OpenHost owner auth.
export OIDC_AUTH_ENABLED=true
export OIDC_AUTO_REDIRECT=true
export ALLOW_PASSWORD_LOGIN=false
export OIDC_SIGNUP_ENABLED=true
export OIDC_REMEMBER_ME=true
export OIDC_REQUIRES_EMAIL_VERIFICATION=false
export OIDC_CONFIGURATION_URL="http://127.0.0.1:8080/_oidc/.well-known/openid-configuration"
export OIDC_CLIENT_ID="mealie"
export OIDC_CLIENT_SECRET="${OIDC_CLIENT_SECRET}"
export OIDC_USER_CLAIM="email"
export OIDC_NAME_CLAIM="name"
export OIDC_PROVIDER_NAME="OpenHost"
# Tell uvicorn/gunicorn to trust the loopback proxy so X-Forwarded-Proto is
# honored and the OIDC redirect URI is built as https.
export GUNICORN_CMD_ARGS="--forwarded-allow-ips=*"
export FORWARDED_ALLOW_IPS="*"

# --- nginx config ---------------------------------------------------------
sed "s|\$HOST_PLACEHOLDER|${PUBLIC_HOST}|g" \
    /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf
mkdir -p /tmp/nginx-client-body /tmp/nginx-proxy /tmp/nginx-fastcgi \
         /tmp/nginx-uwsgi /tmp/nginx-scgi

# --- launch ---------------------------------------------------------------
# OIDC bridge (loopback only).
/opt/oidc_bridge/.venv/bin/uvicorn oidc_bridge.server:app \
    --host 127.0.0.1 --port 9100 --no-access-log &
BRIDGE_PID=$!
echo "[start] oidc bridge pid=${BRIDGE_PID}"

# nginx front proxy.
nginx -c /etc/nginx/nginx.conf -g 'daemon off;' &
NGINX_PID=$!
echo "[start] nginx pid=${NGINX_PID}"

# Mealie via its own entrypoint (handles migrations, drops to uid 911).
/app/run.sh &
MEALIE_PID=$!
echo "[start] mealie pid=${MEALIE_PID}"

# Exit (and let OpenHost restart us) if any component dies.
wait -n
echo "[start] a component exited; shutting down"
kill "${BRIDGE_PID}" "${NGINX_PID}" "${MEALIE_PID}" 2>/dev/null || true
exit 1
