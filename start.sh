#!/bin/bash
# Boot Mealie for OpenHost.
#
# Topology (see Dockerfile for diagram):
#   container :8080  → auth_proxy.py → 127.0.0.1:9000  → mealie
#
# Persistent state lives under $OPENHOST_APP_DATA_DIR (bind-mounted by
# OpenHost). We create $OPENHOST_APP_DATA_DIR/data and chown it to
# uid/gid 911 (the "abc" user the upstream image switches to via gosu),
# then symlink /app/data → that path so mealie reads/writes durable
# state there.
#
# Mealie's upstream entry script (installed at /app/run.sh inside the
# image; the source lives at docker/entry.sh in the mealie repo)
# starts as root, calls `gosu 911 run.sh`, and execs `mealie`
# (uvicorn) on $API_PORT bound to $HOST. We invoke that entrypoint
# verbatim — it handles uid drop, secrets loading, alembic migrations,
# and the web server boot. The only customisation is API_PORT=9000
# and HOST=127.0.0.1 so mealie listens on loopback, leaving the
# auth-proxy the single externally-reachable listener.

set -euo pipefail

PERSIST="${OPENHOST_APP_DATA_DIR:-/data/app_data/mealie}"
DATA_DIR="$PERSIST/data"
CRED_FILE="$PERSIST/admin-credentials.txt"
ZONE_DOMAIN="${OPENHOST_ZONE_DOMAIN:-localhost}"
APP_NAME="${OPENHOST_APP_NAME:-mealie}"

mkdir -p "$DATA_DIR"
# chown so the gosu'd uid 911 can read/write. Done as root before
# the upstream entry.sh re-execs as abc.
chown -R 911:911 "$DATA_DIR" "$PERSIST" 2>/dev/null || true

# Point mealie at our persistent directory instead of the image's
# default /app/data. The upstream image marks /app/data as a VOLUME
# and pre-populates it with empty subdirs, so we can't reliably
# rm/symlink it from inside an unprivileged container. Mealie
# respects the DATA_DIR env var (see mealie/core/config.py:21,
# determine_data_dir()) and uses it as the root for sqlite + recipe
# images + .secret + backups. Setting it here keeps state outside
# /app and on the OpenHost-bind-mounted persistent dir.
export DATA_DIR="$DATA_DIR"

# Emit the public BASE_URL so mealie generates correct OG tags / share
# links. The OpenHost router serves us at https://<app>.<zone>/.
export BASE_URL="https://${APP_NAME}.${ZONE_DOMAIN}"
export API_PORT=9000
export HOST=127.0.0.1
# Disable open self-signup. Mealie reads ALLOW_SIGNUP into
# settings.ALLOW_SIGNUP at startup; the registration endpoint
# (mealie/routes/users/registration.py) gates on that value, so this
# env var is the single source of truth — bootstrap_admin.py does NOT
# additionally flip a DB flag.
export ALLOW_SIGNUP="${ALLOW_SIGNUP:-false}"
# Mealie's login dance is straight password — keep that available
# (default true) so the auth-proxy can mint sessions via /api/auth/token.
export ALLOW_PASSWORD_LOGIN="${ALLOW_PASSWORD_LOGIN:-true}"
export PRODUCTION=true

echo "[start.sh] Persist=$PERSIST Data=$DATA_DIR BASE_URL=$BASE_URL"

# -----------------------------------------------------------------
# Launch mealie via the upstream entry.sh in the background. It
# performs the gosu drop and execs uvicorn.
# -----------------------------------------------------------------
echo "[start.sh] Starting mealie on 127.0.0.1:9000"
/app/run.sh &
MEALIE_PID=$!

# -----------------------------------------------------------------
# Run bootstrap once mealie is up. Best-effort: a failure leaves
# the operator on Mealie's normal login form rather than the
# auto-login redirect.
# -----------------------------------------------------------------
echo "[start.sh] Running bootstrap_admin.py in the background"
(
    BOOTSTRAP_CRED_FILE="$CRED_FILE" \
        MEALIE_UPSTREAM_HOST="127.0.0.1" \
        MEALIE_UPSTREAM_PORT="9000" \
        python3 /opt/openhost-mealie/bootstrap_admin.py || true
) &
BOOTSTRAP_PID=$!

# -----------------------------------------------------------------
# Launch auth-proxy in the foreground-but-backgrounded so we can
# supervise both children with `wait -n`.
# -----------------------------------------------------------------
echo "[start.sh] Starting auth-proxy on 0.0.0.0:8080 -> 127.0.0.1:9000"
AUTH_PROXY_LISTEN_PORT="${AUTH_PROXY_LISTEN_PORT:-8080}" \
    AUTH_PROXY_UPSTREAM_HOST="127.0.0.1" \
    AUTH_PROXY_UPSTREAM_PORT="9000" \
    AUTH_PROXY_CRED_FILE="$CRED_FILE" \
    python3 /opt/openhost-mealie/auth_proxy.py &
PROXY_PID=$!

# -----------------------------------------------------------------
# Supervision: exit when mealie or the proxy dies. The bootstrap
# script is one-shot and harmless if it exits; we only wait for it
# to give it a chance to update credentials.
# -----------------------------------------------------------------
trap 'kill -TERM $MEALIE_PID $PROXY_PID $BOOTSTRAP_PID 2>/dev/null || true; wait 2>/dev/null || true; exit 0' TERM INT

# bash supports `wait -n`; alpine ash also supports it. We supervise
# only mealie + proxy (not bootstrap, which is allowed to exit).
while :; do
    if ! kill -0 "$MEALIE_PID" 2>/dev/null; then
        echo "[start.sh] mealie exited; shutting down"
        break
    fi
    if ! kill -0 "$PROXY_PID" 2>/dev/null; then
        echo "[start.sh] auth-proxy exited; shutting down"
        break
    fi
    sleep 5
done

kill -TERM "$MEALIE_PID" "$PROXY_PID" "$BOOTSTRAP_PID" 2>/dev/null || true
wait 2>/dev/null || true
exit 0
