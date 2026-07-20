# Package Mealie for OpenHost: layer an nginx front proxy and an in-container
# OIDC bridge (OpenHost owner-auth -> OIDC) on top of the official image.
FROM ghcr.io/mealie-recipes/mealie:v3.20.1

USER root

# nginx front proxy + python venv tooling for the OIDC bridge.
# (The base image already has python3.12 as /opt/mealie's venv, but we build a
# separate, isolated venv for the bridge so we never touch Mealie's deps.)
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        nginx \
        python3 \
        python3-venv \
    && rm -rf /var/lib/apt/lists/*

# OIDC bridge in its own isolated venv (never touches Mealie's deps).
# Copy the package into /opt/oidc_bridge so it imports as `oidc_bridge.server`
# with /opt on the module search path.
COPY oidc_bridge /opt/oidc_bridge
RUN python3 -m venv /opt/oidc_bridge/.venv \
    && /opt/oidc_bridge/.venv/bin/pip install --no-cache-dir \
        starlette uvicorn "authlib>=1.3" python-multipart cryptography
ENV PYTHONPATH=/opt

COPY nginx.conf.template /etc/nginx/nginx.conf.template
COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

# OpenHost routes to 8080 (nginx); Mealie stays on loopback :9000.
EXPOSE 8080

# Override the base image's entrypoint with our supervisor.
ENTRYPOINT []
CMD ["/usr/local/bin/start.sh"]
