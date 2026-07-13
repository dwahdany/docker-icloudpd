# icloudpd + supervisor: minimal container
#
# Design notes:
# - Base image is PINNED (the old container used alpine:latest, so every
#   rebuild was a lottery).
# - icloudpd is installed from PyPI, pinned. 1.32.3 (2026-05-30) includes the
#   upstream fix for Apple's 2026+ auth flow (PR-1335) — no source build or
#   cherry-picking required.
# - The supervisor lives in the same venv, so it shares Python and requests.
# - icloudpd's --mfa-provider webui binds 0.0.0.0:8080 INSIDE the container
#   during runs. Do not publish that port; the supervisor talks to it over
#   localhost.

FROM alpine:3.22

ARG icloudpd_version="1.32.3"

ENV XDG_DATA_HOME="/config" \
    TZ="UTC" \
    config_dir="/config"

RUN apk add --no-cache python3 py3-pip tzdata ca-certificates && \
    python3 -m venv /opt/icloudpd && \
    /opt/icloudpd/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/icloudpd/bin/pip install --no-cache-dir "icloudpd==${icloudpd_version}"

COPY supervisor /tmp/supervisor
RUN /opt/icloudpd/bin/pip install --no-cache-dir /tmp/supervisor && \
    ln -s /opt/icloudpd/bin/icloudpd-supervisor /usr/local/bin/icloudpd-supervisor && \
    rm -rf /tmp/supervisor

HEALTHCHECK --start-period=60s --interval=1m --timeout=15s \
    CMD ["/usr/local/bin/icloudpd-supervisor", "healthcheck"]

VOLUME /config

CMD ["/usr/local/bin/icloudpd-supervisor"]
