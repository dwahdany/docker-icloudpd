# icloudpd + supervisor: minimal container
#
# Design notes:
# - Base image is PINNED (the old container used alpine:latest, so every
#   rebuild was a lottery).
# - icloudpd is installed from PyPI, pinned, as its pure-Python wheel. pip
#   would otherwise pick the platform wheel, which wraps a prebuilt binary
#   with its own Python: nothing in it can be imported, and the software
#   security key (softkey_run.py) has to run inside icloudpd's process.
#   1.33.0 is the first release that signs in with security keys.
# - The supervisor lives in the same venv, so it shares Python and requests.
# - icloudpd's --mfa-provider webui binds 0.0.0.0:8080 INSIDE the container
#   during runs. Do not publish that port; the supervisor talks to it over
#   localhost.

FROM alpine:3.22

ARG icloudpd_version="1.33.0"

ENV XDG_DATA_HOME="/config" \
    TZ="UTC" \
    config_dir="/config"

# Build deps are needed on Alpine (musl): PyPI's manylinux wheels target
# glibc, so pip may compile parts of icloudpd's dependency tree
# (cryptography/srp/...) from source. Removed again after install.
RUN apk add --no-cache python3 py3-pip tzdata ca-certificates && \
    apk add --no-cache --virtual build gcc python3-dev libc-dev libffi-dev cargo openssl-dev && \
    python3 -m venv /opt/icloudpd && \
    /opt/icloudpd/bin/pip install --no-cache-dir --upgrade pip && \
    wheel="$(/opt/icloudpd/bin/python -c "import json, sys, urllib.request; files = json.load(urllib.request.urlopen('https://pypi.org/pypi/icloudpd/' + sys.argv[1] + '/json', timeout=60))['urls']; pure = [f for f in files if f['filename'].endswith('-py3-none-any.whl')][0]; print(pure['url'] + '#sha256=' + pure['digests']['sha256'])" "${icloudpd_version}")" && \
    /opt/icloudpd/bin/pip install --no-cache-dir "icloudpd @ ${wheel}" && \
    apk del build

COPY supervisor /tmp/supervisor
RUN /opt/icloudpd/bin/pip install --no-cache-dir /tmp/supervisor && \
    ln -s /opt/icloudpd/bin/icloudpd-supervisor /usr/local/bin/icloudpd-supervisor && \
    rm -rf /tmp/supervisor

HEALTHCHECK --start-period=60s --interval=1m --timeout=15s \
    CMD ["/usr/local/bin/icloudpd-supervisor", "healthcheck"]

VOLUME /config

CMD ["/usr/local/bin/icloudpd-supervisor"]
