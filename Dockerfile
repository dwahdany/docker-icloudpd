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
# - patches/icloudpd-<version>/ holds upstream fixes that are merged but not
#   released yet, as diffs against the installed packages. They are applied
#   only to the icloudpd version they are named for, so bumping the pin drops
#   them, and a patch that does not apply fails the build.
# - yubikey-manager (for a security key held in a YubiKey, piv.py) is
#   installed WITHOUT its dependencies: only its `yubikit` library is used,
#   which needs nothing beyond what icloudpd already brings. Its command line
#   and PC/SC support (pyscard, a C build) are not; the container talks to the
#   YubiKey directly over USB (pyusb + libusb).
# - The supervisor lives in the same venv, so it shares Python and requests.
# - icloudpd's --mfa-provider webui binds 0.0.0.0:8080 INSIDE the container
#   during runs. Do not publish that port; the supervisor talks to it over
#   localhost.

FROM alpine:3.22

ARG icloudpd_version="1.34.0"

ENV XDG_DATA_HOME="/config" \
    TZ="UTC" \
    config_dir="/config"

# Build deps are needed on Alpine (musl): PyPI's manylinux wheels target
# glibc, so pip may compile parts of icloudpd's dependency tree
# (cryptography/srp/...) from source. Removed again after install.
RUN apk add --no-cache python3 py3-pip tzdata ca-certificates libusb && \
    apk add --no-cache --virtual build gcc python3-dev libc-dev libffi-dev cargo openssl-dev && \
    python3 -m venv /opt/icloudpd && \
    /opt/icloudpd/bin/pip install --no-cache-dir --upgrade pip && \
    wheel="$(/opt/icloudpd/bin/python -c "import json, sys, urllib.request; files = json.load(urllib.request.urlopen('https://pypi.org/pypi/icloudpd/' + sys.argv[1] + '/json', timeout=60))['urls']; pure = [f for f in files if f['filename'].endswith('-py3-none-any.whl')][0]; print(pure['url'] + '#sha256=' + pure['digests']['sha256'])" "${icloudpd_version}")" && \
    /opt/icloudpd/bin/pip install --no-cache-dir "icloudpd @ ${wheel}" && \
    /opt/icloudpd/bin/pip install --no-cache-dir pyusb && \
    /opt/icloudpd/bin/pip install --no-cache-dir --no-deps "yubikey-manager>=5.5,<6" && \
    apk del build

COPY patches /tmp/patches
RUN apk add --no-cache --virtual patching patch && \
    site="$(/opt/icloudpd/bin/python -c "import sysconfig; print(sysconfig.get_paths()['purelib'])")" && \
    for file in /tmp/patches/icloudpd-${icloudpd_version}/*.patch; do \
        [ -e "${file}" ] || continue; \
        echo "Applying ${file}" && patch -p1 -d "${site}" < "${file}" || exit 1; \
    done && \
    /opt/icloudpd/bin/python -m compileall -q "${site}/icloudpd" "${site}/pyicloud_ipd" && \
    apk del patching && \
    rm -rf /tmp/patches

COPY supervisor /tmp/supervisor
RUN /opt/icloudpd/bin/pip install --no-cache-dir /tmp/supervisor && \
    ln -s /opt/icloudpd/bin/icloudpd-supervisor /usr/local/bin/icloudpd-supervisor && \
    rm -rf /tmp/supervisor

HEALTHCHECK --start-period=60s --interval=1m --timeout=15s \
    CMD ["/usr/local/bin/icloudpd-supervisor", "healthcheck"]

VOLUME /config

CMD ["/usr/local/bin/icloudpd-supervisor"]
