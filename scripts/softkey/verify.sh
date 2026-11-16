#!/usr/bin/env bash
# Check that Apple accepts the software security key for a sign-in, from this
# machine, before the key file is put on the server.
#
#   scripts/softkey/verify.sh <apple-id> [key-file] [com|cn]
#
# Signs in with icloudpd exactly as the container does (same wrapper, same
# key file), into a temporary directory that is deleted afterwards. You type
# the iCloud password at icloudpd's prompt; nothing is stored. No USB key and
# no Pico are involved: the key file answers Apple's challenge.
set -euo pipefail

APPLE_ID=${1:?usage: verify.sh <apple-id> [key-file] [com|cn]}
KEY=${2:-$HOME/.config/icloudpd-softkey/softkey.json}
DOMAIN=${3:-com}
VERSION=1.33.0
REPO=$(cd "$(dirname "$0")/../.." && pwd)
[ -f "$KEY" ] || { echo "error: no key file at $KEY" >&2; exit 1; }

# Pure-Python wheel, pinned by hash (see copy-session.sh for why).
WHEEL=$(uv run --no-project -q python - "$VERSION" <<'PY'
import json, sys, urllib.request
with urllib.request.urlopen(f"https://pypi.org/pypi/icloudpd/{sys.argv[1]}/json", timeout=30) as r:
    files = json.load(r)["urls"]
pure = [f for f in files if f["filename"].endswith("-py3-none-any.whl")]
print(f'{pure[0]["url"]}#sha256={pure[0]["digests"]["sha256"]}')
PY
)

TMP=$(mktemp -d)
chmod 700 "$TMP"
trap 'rm -rf "$TMP"' EXIT

uv run --no-project -q --with "icloudpd @ $WHEEL" --with "$REPO/supervisor" \
  python -m icloudpd_supervisor.softkey_run "$KEY" \
  --username "$APPLE_ID" --cookie-directory "$TMP" --domain "$DOMAIN" \
  --auth-only --password-provider console --mfa-provider console

if grep -q '"trust_token"' "$TMP"/*.session 2>/dev/null; then
  echo "OK: Apple accepted the software key and issued a trusted session."
else
  echo "FAILED: sign-in finished without a trusted session." >&2
  exit 1
fi
