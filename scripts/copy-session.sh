#!/usr/bin/env bash
# Sign in to iCloud on THIS machine, then install the resulting session into a
# docker-icloudpd container's /config on a remote Docker host.
#
# Why: Apple IDs protected by security keys (FIDO, e.g. YubiKey) never get a
# six-digit code, so the container's Telegram 2FA relay cannot authenticate
# them. icloudpd >= 1.33.0 can do the key ceremony, but only with the key
# plugged into the machine running it. This is upstream's documented
# workaround: sign in where the key is, copy the cookie directory over.
# It also works for ordinary 2FA accounts (you type the code here instead).
#
#   scripts/copy-session.sh [options] <remote-config-dir>
#   scripts/copy-session.sh /mnt/user/appdata/icloudpd/dari
#
# <remote-config-dir> is the HOST path that the container mounts at /config.
#
#   -H, --host HOST         ssh host of the Docker machine (default: $TOWER_HOST or "tower")
#   -u, --apple-id ID       Apple ID (default: apple_id= from <dir>/icloudpd.conf)
#   -c, --container NAME    container to stop/start (default: the one mounting <dir> at /config)
#   -d, --domain com|cn     iCloud domain (default: cn if the conf says auth_china=true, else com)
#   -V, --icloudpd VERSION  icloudpd version to sign in with (default: 1.33.0)
#   -n, --check             show what would happen and exit; contacts neither Apple nor the container
#
# What it does:
#   1. reads the Apple ID from the remote conf and finds the container;
#   2. runs `icloudpd --auth-only` locally (via uvx) into a private temp dir —
#      you enter the password and touch the key / type the code;
#   3. stops the container (a running icloudpd would overwrite the files),
#      backs up the old cookie + session next to the originals, installs the
#      new ones with the old ownership, and starts the container again.
# The password is typed at icloudpd's own prompt and is not stored anywhere
# by this script; the temp dir is deleted on exit.
set -euo pipefail

HOST=${TOWER_HOST:-tower}
APPLE_ID=""
CONTAINER=""
DOMAIN=""
VERSION=1.33.0
CHECK=0
REMOTE_DIR=""

die() { echo "error: $*" >&2; exit 1; }
usage() { sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p;}' "$0"; }

while [ $# -gt 0 ]; do
  case $1 in
    -H|--host) HOST=${2:?}; shift 2 ;;
    -u|--apple-id) APPLE_ID=${2:?}; shift 2 ;;
    -c|--container) CONTAINER=${2:?}; shift 2 ;;
    -d|--domain) DOMAIN=${2:?}; shift 2 ;;
    -V|--icloudpd) VERSION=${2:?}; shift 2 ;;
    -n|--check) CHECK=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) die "unknown option: $1 (see --help)" ;;
    *) [ -z "$REMOTE_DIR" ] || die "only one remote config dir, got a second: $1"; REMOTE_DIR=$1; shift ;;
  esac
done
[ -n "$REMOTE_DIR" ] || { usage >&2; exit 2; }
REMOTE_DIR=${REMOTE_DIR%/}
case $REMOTE_DIR in /*) ;; *) die "remote config dir must be an absolute path: $REMOTE_DIR" ;; esac
command -v uv >/dev/null && command -v uvx >/dev/null || die "uv (with uvx) is required to run icloudpd locally"

# Run a bash script (stdin) on the remote host with safely quoted arguments.
remote() {
  local quoted
  quoted=$(printf '%q ' "$@")
  ssh "$HOST" "bash -s -- $quoted"
}

# ---- 1. discover ---------------------------------------------------------------------------
discovery=$(remote "$REMOTE_DIR" <<'REMOTE'
set -euo pipefail
dir=$1
[ -d "$dir" ] || { echo "error: $dir does not exist on this host" >&2; exit 1; }
conf_value() {  # last non-empty key=value from icloudpd.conf, quotes stripped
  [ -f "$dir/icloudpd.conf" ] || return 0
  sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$dir/icloudpd.conf" | tr -d '"\r' | sed '/^$/d' | tail -n 1
}
echo "apple_id=$(conf_value apple_id)"
echo "auth_china=$(conf_value auth_china)"
for id in $(docker ps -aq); do
  docker inspect --format '{{.Name}}|{{.State.Running}}|{{range .Mounts}}{{.Source}}:{{.Destination}}|{{end}}' "$id"
done | awk -F'|' -v want="$dir:/config" '{ for (i = 3; i <= NF; i++) if ($i == want) { sub("^/", "", $1); print "container=" $1; print "running=" $2 } }'
REMOTE
) || die "could not inspect $REMOTE_DIR on $HOST"

field() { printf '%s\n' "$discovery" | sed -n "s/^$1=//p"; }
[ -n "$APPLE_ID" ] || APPLE_ID=$(field apple_id)
[ -n "$APPLE_ID" ] || die "no apple_id in $HOST:$REMOTE_DIR/icloudpd.conf — pass --apple-id"
if [ -z "$DOMAIN" ]; then
  case $(field auth_china | tr '[:upper:]' '[:lower:]') in true|1|yes|on) DOMAIN=cn ;; *) DOMAIN=com ;; esac
fi
if [ -z "$CONTAINER" ]; then
  found=$(field container)
  [ -n "$found" ] || die "no container on $HOST mounts $REMOTE_DIR at /config — pass --container"
  [ "$(printf '%s\n' "$found" | wc -l)" -eq 1 ] || die "several containers mount $REMOTE_DIR: $(printf '%s' "$found" | tr '\n' ' ') — pass --container"
  CONTAINER=$found
fi

echo "Apple ID:   $APPLE_ID (domain: $DOMAIN)"
echo "Target:     $HOST:$REMOTE_DIR  (container: $CONTAINER)"
echo "Sign-in:    icloudpd $VERSION on this machine"
if [ "$CHECK" = 1 ]; then
  echo "--check: stopping here; nothing was changed and Apple was not contacted."
  exit 0
fi

# ---- 2. sign in locally --------------------------------------------------------------------
# Use the pure-Python wheel, pinned by hash. The platform wheels uv would pick
# by default wrap a prebuilt binary that (in 1.33.0) lacks a data file of the
# security-key library and crashes at the key step.
WHEEL=$(uv run --no-project -q python - "$VERSION" <<'PY'
import json, sys, urllib.request
version = sys.argv[1]
with urllib.request.urlopen(f"https://pypi.org/pypi/icloudpd/{version}/json", timeout=30) as r:
    files = json.load(r)["urls"]
pure = [f for f in files if f["filename"].endswith("-py3-none-any.whl")]
if not pure:
    sys.exit(f"icloudpd {version} has no pure-Python wheel on PyPI")
print(f'{pure[0]["url"]}#sha256={pure[0]["digests"]["sha256"]}')
PY
) || die "could not find the icloudpd $VERSION wheel on PyPI"

TMP=$(mktemp -d)
chmod 700 "$TMP"
STAGING=""
cleanup() {
  rm -rf "$TMP"
  # Best effort: never leave session files in a half-used staging dir on the host.
  [ -z "$STAGING" ] || ssh "$HOST" "rm -rf $(printf '%q' "$STAGING")" 2>/dev/null || true
}
trap cleanup EXIT

echo
echo "Signing in. Enter your iCloud password when asked; with security keys, plug"
echo "the key in now and touch it when it blinks."
echo
# Console providers only: nothing is written to this machine's keyring.
uvx --from "icloudpd @ $WHEEL" icloudpd \
  --username "$APPLE_ID" \
  --cookie-directory "$TMP" \
  --domain "$DOMAIN" \
  --auth-only \
  --password-provider console \
  --mfa-provider console \
  || die "icloudpd sign-in failed; nothing was changed on $HOST"

session_file=$(find "$TMP" -maxdepth 1 -type f -name '*.session' | head -n 1)
[ -n "$session_file" ] || die "icloudpd wrote no .session file; nothing was changed on $HOST"
cookie_name=$(basename "$session_file" .session)
[ -s "$TMP/$cookie_name" ] || die "icloudpd wrote no cookie file; nothing was changed on $HOST"
# An untrusted session would make the container ask for a second factor again.
grep -q '"trust_token"' "$session_file" \
  || die "the sign-in produced no trusted session (no trust token); nothing was changed on $HOST"

# ---- 3. install on the host ----------------------------------------------------------------
STAGING="$REMOTE_DIR/.session-copy.$$"
staging_q=$(printf '%q' "$STAGING")
tar -C "$TMP" -cf - "$cookie_name" "$cookie_name.session" \
  | ssh "$HOST" "mkdir -m 700 $staging_q && tar -C $staging_q -xf -"

remote "$REMOTE_DIR" "$STAGING" "$cookie_name" "$CONTAINER" <<'REMOTE'
set -euo pipefail
dir=$1 staging=$2 name=$3 container=$4
stamp=$(date +%Y%m%d-%H%M%S)

was_running=$(docker inspect --format '{{.State.Running}}' "$container")
restart() { [ "$was_running" != true ] || docker start "$container" >/dev/null; }
trap restart EXIT   # whatever happens below, a container that was up comes back up
if [ "$was_running" = true ]; then
  echo "Stopping $container…"
  docker stop -t 60 "$container" >/dev/null
fi

# New files take the ownership of what they replace (else of the config dir),
# so the container's unprivileged user can still read and rewrite them.
owner_of() { ls -ldn "$1" | awk '{ print $3 ":" $4 }'; }
for f in "$name" "$name.session"; do
  if [ -e "$dir/$f" ]; then
    owner=$(owner_of "$dir/$f")
    cp -p "$dir/$f" "$dir/$f.pre-copy-$stamp"
    echo "Backed up $f -> $f.pre-copy-$stamp"
  else
    owner=$(owner_of "$dir")
  fi
  chown "$owner" "$staging/$f"
  chmod 600 "$staging/$f"
  mv -f "$staging/$f" "$dir/$f"
done
# A leftover reauth backup would be restored over the new files at startup.
rm -f "$dir/$name.reauth-backup" "$dir/$name.session.reauth-backup"
rmdir "$staging"
if [ "$was_running" = true ]; then
  echo "Starting $container…"
else
  echo "$container was not running; left stopped."
fi
REMOTE
STAGING=""

echo
echo "Done. The new session is installed in $HOST:$REMOTE_DIR."
echo "The container syncs at its next scheduled time; send 'sync' (with the"
echo "instance prefix, if any) in Telegram to try it right away."
