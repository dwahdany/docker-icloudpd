# docker-icloudpd (rewritten)

Automatically download your iCloud photo library — personal and shared —
with remote two-factor authentication over Telegram.

This is a hard fork of [boredazfcuk/docker-icloudpd](https://github.com/boredazfcuk/docker-icloudpd).
The original ~3,900 lines of shell/expect orchestration have been replaced by
a small, tested Python supervisor around
[icloudpd](https://github.com/icloud-photos-downloader/icloud_photos_downloader).
A verified audit of the legacy scripts (120 confirmed defects, two of them
account-locking) is preserved in [docs/legacy-audit.md](docs/legacy-audit.md);
the supervisor's design rationale lives in [supervisor/README.md](supervisor/README.md).

## Highlights

- **2FA over Telegram, whenever it's needed.** The listener runs in every
  state — an expired cookie is fixed by replying `reauth` and then the
  6-digit code, not by `docker exec`.
- **Apple-lockout protection by construction.** Password sign-ins are
  counted against a persisted daily budget (default 3/24h); the container
  never exits to let a restart policy retry authentication.
- **Existing `/config` volumes keep working** — same keyring, same cookies,
  core `icloudpd.conf` keys still honoured.

## Quick start

```sh
cp docker-compose.example.yml docker-compose.yml   # edit: apple_id, paths, telegram
docker compose pull
docker compose run --rm -it icloudpd icloudpd-supervisor init   # store password, first auth
docker compose up -d
```

The image is published by CI to `ghcr.io/dwahdany/docker-icloudpd`
(`:latest` + per-commit `:<sha>` tags). To build locally instead, swap the
`image:` line for `build: .` in your compose file.

## Telegram commands

`sync` · `reauth` · `status` · `help` · `<6-digit 2FA code>`

## Configuration

Set as environment variables (or in `/config/icloudpd.conf`):

| Variable | Default | Meaning |
|---|---|---|
| `apple_id` | — | your Apple ID (required) |
| `name` | — | instance name: tags every notification (`[a] …`) and namespaces commands (`a sync`); falls back to the legacy conf's `user` key |
| `libraries` | `personal` | comma list: `personal`, `shared`, or explicit names |
| `download_path` | `/icloud` | download target inside the container |
| `folder_structure` | `{:%Y/%m/%d}` | icloudpd folder structure |
| `download_interval` | `86400` | seconds between syncs (min 3600) |
| `photo_size` | `original` | `original`/`medium`/`thumb`/`adjusted`/`alternative` |
| `skip_videos`, `skip_live_photos` | `false` | |
| `telegram_token`, `telegram_chat_id` | — | bot credentials for 2FA + notifications |
| `telegram_sender_id` | — | optional: restrict commands to one Telegram user id |
| `max_auth_per_day` | `3` | password sign-in budget per rolling 24h |
| `mfa_timeout` | `1800` | seconds to wait for your 2FA code |
| `user_id`, `group_id` | `1000` | filesystem identity for downloads |
| `extra_icloudpd_args` | — | verbatim extra args for every sync run |

Do **not** publish container port 8080 — it is icloudpd's internal MFA
interface, bridged to Telegram by the supervisor over localhost.

## Multiple accounts / containers

Run one container per Apple ID and give each a `name` (e.g. `a`, `b`):

- every notification is tagged — `[a] 🔐 iCloud needs a new two-factor code…`
  tells you whether to answer `a 123456` or `b 123456`;
- a named instance **only** reacts to prefixed commands (`a sync`,
  `a reauth`, bare `a` = sync now), so instances sharing a chat don't all
  grab the same message. Migrated volumes pick the name up from the legacy
  conf's `user=` key automatically.

Sharing **one bot token** across containers works, same as the legacy
container: the supervisor short-polls `getUpdates` (long polling would make
concurrent consumers terminate each other), and Telegram's lazy update
confirmation means instances with similar polling cadences each see every
message. Expected command latency is up to `telegram_poll_interval`
(default 30 s, the legacy cadence; automatically ~3 s while a 2FA prompt is waiting).

## Security keys (FIDO)

An Apple ID protected by security keys never gets a six-digit code, so the
Telegram relay cannot authenticate it — do not answer its code prompt on such
an account. There are two ways to run the container with one.

### Software security key (unattended)

Register one more "security key" that is just a file, and give that file to
the container. When `softkey.json` exists in `/config`, the supervisor
confirms every sign-in with it: an expired session renews itself at the next
sync, with no code, no key to touch and no Telegram round trip.

**The file is a second factor for the whole Apple ID.** Together with the
password (which `/config` also holds) it is enough to sign in. Keep `/config`
private, keep it out of unencrypted backups, and remove the key under
*Sign-In & Security → Security Keys* if the server is ever compromised.

Apple only adds keys through Settings on an Apple device, so the file has to
look like a USB key once, to a Mac. A Raspberry Pi Pico (any RP2040/RP2350
board) does that as a dumb USB bridge; the key itself never leaves the Mac.

1. Build `scripts/softkey/firmware` with the Pico SDK (its `shell.nix` has
   the command) and copy
   `softkey_bridge.uf2` to the board (hold BOOTSEL while plugging it in).
2. Run `scripts/softkey/bridge.py --key ~/.config/icloudpd-softkey/softkey.json`
   (`--self-test` checks the USB path first, without Apple).
3. Unplug other security keys, then on the Mac: *System Settings → Apple
   Account → Sign-In & Security → Security Keys → Add Security Key*. The
   bridge answers by itself after two seconds.
4. Stop the bridge and unplug the board; it is not needed again. Check the
   key with `scripts/softkey/verify.sh <apple-id>` (a real sign-in into a
   temporary directory).
5. Copy `softkey.json` into the container's `/config`, owned by the
   container user and mode `600`. Set `security_key_file` to use another path.

Apple's documentation asks for FIDO Certified keys; a software key is not
certified. Apple accepted it when this was written (November 2026) and may
stop doing so.

### Copying a session from a machine with the key

Without a software key, sign in on a machine that has a hardware key and copy
the session into the container's `/config`:

```sh
scripts/copy-session.sh --check /path/on/host/to/config   # show the plan only
scripts/copy-session.sh /path/on/host/to/config           # sign in here, install there
```

It runs `icloudpd --auth-only` (1.33.0, via `uvx`) locally, then stops the
container, backs up the old cookie and session, installs the new ones and
starts the container again. Repeat when the session expires. `--help` lists
the options (ssh host, Apple ID, container name).

Note: Apple's Advanced Data Protection (ADP) is not supported by icloudpd;
ADP must be disabled for downloads to work.

## Development

```sh
cd supervisor
pip install -e ".[dev]"
pytest            # hermetic test suite: no network, no real icloudpd
```
