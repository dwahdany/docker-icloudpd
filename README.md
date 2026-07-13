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

⚠️ Use a **separate bot token per container**. Telegram delivers each
`getUpdates` message to exactly one consumer — two containers polling the
same token steal updates from each other and commands are randomly lost.
The bots can all sit in one group chat (disable bot privacy mode so they
see all messages).

Note: Apple's Advanced Data Protection (ADP) is not supported by icloudpd;
ADP must be disabled for downloads to work.

## Development

```sh
cd supervisor
pip install -e ".[dev]"
pytest            # 250 hermetic tests, no network, no real icloudpd
```
