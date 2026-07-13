# icloudpd-supervisor

A minimal, from-scratch replacement for the shell orchestration in
boredazfcuk/docker-icloudpd. ~700 lines of tested Python instead of ~3,900
lines of ash.

## What it does

- Runs [icloudpd](https://github.com/icloud-photos-downloader/icloud_photos_downloader)
  on a schedule, once per configured library (personal and/or shared).
- Relays iCloud two-factor prompts to **Telegram** and posts your reply back —
  at any time, in any state. Uses icloudpd's `--mfa-provider webui` HTTP
  interface instead of scraping terminal prompts with `expect`.
- Protects your Apple ID: full password sign-ins are counted against a
  **persisted daily budget** (default 3/24h). When it's spent, the supervisor
  waits for a human instead of retrying. It never exits to let a Docker
  restart policy drive retries.
- Healthcheck is **liveness-only**: "waiting for a 2FA code" is healthy.
  Pairing with autoheal will not create restart loops.

## Why the old design locked accounts

1. Cookie expired → script deleted it, exited 1 → Docker restarted the
   container → 30-minute wait → exit 1 → forever. The Telegram poller only
   ran after a *successful* sync, so remote reauth was unreachable exactly
   when it was needed.
2. With autoheal, the unhealthy container was killed every ~2 minutes, and
   each restart performed a fresh Apple password sign-in. Apple locks
   accounts that do that.
3. `authenticate.exp` had no timeout/EOF handling: any unexpected icloudpd
   output ended the reauth silently, with cookies already deleted.

## Compatibility with an existing /config volume

- Password keyring (`python_keyring/keyring_pass.cfg`): reused as-is.
- Cookies: same files (they belong to icloudpd, named by stripping
  non-`[A-Za-z0-9_]` from your Apple ID).
- `icloudpd.conf`: core keys (apple_id, download_path, folder_structure,
  download_interval, telegram_*, photo_size, skip_videos, skip_live_photos,
  photo_library, notification_days, user_id/group_id) are still read.
  Environment variables take precedence.

## Telegram commands

| Command | Effect |
|---|---|
| `sync` | start a sync now |
| `reauth` | fetch a fresh 2FA trust cookie (old cookies restored on failure) |
| `status` | state, cookie expiry, last/next sync, auth budget |
| `123456` | answer an open 2FA prompt |
| `help` | list commands |

The old `<user> <command>` prefix form is still accepted. Only messages from
the configured `telegram_chat_id` are honoured.

## First-time setup

```sh
docker compose run --rm -it icloudpd icloudpd-supervisor init
```

Stores the password in the keyring and performs the first (interactive)
authentication. Passwords are never sent through Telegram.

## Configuration

See `docker-compose.example.yml` at the repo root. Notable settings:

| Variable | Default | Meaning |
|---|---|---|
| `libraries` | `personal` | comma list: `personal`, `shared`, or explicit names |
| `max_auth_per_day` | `3` | password sign-in budget per rolling 24h |
| `mfa_timeout` | `1800` | seconds to wait for your 2FA code |
| `extra_icloudpd_args` | | verbatim extra args for every sync run |
