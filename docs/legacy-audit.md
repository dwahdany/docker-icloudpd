# Legacy code audit (2026-07-13)

Findings from a multi-agent audit of the original shell implementation
(boredazfcuk/docker-icloudpd at commit e2d9aa0), each independently verified
against the code and the icloudpd 1.32.3 source. This audit motivated the
from-scratch Python rewrite that replaced the shell scripts: **6 critical,
21 high, 53 medium, 40 low** confirmed defects.

The line numbers reference the last commit containing the legacy scripts
(see git history before the repo restructure).

## Critical findings (expanded)

### sync-icloud.sh:845 — Unescaped $? inside double-quoted run_as strings makes every icloudpd exit-code file a constant 0

All 11 run_as call sites that capture icloudpd's exit status (lines 845, 874, 886, 890, 1076, 1079, 1116, 1119, 1146, 1149, 1167) embed `echo $? >/tmp/icloudpd/icloudpd_{check,download}_exit_code` inside a double-quoted string. The parent shell expands `$?` while BUILDING the string (verified: `sh -c 'true; s="(false; echo $? >/tmp/x)"; echo "$s"'` prints `echo 0`). At every call site the preceding command is a log_debug or a redirect that returns 0, so the inner shell literally executes `echo 0 > .../exit_code` regardless of icloudpd's real exit status. Consequences: (a) every `-ne 0` check on these files (sync-icloud.sh:877, 887/893, 1121, 1151, 2299-2300) is dead code; (b) healthcheck.sh:5-27 can never see a nonzero code, so the healthcheck/autoheal recovery contract is broken in ALL configs; (c) failure detection degrades to '[ -s stderr-file ]' only, but icloudpd 1.32.3 logs errors via a stdout handler (src/icloudpd/logger.py:48 StreamHandler(stream=sys.stdout)); graceful failures such as 'Unknown library: X' (base.py:945 logger.error → stdout, then `return 1`) produce EMPTY stderr, so the run is reported as success: 'Check successful', no failure notification, healthcheck healthy forever while nothing syncs. Concrete scenario: photo_library set to a renamed/removed shared library → icloudpd exits 1 with stderr empty → exit-code file says 0 → container reports healthy and 'No new files detected' indefinitely. In non-library album mode (line 1121) a mid-list album failure is additionally masked because 2>/tmp/icloudpd/icloudpd_download_error truncates per album, so if the last album succeeds the earlier failure vanishes entirely.

**Fix (if patching in place):** Escape the dollar sign in every run_as string so the inner shell expands it: `; echo \$? >/tmp/icloudpd/icloudpd_check_exit_code`. Do the same for all 11 sites. (Note pipeline: `(icloudpd; echo \$? >file) | tee ...` is otherwise correct.)

### sync-icloud.sh:2266 — H1 CONFIRMED: Telegram polling only runs in the post-sync sleep window, so an expired/missing MFA cookie makes the remote 'auth' command unreachable forever

The getUpdates polling loop that processes '<user> auth' and forwards MFA codes exists ONLY inside the post-sync sleep window (sync-icloud.sh:2391-2493). Every sync iteration first gates on the MFA cookie (2262-2270 -> check_multifactor_authentication_cookie:740-780). Failure paths there never poll: (a) cookie file missing -> wait_for_cookie:699-708 blocks in a 5s-sleep loop for 30 min then 'exit 1' (706); (b) cookie expired (days_remaining<=0) -> 767-771 rm cookie, sleep 300, exit 1; (c) not MFA-capable -> 774-778 rm, exit 1. After the container restarts, startup goes straight back into synchronise_user -> the same gate -> wait_for_cookie, so the container loops restart/wait forever and the Telegram message '<user> auth' is never read; no prompt is ever sent. This is exactly the reported symptom: once the cookie expires, '2FA through Telegram no longer prompts for a code'. The ONLY recovery is interactive: 'docker exec -it <container> sync-icloud.sh --Initialise' (action initialise_container -> generate_cookie, sync-icloud.sh:2585,607-637), which creates the cookie file that wait_for_cookie is watching. Restarting the container does not help; sending 'auth' again does not help.

**Fix (if patching in place):** Run the Telegram polling/auth loop inside wait_for_cookie (and while waiting on an expired cookie) — e.g. factor the update-processing block (2405-2488) into a function and call it from wait_for_cookie's loop — so a user can trigger authenticate.exp when the cookie is missing/expired. Alternatively, on expiry, enter the polling loop instead of exit 1.

### sync-icloud.sh:890 — Server-side-dead session triggers a fresh Apple password signin plus 2FA push on every check/sync cycle with no backoff; documented restart=always + autoheal amplifies this to ~12+ login attempts/hour, locking the Apple account (H2 CONFIRMED)

check_multifactor_authentication_cookie (sync-icloud.sh:740-779) validates ONLY client-side cookie-file expiry dates and cannot detect server-side session revocation. When Apple revokes the trust/session token while the cookie file dates are still valid, check_files unconditionally invokes icloudpd (sync-icloud.sh:890; also 845, 874, 886). In icloudpd 1.32.3: (a) the stored session token is rejected — _validate_token() raises and authenticate() falls back to a FULL SRP password signin against idmsa.apple.com on EVERY invocation (pyicloud_ipd/base.py:298-327; POST /appleauth/auth/signin/init at base.py:430, /signin/complete at base.py:481, then accountLogin at base.py:363); (b) requires_2fa becomes true and request_2fa() FIRST sends a 2FA push to all trusted devices via PUT /verify/trusteddevice/securitycode (icloudpd/authentication.py:160, pyicloud_ipd/base.py:718) BEFORE prompting; (c) it then blocks on raw input() (authentication.py:33 — 1.32.3 uses input(), not click.prompt); with detached-container stdin (/dev/null) input() raises EOFError which is uncaught (icloudpd/base.py:1237-1239 re-raises) so the process exits 1 with a traceback captured into /tmp/icloudpd/icloudpd_check_error. So every invocation with a dead session = 1 unattended Apple password login + 1 2FA push to the user's devices. Loop amplification: healthcheck.sh:22-26 exits non-zero on the recorded check exit code; HEALTHCHECK interval is 1m with default retries 3 (icloudpd.dockerfile:29), so the container goes unhealthy ~3-4 min after the failure; CONFIGURATION.md:455 recommends autoheal (and itself admits the container is 'restarted by the autoheal container every five minutes or so') and CONFIGURATION.md:270 documents --restart=always; on each restart launcher.sh:165-227 wipes the exit-code/error files, flipping the container back to healthy and re-arming the cycle. Quantified worst realistic config (restart=always + autoheal + server-side-dead session): ~12 cycles/hour, each = 2 idmsa signin POSTs + 1 accountLogin + 1 trusted-numbers GET + 1 2FA-push PUT, i.e. ~12 password logins and ~12 2FA pushes per hour, ~290/day; overnight that is 100+ unattended login events, which Apple's fraud detection answers by locking the account — exactly matching the user report. Multipliers: with photo_album and photo_library configured, check_files runs one icloudpd per album-x-library combination per cycle (sync-icloud.sh:838-857), each a separate signin+push, so 5 albums x 2 libraries = 10 logins per single cycle even without autoheal. There is no backoff, no auth-failure detection (the failure branch at 893-913 only logs/notifies), and login_counter (sync-icloud.sh:924, 2364) is only ever logged, never used to throttle. H4 adjudication: no other Apple-auth traffic exists — launcher.sh:236 icloudpd --version is local, launcher.sh:694 traceroute and sync-icloud.sh:56 nslookup are ICMP/DNS probes, and the update/bot checks hit GitHub/Telegram, so all lockout pressure comes from these icloudpd invocations.

**Fix (if patching in place):** In the check/download failure paths, grep the captured stderr for the 2FA-required/EOFError signature and switch to a 'reauthentication required' wait state that does NOT re-invoke icloudpd: send a notification, write a persistent marker file under /config (surviving restarts, unlike /tmp), have healthcheck.sh treat that marker as healthy-waiting, and run the Telegram polling loop there so remote reauth works. Additionally persist an auth-failure counter with exponential backoff in /config so container restarts cannot bypass it.

### icloudpd.dockerfile-sourcebuild:24 — Cherry-pick of already-merged PR-1335 makes the sourcebuild fail unconditionally

PR-1335 was merged into upstream icloudpd master on 2026-05-28. Line 15 clones master (post-merge), then line 24 runs 'git cherry-pick pr-1335' on the tip of pull/1335/head. Cherry-picking a change already contained in HEAD produces an empty pick and git exits 1 with 'The previous cherry-pick is now empty... please use git cherry-pick --skip' (reproduced locally: exit code 1). If master has since drifted in the touched files, the result is a conflict, which also exits non-zero. Either way the RUN step fails, so 'docker build -f icloudpd.dockerfile-sourcebuild .' can never complete — the sourcebuild image is completely unbuildable, which is the most likely cause of a failed build run using this file. Note: the committed CI workflow (.github/workflows/build-and-push.yml line 52) builds icloudpd.dockerfile, not this file, so a failing published Action would be a separate invocation. Secondary hazard: even if the pick were needed, --depth 1 (line 15) can leave the PR tip's parent commit unavailable, and picking only pull/1335/head takes just the tip commit of a possibly multi-commit PR.

**Fix (if patching in place):** Delete lines 19-24 entirely (master already contains PR-1335; the comment at line 19 is stale). If a defensive pick must remain, make it tolerant: 'git cherry-pick pr-1335 || { git cherry-pick --skip || git cherry-pick --abort; }' or use 'git cherry-pick --empty=drop pr-1335' (git >= 2.45), and drop --depth 1 from the clone so parents are present.

### runner.py:28 — Auth budget is completely inert: the 'Authenticating as ' marker is a pyicloud_ipd DEBUG log that icloudpd never emits, so password sign-ins are never counted

The rewrite's flagship lockout protection (max_auth_per_day) counts sign-ins by matching _AUTH_MARKER 'Authenticating as ' in icloudpd output (runner.py:28,135; scheduler.py:96-104). That line is emitted by logging.getLogger('pyicloud_ipd.base').debug(...) (pyicloud_ipd/base.py:315 in the pinned 1.32.3), but icloudpd's create_logger (icloudpd/base.py:212-233) sets DEBUG only on the 'icloudpd' logger; logging.basicConfig leaves the root logger at WARNING, so every pyicloud_ipd DEBUG record is filtered out regardless of --log-level debug. Verified empirically by replicating create_logger: the pyicloud debug line is not printed while 'icloudpd' debug lines are. Failure scenario: any config -> result.performed_password_auth is always False -> _record_auth never records -> auth_attempts_last_day() is always 0 -> AUTH_RATE_LIMITED can never trigger. With an expired cookie and an unresponsive user, every scheduled sync and every 'reauth' command performs an uncounted full Apple password sign-in indefinitely, silently defeating the advertised 3-per-24h budget the README promises.

**Fix (if patching in place):** Do not rely on pyicloud_ipd debug logs. Conservatively record an auth attempt whenever a run starts with a missing/invalid MFA trust cookie (read_cookie_status before the run), or whenever the webui bridge observes NEED_MFA; optionally also detect session-file rewrite. Add a unit test that feeds real icloudpd output (without the marker) and asserts the budget still increments.

### runner.py:179 — list_libraries() with an invalid cookie hangs in webui MFA with no Telegram bridging, then uncaught subprocess.TimeoutExpired crashes the supervisor into a restart loop of unattended Apple sign-ins

runner.list_libraries() uses subprocess.run(capture_output=True, timeout=600) with --mfa-provider webui but is never wrapped with the tick/webui bridge (unlike runner.run). When libraries includes 'shared' (the documented example: docker/docker-compose.example.yml line 14 'personal,shared') and the MFA cookie is expired, icloudpd performs a full password sign-in, triggers an Apple 2FA push, and request_2fa_web (icloudpd/authentication.py:269) waits forever for a code nobody can supply (no Telegram prompt is sent because _tick_during_run never runs). After 600s subprocess.run raises TimeoutExpired, which is caught nowhere (scheduler._resolve_libraries:210 -> run_sync_cycle:255 -> run_forever:456 -> main.py only catches ConfigError) -> the supervisor process exits with a traceback -> restart: unless-stopped relaunches it -> next_sync_time is initialised to now (scheduler.py:55) -> the cycle repeats every ~10 minutes: an uncounted password sign-in plus a 2FA push storm, ~140 sign-ins/day, exactly the lockout scenario the rewrite claims to prevent. The auth budget offers no protection here even if it worked, because list_libraries never records auth attempts.

**Fix (if patching in place):** Route --list-libraries through runner.run() with the tick bridge and a RunResult, catch subprocess.TimeoutExpired/OSError in list_libraries returning [], and wrap run_sync_cycle in run_forever with a broad exception guard so a failed cycle never kills the main loop.


## All findings

| Sev | Location | Finding |
|---|---|---|
| critical | sync-icloud.sh:845 | Unescaped $? inside double-quoted run_as strings makes every icloudpd exit-code file a constant 0 |
| critical | sync-icloud.sh:2266 | H1 CONFIRMED: Telegram polling only runs in the post-sync sleep window, so an expired/missing MFA cookie makes the remote 'auth' command unreachable forever |
| critical | sync-icloud.sh:890 | Server-side-dead session triggers a fresh Apple password signin plus 2FA push on every check/sync cycle with no backoff; documented restart=always + autoheal amplifies this to ~12+ login attempts/hour, locking the Apple account (H2 CONFIRMED) |
| critical | icloudpd.dockerfile-sourcebuild:24 | Cherry-pick of already-merged PR-1335 makes the sourcebuild fail unconditionally |
| critical | runner.py:28 | Auth budget is completely inert: the 'Authenticating as ' marker is a pyicloud_ipd DEBUG log that icloudpd never emits, so password sign-ins are never counted |
| critical | runner.py:179 | list_libraries() with an invalid cookie hangs in webui MFA with no Telegram bridging, then uncaught subprocess.TimeoutExpired crashes the supervisor into a restart loop of unattended Apple sign-ins |
| high | sync-icloud.sh:1325 | nextcloud_upload uploads the HEIC source file to the .JPG destination instead of the converted JPEG |
| high | sync-icloud.sh:1076 | Shell injection / command breakage via album names interpolated into su -c strings |
| high | sync-icloud.sh:886 | check_files passes the whole comma-delimited photo_album as one --album when photo_library is unset |
| high | sync-icloud.sh:1029 | skip_album / skip_library compare the whole comma-delimited skip list against each name, so multi-entry skip lists are silently ignored |
| high | sync-icloud.sh:1625 | sideways copy 'move' mode uses invalid 'mv --preserve' so videos are never moved |
| high | sync-icloud.sh:1545 | Malformed cut invocation breaks destination-directory creation in sideways_copy_all_videos |
| high | sync-icloud.sh:1838 | remove_recently_deleted_accompanying_files strips first '!' anywhere in path and can rm the wrong files |
| high | sync-icloud.sh:2444 | Cookie and session deleted on 'auth' request before new authentication succeeds, with no recovery path |
| high | sync-icloud.sh:2444 | H2 CONFIRMED: cookie+session are deleted before spawning authenticate.exp with no restore/retry path, converting any auth failure into a permanent restart spiral |
| high | sync-icloud.sh:771 | Client-side cookie expiry produces an infinite restart loop (rm cookie -> exit 1 -> wait_for_cookie 30min -> exit 1) with no notification at expiry, no Telegram polling, and no automatic recovery path (H1 CONFIRMED) |
| high | healthcheck.sh:69 | exit 1 on expired/missing cookie plus autoheal creates an unbounded restart loop that hammers Apple auth |
| high | healthcheck.sh:48 | Healthcheck fails the moment the cookie is deleted for remote reauth; with autoheal the container is killed ~3-4 min into a 10-minute auth window |
| high | healthcheck.sh:48 | Healthcheck exits 1 when the cookie file is missing, directly contradicting its own presume-healthy-while-waiting-for-user-input design (lines 10-12) and letting autoheal kill interactive --Initialise recovery sessions every ~4 minutes |
| high | authenticate.exp:20 | No timeout/eof/catch-all handling with `set timeout -1`: unexpected output hangs forever, crashes exit silently |
| high | authenticate.exp:25 | inotifywait timeout (exit 2) raises uncaught Tcl exec error, killing the expect script mid-auth |
| high | authenticate.exp:20 | H3 CONFIRMED: outer expect block has no eof/timeout/default clause, so any early icloudpd failure exits silently with no Telegram message (H4 refuted: prompt strings all match 1.32.3) |
| high | launcher.sh:741 | Update check falls through to 'sleep infinity' on any non-numeric GitHub response, permanently halting the container while healthcheck reports healthy |
| high | launcher.sh:337 | download_interval normalization sed missing -i: invalid intervals are never corrected and the full config (with secrets) is dumped to the log |
| high | init_config.sh:27 | Env values written unquoted/unescaped into a config file that sync-icloud.sh sources, enabling parse breakage and shell command injection |
| high | example.env:15 | example.env documents authentication_type=2FA but code only recognises 'MFA', silently routing MFA accounts down the Web-auth path |
| high | build-and-push.yml:56 | Image tags and buildcache refs are hardcoded to the boredazfcuk namespace, so CI publish fails in this fork |
| medium | sync-icloud.sh:235 | run_as() executes unset ${command_to_run} instead of "${1}" when running as non-root |
| medium | sync-icloud.sh:56 | icloud.com DNS reachability check false-passes on lookup failure with non-loopback resolvers |
| medium | sync-icloud.sh:508 | --ListLibraries/--ListAlbums silently print an empty list when skip_download=true |
| medium | sync-icloud.sh:235 | run_as executes undefined ${command_to_run} when not root, silently no-op'ing every icloudpd invocation |
| medium | sync-icloud.sh:1299 | Paths longer than 96 chars are middle-truncated in icloudpd's 'Downloaded' log lines, so log-parsing consumers silently skip those files |
| medium | sync-icloud.sh:993 | resolve_library_list failure yields an empty list, making check_files and download_libraries silently succeed doing nothing |
| medium | sync-icloud.sh:1315 | file_extension is global and never reset per file in nextcloud_upload/nextcloud_delete, so stale values trigger companion upload/delete for non-HEIC files |
| medium | sync-icloud.sh:1146 | download_libraries: nested unescaped quotes cancel out, leaving --folder-structure/--library values unquoted in the su shell |
| medium | sync-icloud.sh:1036 | Album names containing commas corrupt the 'all albums' list because it is joined and re-split on commas |
| medium | sync-icloud.sh:2008 | Notification payloads built by string interpolation; metacharacters in filenames cause HTTP 4xx and container exit |
| medium | sync-icloud.sh:1596 | Log-parsing functions break on paths >96 chars because icloudpd truncates logged paths |
| medium | sync-icloud.sh:2207 | command_line_builder emits --keep-icloud-recent-days together with --delete-after-download, which icloudpd hard-rejects |
| medium | sync-icloud.sh:2156 | command_line holds unquoted paths; spaces in download_path/folder_structure corrupt the icloudpd argument list |
| medium | sync-icloud.sh:1485 | Unanchored 'grep -i ".HEIC"' matches non-HEIC files and recompresses JPGs onto themselves |
| medium | sync-icloud.sh:2399 | expect_error_flag is dead code — nothing in the repo ever creates /tmp/icloudpd/expect_error_flag |
| medium | sync-icloud.sh:2451 | Race between printf-append to expect_input.txt and inotifywait watch start; appends leave stale codes that corrupt later reads |
| medium | sync-icloud.sh:2446 | Repeated 'auth' messages spawn concurrent authenticate.exp instances sharing expect_input.txt, reauth.log and the cookie files |
| medium | sync-icloud.sh:2472 | getUpdates offset confirmation discards other containers' commands when multiple containers share one bot token |
| medium | sync-icloud.sh:2399 | Dead man's switch never fires: /tmp/icloudpd/expect_error_flag is checked but never created anywhere |
| medium | sync-icloud.sh:330 | telegram_polling is silently disabled when telegram_bot_initialised != true (one-shot launcher check), leaving notifications working but 'auth' commands ignored |
| medium | sync-icloud.sh:2451 | Stale codes accumulate in /tmp/icloudpd/expect_input.txt and are replayed to icloudpd on the next auth attempt |
| medium | sync-icloud.sh:235 | run_as() non-root branch executes an empty command: uses undefined ${command_to_run} instead of ${1} |
| medium | sync-icloud.sh:874 | photo_library branch cannot detect --list-libraries authentication failure: dead session yields an empty or garbage library list, so the check silently reports success (healthcheck stays green) or spawns extra Apple logins per junk line |
| medium | healthcheck.sh:56 | Healthcheck reads MFA expiry from X-APPLE-DS-WEB-SESSION-TOKEN while sync-icloud.sh uses X-APPLE-WEBAUTH-USER (the correct one) |
| medium | healthcheck.sh:3 | Healthcheck sources user-writable /config/icloudpd.conf as root every minute (arbitrary code execution as container root) |
| medium | healthcheck.sh:56 | Healthcheck derives MFA expiry from the X-APPLE-DS-WEB-SESSION-TOKEN cookie while sync-icloud.sh uses X-APPLE-WEBAUTH-USER; a missing/divergent token line yields a false 'expired' verdict and a permanent autoheal restart loop with a working cookie |
| medium | reauth.sh:18 | reauth.sh cookie-file derivation differs from sync-icloud.sh/healthcheck.sh and from icloudpd for mixed-case Apple IDs, silently breaking remote MFA re-auth |
| medium | launcher.sh:654 | All run_as writability checks are no-ops: $? inside double quotes expands in the parent shell before the test runs |
| medium | launcher.sh:349 | root/uid-0 guard seds only match empty assignments, so user=root / user_id=0 / group=root / group_id=0 are never actually reset |
| medium | launcher.sh:36 | create_group/create_user overwrite /etc/group and /etc/passwd with minimal files; collision check runs only after destruction and errors are unchecked |
| medium | launcher.sh:149 | Drive-space guards log 'Cannot continue' but continue anyway, and error out silently when df\|grep yields empty or multiple lines |
| medium | launcher.sh:491 | Nextcloud mandatory-variable check uses invalid '-Z' operator and AND logic, so it can never halt |
| medium | launcher.sh:139 | disable_notifications sed missing -i: notifications never disabled and the entire config file (with credentials) is printed to the container log |
| medium | init_config.sh:209 | Path-normalisation rewrite strips users' double quotes, permanently corrupting quoted values containing spaces |
| medium | init_config.sh:209 | Config values are interpolated unescaped into sed replacement text: '&', '\\', and delimiter characters ('#', '%') mangle values or abort normalisation |
| medium | init_config.sh:249 | Boolean normalisation `s/=True/=true/gI` rewrites '=true'/'=false' substrings anywhere in any line, corrupting passwords, URLs and comments |
| medium | init_config.sh:239 | nextcloud_target_dir is sanitised by init_config.sh but never written: the documented env var is never persisted to the config file |
| medium | init_config.sh:140 | notification_title is documented and consumed but never written to the config file; sendmessage.sh reads it only from the config file |
| medium | init_config.sh:181 | webhook_body is documented and consumed but never written to the config file |
| medium | init_config.sh:124 | msmtp_args silently defaults to --tls-starttls=off, contradicting the docs, and an empty env override cannot clear a non-empty default |
| medium | example.env:34 | synchronisation_interval / synchronisation_delay env vars documented in example.env are never read; only config-file keys are migrated |
| medium | example.env:28 | example.env documents variables that no script reads: delete_heic_jpegs, command_line_options, pushbullet_api_key (and Pushbullet as a notification_type) |
| medium | CONFIGURATION.md:153 | CONFIGURATION.md documents telegram_silent_file_notifications, but the only key the code reads is silent_file_notifications |
| medium | build-and-push.yml:8 | Builds trigger only on build_version.txt changes, so script/dockerfile fixes silently never ship |
| medium | build-and-push.yml:60 | Registry buildcache (mode=max) plus FROM alpine:latest and one mega-RUN means rebuilds ship stale apk/pip layers indefinitely |
| medium | build-and-push.yml:7 | Stale published image is possible: builds trigger only on build_version.txt changes, not on dockerfile/script edits |
| medium | sendmessage.sh:7 | Telegram message text is not URL-encoded, is sent as parse_mode=markdown with raw asterisks, and the HTTP result is never checked — MFA prompts can silently never arrive |
| medium | icloudpd.dockerfile-sourcebuild:15 | git clone of moving 'master' branch is layer-cached forever, silently freezing upstream source |
| medium | icloudpd.dockerfile:29 | HEALTHCHECK start-period of 10s is far shorter than first-run initialisation/2FA, causing unhealthy state and autoheal restart loops during setup |
| medium | webui.py:70 | SUPPLIED_MFA/CHECKING_MFA webui states are classified as IDLE, producing a false 'Two-factor authentication successful' for codes Apple then rejects, followed by a false 'push notification has been sent' re-prompt |
| medium | main.py:180 | Preflight failure keeps the process alive via signal.pause() but never writes the status file, so the healthcheck fails every minute and autoheal restart-loops the container, defeating the stated design |
| medium | main.py:85 | Legacy '<user> <command>' Telegram convention only works for the literal aliases 'user'/'icloudpd', and multi-container setups sharing one bot token cannot route commands at all |
| medium | config.py:86 | webui_port only moves where the bridge polls; icloudpd's webui is hardcoded to 8080, so any non-default webui_port silently breaks all MFA relaying |
| low | sync-icloud.sh:615 | generate_cookie backs up the session file to a misnamed path (missing dot before 'session.bak') |
| low | sync-icloud.sh:621 | generate_cookie validation greps a possibly nonexistent cookie file, producing 'bad number' test errors |
| low | sync-icloud.sh:344 | openhab/webhook notification_url is composed before webhook_port/webhook_path defaults are assigned; openhab-specific default path can never apply |
| low | sync-icloud.sh:736 | check_web_cookie never extracts web_cookie_expire_date after waiting for a newly created cookie |
| low | sync-icloud.sh:817 | Next-notification debug log treats an epoch timestamp as a relative seconds offset |
| low | sync-icloud.sh:582 | configure_password declares 'local counteraction' instead of 'local counter' |
| low | sync-icloud.sh:303 | Telegram debug log prints notification URL with stray 'y' after server name |
| low | sync-icloud.sh:27 | Cookie filename derivation diverges from pyicloud_ipd for non-ASCII Apple IDs |
| low | sync-icloud.sh:1301 | Unquoted filename expansions in nextcloud/HEIC loops allow glob substitution and sed metacharacter breakage |
| low | sync-icloud.sh:1512 | touch --reference after a failed magick conversion creates a 0-byte JPG that permanently blocks re-conversion |
| low | sync-icloud.sh:1783 | force_convert_all_mnt_heic_files runs unconditional rm on possibly nonexistent JPG |
| low | sync-icloud.sh:1879 | remove_empty_directories can delete the jpeg_path root directory itself |
| low | sync-icloud.sh:2382 | Negative sleep_time when a sync outlasts download_interval: sleep errors and Telegram polling is silently skipped |
| low | sync-icloud.sh:2447 | poll_sleep stays at 3 seconds indefinitely if the user never replies after an 'auth' request |
| low | sync-icloud.sh:2578 | Invalid launch parameter permanently disables Telegram polling even after the parameter is discarded |
| low | healthcheck.sh:35 | healthcheck uses -f instead of -s for icloudpd_check_error, mis-attributing download errors to the file check |
| low | healthcheck.sh:71 | Web authentication branch computes expiry but never fails or warns on an expired web cookie |
| low | healthcheck.sh:35 | Uses -f instead of -s for icloudpd_check_error, producing a wrong failure diagnosis |
| low | healthcheck.sh:35 | Download errors are misreported as file-check errors because the inner test uses -f on a file that launcher always pre-creates |
| low | launcher.sh:694 | traceroute gate exits the container on transient startup DNS failure, causing a restart loop |
| low | launcher.sh:342 | download_delay cap sed missing -i: cap never applied and config (with secrets) dumped to log |
| low | launcher.sh:602 | Mount check uses unanchored substring grep against /proc/mounts, allowing a false pass that sends downloads to the ephemeral container layer |
| low | launcher.sh:727 | Telegram getUpdates curl has no timeout and can hang container startup indefinitely |
| low | init_config.sh:176 | Dead, misspelled key trigger_nextlcoudcli_download is written into every user's config |
| low | init_config.sh:255 | chown of the rewritten config uses raw user_id/group_id values without quote-stripping or validation |
| low | init_config.sh:172 | telegram_polling defaults to true while CONFIGURATION.md describes it as opt-in |
| low | init_config.sh:160 | Functional config keys written by init_config.sh are undocumented: skip_created_after, skip_created_before, skip_download, debug_logging |
| low | init_config.sh:43 | config_content is read but never used (dead code) |
| low | build-and-push.yml:16 | No shellcheck/lint or PR validation despite change.log claiming a 'shellcheck failsafe'; scripts ship untested |
| low | build-and-push.yml:52 | icloudpd.dockerfile-sourcebuild is never built by CI and is already known-broken |
| low | sendmessage.sh:64 | Config values parsed with awk -F= are truncated at the first '=' in the value |
| low | sendmessage.sh:17 | H5 adjudicated: SMS-choice parsing works with 1.32.3 output; only the number-prettifying sed no longer matches the new obfuscated format (cosmetic) |
| low | profile:15 | dl_path parse uses whitespace-splitting awk on a key=value line, so the dls alias always ignores the configured download_path |
| low | icloudpd.dockerfile:33 | No init process (tini/--init): ash PID 1 never handles SIGTERM, so docker stop always escalates to SIGKILL mid-download; orphaned expect children unreaped |
| low | icloudpd.dockerfile:1 | Unpinned alpine:latest base makes builds non-reproducible and exposed to Python minor-version and musl breakage |
| low | icloudpd.dockerfile:8 | python3 runtime dependency is only transitive (via py3-pip); venv does not carry its own interpreter |
| low | cookies.py:25 | cookie_filename strips non-ASCII characters that pyicloud_ipd keeps, diverging from icloudpd's cookiejar path despite claiming exact replication |
| low | scheduler.py:409 | Cookie expiry messaging is off by one day: a cookie with up to 24h of validity left is announced as 'has expired', and expired cookies report negative day counts |
| low | scheduler.py:113 | SIGTERM never aborts an in-flight icloudpd run: _tick_during_run ignores the stop flag, so docker stop always escalates to SIGKILL during a sync |
| low | scheduler.py:336 | Crash or kill during run_reauth leaves the account cookie-less: .reauth-backup files are never restored on startup |

## How the rewrite addresses the structural failures

| Legacy failure | Rewrite design |
|---|---|
| Telegram polling only ran between successful syncs; reauth unreachable once the cookie expired | Always-on listener thread, commands work in every state |
| Cookie expiry → `exit 1` → Docker restart loop | Supervisor never exits; states + persisted schedule |
| Restart loop + autoheal → password sign-in every ~2 min → Apple account lock | Persisted daily auth budget; icloudpd webui mode pauses inside one attempt |
| `expect` prompt-scraping died silently on unexpected output | HTTP status bridge with explicit states and error relay |
| Cookies deleted before reauth succeeded | Backup → attempt → restore-on-failure, with startup recovery |
| Healthcheck unhealthy while waiting for user input | Liveness-only healthcheck |
| `$?` captured at string-build time → all icloudpd exit codes read 0 | Direct subprocess return codes |
