# CampusShield — Cross-Device Safety

CampusShield is a local-first device safety app built for campus life. It checks the security posture
of a computer with read-only commands, scans files with a local signature set and explainable
heuristics, quarantines what you choose, and averages checked devices into one **cross-device safety
score**. Two privacy tools — a phishing link inspector and a breached-password check — work without
sending sensitive data anywhere. An optional campus threat queue keeps the original analyst workflow
for operators who connect it to real telemetry.

The same front end runs in a browser, as a PWA, inside an Electron desktop app, inside Capacitor
iOS/Android shells, and as a Flutter application. The first sign-up creates the owner account; after
sign-in the assistant shows what the stored checks recommend and runs a real security test on request.
Nothing is fabricated: a new install has no events, an unchecked device has no score, and every finding
shows what was actually read.

## How it compares to a classic antivirus

| Classic antivirus | CampusShield |
| --- | --- |
| Signature/behaviour scanning of files | Both: local file scanning **and** read-only posture checks |
| Real-time protection toggle, scheduled scans, exclusions, custom folder scans | Same controls, persisted in Settings |
| One machine at a time | One shared score across linked computers, phones, and tablets |
| Opaque "risk" number | Every point is explained: rule, weight, evidence, fix |
| Background drivers and kernel extensions (real-time blocking) | User-space folder watch that scans new files but cannot block execution |
| Accounts and cloud sync | Local accounts on your own server; no vendor cloud or sync |
| Built-in chatbot bolted on | Assistant whose recommendations come from stored checks and scans; the optional AI endpoint only explains them and never makes detection decisions |

CampusShield is **not a full antivirus**. The desktop build scans files against a small local
signature set plus heuristics, and its real-time watch runs in the user session, so the OS does not
let it block execution the way a kernel extension or system driver can. On iOS and the Mac App Store
the sandbox forbids scanning other apps' files entirely. The store-readiness guide maps exactly what
each store version can promise.

## Features

- **Accounts and sessions** — the first sign-up creates the owner account with a name, username,
  e-mail, and password; every later visit asks for the e-mail or username and password. Passwords are
  scrypt-hashed, session tokens are stored hashed, and the session is an HttpOnly `SameSite=Lax` cookie
  plus a bearer token the web and Flutter clients send. The API stays open only until the first account
  exists (or an API token is configured).
- **Assistant home** — the first screen after sign-in. It shows the device score, last scan, open
  detections, network exposure, and a recommendation list generated from stored checks and scans. The
  primary button runs a real security test: a read-only posture check, a full file scan of the home
  folder, and a read of every listening socket. A quick-scan button sits next to it. Without an AI
  endpoint the view asks you to connect one; the recommendations themselves always come from the
  local checks.
- **Protection home** — score ring, grade (Protected / Good / Needs attention / At risk), average of
  checked devices, weakest device, and read-only findings with plain-language fixes.
- **Cross-device registry** — link phones, tablets, computers, and browsers; checked devices feed the
  average, unchecked devices stay visibly "Not checked" instead of guessing.
- **Malware scan** — quick scan (Downloads, Desktop, Documents, launch agents) or full scan (whole home
  folder plus application and launch folders). SHA-256 signature matching, double extensions, hidden
  executables, content/extension mismatches, and script patterns such as download-and-execute,
  encoded PowerShell, reverse shells, and security-tampering commands.
- **Quarantine** — move a finding into the app vault, restore it to its original path, or delete it.
  Quarantined and deleted files stop counting against the score.
- **Real-time protection** — a persisted toggle for the folder watch. `fs.watch` on the quick-scan
  folders scans new files as they appear and can toast a desktop notification. It runs in the user
  session: it can report and quarantine, but it cannot block execution.
- **Scheduled scans** — daily or weekly quick/full scans at a chosen time, with the next run shown in
  the UI. The scheduler is in-process, so a scan only starts while CampusShield is running.
- **Exclusions and custom scans** — exclude folders from automated scans, or scan one specific folder
  or file on demand. An explicit custom scan always runs, even inside an excluded folder.
- **Desktop notifications and tray** — the Electron build shows a notification for new findings, keeps
  a tray/menu-bar icon with Open, Run quick scan, and Quit, and asks for notification permission only
  when you enable it.
- **macOS device audit** — FileVault, Application Firewall, Gatekeeper, SIP, screen lock, guest account,
  automatic updates, pending macOS updates, Downloads installers/scripts, and third-party login items.
- **Windows device audit** — BitLocker, firewall profiles, Microsoft Defender real-time state and
  signature age, UAC, machine inactivity lock, Guest account, most recent installed update, startup
  commands, and Downloads installers/scripts. Unreadable values stay "Unverified".
- **Network exposure audit** — reads the listening socket table (`lsof` on macOS, `ss` on Linux,
  `netstat` on Windows) and lists each address, port, and owning process. Sockets reachable beyond
  loopback are separated from loopback-only ones, and sensitive services (SMB, RDP, databases, Redis,
  Elasticsearch, and similar) are called out with a reason. Nothing is connected to or probed, and
  exposure is reported, never folded into the score.
- **API access tokens** — optional shared-secret access for scripts and integrations alongside accounts:
  one full-access token and one read-only token, entered once in Settings.
- **Signature feeds** — the built-in set plus a local JSON feed and/or an HTTPS feed fetched at startup
  and on demand from Settings; the UI reports how many hashes a feed added or why it failed.
- **AI assistant (optional)** — connect any OpenAI-compatible endpoint (OpenAI, Azure OpenAI, OpenRouter,
  Groq, or a local Ollama) to get plain-language suggestions in the assistant view, an explanation of
  one finding, or a summary of a finished security test. The key stays in browser local storage and is
  sent per request; remote endpoints must be HTTPS. The assistant is advisory only: recommendations,
  scores, and detections are produced by the local checks, never by the model.
- **Assistant chat** — ask for a security test, the current status, or open detections. With an AI
  endpoint the answer is phrased by the model; without one, the same three questions are answered from
  stored facts. Chat answers never change scores, detections, quarantine, or settings.
- **Explainable scoring** — start at 100; critical −30, high −18, medium −10, low −4; unverified checks
  cost nothing but stay visible; open malware findings use the same weights, capped at 45 per device.
- **Link inspector** — client-side heuristics for plain HTTP, embedded credentials, raw IP hosts,
  punycode, deep subdomains, shorteners, risky TLDs, brand impersonation, and one-character lookalikes.
  The link is never opened.
- **Breached-password check** — SHA-1 is computed in the browser; only the first five hash characters
  go to the Pwned Passwords range API (k-anonymity). The password and full hash never leave the device.
- **Threat queue** — search, severity/status/type filters, sorting, paging, and a decision drawer.
- **Actions and audit trail** — Investigate and Reopen review decisions, each appended to an
  activity log with kind filters that now include device checks. The old "Contain (demo)" action was
  removed because it only changed a label. Each queued event also shows where it came from.
- **Coverage** — an honest map of what is collected and what is not.
- **Storage** — MongoDB Atlas when `MONGODB_URI` is set, otherwise a zero-config local JSON store.
- **PWA, Electron, Capacitor** — installable web app, embedded-server desktop app, and native shells.
- **Flutter application** — the same API in a Flutter client (`flutter_app/`) with sign-in/sign-up,
  the assistant and security-test flow, protection, scans, threats, quarantine, activity, coverage,
  and settings. It builds for web (served at `/app`), macOS, iOS, and Android using the standard
  Flutter toolchains.

## Platform coverage

| Capability | macOS host (Electron / self-hosted) | iOS / iPadOS | Android | Windows |
| --- | --- | --- | --- | --- |
| Read-only device audit | Yes | No (sandbox) | Not yet | Yes |
| File scanning (quick/full) | Yes | No (sandbox) | No | Yes (same engine) |
| Quarantine and restore | Yes | No | No | Yes |
| Real-time folder watch | Yes (user space) | No | No | Yes (user space) |
| Scheduled / custom scans and exclusions | Yes | No | No | Yes |
| Desktop notifications, tray | Yes | No | No | Yes |
| Accounts, sessions, assistant view | Yes | Yes | Yes | Yes |
| AI explanation (optional endpoint) | Yes | Yes | Yes | Yes |
| Cross-device score | Yes | Linked only | Linked only | Yes |
| Link inspector | Yes | Yes | Yes | Yes |
| Breached-password check | Yes | Yes (HTTPS) | Yes (HTTPS) | Yes |
| Campus threat queue | Yes | With server URL | With server URL | With server URL |
| Flutter client | Yes (web + native) | Yes (links only) | Yes (links only) | Yes (web + native) |

Native phone checks require platform plugins (DeviceCheck/Keychain posture on iOS, Play Integrity and
settings intents on Android). Until those exist, the mobile builds link into the score without
reporting a score of their own — the UI says so. Scanning is deliberately absent from the iOS build:
App Store Guideline 2.5.1 forbids one app from inspecting another app's files.

## Architecture

```
public/                Single-page website (vanilla ES modules, hash router, no bundler)
  js/auth.js           sign-up/sign-in gate and session helpers
  js/views/            assistant, protection, threats, activity, coverage, settings
  js/tools.js          link heuristics + Pwned Passwords k-anonymity client
  js/ui.js             icons, formatting, toasts, empty states
  css/app.css          design system
  sw.js                offline shell cache (bypasses /api and /app)
flutter_app/           Flutter application client (web, macOS, iOS, Android)
  lib/                 models, API client, state, screens, theme
  test/                Flutter unit tests plus widget tests that render the shell from API fixtures
  web/                 Flutter web shell and bootstrap (self-hosted CanvasKit), served by Express at /app
src/
  server.js            Express API + static hosting + SPA fallback
  auth.js              scrypt passwords, hashed sessions, sign-up/sign-in routes
  assistant.js         grounded snapshot, recommendations, intent answers (never detects)
  ai.js                optional OpenAI-compatible assistant proxy (never detects)
  store.js             MongoDB or local JSON persistence (events, actions, audit, devices, scans, quarantine, settings)
  deviceAudit.js       read-only macOS posture checks and scoring
  networkAudit.js      read-only listening-socket audit (lsof / ss / netstat)
  localScanner.js      macOS Unified Log indicator scanner
  scanner/
    engine.js          directory walk, SHA-256 hashing, scan budgets
    signatures.js      built-in signature set + optional trusted feed
    heuristics.js      file-type, naming, and script-pattern rules
    preferences.js     persisted AV settings, exclusions, schedule math
    quarantine.js      encrypted-location vault (files moved, chmod 0600)
    watcher.js         user-space real-time folder watch
    manager.js         scan jobs, scheduler, progress, quarantine actions, watch lifecycle
electron/              Desktop main process (tray, notifications) and preload bridge
ios/ android/          Capacitor native projects
build/                 Desktop packaging icons
tests/                 node:test unit tests for auth, the assistant, scanner, preferences, manager, network audit, and AI guard
docs/                  Store submission assets
```

The desktop app starts the Express server on `127.0.0.1` with an ephemeral port, so the audit runs
locally and no data leaves the machine.

## Quick start (web)

Requires Node.js 22+.

```bash
npm install
npm start
```

Open http://localhost:3000. Without a `.env` file the app uses `data/store.json`, starts with no
events and no devices, and asks you to create the owner account. That first sign-up is the only one
that can create an account without a session; after it the API requires a signed-in session or an API
token. Delete the account records from the store (or start with an empty data folder) to sign up again.

The Flutter client is served from the same server. With the Flutter SDK installed:

```bash
npm run flutter:get     # resolve Dart packages
npm run flutter:web     # build to flutter_app/build/web
npm start               # restart the server
```

Then open http://localhost:3000/app. The build is embedded at `/app`; the website at `/` is unchanged.
If the Flutter build is missing, `/app` returns a message instead of failing silently. The build loads
CanvasKit from `/app/canvaskit/` (set in `flutter_app/web/flutter_bootstrap.js`), so the renderer is
served by your own server; the only third-party request is the Roboto font from Google Fonts.

Optional `.env`:

```bash
PORT=3000
MONGODB_URI=mongodb+srv://...            # use Atlas instead of the JSON store
CAMPUSSHIELD_DATA_DIR=./data             # where the JSON store lives
CAMPUSSHIELD_SIGNATURES=./feed.json      # optional trusted signature file
CAMPUSSHIELD_SIGNATURES_URL=https://…    # optional HTTPS signature feed, merged at startup
CAMPUSSHIELD_API_TOKEN=change-me         # optional full-access API token
CAMPUSSHIELD_VIEW_TOKEN=read-only        # optional GET-only API token
CORS_ORIGIN=https://your-frontend.example
```

The built-in signature set contains only the EICAR test file, so a fresh install cannot claim to know
real malware. Point `CAMPUSSHIELD_SIGNATURES` at a trusted local feed, or `CAMPUSSHIELD_SIGNATURES_URL`
at an HTTPS JSON feed (`{"version":"…","entries":[{"sha256":"…","name":"…","severity":"high"}]}`) that
is merged at startup and can be refreshed from **Settings → Update signatures**. Feeds larger than 5 MB
are rejected.

Protection preferences are saved by the server, not the browser: the real-time toggle, notifications,
exclusions, and the daily/weekly schedule are stored in the data store under `settings.preferences`, so
they survive a restart and apply to the desktop app and a self-hosted deployment alike. The scheduler
runs inside the server process, which means a scheduled scan starts only while CampusShield is open;
there is no OS service or background daemon.

The AI assistant is optional and off until you configure it. In **Settings → AI assistant**, enter an
OpenAI-compatible base URL (for example `https://api.openai.com/v1`), a model, and a key. The key is
kept in browser local storage and sent only to the CampusShield server with each AI request; it is never
written to the data store. Remote endpoints must be HTTPS; plain HTTP is allowed only for localhost, so
a local Ollama works. The server forwards the request to `/chat/completions` with a 30-second timeout.
The assistant view still builds its recommendations and answers from stored checks and scans without an
endpoint — it shows a setup card instead of AI prose. With an endpoint, the model labels the settings
that need attention, phrases chat replies, and summarizes a finished run; it cannot create, confirm, or
clear a detection or alter a score.

Accounts gate the API by default. Every `/api` route except `/api/health` and `/api/auth/*` requires a
signed-in session (the cookie or `Authorization: Bearer <session-token>` that sign-up and sign-in
return) or an API token. When either API token is set, it is accepted alongside accounts:
`Authorization: Bearer <token>` or `X-Api-Token`. The admin token can read and change data; the view
token can only issue GET/HEAD requests. Enter the token once under **Settings → API access token**.
While the store has no account and no token is configured, the API stays open so the first person can
sign up.

The API allows `capacitor://localhost`, `ionic://localhost`, and localhost origins for the native
shells; `CORS_ORIGIN` adds one extra origin. To reset the workspace, use **Settings → Clear all data**
or `DELETE /api/events` (events, decisions, devices, scans, quarantined files, and audit history).

## Desktop app (Electron)

```bash
npm run electron     # run unpackaged
npm run dist:mac     # build dist/CampusShield-1.0.0-arm64.dmg
npm run dist:win     # Windows installer
npm run dist:linux   # AppImage
```

The desktop app keeps data in the OS app-data directory
(`~/Library/Application Support/CampusShield/data` on macOS). Builds are unsigned: macOS Gatekeeper
warns until the app is signed with a Developer ID certificate and notarized.

### Flutter application

The Flutter client in `flutter_app/` is the cross-platform application UI. It talks to the same API, so
it works with the embedded desktop server or a self-hosted deployment.

```bash
cd flutter_app
flutter pub get
flutter analyze            # no issues
flutter test               # unit + widget tests
flutter run -d macos       # requires Xcode
flutter run -d chrome      # requires Chrome; the website build is already served at /app
flutter build macos        # requires Xcode
flutter build apk          # requires Android SDK and Java
flutter build ios          # requires Xcode and a signing team
```

`npm run flutter:web` produces the web build served at `/app`, so `flutter run -d chrome` is only needed
while developing the client itself.

Platform folders (`web/`, `macos/`, `ios/`, `android/`) are committed with the permissions the client
needs: `com.apple.security.network.client` on macOS, `INTERNET` plus debug-only cleartext traffic on
Android, and `NSAllowsLocalNetworking` on iOS so the app can reach a server on your own network. The
native builds still require Xcode or the Android SDK, neither of which exists on this machine, so only
the web build is compiled here. `flutter_app/test/shell_test.dart` renders the shell against recorded API
payloads (`test/fixtures/`) at desktop and phone widths, which catches layout overflows and broken API
parsing without a native toolchain.

## Mobile app (Capacitor)

```bash
npm run cap:sync
npm run cap:ios       # opens Xcode
npm run cap:android   # opens Android Studio
```

A native shell does not host the API. Start CampusShield on a reachable machine and set
**Settings → API base URL**, for example `http://192.168.1.20:3000`. The app shows a banner until a URL
is configured. For LAN development over plain HTTP:

- iOS: `NSAllowsLocalNetworking` is enabled in `ios/App/App/Info.plist`; bare-IP HTTP may still need an
  ATS exception depending on the iOS version.
- Android: `android:usesCleartextTraffic="true"` is enabled for development. Use HTTPS in production.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Status, storage, platform, scanner and device-audit availability (open) |
| `GET` | `/api/auth/status` | Whether sign-up is open, whether an account exists, and the current user (open) |
| `POST` | `/api/auth/signup` | `{"name":"…","username":"…","email":"…","password":"…"}` — first account becomes owner; returns a session |
| `POST` | `/api/auth/login` | `{"identifier":"…","password":"…"}` — username or e-mail; returns a session and sets the session cookie |
| `POST` | `/api/auth/logout` | Ends the current session |
| `GET` | `/api/auth/me` | The signed-in user for the current session |
| `POST` | `/api/assistant/suggest` | Stored facts plus recommended next steps; optional `{"ai":{…}}` adds AI explanations |
| `POST` | `/api/assistant/chat` | `{"message":"…","history":[…]}` — answers from stored facts, optionally phrased by AI |
| `POST` | `/api/assistant/security-test` | `{"scope":"full"\|"quick"}` (default `full`) — real device check, file scan, and socket-table read |
| `POST` | `/api/assistant/run-summary` | Plain-language summary of the latest recorded scan |
| `GET` | `/api/summary` | Counts, severity mix, 7-day volume, device total, rules version |
| `GET` | `/api/protection` | Devices, cross-device summary, scanner status, recent scans, quarantine |
| `POST` | `/api/protection/scan` | Run read-only host checks (macOS; `501` elsewhere) |
| `GET` | `/api/scanner` | Engine version, signature set, active scan, watch status, preferences, next scheduled run |
| `PATCH` | `/api/scanner/settings` | Flat preferences body: `{"realtime":true,"notify":true,"exclusions":[],"schedule":{…}}` |
| `POST` | `/api/scanner/signatures/update` | Re-fetch the configured HTTPS signature feed |
| `POST` | `/api/scans` | `{"scope":"quick"\|"full"}` or `{"scope":"custom","path":"/some/folder"}` — start a background scan (`202`) |
| `GET` | `/api/scans` | Recent scans, newest first |
| `GET` | `/api/scans/:id` | One scan with live progress while it runs |
| `POST` | `/api/scans/:id/cancel` | Cancel the running scan |
| `POST` | `/api/threats/:scanId/:threatId/quarantine` | Move the file into the vault |
| `DELETE` | `/api/threats/:scanId/:threatId` | Delete the file permanently |
| `GET` | `/api/quarantine` | Files held in the vault |
| `POST` | `/api/quarantine/:id/restore` | Put a held file back where it came from |
| `DELETE` | `/api/quarantine/:id` | Delete a held file permanently |
| `POST` | `/api/scanner/watch` | `{"enabled":true\|false}` — start or stop real-time protection |
| `POST` | `/api/ai/test` | Validate an endpoint/model/key pair without storing it |
| `POST` | `/api/ai/explain` | `{"config":{…},"scanId":"…","threatId":"…"}` — plain-language finding explanation |
| `POST` | `/api/ai/summary` | `{"config":{…}}` — advisory summary of current protection state |
| `GET` | `/api/devices` | Linked devices |
| `POST` | `/api/devices` | `{"name":"…","kind":"phone|tablet|computer|browser","platform":"ios|android|darwin|win32|linux|web","source":"web|native|electron"}` |
| `DELETE` | `/api/devices/:id` | Remove a device from the shared score |
| `GET` | `/api/events` | Filtered queue (`q`, `severity`, `status`, `type`, `sort`, `limit`, `offset`, `group`) |
| `GET` | `/api/events/:id` | One event plus its decision history |
| `GET` | `/api/activity` | Audit trail (`kind`, `limit`, `offset`) |
| `POST` | `/api/events` | Ingest an approved event |
| `POST` | `/api/scan` | Scan the local macOS log (macOS only, otherwise `501`) |
| `POST` | `/api/alerts/:id/action` | `{"action":"Investigate" \| "Reopen"}` (`Contain` returns 400) |
| `DELETE` | `/api/events` | Clear events, actions, devices, scans, quarantine, and audit history |

Device check example:

```bash
curl -X POST http://localhost:3000/api/protection/scan
```

The ingest endpoint accepts events from an approved source but does not verify that submitted events
are genuine. Accounts and tokens gate who can call the API, not whether an ingested event is true, so
treat any event source as trusted input. Serve a deployment beyond localhost over HTTPS.

## Ransomware shield (opt-in)

Off by default. When on, CampusShield watches Documents, Desktop, Pictures, and any folders you add (inside your home folder, at most 10). It raises an alert when at least 25 files in one folder change within 10 seconds and at least 60% show a sign of encryption: an extension never seen in that folder, or a text file whose first 8 KB now looks random (entropy of 7.5 bits per byte or more). The three numbers are shown in the app and can be changed within fixed ranges.

- **Contain** stops the suspect program and/or turns off network connections. The suspect is a best guess from open-file sampling (`lsof` on macOS and Linux; Sysinternals `handle.exe` on Windows only if it is already installed, never downloaded). It is labelled a suspect, not a culprit.
- Network isolation records what it turned off, restores only that, and restores automatically after 30 minutes (5 to 240) unless you choose Keep isolated. A remote Contain can stop a program but turning the network off always needs approval on the protected computer.
- Scoring: an open alert costs the critical weight (30) through the existing malware penalty and its 45-point cap. The posture check `ransomware-shield` costs 4 points when the shield is supported but off, and nothing when unsupported or unable to start. `RULES_VERSION` is 2026.12.
- API: `GET /api/shield`, `PATCH /api/shield/settings`, `GET /api/shield/alerts`, `GET /api/shield/alerts/:id` (issues a 60-second single-use confirmation), and `POST` `contain`, `undo`, `keep-isolated`, `dismiss`. Changes need a signed-in account or the admin token; the viewer token is read-only.
- Limits: this is a heuristic on file changes, not a kernel driver. It can miss slow encryption, can be wrong about the program, and cannot stop damage already done. Windows and Linux paths are untested on real machines.

Manual check before relying on it: on a spare folder, rename 30 files to `.locked` within a few seconds, confirm the alert, then try Contain with only "Turn off network" and confirm Restore network brings the connection back.

## Scoring rules

- Start at 100. Deduct 30 (critical), 18 (high), 10 (medium), 4 (low). Info and unverified checks cost 0.
- Open malware findings use the same weights and are capped at 45 points per device. Quarantining or
  deleting the file removes its penalty.
- 95+ **Protected**, 80+ **Good**, 60+ **Needs attention**, below 60 **At risk**.
- The cross-device score is the mean of checked devices; linked devices join the mean only after
  their own check runs.
- Rules version `2026.11` is returned by `/api/health` and `/api/protection`; the file scanner reports
  its own engine and signature versions.

## Privacy

- Device checks read settings only. The file scanner reads file names, a 64 KB header, and a SHA-256
  hash; file contents are not uploaded anywhere.
- Scans, findings (path, hash, severity, reasons), and quarantine records stay in the configured local
  store. On desktop that is the app-data folder, and quarantined files sit in
  `<dataDir>/quarantine` with mode 0600.
- The socket audit reads only the local socket table and the owning process names and PIDs. It does
  not capture packets, resolve remote hosts, or connect to any port. The snapshot (counts, addresses,
  ports, process names, read time) is stored with the other scan results and is never sent off the
  server.
- The link inspector runs entirely in the browser and never fetches the inspected URL.
- The password check sends only a five-character SHA-1 prefix to
  `api.pwnedpasswords.com`; see [docs/privacy-policy.md](docs/privacy-policy.md).
- Accounts store a name, username (with a lowercase lookup copy), e-mail, scrypt password hash, role,
  creation and last sign-in times. Sessions store only a SHA-256 hash of the token; raw passwords and
  session tokens are never written to the store. Signing out deletes the session.
- The optional AI assistant sends data only when an endpoint is configured and you use the assistant
  view, chat, **Explain**, or **Summary**: the finding's name, severity, and matched reasons, the
  stored scan counts, or your chat message and the last few replies. File contents are never sent, full
  folder paths are shortened to their parent folder name, and the API key stays in browser local
  storage. Nothing is sent to the developer.
- No ads, analytics, or developer-operated telemetry.

## Limits

- Not a full antivirus, firewall, or VPN. The signature set ships with one test hash; heuristics catch
  specific patterns, not unknown malware.
- Real-time watching runs in the user session. It scans new files but cannot block execution;
  kernel-level blocking needs an Apple Endpoint Security entitlement or a signed Windows minifilter
  driver, neither of which this build ships.
- Device checks are implemented for macOS and Windows hosts. Phone posture checks need native plugins.
  The Windows checks were exercised through parser tests; this build has not been run end to end on a
  Windows machine.
- The macOS audit may show "Unverified" when TCC blocks a path (for example Downloads) or a command is
  unavailable; it never converts an unknown into a pass.
- macOS also blocks file scanning outside the app sandbox until you grant CampusShield **Full Disk
  Access** (System Settings → Privacy & Security). Without it a scan completes over only the files it
  can read and the Protection view says so instead of reporting a clean result.
- Detection is a small, illustrative rule set — not a validated detection engine.
- The socket audit is not a port scanner. It lists what the OS already has open, cannot see sockets
  owned by other users (or, on macOS, by system daemons) unless the server runs as root, and the
  sensitive-port list is a readability hint, not a verified vulnerability. On a sandboxed Mac App
  Store build the socket table may be limited to the app's own process, so that build does not
  advertise the audit.
- The AI assistant is advisory. It explains or summarizes what the scanner already found, can be wrong,
  and never influences detection, scoring, or quarantine. Its absence changes only wording, never the
  recommendations.
- Scheduled scans run only while the app/server process is open; there is no background service, so a
  missed schedule waits for the next launch instead of running silently.
- Queue actions record a review decision only; no device, account, or network state is changed.
  Older stores that hold the removed "Contained (demo)" status show those events as Open.
- Real data only: every score, count, and timestamp comes from a measurement on this computer. What
  cannot be measured shows "Not checked" with a reason. The scan progress bar is indeterminate because
  the total file count is unknown until the walk ends; the numbers beside it are the measurement.
- Accounts are local to the server you run: no e-mail verification, password reset, or multi-factor
  authentication, and roles are only owner/member. The API is open to anyone who can reach it only
  until the first account (or API token) exists; after that, callers need a session or token.

## Store submission

See **[docs/store-readiness.md](docs/store-readiness.md)** for per-store requirements, honest feature
mapping, signing, fees, and review notes; **[docs/store-listing.md](docs/store-listing.md)** for listing
copy and data-safety answers. The build is ready to package; developer accounts, signing certificates,
and final support/privacy URLs are still required before submission.

## Documentation

- [Privacy policy](docs/privacy-policy.md)
- [Terms of use](docs/terms.md)
- [Store listing copy](docs/store-listing.md)
- [Store readiness and release checklist](docs/store-readiness.md)
