# CampusShield — Cross-Device Safety

CampusShield is a local-first device safety app built for campus life. It checks the security posture
of a computer with read-only commands, scans files with a local signature set and explainable
heuristics, quarantines what you choose, and averages checked devices into one **cross-device safety
score**. Two privacy tools — a phishing link inspector and a breached-password check — work without
sending sensitive data anywhere. An optional campus threat queue keeps the original analyst workflow
for operators who connect it to real telemetry.

The same front end runs in a browser, as a PWA, inside an Electron desktop app, and inside Capacitor
iOS/Android shells. Nothing is fabricated: a new install has no events, an unchecked device has no
score, and every finding shows what was actually read.

## How it compares to a classic antivirus

| Classic antivirus | CampusShield |
| --- | --- |
| Signature/behaviour scanning of files | Both: local file scanning **and** read-only posture checks |
| Real-time protection toggle, scheduled scans, exclusions, custom folder scans | Same controls, persisted in Settings |
| One machine at a time | One shared score across linked computers, phones, and tablets |
| Opaque "risk" number | Every point is explained: rule, weight, evidence, fix |
| Background drivers and kernel extensions (real-time blocking) | User-space folder watch that scans new files but cannot block execution |
| Account and cloud sync | Local-first storage with an optional self-hosted MongoDB |
| Built-in chatbot bolted on | Optional assistant you point at your own OpenAI-compatible endpoint; it explains findings and never makes detection decisions |

CampusShield is **not a full antivirus**. The desktop build scans files against a small local
signature set plus heuristics, and its real-time watch runs in the user session, so the OS does not
let it block execution the way a kernel extension or system driver can. On iOS and the Mac App Store
the sandbox forbids scanning other apps' files entirely. The store-readiness guide maps exactly what
each store version can promise.

## Features

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
- **API access tokens** — optional shared-secret access for a self-hosted deployment: one full-access
  token and one read-only token, entered once in Settings. No per-user accounts or audit of callers.
- **Signature feeds** — the built-in set plus a local JSON feed and/or an HTTPS feed fetched at startup
  and on demand from Settings; the UI reports how many hashes a feed added or why it failed.
- **AI assistant (optional)** — connect any OpenAI-compatible endpoint (OpenAI, Azure OpenAI, OpenRouter,
  Groq, or a local Ollama) to get a plain-language explanation of one finding or a summary of current
  protection. The key stays in browser local storage and is sent per request; remote endpoints must be
  HTTPS. The assistant is advisory only: detections are always produced by the local scanner, never by
  the model.
- **Explainable scoring** — start at 100; critical −30, high −18, medium −10, low −4; unverified checks
  cost nothing but stay visible; open malware findings use the same weights, capped at 45 per device.
- **Link inspector** — client-side heuristics for plain HTTP, embedded credentials, raw IP hosts,
  punycode, deep subdomains, shorteners, risky TLDs, brand impersonation, and one-character lookalikes.
  The link is never opened.
- **Breached-password check** — SHA-1 is computed in the browser; only the first five hash characters
  go to the Pwned Passwords range API (k-anonymity). The password and full hash never leave the device.
- **Threat queue** — search, severity/status/type filters, sorting, paging, and a decision drawer.
- **Actions and audit trail** — Investigate, Contain (label only), and Reopen, each appended to an
  activity log with kind filters that now include device checks.
- **Coverage** — an honest map of what is collected and what is not.
- **Storage** — MongoDB Atlas when `MONGODB_URI` is set, otherwise a zero-config local JSON store.
- **PWA, Electron, Capacitor** — installable web app, embedded-server desktop app, and native shells.

## Platform coverage

| Capability | macOS host (Electron / self-hosted) | iOS / iPadOS | Android | Windows |
| --- | --- | --- | --- | --- |
| Read-only device audit | Yes | No (sandbox) | Not yet | Yes |
| File scanning (quick/full) | Yes | No (sandbox) | No | Yes (same engine) |
| Quarantine and restore | Yes | No | No | Yes |
| Real-time folder watch | Yes (user space) | No | No | Yes (user space) |
| Scheduled / custom scans and exclusions | Yes | No | No | Yes |
| Desktop notifications, tray | Yes | No | No | Yes |
| AI explanation (optional endpoint) | Yes | Yes | Yes | Yes |
| Cross-device score | Yes | Linked only | Linked only | Yes |
| Link inspector | Yes | Yes | Yes | Yes |
| Breached-password check | Yes | Yes (HTTPS) | Yes (HTTPS) | Yes |
| Campus threat queue | Yes | With server URL | With server URL | With server URL |

Native phone checks require platform plugins (DeviceCheck/Keychain posture on iOS, Play Integrity and
settings intents on Android). Until those exist, the mobile builds link into the score without
reporting a score of their own — the UI says so. Scanning is deliberately absent from the iOS build:
App Store Guideline 2.5.1 forbids one app from inspecting another app's files.

## Architecture

```
public/                Single-page app (vanilla ES modules, hash router, no bundler)
  js/views/            protection, threats, activity, coverage, settings
  js/tools.js          link heuristics + Pwned Passwords k-anonymity client
  js/ui.js             icons, formatting, toasts, empty states
  css/app.css          design system
  sw.js                offline shell cache (bypasses /api)
src/
  server.js            Express API + static hosting + SPA fallback
  ai.js                optional OpenAI-compatible assistant proxy (never detects)
  store.js             MongoDB or local JSON persistence (events, actions, audit, devices, scans, quarantine, settings)
  deviceAudit.js       read-only macOS posture checks and scoring
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
tests/                 node:test unit tests for the scanner, preferences, manager, and AI guard
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

Open http://localhost:3000. Without a `.env` file the app uses `data/store.json` and starts with no
events and no devices.

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
Nothing is sent until you press **Explain** or **Summary**, and the assistant cannot create, confirm, or
clear a detection.

When either API token is set, every `/api` route except `/api/health` requires
`Authorization: Bearer <token>` or `X-Api-Token`. The admin token can read and change data; the view
token can only issue GET/HEAD requests. Enter the token once under **Settings → API access token**.
There are still no per-user accounts.

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
| `GET` | `/api/health` | Status, storage, platform, scanner and device-audit availability |
| `GET` | `/api/summary` | Counts, severity mix, 7-day volume, device total, rules version |
| `GET` | `/api/protection` | Devices, cross-device summary, scanner status, recent scans, quarantine |
| `POST` | `/api/protection/scan` | Run read-only host checks (macOS; `501` elsewhere) |
| `GET` | `/api/scanner` | Engine version, signature set, active scan, watch status, preferences, next scheduled run |
| `PATCH` | `/api/scanner/settings` | `{"preferences":{…}}` — real-time, notifications, exclusions, schedule |
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
| `POST` | `/api/alerts/:id/action` | `{"action":"Investigate" \| "Contain" \| "Reopen"}` |
| `DELETE` | `/api/events` | Clear events, actions, devices, scans, quarantine, and audit history |

Device check example:

```bash
curl -X POST http://localhost:3000/api/protection/scan
```

The ingest endpoint accepts events from an approved source but does not verify that submitted events
are genuine. Put authentication and authorization in front of the API before exposing it beyond
localhost.

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
- The link inspector runs entirely in the browser and never fetches the inspected URL.
- The password check sends only a five-character SHA-1 prefix to
  `api.pwnedpasswords.com`; see [docs/privacy-policy.md](docs/privacy-policy.md).
- The optional AI assistant sends data only when you press **Explain** or **Summary**: the finding's
  name, severity, and matched reasons, or a summary of scan counts and your own endpoint. File contents
  are never sent, full folder paths are shortened to their parent folder name in the summary, and the
  API key stays in browser local storage. Nothing is sent to the developer.
- This build has no accounts, ads, or analytics.

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
- The AI assistant is advisory. It explains or summarizes what the scanner already found, can be wrong,
  and never influences detection, scoring, or quarantine.
- Scheduled scans run only while the app/server process is open; there is no background service, so a
  missed schedule waits for the next launch instead of running silently.
- Containment records a status only; no device, account, or network state is changed.
- API access is a shared secret, not user accounts: no per-user roles, sessions, or caller audit.
  Without a token the server is open to anyone who can reach it.

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
