# CampusShield — Cross-Device Safety

CampusShield is a local-first device safety app built for campus life. It checks the security posture
of a computer with read-only commands, explains every deduction, and averages checked devices into one
**cross-device safety score**. Two privacy tools — a phishing link inspector and a breached-password
check — work without sending sensitive data anywhere. An optional campus threat queue keeps the
original analyst workflow for operators who connect it to real telemetry.

The same front end runs in a browser, as a PWA, inside an Electron desktop app, and inside Capacitor
iOS/Android shells. Nothing is fabricated: a new install has no events, an unchecked device has no
score, and every check shows what it actually read.

## Why it is different from a classic antivirus

| Classic antivirus | CampusShield |
| --- | --- |
| Signature/behaviour scanning of files | Read-only posture checks of the device's own settings |
| One machine at a time | One shared score across linked computers, phones, and tablets |
| Opaque "risk" number | Every point is explained: rule, weight, evidence, fix |
| Background drivers and kernel extensions | No drivers, no traffic interception, no file access |
| Account and cloud sync | Local-first storage with an optional self-hosted MongoDB |

CampusShield is **not** a malware scanner and does not claim to be one. On macOS it reports what the
operating system allows an app to read; on iOS and Android the platform sandbox limits checks further.
The store-readiness guide maps exactly what each store version can promise.

## Features

- **Protection home** — score ring, grade (Protected / Good / Needs attention / At risk), average of
  checked devices, weakest device, and read-only findings with plain-language fixes.
- **Cross-device registry** — link phones, tablets, computers, and browsers; checked devices feed the
  average, unchecked devices stay visibly "Not checked" instead of guessing.
- **macOS device audit** — FileVault, Application Firewall, Gatekeeper, SIP, screen lock, guest account,
  automatic updates, pending macOS updates, Downloads installers/scripts, and third-party login items.
- **Explainable scoring** — start at 100; critical −30, high −18, medium −10, low −4; unverified checks
  cost nothing but stay visible.
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
| Read-only device audit | Yes | No (sandbox) | Not yet | Not yet |
| Cross-device score | Yes | Linked only | Linked only | Linked only |
| Link inspector | Yes | Yes | Yes | Yes |
| Breached-password check | Yes | Yes (HTTPS) | Yes (HTTPS) | Yes |
| Campus threat queue | Yes | With server URL | With server URL | With server URL |

Native phone checks require platform plugins (DeviceCheck/Keychain posture on iOS, Play Integrity and
settings intents on Android). Until those exist, the mobile builds link into the score without
reporting a score of their own — the UI says so.

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
  store.js             MongoDB or local JSON persistence (events, actions, audit, devices)
  deviceAudit.js       read-only macOS posture checks and scoring
  localScanner.js      macOS Unified Log indicator scanner
electron/              Desktop main process and preload bridge
ios/ android/          Capacitor native projects
build/                 Desktop packaging icons
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
MONGODB_URI=mongodb+srv://...          # use Atlas instead of the JSON store
CAMPUSSHIELD_DATA_DIR=./data           # where the JSON store lives
CORS_ORIGIN=https://your-frontend.example
```

The API allows `capacitor://localhost`, `ionic://localhost`, and localhost origins for the native
shells; `CORS_ORIGIN` adds one extra origin. To reset the workspace, use **Settings → Clear all data**
or `DELETE /api/events` (events, decisions, devices, and audit history).

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
| `GET` | `/api/protection` | Devices, cross-device summary, rules version, audit availability |
| `POST` | `/api/protection/scan` | Run read-only host checks (macOS; `501` elsewhere) |
| `GET` | `/api/devices` | Linked devices |
| `POST` | `/api/devices` | `{"name":"…","kind":"phone|tablet|computer|browser","platform":"ios|android|darwin|win32|linux|web","source":"web|native|electron"}` |
| `DELETE` | `/api/devices/:id` | Remove a device from the shared score |
| `GET` | `/api/events` | Filtered queue (`q`, `severity`, `status`, `type`, `sort`, `limit`, `offset`, `group`) |
| `GET` | `/api/events/:id` | One event plus its decision history |
| `GET` | `/api/activity` | Audit trail (`kind`, `limit`, `offset`) |
| `POST` | `/api/events` | Ingest an approved event |
| `POST` | `/api/scan` | Scan the local macOS log (macOS only, otherwise `501`) |
| `POST` | `/api/alerts/:id/action` | `{"action":"Investigate" \| "Contain" \| "Reopen"}` |
| `DELETE` | `/api/events` | Clear events, actions, devices, and audit history |

Device check example:

```bash
curl -X POST http://localhost:3000/api/protection/scan
```

The ingest endpoint accepts events from an approved source but does not verify that submitted events
are genuine. Put authentication and authorization in front of the API before exposing it beyond
localhost.

## Scoring rules

- Start at 100. Deduct 30 (critical), 18 (high), 10 (medium), 4 (low). Info and unverified checks cost 0.
- 95+ **Protected**, 80+ **Good**, 60+ **Needs attention**, below 60 **At risk**.
- The cross-device score is the mean of checked devices; linked devices join the mean only after
  their own check runs.
- Rules version `2026.11` is returned by `/api/health` and `/api/protection`.

## Privacy

- Device checks read settings only. No files, keystrokes, browsing history, or traffic are collected.
- The link inspector runs entirely in the browser and never fetches the inspected URL.
- The password check sends only a five-character SHA-1 prefix to
  `api.pwnedpasswords.com`; see [docs/privacy-policy.md](docs/privacy-policy.md).
- This build has no accounts, ads, or analytics. Data stays in the configured store.

## Limits

- Not a malware scanner, firewall, VPN, or real-time protection engine.
- Device checks are implemented for macOS hosts. Phone and Windows checks need native plugins.
- The macOS audit may show "Unverified" when TCC blocks a path (for example Downloads) or a command is
  unavailable; it never converts an unknown into a pass.
- Detection is a small, illustrative rule set — not a validated detection engine.
- Containment records a status only; no device, account, or network state is changed.
- There is no authentication or role-based access in this build.

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
