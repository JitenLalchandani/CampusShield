# CampusShield Privacy Policy

**Effective date:** 13 November 2026
**Last updated:** 18 November 2026

CampusShield is published by **[YOUR LEGAL NAME OR COMPANY]** ("CampusShield", "we", "us").
Contact: **[privacy@your-domain.example]** · **[your postal address]**

This policy covers the CampusShield web app, progressive web app (PWA), macOS desktop app, iOS/iPadOS
app, Android app, and the self-hosted CampusShield server. It explains exactly what the software reads,
where that information goes, and how to delete it.

> **Template notice:** replace the bracketed placeholders, have the final text reviewed for your
> jurisdiction, and host it at a public HTTPS URL before submitting to any store. Apple, Google, and
> Microsoft all require a reachable privacy-policy link on the store listing and inside the app.

## 1. Short version

- Accounts are **local to the CampusShield server you or your operator runs**. The developer receives
  no account data. There are **no ads, no analytics, and no developer-operated telemetry**.
- Device checks are **read-only**. The offline file scanner reads file names, a small file header, and
  a SHA-256 hash on your own machine; it never uploads file contents. The security test also reads the
  local **listening-socket table** (addresses, ports, process names and PIDs) to show which services
  accept connections; it never contacts a port, captures packets, or resolves anything remotely. We
  never read keystrokes, browsing history, screen, camera, microphone, contacts, photos, or location.
- Results are stored **on your device or on the server you choose**. The developer does not receive them.
- Two features use the network on their own: the optional breached-password check (five characters of a
  SHA-1 hash) and the connection to your own CampusShield server. The link inspector never opens or
  fetches the link. The optional AI assistant contacts only the endpoint you configure, and only when
  you use the assistant view, send a chat message, press Explain, or ask for a summary.
- You can erase everything from **Settings → Clear all data**, or by uninstalling the app.

## 2. Scope

This policy applies to the apps and server software we distribute. It does **not** apply to a
CampusShield server operated by a university, employer, or other third party. In that case, the
operator of that server is the data controller and their own privacy notice applies. CampusShield
software is self-hosted by design; we do not run a shared backend for the shipped apps.

## 3. Information the app handles

### 3.1 Accounts and sessions

The first person to sign up on a server creates the owner account. The server stores the following in
the configured data store:

| Item | Example | Why |
| --- | --- | --- |
| Name you type | `Meera Patel` | Label the account |
| E-mail you type | `meera@campus.edu` | Sign-in identifier; it is not verified by e-mail |
| Password hash | scrypt hash with a random salt | Verify sign-in; the password itself is never stored |
| Role and timestamps | `owner`, created and last-signed-in ISO dates | Show who owns the server |
| Session records | SHA-256 hash of the session token, creation and expiry dates (30 days) | Keep you signed in without storing the raw token |

The raw session token is returned to the client once and kept in browser local storage (or the Flutter
app's preferences); the server also sets an HttpOnly `SameSite=Lax` cookie. Signing out deletes the
session record. Anyone who can run the server can read the store and should treat it as trusted
infrastructure.

### 3.2 Device check results (created only when you press "Check device")

On macOS, the desktop app and self-hosted web server run read-only system commands and store the
following in the configured data store:

| Item | Example | Why |
| --- | --- | --- |
| macOS version and Mac model family | `macOS 15.6`, `MacBook Pro` | Identify the checked device |
| Hostname | `lab-mac-04` | Label the device in your list |
| Security-setting status | FileVault on/off, firewall on/off, Gatekeeper, SIP, screen-lock delay, guest account, automatic-update setting | Produce the score and findings |
| Names of recent installer/script files in `~/Downloads` | `installer.dmg` | Point out files worth reviewing (names only; file contents are never opened) |
| Names of third-party login-item files | `com.example.agent.plist` | Point out background items worth reviewing |
| Pending macOS update labels | `macOS Sequoia 15.7.1` | Show available updates |
| Score, grade, rule version, timestamps | `90`, `Good`, `2026.11`, ISO date | Explain and compare checks |

Full findings, including the plain-language recommendation for each item, are stored so the history is
reproducible. The check does not read file contents, does not require administrator rights, does not
install a driver or kernel extension, and does not monitor activity in the background.

### 3.3 File scan results (created only when you run a scan or enable the watch)

The desktop build can scan files for known hashes and suspicious patterns. Scanning happens on the
machine running the server; file contents are never uploaded. The following is stored in the
configured data store:

| Item | Example | Why |
| --- | --- | --- |
| File path and name | `/Users/me/Downloads/invoice.pdf.exe` | Show the finding and support quarantine |
| File size and SHA-256 hash | `…`, `275a021b…` | Match signatures and identify the file |
| Severity and matched reasons | `high`, "Disguised file type" | Explain why the file was flagged |
| Scan scope, counters, timestamps | `quick`, 12 431 files, ISO date | Show progress and history |
| Quarantine record | original path, stored file name | Restore a file you choose to release |

A quarantined file is moved to `<dataDir>/quarantine` on the same machine with owner-only permissions.
Turning on the real-time folder watch only expands *when* those quick-scan folders are inspected; it
does not add a new destination for data. Files are **not** transmitted to the developer, and no
reputation lookup leaves the device.

### 3.4 Network exposure snapshot (created only when you run the security test)

The security test also reads the **local socket table** to show which services on this machine are
listening and from where they accept connections. Nothing is sent over the network to do this: the
server runs the operating system's own listing command (`lsof` on macOS, `ss` on Linux, `netstat` on
Windows) and parses its output. The snapshot stored in the configured data store contains:

| Item | Example | Why |
| --- | --- | --- |
| Protocol, address, and port | `tcp 127.0.0.1:4111`, `udp *:59376` | Show where a service is reachable |
| Reachability label | `loopback` or `network` | Separate services only this machine can reach from those the network can reach |
| Process name and PID, when the OS exposes it | `node`, `rapportd` | Help you identify the service |
| Sensitive-service note | "Database port" | Readability hint for well-known ports |
| Counts, platform, read timestamp, or an error | `11 listeners`, `macOS`, ISO date | Explain what was and was not readable |

This is a **read of the socket table, not a port scan**: CampusShield does not connect to a port, send a
probe, capture or inspect packets, identify remote hosts, or look anything up online. Exposure is
reported separately and never added to the safety score. A standard per-user build can only see its own
sockets and some system daemons; anything it cannot read is left out and the snapshot says the read was
partial instead of implying the machine has no other listeners. Omit the security test if you do not
want process names stored; **Clear all data** removes the snapshot with the rest of your records.

### 3.5 Linked devices (created when you add a device)

The name you type, device kind (computer, phone, tablet, browser), platform, source, timestamps, role,
and — once that device is actually checked — its score and grade. A linked device with no check shows
"Not checked" and does not affect the average. Linking a device does not transmit anything from that
device.

### 3.6 Campus threat queue (operator feature)

If an operator ingests events into their own CampusShield server, those events and the analyst's
actions are stored in that server's data store. An event may contain a group name, event type, source
label, count, detail text, severity, rule, recommendation, and arbitrary metadata supplied by the
ingesting system. **The operator decides what to ingest and must ensure it is authorized and lawful.**
Do not submit special-category data, and avoid personal data that is not needed for triage.

### 3.7 On-device settings

The web, desktop, and mobile apps keep a small number of values in browser local storage: the API base
URL you configure, your session token, auto-refresh preference (on/off and interval), the optional
API access token, and — if you configure the AI assistant — its base URL, model name, and API key.
These values stay in that browser profile; clearing site data removes them and signs you out.

Protection preferences (real-time toggle, notifications, folder exclusions, and the scan schedule) are
saved by the server in the configured data store under `settings.preferences`, so the desktop app and a
self-hosted server share them across restarts. Exclusions are folder paths; exclude a folder if you do
not want its path stored. On the desktop app the server stores its data in the OS application-data
directory (`~/Library/Application Support/CampusShield/data` on macOS).

### 3.8 Optional AI assistant

The AI assistant is off until you enter an endpoint, model, and key in Settings. The assistant view and
the recommendation list work without it: they are built from stored checks and scans on your server.
Once configured, the app sends the model only what it needs to phrase an answer:

- **Suggestions:** the stored score, last scan counts, open detections, and the recommendations already
  computed locally.
- **Chat:** your message plus the last few chat turns and the same stored facts.
- **Explain / Summary:** the finding's file name, severity, hash, and matched reason labels, or scan
  and finding counts with parent folder names (not full paths).

File contents, passwords, and session tokens are never sent to the AI endpoint.

- The API key is stored only in browser local storage and is sent with each request to your own server;
  the server does not save it.
- Remote AI endpoints must use HTTPS. Plain HTTP is accepted only for localhost, so a local model such
  as Ollama can be used without TLS.
- Your AI provider's own privacy policy governs what it does with the request. We do not receive the
  request, the key, or the response, and cannot delete data held by that provider.
- The assistant is advisory. It cannot create, confirm, or clear a detection, and it is never consulted
  when the scanner decides whether a file is suspicious.

### 3.9 What we never collect

No file contents, keystrokes, clipboard, browsing history, screen recordings, screenshots, camera or
microphone input, contacts, calendars, photos, precise location, advertising identifiers, or
installed-app inventory beyond the login-item filenames listed above are sent to us. The scanner reads
a small header and a hash locally, but never transmits the file itself. No crash reports, usage
analytics, or device fingerprints are sent to us.

## 4. Network connections

| Destination | When | What is sent | Notes |
| --- | --- | --- | --- |
| Your CampusShield server (self-hosted, or `127.0.0.1` in the desktop app) | Loading data and running checks | The API request and its JSON payload | Under your control; use HTTPS if it is reachable beyond localhost |
| `api.pwnedpasswords.com` (Pwned Passwords range API, operated by Have I Been Pwned) | Only when you submit a password to the password tool | The **first five characters** of the password's SHA-1 hash, with `Add-Padding: true` | The password and the full hash never leave the device; the response is only a list of hash suffixes and counts |
| Apple's software-update service | Only during a macOS device check, via the system `softwareupdate` tool | No CampusShield data; the request is made by macOS | Needed to list pending updates; governed by Apple's privacy policy |
| `fonts.gstatic.com` (Google Fonts) | First load of the Flutter build at `/app` | A request for the Roboto font file; no CampusShield data, no cookies, no identifier | The renderer's CanvasKit engine is self-hosted by the CampusShield server, so the font is the only third-party request the Flutter build makes |
| MongoDB Atlas | Only if the operator sets `MONGODB_URI` on their own server | Events, actions, audit entries, devices, settings | The operator's own Atlas account and MongoDB's privacy terms apply |
| The AI endpoint you configure (OpenAI, Azure OpenAI, OpenRouter, Groq, Ollama, etc.) | Only when AI is configured and you use the assistant view, chat, **Explain**, or **Summary** | Stored score and recommendations, chat message and recent turns, or finding name, severity, hash, and reason labels — plus your API key | Off by default; HTTPS required except localhost. Governed by that provider's privacy policy |

The link inspector performs all checks in the browser and never opens, resolves, or fetches the URL you
paste. Timestamps and device names are not attached to the password request. The network exposure
audit adds no destination to this table: it only reads the local socket table and never contacts,
probes, or resolves a listed port.

## 5. macOS permissions

- **Downloads, Desktop, and Documents folders:** macOS may ask for permission to read these folders
  during a device check, a file scan, or after you start the folder watch. If you decline, those
  folders are skipped and the related finding shows "Unverified" or the scan names the folders it
  could not read.
- CampusShield does **not** request Accessibility, Screen Recording, Input Monitoring, or
  administrator/sudo rights, and it cannot grant itself Full Disk Access. macOS blocks some folders
  for unsandboxed and development builds; if you want those included, you may grant Full Disk Access
  manually in System Settings → Privacy & Security. The app never pretends a skipped folder was clean.
- You can revoke Downloads access at any time in System Settings → Privacy & Security → Files and
  Folders.

## 6. Storage, retention, and deletion

- Data lives in the store configured by the person running the server: a local JSON file or their own
  MongoDB database. There is no developer cloud copy.
- Retention is controlled by that operator. The default build keeps records until deleted.
- **Delete everything:** Settings → Clear all data (also available as `DELETE /api/events`), which
  removes events, decisions, audit entries, devices, scans, quarantine records, and saved protection
  preferences. Accounts and sessions are kept so the owner can still sign in; to remove them, delete
  the `users` and `sessions` records from the store (or use a fresh data folder, which reopens sign-up).
  Remove a single device from the Protection screen. Uninstalling the desktop or mobile app removes its
  local app data; a self-hosted server's data must be deleted on that server.
- Browser local storage (API base URL, session token, API access token, AI settings) can be cleared
  through the browser's site-data settings, the sign-out button, or the AI card's **Remove** button.
  Clearing it signs that browser out but does not delete the account.

## 7. Security

- The desktop app binds its server to `127.0.0.1` on an ephemeral port, so checks and data stay on the
  machine.
- Authentication is account-based. Passwords are hashed with scrypt and a random salt; session tokens
  are generated with a cryptographic random source and stored only as SHA-256 hashes; the session is an
  HttpOnly `SameSite=Lax` cookie plus a bearer token with a 30-day expiry; sign-in is rate-limited.
  Optional shared secrets (`CAMPUSSHIELD_API_TOKEN`, `CAMPUSSHIELD_VIEW_TOKEN`) are accepted alongside
  accounts for scripts, and the view token is GET-only. The API is open only until the first account or
  token exists; it is not built for exposure to the open internet, so put TLS and network controls in
  front of it if you do.
- A remote signature feed is optional. If `CAMPUSSHIELD_SIGNATURES_URL` is set, the server downloads
  hash entries from that operator-chosen HTTPS URL at startup and when **Update signatures** is
  pressed; hashes are not personal data, and no local file names or scan results are sent.
- AI credentials are entered by the user, kept in browser local storage, and never written to the
  server's data store. The server forwards each request without logging the key.
- Mobile builds require you to enter the server URL; use HTTPS for anything beyond a trusted LAN.
- No method of storage or transmission is completely secure. We cannot guarantee absolute security.

## 8. Children

CampusShield is intended for university and workplace audiences and is not directed to children under
13 (or the minimum age in your country). We do not knowingly collect personal information from
children. If you believe a child has provided information to a CampusShield server, contact the
operator of that server to delete it.

## 9. Your rights

Because we do not receive your data, requests to access, correct, export, or delete it are handled on
the device or server that holds it. The app includes a JSON export and a full reset. If you believe we
hold your data (for example, you contacted support by email), contact us at
**[privacy@your-domain.example]** and we will respond within the period required by applicable law
(typically 30 days). You may also complain to your local data-protection authority.

## 10. International transfers

The apps do not transfer data to us. If an operator configures a server or MongoDB Atlas in another
region, that operator is responsible for the lawful basis and safeguards for the transfer.

## 11. Changes

We will update this policy when the app's data practices change and revise the date above. Material
changes will be noted in the release notes and, where required, in-app before the change takes effect.

## 12. Contact

**[YOUR LEGAL NAME OR COMPANY]**
**[privacy@your-domain.example]**
**[your postal address]**

## Appendix A — Store privacy disclosures

These are the answers that match the shipped build. Re-check them whenever you add a developer-operated
backend, analytics SDK, crash reporter, ads, or third-party sign-in.

### Apple App Store / Mac App Store (App Privacy)

- **Data Not Collected.** The shipped apps send data only to a server the user configures, and the
  developer operates no backend. Accounts are created on and stored by that server, so the developer
  receives no account, device, or scan data. Complete the questionnaire with "No" for tracking and
  "No" for data collection, and add the review note in [store-listing.md](store-listing.md).
- If you later ship a hosted CampusShield backend, declare at minimum *Contact Info* (name, e-mail),
  *Device ID*, and *Other Usage Data* (device posture results) linked to the user, used for App
  Functionality, and update this policy.
- The app does not use the Advertising Identifier and does not track across apps or websites.

### Google Play (Data safety)

- **No data collected or shared** for the shipped configuration (no developer backend, no analytics,
  no ads). If the user points the app at their own CampusShield server, the account and scan data live
  on that server, which the developer does not operate.
- Data is encrypted in transit when the user configures an HTTPS server. The app declares only the
  `INTERNET` permission. Release builds block cleartext traffic; debug builds allow it for LAN testing.
- Data deletion: users can delete all data in-app (Settings → Clear all data) and by uninstalling.
  Provide **[privacy@your-domain.example]** as the deletion-request contact.

### Microsoft Store

- The package makes no network calls to Microsoft or to the publisher. Declare no collected data and
  link this policy in Partner Center. The desktop app stores data in the local app-data folder.
