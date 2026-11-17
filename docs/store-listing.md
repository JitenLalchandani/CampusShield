# CampusShield — Store Listing Copy

Ready-to-paste listing text and questionnaire answers for the Apple App Store, Mac App Store, Google
Play, and Microsoft Store. Replace **[bracketed]** values before submitting.

> **Positioning rule:** CampusShield is a *device posture checker, file scanner, and privacy toolbox*.
> The desktop build scans files with a small local signature set and heuristics; the iOS, Android, and
> Mac App Store builds cannot scan files because their sandboxes forbid it. Every store has policies
> against misleading security claims, so each listing below states exactly what that build does. Keep
> the listing consistent with the app. If you mention the AI assistant, always state that it only
> explains findings and never decides whether a file is malicious. The app now has an account gate
> (the first sign-up on a server creates its owner), so do not claim "no account" in any listing.

## Shared basics

| Field | Value |
| --- | --- |
| App name | `CampusShield` |
| Bundle / application ID | `edu.campusshield.app` (mobile) · `edu.campusshield.desktop` (desktop) |
| Version | `1.0.0` (iOS/Android build `1`) |
| Category | Utilities (primary), Education (secondary) |
| Price | Free |
| In-app purchases | None |
| Ads | None |
| Account required | Yes — created on the CampusShield server the user runs (first sign-up becomes owner); no developer account |
| Languages | English |
| Support email | **[support@your-domain.example]** |
| Privacy policy URL | **[https://your-domain.example/privacy]** |
| Terms URL | **[https://your-domain.example/terms]** |
| Marketing URL | **[https://your-domain.example]** |

## Apple App Store (iPhone / iPad)

**Subtitle (30 characters):** `Cross-device safety score`

**Promotional text (170 characters):**
`See one honest safety score for every device you add, inspect suspicious links, and check passwords without sending them anywhere. No ads, no tracking.`

**Keywords (100 characters):**
`safety,security,privacy,phishing,password,device,score,campus,checker,link,breach,settings`

**Description (iPhone / iPad):**
```
One honest safety score for all your devices.

CampusShield keeps one shared safety score across the computers, phones, tablets, and browsers you add. Checked devices feed the average; unchecked devices stay marked "Not checked" instead of guessing, and the weakest device is called out so you know where to start.

This iPhone and iPad app gives you:

• One score across your linked devices
• An assistant that recommends next steps from stored results and runs a real security test on request
• A phishing link inspector that never opens the link
• A breached-password check that never sends your password
• An optional campus threat queue, connected to your own server

Sign in with an account you create on your own CampusShield server. The first sign-up becomes that server's owner; nothing is sent to the developer.

PHISHING LINK INSPECTOR
Paste a link and get plain-language warnings about plain HTTP, embedded credentials, raw IP hosts, punycode, deep subdomains, shorteners, risky top-level domains, brand impersonation, and one-character lookalikes. All checks run on your device and the link is never opened.

BREACHED-PASSWORD CHECK
See whether a password appears in a public breach corpus. Your password never leaves the device: only the first five characters of a SHA-1 hash are sent, using k-anonymity.

CROSS-DEVICE SCORE
Run CampusShield's read-only device checks on a Mac (desktop app) and link this phone to see one combined score. iPhone and iPad sandboxing prevents an app from scanning the device, so this app links into the score and does not report a phone score of its own.

OPTIONAL CAMPUS THREAT QUEUE
Connect your own CampusShield server to review alerts, record decisions, and keep an audit trail.

PRIVATE BY DEFAULT
No ads, no analytics, no tracking. Your account and results stay on the server you choose; the developer operates no backend.

WHAT THIS IPHONE APP DOES NOT DO
iOS does not allow one app to inspect other apps' files, so this build does not scan files or remove malware. The desktop CampusShield app does scan files with a local signature set and heuristics; install it there if you need scanning. A high score reflects the settings checked at that moment, not a guarantee that a device is secure.

Terms and privacy: [https://your-domain.example/terms]
```

**What's New (first release):**
```
First release: cross-device safety score, phishing link inspector, breached-password check, linked devices, and an optional campus threat queue.
```

**App Review notes (paste into "Notes for Review"):**
```
CampusShield is a device posture checker, not an antivirus.

- CampusShield is self-hosted and the developer operates no backend. The app needs a CampusShield server the user runs; on first launch, enter that server's URL and create the owner account. With no server the app shows a setup state and does not fabricate results. Reviewers can run the server with `npm install && npm start` from the public repository and use a LAN or tunnel URL.
- The iOS build does not scan the device or other apps (Guideline 2.5.1). It links a phone into a cross-device score and provides two client-side privacy tools.
- The optional threat queue needs a CampusShield server URL that the user configures in Settings. No server is operated by the developer, so the queue and score screens show empty states by default.
- Local Network permission is used only to reach the user's own CampusShield server. The password tool sends only a five-character SHA-1 prefix to api.pwnedpasswords.com; the link inspector never opens links.
- No tracking, ads, or analytics. Accounts are created on the user's own server, not with the developer.
```

**App Privacy answers:** Data Not Collected, no tracking. See
[privacy-policy.md](privacy-policy.md#appendix-a--store-privacy-disclosures).

**Age rating:** 4+ (no objectionable content, no user-generated content, no ads, no purchases).

**Export compliance:** the app only uses standard HTTPS/TLS provided by the OS and WebKit. Answer that
it does **not** use non-exempt encryption and does not require a CCATS/ERN.

**Screenshots needed** (capture from a running server; no fabricated data):

| Device | Size (portrait) | Caption |
| --- | --- | --- |
| iPhone 6.9" | 1320 × 2868 or 1290 × 2796 | One score across your devices |
| iPhone 6.5" | 1284 × 2778 or 1242 × 2688 | Every finding explained |
| iPad 13" | 2064 × 2752 | Your devices, one shared score |
| iPad 12.9" (2nd gen) | 2048 × 2732 | Inspect a link without opening it |

## Mac App Store

**Subtitle (30 characters):** `Cross-device safety score`

A sandboxed Mac App Store build cannot run `fdesetup`, `spctl`, `csrutil`, `softwareupdate`, read
`~/Downloads`, or scan files outside its own container, so it cannot produce a host score or a file
scan. Use the copy below **only** for a sandboxed build that disables device checks and scanning. Do
not submit the current unsandboxed DMG as-is; it will be rejected.

**Description (Mac App Store, sandboxed build):**
```
One honest safety score for all your devices.

CampusShield keeps one shared safety score across the computers, phones, tablets, and browsers you add. Checked devices feed the average; unchecked devices stay marked "Not checked" instead of guessing.

• One score across your linked devices
• An assistant that recommends next steps and runs a real security test
• A phishing link inspector that never opens the link
• A breached-password check that never sends your password
• An optional campus threat queue, connected to your own server

Sign in with an account you create on your own CampusShield server. All checks run on your Mac, and no ads, analytics, or tracking are included; results stay on your device or on the server you choose.

This sandboxed App Store build cannot read system security settings or scan files, so device checks
and malware scans show "Not available in this build". The full read-only device audit and file scanner
are available in the direct-download version of CampusShield for macOS.

CampusShield is not a full antivirus. It does not filter traffic, scan process memory, or block
execution with a kernel extension.
```

For the **direct-download Mac app** (not a store listing), use the Google Play feature list below and add
this section near the top:

```
ACCOUNTS ON YOUR OWN SERVER
The first sign-up creates the owner account on the CampusShield server you run. Passwords are hashed with scrypt, sessions are stored only as hashes and expire after 30 days, and you can sign out from Settings. No developer account, cloud sync, or analytics are involved.

READ-ONLY DEVICE CHECKS
FileVault, firewall, Gatekeeper, System Integrity Protection, screen lock, guest account, automatic updates, pending updates, recent installers, and background login items. Every finding includes the reason and the fix. No administrator rights, no drivers, no background monitoring.

MALWARE SCAN AND QUARANTINE
Scan Downloads, Desktop, Documents, and launch agents (quick), or your whole home folder plus app and launch folders (full). Matches SHA-256 signatures, double extensions, hidden executables, content/extension mismatches, and script patterns such as download-and-execute, encoded PowerShell, reverse shells, and security-tampering commands. Quarantine, restore, or permanently delete each finding. Quarantined and deleted files stop counting against the score.

REAL-TIME FOLDER WATCH
Optional user-space watch scans new files as they land in your quick-scan folders. It reports and can quarantine; macOS does not let a user-space app block execution without an Endpoint Security entitlement.

SCHEDULES, EXCLUSIONS, AND CUSTOM SCANS
Turn on real-time protection, schedule a daily or weekly quick or full scan, exclude folders you never want scanned, or scan one specific folder or file on demand. Desktop notifications and a menu-bar icon keep the app reachable; scheduled scans run only while CampusShield is open.

ASSISTANT AND SECURITY TEST
The first screen after sign-in shows what the stored checks recommend and one button that runs a read-only device check plus a real quick file scan. Ask the assistant for your status or open detections and it answers from the same stored results.

OPTIONAL AI ASSISTANT
Connect your own OpenAI-compatible endpoint, including a local Ollama model, to have the assistant phrase its suggestions and answers in plain language, explain a finding, or summarize a finished test. Suggestions and scores are always computed locally; the model cannot change a detection. Your key stays in the app's local storage, and remote endpoints must use HTTPS.
```

**Mac screenshots:** 1280 × 800, 1440 × 900, 2560 × 1600, or 2880 × 1800 (16:10).

## Google Play

**App name (30 characters):** `CampusShield`

**Short description (80 characters):**
`One cross-device safety score, a link inspector, and a password breach check.`

**Full description:**
```
One honest safety score for all your devices.

CampusShield keeps one shared safety score across the computers, phones, tablets, and browsers you add. Checked devices feed the average; unchecked devices stay marked "Not checked" instead of guessing.

• One score across your linked devices
• Assistant that recommends next steps and runs a real security test
• Phishing link inspector that never opens the link
• Breached-password check using k-anonymity — your password never leaves the device
• Optional campus threat queue with an audit trail, connected to your own server
• Accounts on your own server; no ads, no analytics, no tracking

PHISHING LINK INSPECTOR
Paste a link and get plain-language warnings about plain HTTP, embedded credentials, raw IP hosts, punycode, deep subdomains, shorteners, risky top-level domains, brand impersonation, and one-character lookalikes. All checks run on your device and the link is never opened.

BREACHED-PASSWORD CHECK
See whether a password appears in a public breach corpus. Only the first five characters of a SHA-1 hash are sent, using k-anonymity; the password and full hash stay on your device.

CROSS-DEVICE SCORE
Run CampusShield's read-only device checks or a file scan on a Mac or Windows computer (desktop app) and link this phone to see one combined score. Android sandboxing prevents this app from scanning the phone's own files in this release, so the Android app links into the score and does not report a phone score of its own.

Start the CampusShield server on a computer you control, enter its URL, and create the owner account on first run. Results and account data stay on your device or on the server you choose.

CampusShield is not a full antivirus. The desktop app scans files with a small local signature set and heuristics; it does not filter traffic, scan process memory, or block execution with a kernel driver. A high score reflects the settings checked at that moment, not a guarantee.
```

**Data safety:**
| Question | Answer |
| --- | --- |
| Does your app collect or share any required user data types? | No |
| Is all user data encrypted in transit? | Yes (when an HTTPS server is configured) |
| Does your app provide a way for users to request data deletion? | Yes — in-app "Clear all data", plus **[support@your-domain.example]** |
| Does your app contain ads? | No |
| App access | An account is required. The first sign-up on the user's own server creates the owner; no developer credentials exist. Reviewers can run the self-hosted server from the public repository |
| Content rating questionnaire | Utility; no violence, sex, language, gambling, drugs, or user interaction |
| Target audience | 13+ (campus and workplace) |
| Ads declaration | No ads |
| Government app | No |
| Financial features | None |
| Health features | None |
| News app | No |

**Permissions declared:** `INTERNET` only. Release builds block cleartext HTTP; debug builds allow it
for LAN testing. No location, camera, microphone, contacts, SMS, or accessibility permissions.

**Store listing graphics:** 512 × 512 icon (use `build/icon.png`), feature graphic 1024 × 500, at least
two phone screenshots (minimum 320 px, 16:9 or 9:16), plus 7" and 10" tablet screenshots if tablets are
supported (they are).

## Microsoft Store

**Product name:** `CampusShield`
**Category:** Utilities & tools (or Security)
**Age rating:** 3+ / Everyone
**Price:** Free

**Description:**
```
CampusShield gives you one honest safety score across every device you add.

Link computers, phones, tablets, and browsers. Checked devices feed the average; unchecked devices stay visibly "Not checked" instead of guessing, and the weakest device is called out so you know where to start.

Also included:
• An assistant that recommends next steps from stored results and runs a real security test on request
• A phishing link inspector that never opens the link
• A breached-password check that never sends your password
• An optional campus threat queue with an audit trail, connected to your own server
• Accounts created on the server you run — the first sign-up becomes its owner

The read-only device audit runs in the macOS desktop app, which can check disk encryption, firewall, app verification, system integrity, screen lock, guest account, updates, recent installers, and background login items.

The desktop app also scans files on macOS and Windows: SHA-256 signature matching plus heuristics for disguised file types, hidden executables, content mismatches, and risky script patterns. Findings can be quarantined, restored, or deleted. Real-time protection watches quick-scan folders as new files arrive; scheduled quick/full scans, folder exclusions, and one-off custom folder scans are built in. The Windows build adds desktop notifications and a tray icon.

An optional AI assistant can explain a finding or summarize your protection state using an OpenAI-compatible endpoint that you supply, including a local model. The assistant is advisory only and never decides what is malicious.

Mobile builds link into the shared score; they do not scan their own device in this release.

The Windows build checks BitLocker, firewall profiles, Microsoft Defender, UAC, inactivity lock, the Guest account, installed-update age, and startup commands, and links into the shared score. Checks that Windows does not allow without administrator rights are shown as unverified rather than guessed.

Accounts and data stay on your own server. No ads, no analytics, no tracking.

CampusShield is not a full antivirus. Its signature set is small and updated only from a feed you supply, its real-time watch cannot block execution without a signed driver, and it does not filter traffic or scan process memory.
```

**System requirements:** Windows 10 1809 or later, x64/ARM64 (NSIS installer) or MSIX for the Store.

**Store package:** Partner Center requires an MSIX/APPX (or a packaged EXE with a Store association).
Store identity values (`identityName`, `publisher`, `publisherDisplayName`, `applicationId`) come from
Partner Center and must be added to the `build.appx` block in `package.json`. A full-trust packaged
desktop app may run the local server, scan files, and run the read-only Windows posture checks; validate
those checks on real Windows hardware before the listing promises them.

## Screenshot storyboard

Capture these states from a real running build (no invented data):

1. **Assistant home** — a signed-in account with a real score, one recommendation, and the chat box.
2. **Protection home** — a checked device with a Good score and two findings.
3. **Why the score changed** — findings list showing a passed and a failed check with fixes.
4. **Malware scan** — a completed quick scan with one quarantined finding and the score penalty visible.
5. **Devices** — one checked computer, one phone marked "Not checked".
6. **Link inspector** — a high-risk lookalike domain result.
7. **Password check** — a breached result showing a count and the k-anonymity note.
8. **Activity** — device checks, scans, and analyst decisions in one timeline.
9. **Settings → Protection** — real-time toggle, a scheduled scan with its next run, and one excluded folder.
10. **AI explanation** — a finding explained in plain language, with the provider name and the "advisory only" note visible.

Add device frames only if the store allows them; keep text legible at thumbnail size.
