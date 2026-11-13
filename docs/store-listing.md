# CampusShield — Store Listing Copy

Ready-to-paste listing text and questionnaire answers for the Apple App Store, Mac App Store, Google
Play, and Microsoft Store. Replace **[bracketed]** values before submitting.

> **Positioning rule:** CampusShield is a *device posture checker, file scanner, and privacy toolbox*.
> The desktop build scans files with a small local signature set and heuristics; the iOS, Android, and
> Mac App Store builds cannot scan files because their sandboxes forbid it. Every store has policies
> against misleading security claims, so each listing below states exactly what that build does. Keep
> the listing consistent with the app.

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
| Account required | No |
| Languages | English |
| Support email | **[support@your-domain.example]** |
| Privacy policy URL | **[https://your-domain.example/privacy]** |
| Terms URL | **[https://your-domain.example/terms]** |
| Marketing URL | **[https://your-domain.example]** |

## Apple App Store (iPhone / iPad)

**Subtitle (30 characters):** `Cross-device safety score`

**Promotional text (170 characters):**
`See one honest safety score for every device you add, inspect suspicious links, and check passwords without sending them anywhere. No account, no ads, no tracking.`

**Keywords (100 characters):**
`safety,security,privacy,phishing,password,device,score,campus,checker,link,breach,settings`

**Description (iPhone / iPad):**
```
One honest safety score for all your devices.

CampusShield keeps one shared safety score across the computers, phones, tablets, and browsers you add. Checked devices feed the average; unchecked devices stay marked "Not checked" instead of guessing, and the weakest device is called out so you know where to start.

This iPhone and iPad app gives you:

• One score across your linked devices
• A phishing link inspector that never opens the link
• A breached-password check that never sends your password
• An optional campus threat queue, connected to your own server

PHISHING LINK INSPECTOR
Paste a link and get plain-language warnings about plain HTTP, embedded credentials, raw IP hosts, punycode, deep subdomains, shorteners, risky top-level domains, brand impersonation, and one-character lookalikes. All checks run on your device and the link is never opened.

BREACHED-PASSWORD CHECK
See whether a password appears in a public breach corpus. Your password never leaves the device: only the first five characters of a SHA-1 hash are sent, using k-anonymity.

CROSS-DEVICE SCORE
Run CampusShield's read-only device checks on a Mac (desktop app) and link this phone to see one combined score. iPhone and iPad sandboxing prevents an app from scanning the device, so this app links into the score and does not report a phone score of its own.

OPTIONAL CAMPUS THREAT QUEUE
Connect your own CampusShield server to review alerts, record decisions, and keep an audit trail.

PRIVATE BY DEFAULT
No account, no ads, no analytics, no tracking. Results stay on your device or on the server you choose.

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

- No account or demo credentials are required. The app opens to the Protection screen; the link inspector and breached-password check work immediately without a server.
- The iOS build does not scan the device or other apps (Guideline 2.5.1). It links a phone into a cross-device score and provides two client-side privacy tools.
- The optional threat queue needs a CampusShield server URL that the user configures in Settings. No server is operated by the developer, so the queue and score screens show empty states by default.
- Local Network permission is used only to reach the user's own CampusShield server. The password tool sends only a five-character SHA-1 prefix to api.pwnedpasswords.com; the link inspector never opens links.
- No tracking, ads, analytics, or account creation.
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
• A phishing link inspector that never opens the link
• A breached-password check that never sends your password
• An optional campus threat queue, connected to your own server

All checks run on your Mac. No account, no ads, no analytics, no tracking. Results stay on your device or on the server you choose.

This sandboxed App Store build cannot read system security settings or scan files, so device checks
and malware scans show "Not available in this build". The full read-only device audit and file scanner
are available in the direct-download version of CampusShield for macOS.

CampusShield is not a full antivirus. It does not filter traffic, scan process memory, or block
execution with a kernel extension.
```

For the **direct-download Mac app** (not a store listing), use the Google Play feature list below and add
this section near the top:

```
READ-ONLY DEVICE CHECKS
FileVault, firewall, Gatekeeper, System Integrity Protection, screen lock, guest account, automatic updates, pending updates, recent installers, and background login items. Every finding includes the reason and the fix. No administrator rights, no drivers, no background monitoring.

MALWARE SCAN AND QUARANTINE
Scan Downloads, Desktop, Documents, and launch agents (quick), or your whole home folder plus app and launch folders (full). Matches SHA-256 signatures, double extensions, hidden executables, content/extension mismatches, and script patterns such as download-and-execute, encoded PowerShell, reverse shells, and security-tampering commands. Quarantine, restore, or permanently delete each finding. Quarantined and deleted files stop counting against the score.

REAL-TIME FOLDER WATCH
Optional user-space watch scans new files as they land in your quick-scan folders. It reports and can quarantine; macOS does not let a user-space app block execution without an Endpoint Security entitlement.
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
• Phishing link inspector that never opens the link
• Breached-password check using k-anonymity — your password never leaves the device
• Optional campus threat queue with an audit trail, connected to your own server
• No account, no ads, no analytics, no tracking

PHISHING LINK INSPECTOR
Paste a link and get plain-language warnings about plain HTTP, embedded credentials, raw IP hosts, punycode, deep subdomains, shorteners, risky top-level domains, brand impersonation, and one-character lookalikes. All checks run on your device and the link is never opened.

BREACHED-PASSWORD CHECK
See whether a password appears in a public breach corpus. Only the first five characters of a SHA-1 hash are sent, using k-anonymity; the password and full hash stay on your device.

CROSS-DEVICE SCORE
Run CampusShield's read-only device checks or a file scan on a Mac or Windows computer (desktop app) and link this phone to see one combined score. Android sandboxing prevents this app from scanning the phone's own files in this release, so the Android app links into the score and does not report a phone score of its own.

Start the CampusShield server on a computer you control and enter its URL in Settings to use the queue. Results stay on your device or on the server you choose.

CampusShield is not a full antivirus. The desktop app scans files with a small local signature set and heuristics; it does not filter traffic, scan process memory, or block execution with a kernel driver. A high score reflects the settings checked at that moment, not a guarantee.
```

**Data safety:**
| Question | Answer |
| --- | --- |
| Does your app collect or share any required user data types? | No |
| Is all user data encrypted in transit? | Yes (when an HTTPS server is configured) |
| Does your app provide a way for users to request data deletion? | Yes — in-app "Clear all data", plus **[support@your-domain.example]** |
| Does your app contain ads? | No |
| App access | All functionality is available without special access; the optional queue shows an empty state until a server URL is configured |
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
• A phishing link inspector that never opens the link
• A breached-password check that never sends your password
• An optional campus threat queue with an audit trail, connected to your own server

The read-only device audit runs in the macOS desktop app, which can check disk encryption, firewall, app verification, system integrity, screen lock, guest account, updates, recent installers, and background login items.

The desktop app also scans files on macOS and Windows: SHA-256 signature matching plus heuristics for disguised file types, hidden executables, content mismatches, and risky script patterns. Findings can be quarantined, restored, or deleted, and an optional user-space folder watch scans new files as they arrive. Mobile builds link into the shared score; they do not scan their own device in this release.

The Windows build checks BitLocker, firewall profiles, Microsoft Defender, UAC, inactivity lock, the Guest account, installed-update age, and startup commands, and links into the shared score. Checks that Windows does not allow without administrator rights are shown as unverified rather than guessed.

No account. No ads. No analytics. Data stays on your device.

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

1. **Protection home** — a checked device with a Good score and two findings.
2. **Why the score changed** — findings list showing a passed and a failed check with fixes.
3. **Malware scan** — a completed quick scan with one quarantined finding and the score penalty visible.
4. **Devices** — one checked computer, one phone marked "Not checked".
5. **Link inspector** — a high-risk lookalike domain result.
6. **Password check** — a breached result showing a count and the k-anonymity note.
7. **Activity** — device checks, scans, and analyst decisions in one timeline.

Add device frames only if the store allows them; keep text legible at thumbnail size.
