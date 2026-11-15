# CampusShield Store Readiness

What is already built, what each store still requires, and the honest limits of each channel. Nothing
here guarantees approval: stores review the app, the listing, and the privacy answers together.

## 1. Status at a glance

| Store | Buildable now | Submission-ready | What is missing |
| --- | --- | --- | --- |
| Apple App Store (iPhone/iPad) | Yes — Capacitor project + 1024 px opaque icon | Almost | Apple Developer account, signing, privacy manifest, screenshots, final URLs |
| Mac App Store | No — current build is not sandboxed | No | A sandboxed build that drops host checks (see §4) |
| Direct macOS download | Yes — DMG (arm64) | After signing | Developer ID certificate, notarization, x64/universal build |
| Google Play | Yes — web assets + Gradle signing config | Almost | Play account, upload key, AAB, store assets, closed test |
| Microsoft Store | Partly — NSIS installer works | No | MSIX/APPX identity config, Partner Center account, signing |
| PWA (no store) | Yes | Yes | Public HTTPS hosting |

Legend: "submission-ready" means the repository contains everything the developer controls. Accounts,
certificates, and public URLs are external prerequisites.

## 2. Identifiers and versions

| Item | Value |
| --- | --- |
| iOS bundle ID | `edu.campusshield.app` |
| Android application ID | `edu.campusshield.app` |
| Electron app ID | `edu.campusshield.desktop` |
| Marketing version | `1.0` / `1.0.0` |
| iOS build number | `1` (`CURRENT_PROJECT_VERSION`) |
| Android version code | `1` |
| Rules version | `2026.11` |

Bump the build number/version code for **every** upload, even when the marketing version is unchanged.
Keep the three platform versions in step to avoid support confusion.

## 3. Apple App Store (iOS / iPadOS)

### Prerequisites

1. Enrol in the Apple Developer Program (US$99/year, includes App Store and Mac App Store distribution).
2. Create the app record in App Store Connect with bundle ID `edu.campusshield.app`.
3. Complete **trader status** for EU distribution (DSA) and tax/banking details (free apps still need
   agreements accepted).
4. Create an Apple Distribution certificate and an App Store provisioning profile, or let Xcode manage
   signing automatically with your team.

### Build and upload

```bash
npm run cap:sync                 # copy public/ into the iOS project
npx cap open ios                 # opens ios/App/App.xcworkspace
```

In Xcode: select the App target → Signing & Capabilities → choose your team, confirm the bundle ID, then
**Product → Archive → Distribute App → App Store Connect → Upload**. Increment the build number first.
Test through TestFlight before submitting.

### Required checks

- **App icon:** `ios/App/App/Assets.xcassets/AppIcon.appiconset/AppIcon-512@2x.png` is 1024 × 1024 with
  **no alpha channel** (already fixed). Do not replace it with a transparent PNG.
- **Privacy manifest:** add `ios/App/App/PrivacyInfo.xcprivacy` to the App target (Copy Bundle
  Resources). Minimal content for this build:

  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
  <plist version="1.0">
  <dict>
    <key>NSPrivacyTracking</key><false/>
    <key>NSPrivacyTrackingDomains</key><array/>
    <key>NSPrivacyCollectedDataTypes</key><array/>
    <key>NSPrivacyAccessedAPITypes</key><array/>
  </dict>
  </plist>
  ```

  Re-check this if you add plugins (filesystem, contacts, analytics) or required-reason APIs.
- **Local Network permission string:** already present in `Info.plist`
  (`NSLocalNetworkUsageDescription`). Keep it accurate — it is only for the user's own server.
- **Encryption:** standard HTTPS only; answer the export-compliance question as using no non-exempt
  encryption. No CCATS/ERN needed.
- **App Privacy:** "Data Not Collected", no tracking (see
  [privacy-policy.md](privacy-policy.md#appendix-a--store-privacy-disclosures)).
- **Screenshots:** 6.9" and 6.5" iPhone plus 13" iPad, or use the current required sizes shown in App
  Store Connect at submission time. See [store-listing.md](store-listing.md).

### Review risks and mitigations

| Guideline | Risk | Mitigation |
| --- | --- | --- |
| 2.5.1 — no scanning other apps/files | Reviewer may think the iOS app scans the device | The iOS build ships without the file scanner and only reads the user's own server; review notes say so explicitly |
| 4.2 — minimum functionality | Native shell around a website can be rejected | App works offline (link/password tools), stores settings locally, and explains cross-device value; be ready to add native device signals after launch |
| 2.3.1 — hidden features | The threat queue is demo-only and empty by default | Empty states explain that a server URL is required; no hidden modes |
| 2.3.7 — accurate metadata | "Antivirus" or "protects your phone" wording | Listing states the desktop build scans files with a small local signature set and that mobile builds cannot scan; the app repeats the limit |
| 5.1.1 — purpose strings | Local Network prompt | String names the exact purpose (connect to your CampusShield server) |
| 4.7 / 5.2 — third-party services | Pwned Passwords dependency | Disclosed in the privacy policy; no account data sent |

If review asks for a demo server, you can run CampusShield locally and give the reviewer a temporary
HTTPS URL, or point them to the empty-state explanation. Never ship test credentials in the binary.

## 4. Mac App Store vs direct download

### The sandbox problem

A Mac App Store app must be sandboxed. A sandboxed app cannot execute `fdesetup`, `spctl`, `csrutil`,
`sysadminctl`, `softwareupdate`, or read `~/Downloads` and `/Library/LaunchDaemons`. That is exactly what
the host audit needs. The current Electron build is **not** sandboxed, so submitting it to the Mac App
Store would fail review.

Choose one:

**Option A — Direct distribution (recommended for the full product).** Ship the current Electron app
from your website, signed with a Developer ID certificate and notarized. This is not store distribution,
but it delivers the full macOS audit and is the normal path for utilities that need system access.

```bash
# After installing a "Developer ID Application" certificate and setting:
# APPLE_ID, APPLE_APP_SPECIFIC_PASSWORD, APPLE_TEAM_ID
npm run dist:mac
xcrun notarytool submit dist/CampusShield-1.0.0-arm64.dmg \
  --apple-id "$APPLE_ID" --password "$APPLE_APP_SPECIFIC_PASSWORD" --team-id "$APPLE_TEAM_ID" --wait
xcrun stapler staple dist/CampusShield-1.0.0-arm64.dmg
spctl --assess --type open --context context:primary-signature -v dist/CampusShield-1.0.0-arm64.dmg
```

Add to the `build.mac` block in `package.json`: `"hardenedRuntime": true`, `"gatekeeperAssess": false`,
`"entitlements": "build/entitlements.mac.plist"`, and `"entitlementsInherit"` with the same file.
Electron needs `com.apple.security.cs.allow-jit` and
`com.apple.security.cs.allow-unsigned-executable-memory`; some builds also need
`com.apple.security.cs.disable-library-validation`. Current builds are **unsigned** and the DMG is
**arm64 only** — add `x64` or `universal` to `build.mac.target.arch` if you want Intel Macs.

**Option B — Mac App Store companion build.** Ship a sandboxed build with entitlements
`com.apple.security.app-sandbox` and `com.apple.security.network.client`, no host audit, and clear
in-app copy such as "Device checks are available in CampusShield for macOS (direct download)." This
requires a build flag to disable `/api/protection/scan` and `/api/scans`; it is **not implemented yet**
and must be done before submitting to the Mac App Store. The sandbox also prevents scanning files
outside the app container, so the scanner must be disabled in that build, not merely hidden.

Do not submit the unsandboxed build and hope for the best; App Review tests sandbox entitlements.

## 5. Google Play

### Prerequisites

1. Create a Google Play developer account (US$25 one-time) and complete identity verification.
2. New **personal** accounts must run a closed test with the required number of testers (currently 12)
   for 14 continuous days before production access. Organisation accounts are exempt from that gate.
3. Create the app, complete the **Data safety** form, **Content rating** questionnaire, **Ads**
   declaration, **App access** declaration, and **Target audience** section.
4. Provide the privacy policy URL and support email.

### Signing

The Gradle config now reads `android/keystore.properties` (ignored by git):

```properties
storeFile=/absolute/path/to/upload-keystore.jks
storePassword=…
keyAlias=upload
keyPassword=…
```

Create an upload keystore once and keep it backed up outside the repository:

```bash
keytool -genkeypair -v -keystore upload-keystore.jks -alias upload \
  -keyalg RSA -keysize 4096 -validity 10000
```

Without that file, `bundleRelease` produces an unsigned bundle — acceptable for local verification only.
Enrol in **Play App Signing** so Google holds the app-signing key and you keep the upload key.

### Build

```bash
npm run cap:sync
cd android
./gradlew bundleRelease          # android/app/build/outputs/bundle/release/app-release.aab
```

Upload the `.aab`, not an APK. Target API 36 is already configured (meets the current requirement;
re-check before every submission). `minSdkVersion` is 24.

### Release behavior

- Release builds set `android:usesCleartextTraffic="false"`; debug builds re-enable it for LAN testing
  (`android/app/src/debug/AndroidManifest.xml`). Production users must point the app at an HTTPS server.
- Only `INTERNET` is declared. No location, camera, microphone, contacts, SMS, or accessibility access.
- No ads, no analytics SDKs, no foreground service.

### Policy risks

| Policy | Risk | Mitigation |
| --- | --- | --- |
| Misrepresentation / deceptive claims | Listing implies full antivirus protection | Copy says desktop scanning uses a small local signature set and a user-space watch; mobile builds cannot scan; app repeats the limit |
| Device and Network Abuse | File scanning might appear to inspect other people's devices | Scanning reads only the host running its own server, with the operator's consent; the watch covers that host's own user folders; no remote device access |
| User Data | Data sent to a self-hosted server | Disclose in privacy policy and data safety; no developer collection |
| Third-party AI | The optional assistant forwards findings to a provider the user chooses | Off by default; user supplies endpoint and key; key stays in local storage; notification permission requested only when notifications are enabled |
| Stalkerware | "Monitor devices" framing | Never market it as monitoring someone else; the queue is analyst triage of approved events |

## 6. Microsoft Store

### Prerequisites

1. Register in Partner Center (individual about US$19, company about US$99 — verify the current fee;
   Microsoft has periodically waived it).
2. Reserve the app name `CampusShield` and copy the **identity values** (`Package/Identity/Name`,
   `Package/Identity/Publisher`, `Package/Properties/DisplayName`, `Application/Application Id`).
3. Complete the age-rating questionnaire (IARC), privacy policy URL, and support contact.

### Packaging gap

`package.json` currently builds only an NSIS installer (`npm run dist:win`), which is not a Store
package. Add an `appx` target and the Partner Center identity values, for example:

```json
"win": { "target": ["nsis", "appx"], "icon": "build/icon.png" },
"appx": {
  "applicationId": "CampusShield",
  "identityName": "<PartnerCenterIdentityName>",
  "publisher": "CN=<PartnerCenterPublisher>",
  "publisherDisplayName": "CampusShield",
  "displayName": "CampusShield",
  "backgroundColor": "#070e1c"
}
```

Then run `npx electron-builder --win appx`. The Store re-signs MSIX packages, so a separate code-signing
certificate is optional for Store-only distribution (still required for a downloadable `.exe`). NSIS
builds are unsigned and will trigger SmartScreen until signed with an OV/EV certificate or Azure Trusted
Signing.

### Feature honesty

The Windows device audit is implemented in `src/deviceAudit.js` (`win32` via read-only PowerShell:
BitLocker, firewall profiles, Defender, UAC, inactivity lock, Guest account, update age, startup
commands). Its data parsing is covered by unit tests, but this build has **not been run end to end on
a Windows machine**. Run a check on real Windows hardware (Home and Pro) before claiming Windows
posture coverage in the listing, and keep the "Unverified" wording when a cmdlet is unavailable.

## 7. What each channel actually delivers

| Capability | iOS/iPadOS | Android | macOS direct | Mac App Store | Windows Store |
| --- | --- | --- | --- | --- | --- |
| Host device check | No | No | Yes | No (sandbox) | Yes (new, not yet run on real Windows hardware) |
| Cross-device score | Linked only | Linked only | Yes | Linked only | Linked only |
| Link inspector | Yes | Yes | Yes | Yes | Yes |
| Breached-password check | Yes | Yes | Yes | Yes | Yes |
| Campus threat queue | With server URL | With server URL | Yes | With server URL | With server URL |
| Works offline | Tools only | Tools only | Yes | Tools only | Yes |

This table belongs in the listing copy and review notes. Overstating coverage is the fastest route to a
rejection or a refund request.

### Flutter client

`flutter_app/` is the cross-platform application UI and is the intended native app on macOS, iOS, and
Android. What is true today:

- The web build is compiled here and served by CampusShield itself at `/app`. CanvasKit is self-hosted
  and the page carries its own CSP; the only third-party request is the Roboto font from Google Fonts.
- The macOS, iOS, and Android runners are committed with the permissions each one needs
  (`network.client` on macOS, `INTERNET` plus debug-only cleartext on Android, `NSAllowsLocalNetworking`
  on iOS). This machine has no Xcode and no Android SDK, so none of those builds has been compiled
  here; a store upload still needs a Mac with Xcode plus a signing team, or the Android SDK and Java.
- The Flutter client delivers the same mobile capabilities as the Capacitor shells: it links into the
  shared score and does not scan the phone's own files.
- `flutter analyze` and `flutter test` pass. `test/shell_test.dart` renders the shell from recorded API
  payloads at desktop and phone widths, which catches layout overflows and API parsing regressions
  without a native toolchain.

The Capacitor projects (`ios/`, `android/`) still wrap the same website. Submit one client per store so
the review matches the build.

## 8. Assets checklist

| Asset | Status |
| --- | --- |
| App icon 1024 × 1024, opaque | Done (`build/icon.png`, iOS app icon) |
| PWA 192/512/maskable icons | Done (`public/icons/`) |
| Launch/splash screens | Capacitor defaults — replace with branded art before launch |
| Store screenshots | **Missing** — capture from a real build; sizes in [store-listing.md](store-listing.md) |
| Feature graphic 1024 × 500 (Play) | **Missing** |
| Privacy policy URL | Template ready, **not hosted** |
| Terms URL | Template ready, **not hosted** |
| Support email / URL | **Placeholder** |
| Review notes | Drafted in [store-listing.md](store-listing.md) |
| Promo video | Optional |

## 9. Release checklist

Copy this into the release issue and tick every line.

**Code**

- [ ] `npm start` serves the app; `/api/health` returns 200.
- [ ] Device check succeeds on a real Mac; score and findings look sane.
- [ ] Link inspector and password check work offline.
- [ ] No console errors on any route at 390 px and 1440 px.
- [ ] `npm run cap:sync` completed after the last web change.
- [ ] Version/build numbers bumped on every platform.
- [ ] `git status` contains no `.env`, keystore, certificate, or `data/` files.

**Apple**

- [ ] Apple Developer Program active; agreements signed.
- [ ] Bundle ID registered; distribution certificate and profile created.
- [ ] Privacy manifest added to the target.
- [ ] Icon has no alpha (verify with `sips -g hasAlpha`).
- [ ] Archive uploaded; TestFlight smoke test passed.
- [ ] App Privacy = Data Not Collected; export compliance answered.
- [ ] Review notes explain that the iOS/Android builds do not scan device files, and that the desktop scanner is a small local signature set plus heuristics, not a full antivirus.
- [ ] EU trader status completed.

**Google**

- [ ] Play account verified; app created; package name matches.
- [ ] Upload keystore created, backed up, and excluded from git.
- [ ] Signed AAB built; internal test install passed.
- [ ] Data safety, content rating, ads, app access, target audience completed.
- [ ] Closed test completed (personal accounts) before production.
- [ ] Release build blocks cleartext traffic; HTTPS server tested.

**Microsoft**

- [ ] Partner Center app reserved; identity values added to `build.appx`.
- [ ] MSIX built and installed from the package.
- [ ] Age rating and privacy policy URL completed.
- [ ] Windows device check run on real Home and Pro hardware before the listing promises posture coverage.

**Direct macOS**

- [ ] Developer ID certificate installed; hardened runtime + entitlements configured.
- [ ] DMG signed, notarized, stapled, and accepted by `spctl`.
- [ ] Universal or x64 build available if Intel support is promised.

## 10. Costs and timing (verify current prices)

| Item | Approximate cost | Typical timing |
| --- | --- | --- |
| Apple Developer Program | US$99/year | 24–48 hours for individual enrolment |
| Google Play developer account | US$25 one-time | 1–3 days verification |
| Microsoft Partner Center | US$19 individual / US$99 company | 1–3 days |
| Windows OV/EV code-signing certificate | US$200–600/year (or Azure Trusted Signing, ~US$10/month) | Days to weeks |
| Apple review | Included | 1–3 days (longer for first submission) |
| Google review | Included | Up to 7 days, plus the closed-test period |
| Microsoft certification | Included | 1–3 days |

Budget several review rounds. First submissions commonly get one metadata or guideline question.

## 11. Known gaps before a public launch

1. **Native phone checks** — iOS DeviceCheck/Keychain posture and Android Play Integrity/settings intents
   would let phones contribute a real score. Until then, mobile is explicit about being "Linked only".
2. **Windows audit validation** — `win32` checks are implemented; verify them on real Home and Pro
   hardware (and add Secure Boot) before advertising Windows protection.
3. **Authentication** — optional shared-secret tokens exist (`CAMPUSSHIELD_API_TOKEN` /
   `CAMPUSSHIELD_VIEW_TOKEN`). Per-user accounts, sessions, and caller audit are still missing and are
   required before a hosted multi-tenant deployment.
4. **Mac App Store variant** — needs a sandboxed build and a feature flag that disables host checks.
5. **Screenshots, feature graphic, hosted legal pages, support inbox** — listing assets only.
6. **Accessibility and localization** — keyboard focus states and a screen-reader pass are worth doing
   before a wide release; only English is shipped.
7. **Detection rules** — the campus queue's rules are illustrative. Validate them against real telemetry
   before calling them a detection engine.

## 12. References

- Apple App Store Review Guidelines: <https://developer.apple.com/app-store/review/guidelines/>
- Apple privacy manifests: <https://developer.apple.com/documentation/bundleresources/privacy_manifest_files>
- Google Play policies: <https://play.google.com/about/developer-content-policy/>
- Google Play data safety: <https://support.google.com/googleplay/android-developer/answer/10787469>
- Microsoft Store policies: <https://learn.microsoft.com/windows/apps/publish/store-policies>
- electron-builder code signing: <https://www.electron.build/code-signing>
