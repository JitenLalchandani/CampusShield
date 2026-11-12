# CampusShield Terms of Use

**Effective date:** 13 November 2026
**Last updated:** 13 November 2026

These terms govern your use of the CampusShield web app, PWA, macOS desktop app, iOS/iPadOS app,
Android app, and self-hosted server software (together, the "Software"), published by
**[YOUR LEGAL NAME OR COMPANY]** ("we", "us"). By installing or using the Software you agree to these
terms. If you do not agree, do not use the Software.

> **Template notice:** replace the bracketed placeholders and have this document reviewed by a lawyer
> for your jurisdiction before publishing. Stores require a reachable terms (EULA) link.

## 1. What CampusShield is

CampusShield is a **device posture checker, file scanner, and privacy toolbox**. It is not a full
antivirus, endpoint-protection platform, firewall, VPN, or managed detection-and-response service. It:

- reads a limited set of operating-system settings with read-only commands and explains the result;
- scans files on desktop computers against a local signature set and heuristics, and can move a
  finding you select into a quarantine folder;
- can watch a few user folders for new files and scan them as they appear, without blocking execution;
- averages the scores of checked devices into a cross-device safety score;
- inspects links with local heuristics and checks passwords against a public breach corpus using
  k-anonymity;
- optionally displays a campus threat queue fed by an operator's own telemetry.

CampusShield does **not** intercept network traffic, scan process memory, use a kernel extension or
system driver, or prevent compromise. Its signature set is small by design, its heuristics match
specific patterns rather than unknown malware, and the folder watch runs in the user session, so the
operating system does not let it stop a program from running. On iOS and in the Mac App Store build,
the sandbox prevents scanning other apps' files entirely. A high score means the checked settings and
files matched the current rules at the time of the check. It is not a guarantee that a device is
secure, and a low score is not proof of compromise. Do not rely on it as your only safeguard.

## 2. Licence

The Software's source code is released under the MIT License (see [LICENSE](../LICENSE)). Your use of
the compiled apps distributed through an app store is also subject to that store's terms. Nothing in
these terms limits rights you have under the MIT License for the source code.

## 3. Your responsibilities

You agree to:

- use the Software only on devices you own or are authorized to check;
- keep the Software and your operating system updated, and use HTTPS and authentication if you expose a
  CampusShield server beyond localhost;
- treat findings as indicators for review, not as proof of an attack;
- comply with the laws and institutional policies that apply to you.

If you operate a CampusShield server, you are responsible for:

- what you ingest, including ensuring you have a lawful basis to process it;
- access control, TLS, backups, retention, and deletion;
- any privacy notice you give to the people whose data appears in the threat queue;
- not presenting the Software's illustrative detection rules as a validated detection engine.

## 4. Acceptable use

You must not:

- use the Software to access, scan, or monitor devices, accounts, or networks without authorization;
- use it to harass, stalk, discriminate against, or unlawfully profile any person;
- upload malware, unlawful content, or special-category personal data into a threat queue;
- remove or misrepresent proprietary notices, or claim the Software provides protection it does not;
- interfere with the Software's operation or use it to attack a store, service, or network;
- use the breached-password check to test credentials you do not own or are not authorized to assess.

We may suspend distribution or support for anyone violating these terms.

## 5. Third-party services

The Software can contact services we do not control:

- **Pwned Passwords** (`api.pwnedpasswords.com`), operated by Have I Been Pwned, for the optional
  breached-password check. Its availability and terms are outside our control.
- **Apple software-update services**, invoked by macOS during a device check.
- **Your own server or MongoDB Atlas deployment**, if configured by the operator.
- **App stores** that distribute the Software.

We are not responsible for third-party services, their availability, or their data practices.

## 6. No warranty

THE SOFTWARE IS PROVIDED "AS IS" AND "AS AVAILABLE", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, AND
NON-INFRINGEMENT. WE DO NOT WARRANT THAT CHECKS WILL BE COMPLETE, ERROR-FREE, OR AVAILABLE ON EVERY
PLATFORM, OR THAT THE SOFTWARE WILL PREVENT ANY SECURITY INCIDENT.

Some checks may show "Unverified" when the operating system blocks access or a command is unavailable.
That is expected behavior, not a defect. Platform capabilities differ; see the coverage table in the
[README](../README.md).

## 7. Limitation of liability

TO THE MAXIMUM EXTENT PERMITTED BY LAW, WE ARE NOT LIABLE FOR INDIRECT, INCIDENTAL, SPECIAL,
CONSEQUENTIAL, OR PUNITIVE DAMAGES, OR FOR LOSS OF DATA, PROFITS, REVENUE, OR GOODWILL, ARISING FROM
YOUR USE OF OR INABILITY TO USE THE SOFTWARE. WHERE LIABILITY CANNOT BE EXCLUDED, OUR TOTAL LIABILITY
IS LIMITED TO THE AMOUNT YOU PAID FOR THE SOFTWARE IN THE TWELVE MONTHS BEFORE THE CLAIM (OR USD 10 IF
THE SOFTWARE WAS FREE). NOTHING HERE EXCLUDES LIABILITY THAT CANNOT LAWFULLY BE EXCLUDED.

## 8. Updates and changes

We may release updates that change checks, weights, rules, or features. Scores are only comparable
within the same rules version (shown in the app). We may modify these terms; the updated version will
carry a new date. Continued use after an update means you accept the revised terms.

## 9. Termination

You may stop using the Software at any time and delete its data. We may stop distributing or supporting
the Software, or terminate access to any service we operate, if you breach these terms or if required
by law.

## 10. Governing law and disputes

These terms are governed by the laws of **[your jurisdiction]**, without regard to conflict-of-law
rules. Disputes will be brought in the courts of **[your jurisdiction]**, unless mandatory consumer law
in your country gives you another forum.

## 11. Contact

**[YOUR LEGAL NAME OR COMPANY]**
**[support@your-domain.example]**
**[your postal address]**
