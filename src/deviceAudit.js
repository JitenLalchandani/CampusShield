"use strict";

const { execFile } = require("node:child_process");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { promisify } = require("node:util");

const execFileAsync = promisify(execFile);

// 2026.12 added the ransomware-shield posture check; 2026.13 added usb-autoscan; 2026.14 adds web-protection. Older scores are not comparable.
const RULES_VERSION = "2026.14";
const WEIGHT = { critical: 30, high: 18, medium: 10, low: 4, info: 0 };

async function run(command, args = [], timeout = 8000) {
  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      timeout,
      maxBuffer: 2 * 1024 * 1024
    });
    return { ok: true, stdout: String(stdout || ""), stderr: String(stderr || "") };
  } catch (error) {
    return {
      ok: false,
      stdout: String(error.stdout || ""),
      stderr: String(error.stderr || ""),
      message: error.message
    };
  }
}

function finding(id, title, status, severity, detail, recommendation) {
  return { id, title, status, severity, detail, recommendation };
}

function gradeFor(score) {
  if (score == null) return "Not checked";
  if (score >= 95) return "Protected";
  if (score >= 80) return "Good";
  if (score >= 60) return "Needs attention";
  return "At risk";
}

function scoreFindings(checks) {
  let score = 100;

  for (const check of checks) {
    if (check.status === "pass" || check.status === "info" || check.status === "unknown") {
      continue;
    }
    score -= WEIGHT[check.severity] ?? 0;
  }

  score = Math.max(0, Math.min(100, score));

  return {
    score,
    grade: gradeFor(score),
    passed: checks.filter(check => check.status === "pass").length,
    attention: checks.filter(
      check => check.status === "fail" || check.status === "warn"
    ).length,
    unverified: checks.filter(check => check.status === "unknown").length
  };
}

function deviceModelLabel(model) {
  const value = String(model || "");
  const map = [
    ["MacBookPro", "MacBook Pro"],
    ["MacBookAir", "MacBook Air"],
    ["MacBook", "MacBook"],
    ["Macmini", "Mac mini"],
    ["MacStudio", "Mac Studio"],
    ["MacPro", "Mac Pro"],
    ["iMac", "iMac"]
  ];
  const match = map.find(([prefix]) => value.startsWith(prefix));
  return match ? match[1] : "Mac";
}

function parseRecommendedUpdates(output) {
  if (/No new software available/i.test(output)) {
    return { ok: true, labels: [] };
  }

  const labels = [];
  const blocks = output.split(/\n(?=\* Label:)/);

  for (const block of blocks) {
    if (!block.includes("Recommended: YES")) continue;
    const label = block.match(/\* Label:\s*([^\n]+)/i)?.[1]?.trim();
    const title = block.match(/Title:\s*([^,\n]+)/i)?.[1]?.trim();
    if (label || title) labels.push(title || label);
  }

  if (labels.length === 0 && /Software Update found the following/i.test(output)) {
    return { ok: true, labels: [] };
  }

  return { ok: true, labels };
}

async function riskyDownloads() {
  const dir = path.join(os.homedir(), "Downloads");
  const risky = new Set([
    ".app", ".pkg", ".dmg", ".command", ".sh", ".jar", ".exe", ".msi", ".scr", ".vbs"
  ]);
  const found = [];
  const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1000;

  try {
    const entries = await fs.readdir(dir, { withFileTypes: true });

    for (const entry of entries) {
      if (found.length >= 8) break;
      const ext = path.extname(entry.name).toLowerCase();
      if (!risky.has(ext)) continue;

      try {
        const stat = await fs.stat(path.join(dir, entry.name));
        if (stat.mtimeMs >= cutoff) found.push(entry.name);
      } catch {
        /* skip unreadable entries */
      }
    }
  } catch {
    return { available: false, found: [] };
  }

  return { available: true, found };
}

async function thirdPartyLoginItems() {
  const dirs = [
    path.join(os.homedir(), "Library", "LaunchAgents"),
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons"
  ];
  const names = [];

  for (const dir of dirs) {
    try {
      const entries = await fs.readdir(dir);
      for (const entry of entries) {
        if (!entry.endsWith(".plist")) continue;
        if (entry.startsWith("com.apple.")) continue;
        if (!names.includes(entry)) names.push(entry);
      }
    } catch {
      /* directory may not exist */
    }
  }

  return names;
}

async function auditMac() {
  const [
    version,
    model,
    filevault,
    firewall,
    gatekeeper,
    sip,
    screenLock,
    guest,
    autoCheck,
    updates,
    downloads,
    loginItems
  ] = await Promise.all([
    run("/usr/bin/sw_vers"),
    run("/usr/sbin/sysctl", ["-n", "hw.model"]),
    run("/usr/bin/fdesetup", ["status"]),
    run("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"]),
    run("/usr/sbin/spctl", ["--status"]),
    run("/usr/bin/csrutil", ["status"]),
    run("/usr/sbin/sysadminctl", ["-screenLock", "status"]),
    run("/usr/bin/defaults", [
      "read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"
    ]),
    run("/usr/bin/defaults", [
      "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"
    ]),
    run("/usr/bin/softwareupdate", ["--list", "--no-scan"], 20000),
    riskyDownloads(),
    thirdPartyLoginItems()
  ]);

  const checks = [];
  const versionText = version.ok
    ? `${version.stdout.match(/ProductVersion:\s*(\S+)/)?.[1] || ""}`
    : "";

  const filevaultOn = /FileVault is On/i.test(filevault.stdout);
  checks.push(finding(
    "disk-encryption",
    "Disk encryption",
    filevaultOn ? "pass" : "fail",
    filevaultOn ? "info" : "high",
    filevaultOn
      ? "FileVault protects data if the Mac is lost or stolen."
      : "FileVault is off, so files are readable if the disk is removed.",
    filevaultOn
      ? "No action needed."
      : "Turn on FileVault in System Settings → Privacy & Security."
  ));

  const firewallOn = /enabled/i.test(firewall.stdout) && !/disabled/i.test(firewall.stdout);
  checks.push(finding(
    "firewall",
    "Application firewall",
    firewallOn ? "pass" : "fail",
    firewallOn ? "info" : "medium",
    firewallOn
      ? "The macOS application firewall is enabled."
      : "The macOS application firewall is disabled.",
    firewallOn
      ? "No action needed."
      : "Enable the firewall in System Settings → Network → Firewall."
  ));

  const gatekeeperOn = /assessments enabled/i.test(gatekeeper.stdout);
  checks.push(finding(
    "gatekeeper",
    "App verification (Gatekeeper)",
    gatekeeperOn ? "pass" : "fail",
    gatekeeperOn ? "info" : "high",
    gatekeeperOn
      ? "Apps are checked before they are allowed to run."
      : "App verification is disabled, so unsigned apps can run without review.",
    gatekeeperOn
      ? "No action needed."
      : "Re-enable Gatekeeper with: sudo spctl --global-enable"
  ));

  const sipOn = /status:\s*enabled/i.test(sip.stdout);
  checks.push(finding(
    "sip",
    "System Integrity Protection",
    sipOn ? "pass" : "fail",
    sipOn ? "info" : "high",
    sipOn
      ? "SIP is protecting system files and processes."
      : "SIP is disabled, which weakens system-level protections.",
    sipOn
      ? "No action needed."
      : "Re-enable SIP from macOS Recovery before trusting this device."
  ));

  let screenLockStatus = "unknown";
  let screenLockSeverity = "info";
  let screenLockDetail = "Screen-lock status could not be read.";

  if (screenLock.ok) {
    const output = `${screenLock.stdout}\n${screenLock.stderr}`.toLowerCase();
    if (output.includes("immediate")) {
      screenLockStatus = "pass";
      screenLockDetail = "The screen locks immediately when the Mac sleeps.";
    } else if (output.includes("off")) {
      screenLockStatus = "fail";
      screenLockSeverity = "medium";
      screenLockDetail = "A password is not required after sleep.";
    } else {
      const delay = Number.parseInt(output.match(/delay is (\d+)/)?.[1] || "", 10);
      if (Number.isFinite(delay)) {
        screenLockStatus = delay <= 60 ? "pass" : "warn";
        screenLockSeverity = delay <= 60 ? "info" : "low";
        screenLockDetail = `The screen locks after ${delay} seconds.`;
      }
    }
  }

  checks.push(finding(
    "screen-lock",
    "Screen lock",
    screenLockStatus,
    screenLockSeverity,
    screenLockDetail,
    screenLockStatus === "pass"
      ? "No action needed."
      : "Require a password immediately after sleep in System Settings → Lock Screen."
  ));

  const guestEnabled = guest.ok && guest.stdout.trim() === "1";
  checks.push(finding(
    "guest-account",
    "Guest account",
    guest.ok ? (guestEnabled ? "fail" : "pass") : "unknown",
    guestEnabled ? "medium" : "info",
    !guest.ok
      ? "Guest-account status could not be read."
      : guestEnabled
        ? "A guest account can sign in without a personal password."
        : "The guest account is disabled.",
    guestEnabled
      ? "Disable the guest account in System Settings → Users & Groups."
      : "No action needed."
  ));

  const autoUpdatesOn = autoCheck.ok && autoCheck.stdout.trim() === "1";
  checks.push(finding(
    "auto-updates",
    "Automatic update checks",
    autoCheck.ok ? (autoUpdatesOn ? "pass" : "warn") : "unknown",
    autoUpdatesOn ? "info" : "low",
    !autoCheck.ok
      ? "Automatic update settings could not be read."
      : autoUpdatesOn
        ? "macOS checks for updates automatically."
        : "macOS is not set to check for updates automatically.",
    autoUpdatesOn
      ? "No action needed."
      : "Enable automatic updates in System Settings → General → Software Update."
  ));

  const pending = parseRecommendedUpdates(updates.stdout);
  const pendingCount = pending.labels.length;
  checks.push(finding(
    "os-updates",
    "macOS updates",
    !updates.ok && pendingCount === 0
      ? "unknown"
      : pendingCount > 0
        ? "fail"
        : "pass",
    pendingCount > 0 ? "medium" : "info",
    !updates.ok && pendingCount === 0
      ? "Update status could not be verified in this environment."
      : pendingCount > 0
        ? `${pendingCount} recommended update${pendingCount === 1 ? "" : "s"} available: ${pending.labels.slice(0, 3).join(", ")}.`
        : "No recommended macOS updates are waiting.",
    pendingCount > 0
      ? "Install updates from System Settings → General → Software Update, then restart."
      : "No action needed."
  ));

  checks.push(finding(
    "downloads",
    "Recent installers and scripts",
    !downloads.available ? "unknown" : downloads.found.length ? "info" : "pass",
    "info",
    !downloads.available
      ? "The Downloads folder could not be read."
      : downloads.found.length
        ? `${downloads.found.length} recent installer or script file${downloads.found.length === 1 ? "" : "s"} in Downloads: ${downloads.found.slice(0, 4).join(", ")}.`
        : "No recent installer or script files in Downloads.",
    downloads.found.length
      ? "Confirm you expected these files before opening them."
      : "No action needed."
  ));

  checks.push(finding(
    "login-items",
    "Background login items",
    "info",
    "info",
    loginItems.length
      ? `${loginItems.length} third-party background item${loginItems.length === 1 ? "" : "s"} registered.`
      : "No third-party background login items were found.",
    loginItems.length
      ? "Review login items in System Settings → General → Login Items."
      : "No action needed."
  ));

  const summary = scoreFindings(checks);
  const hostname = os.hostname().replace(/\.local$/i, "");

  return {
    supported: true,
    platform: "darwin",
    platformLabel: versionText ? `macOS ${versionText}` : "macOS",
    hostname,
    model: deviceModelLabel(model.stdout.trim()),
    checkedAt: new Date().toISOString(),
    rulesVersion: RULES_VERSION,
    checks,
    ...summary
  };
}

function parseJson(output) {
  const text = String(output || "").trim();
  if (!text) return null;

  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function asArray(value) {
  if (value == null) return [];
  return Array.isArray(value) ? value : [value];
}

function parseBitLocker(output) {
  const data = parseJson(output);
  if (!data) return { known: false };

  const protection = Number(data.ProtectionStatus);
  const status = String(data.VolumeStatus || "");

  return {
    known: true,
    on: protection === 1 || /FullyEncrypted/i.test(status)
  };
}

function parseFirewallProfiles(output) {
  const profiles = asArray(parseJson(output));

  if (!profiles.length) return { known: false };

  return {
    known: true,
    on: profiles.every(profile => profile?.Enabled === true),
    names: profiles.filter(profile => profile?.Enabled === true).length,
    total: profiles.length
  };
}

function parseDefenderStatus(output) {
  const data = parseJson(output);
  if (!data) return { known: false };

  return {
    known: true,
    realtime: data.RealTimeProtectionEnabled === true,
    enabled: data.AntivirusEnabled !== false,
    signatureAge: Number.isFinite(Number(data.AntivirusSignatureAge))
      ? Number(data.AntivirusSignatureAge)
      : null
  };
}

function parseHotFix(output) {
  const data = parseJson(output);
  if (!data?.HotFixID) return { known: false };

  const installedOn = String(data.InstalledOn || "");
  const date = /^\d{4}-\d{2}-\d{2}$/.test(installedOn) ? new Date(`${installedOn}T00:00:00Z`) : null;

  return {
    known: true,
    id: String(data.HotFixID),
    installedOn: date && !Number.isNaN(date.getTime()) ? date : null
  };
}

function parseWindowsCaption(output) {
  const data = parseJson(output);
  const caption = String(data?.Caption || "").trim();

  if (!caption) return "";

  return caption.replace(/^Microsoft\s+/i, "").replace(/\s+Insider Preview$/i, "");
}

function powershell(command, timeout = 15000) {
  return run(
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command],
    timeout
  );
}

async function auditWindows() {
  const [
    osInfo,
    modelInfo,
    bitlocker,
    firewall,
    defender,
    uac,
    lockTimeout,
    guest,
    hotfix,
    startup,
    downloads
  ] = await Promise.all([
    powershell("Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version | ConvertTo-Json -Compress"),
    powershell("Get-CimInstance Win32_ComputerSystem | Select-Object Model | ConvertTo-Json -Compress"),
    powershell("Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop | Select-Object VolumeStatus,ProtectionStatus | ConvertTo-Json -Compress"),
    powershell("Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name,Enabled | ConvertTo-Json -Compress"),
    powershell("Get-MpComputerStatus -ErrorAction Stop | Select-Object RealTimeProtectionEnabled,AntivirusEnabled,AntivirusSignatureAge | ConvertTo-Json -Compress"),
    powershell("Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -ErrorAction Stop | Select-Object EnableLUA | ConvertTo-Json -Compress"),
    powershell("$p='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'; (Get-ItemProperty $p -Name InactivityTimeoutSecs -ErrorAction SilentlyContinue).InactivityTimeoutSecs"),
    powershell("Get-LocalUser -Name Guest -ErrorAction Stop | Select-Object Enabled | ConvertTo-Json -Compress"),
    powershell("$h = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 HotFixID, @{n='InstalledOn';e={$_.InstalledOn.ToString('yyyy-MM-dd')}}; $h | ConvertTo-Json -Compress", 25000),
    powershell("Get-CimInstance Win32_StartupCommand -ErrorAction Stop | Select-Object Name | ConvertTo-Json -Compress"),
    riskyDownloads()
  ]);

  const checks = [];
  const caption = parseWindowsCaption(osInfo.stdout);

  const bitlockerState = bitlocker.ok ? parseBitLocker(bitlocker.stdout) : { known: false };
  checks.push(finding(
    "disk-encryption",
    "Disk encryption",
    !bitlockerState.known ? "unknown" : bitlockerState.on ? "pass" : "fail",
    bitlockerState.known && !bitlockerState.on ? "high" : "info",
    !bitlockerState.known
      ? "BitLocker status could not be read. Windows Home editions may not support BitLocker."
      : bitlockerState.on
        ? "BitLocker protects the system drive if the device is lost or stolen."
        : "BitLocker is not protecting the system drive, so data is readable if the disk is removed.",
    bitlockerState.known && !bitlockerState.on
      ? "Turn on BitLocker for the system drive in Settings → Privacy & security → Device encryption."
      : "No action needed."
  ));

  const firewallState = firewall.ok ? parseFirewallProfiles(firewall.stdout) : { known: false };
  checks.push(finding(
    "firewall",
    "Windows firewall",
    !firewallState.known ? "unknown" : firewallState.on ? "pass" : "fail",
    firewallState.known && !firewallState.on ? "medium" : "info",
    !firewallState.known
      ? "Firewall profile status could not be read."
      : firewallState.on
        ? `All ${firewallState.total} firewall profiles are enabled.`
        : `${firewallState.names} of ${firewallState.total} firewall profiles are enabled.`,
    firewallState.known && !firewallState.on
      ? "Enable every profile in Windows Security → Firewall & network protection."
      : "No action needed."
  ));

  const defenderState = defender.ok ? parseDefenderStatus(defender.stdout) : { known: false };
  let defenderStatus = "unknown";
  let defenderSeverity = "info";
  let defenderDetail = "Microsoft Defender status could not be read. Another antivirus may be managing protection.";

  if (defenderState.known) {
    if (!defenderState.realtime) {
      defenderStatus = "fail";
      defenderSeverity = "high";
      defenderDetail = "Real-time protection is off, so new malware can run unchecked.";
    } else if (defenderState.signatureAge != null && defenderState.signatureAge > 7) {
      defenderStatus = "warn";
      defenderSeverity = "low";
      defenderDetail = `Real-time protection is on, but virus definitions are ${defenderState.signatureAge} days old.`;
    } else {
      defenderStatus = "pass";
      defenderDetail = "Real-time protection is on and virus definitions are current.";
    }
  }

  checks.push(finding(
    "antivirus",
    "Microsoft Defender",
    defenderStatus,
    defenderSeverity,
    defenderDetail,
    defenderStatus === "pass"
      ? "No action needed."
      : "Open Windows Security → Virus & threat protection and turn on real-time protection."
  ));

  const uacData = uac.ok ? parseJson(uac.stdout) : null;
  const uacOn = uacData ? Number(uacData.EnableLUA) === 1 : null;
  checks.push(finding(
    "uac",
    "User Account Control",
    uacOn == null ? "unknown" : uacOn ? "pass" : "fail",
    uacOn === false ? "medium" : "info",
    uacOn == null
      ? "User Account Control status could not be read."
      : uacOn
        ? "User Account Control prompts before administrative changes."
        : "User Account Control is disabled, so apps can elevate without a prompt.",
    uacOn === false
      ? "Enable UAC in Control Panel → User Accounts → Change User Account Control settings."
      : "No action needed."
  ));

  const lockSeconds = Number.parseInt(String(lockTimeout.stdout || "").trim(), 10);
  const lockSet = lockTimeout.ok && Number.isFinite(lockSeconds) && lockSeconds > 0;
  checks.push(finding(
    "screen-lock",
    "Screen lock",
    lockSet ? (lockSeconds <= 900 ? "pass" : "warn") : "unknown",
    lockSet && lockSeconds > 900 ? "low" : "info",
    !lockSet
      ? "No machine inactivity lock is configured. Per-user lock settings are not readable without administrator rights."
      : `The machine locks after ${lockSeconds} seconds of inactivity.`,
    lockSet && lockSeconds <= 900
      ? "No action needed."
      : "Configure a machine inactivity limit of 15 minutes or less in Local Security Policy."
  ));

  const guestData = guest.ok ? parseJson(guest.stdout) : null;
  const guestEnabled = guestData ? guestData.Enabled === true : null;
  checks.push(finding(
    "guest-account",
    "Guest account",
    guestEnabled == null ? "unknown" : guestEnabled ? "fail" : "pass",
    guestEnabled ? "medium" : "info",
    guestEnabled == null
      ? "Guest-account status could not be read."
      : guestEnabled
        ? "The built-in Guest account is enabled and can sign in without a personal password."
        : "The built-in Guest account is disabled.",
    guestEnabled
      ? "Disable the Guest account in Computer Management → Local Users and Groups."
      : "No action needed."
  ));

  const hotfixState = hotfix.ok ? parseHotFix(hotfix.stdout) : { known: false };
  const hotfixDays = hotfixState.installedOn
    ? Math.floor((Date.now() - hotfixState.installedOn.getTime()) / 86400000)
    : null;
  checks.push(finding(
    "os-updates",
    "Windows updates",
    !hotfixState.known
      ? "unknown"
      : hotfixDays != null && hotfixDays > 60
        ? "warn"
        : "pass",
    hotfixDays != null && hotfixDays > 60 ? "medium" : "info",
    !hotfixState.known
      ? "Installed-update history could not be read."
      : hotfixDays != null && hotfixDays > 60
        ? `The most recent installed update is ${hotfixDays} days old (${hotfixState.id}).`
        : `The most recent installed update is ${hotfixState.id}${hotfixDays != null ? ` (${hotfixDays} days ago)` : ""}.`,
    hotfixDays != null && hotfixDays > 60
      ? "Check Windows Update for pending quality and security updates, then restart."
      : "No action needed."
  ));

  const startupItems = startup.ok ? asArray(parseJson(startup.stdout)).filter(item => item?.Name) : [];
  checks.push(finding(
    "login-items",
    "Background startup items",
    "info",
    "info",
    startupItems.length
      ? `${startupItems.length} startup command${startupItems.length === 1 ? "" : "s"} registered.`
      : "No startup commands were read.",
    startupItems.length
      ? "Review startup apps in Task Manager → Startup apps."
      : "No action needed."
  ));

  checks.push(finding(
    "downloads",
    "Recent installers and scripts",
    !downloads.available ? "unknown" : downloads.found.length ? "info" : "pass",
    "info",
    !downloads.available
      ? "The Downloads folder could not be read."
      : downloads.found.length
        ? `${downloads.found.length} recent installer or script file${downloads.found.length === 1 ? "" : "s"} in Downloads: ${downloads.found.slice(0, 4).join(", ")}.`
        : "No recent installer or script files in Downloads.",
    downloads.found.length
      ? "Confirm you expected these files before opening them."
      : "No action needed."
  ));

  const model = parseJson(modelInfo.stdout)?.Model;
  const summary = scoreFindings(checks);

  return {
    supported: true,
    platform: "win32",
    platformLabel: caption || "Windows",
    hostname: os.hostname().replace(/\.local$/i, ""),
    model: model ? String(model).slice(0, 80) : "Windows PC",
    checkedAt: new Date().toISOString(),
    rulesVersion: RULES_VERSION,
    checks,
    ...summary
  };
}

async function auditHost() {
  if (process.platform === "darwin") {
    return auditMac();
  }

  if (process.platform === "win32") {
    return auditWindows();
  }

  return {
    supported: false,
    platform: process.platform,
    platformLabel: process.platform,
    hostname: os.hostname().replace(/\.local$/i, ""),
    model: "",
    checkedAt: new Date().toISOString(),
    rulesVersion: RULES_VERSION,
    checks: [],
    score: null,
    grade: "Not available",
    passed: 0,
    attention: 0,
    unverified: 0,
    message:
      "Device auditing is implemented for macOS and Windows hosts. Linux checks need command mappings that are not built yet."
  };
}

module.exports = {
  auditHost,
  gradeFor,
  scoreFindings,
  parseBitLocker,
  parseFirewallProfiles,
  parseDefenderStatus,
  parseHotFix,
  parseWindowsCaption,
  RULES_VERSION
};
