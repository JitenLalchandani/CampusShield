"use strict";

const { execFile } = require("node:child_process");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { promisify } = require("node:util");

const execFileAsync = promisify(execFile);

const RULES_VERSION = "2026.11";
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

  const guestEnabled = guest.ok && guest.stdout.trim() === "1";  checks.push(finding(
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

async function auditHost() {
  if (process.platform === "darwin") {
    return auditMac();
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
      "Device auditing is implemented for macOS hosts. Link this device from the mobile or desktop app for platform-specific checks."
  };
}

module.exports = { auditHost, gradeFor, scoreFindings, RULES_VERSION };
