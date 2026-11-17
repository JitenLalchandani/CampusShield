"use strict";

const MAX_OPEN_THREATS = 20;
const MAX_RECOMMENDATIONS = 6;

function clip(value, max) {
  return String(value == null ? "" : value).slice(0, max);
}

function scanLite(scan) {
  return {
    id: scan.id,
    scope: scan.scope,
    status: scan.status,
    startedAt: scan.startedAt || null,
    finishedAt: scan.finishedAt || null,
    filesScanned: Number(scan.filesScanned) || 0,
    threatCount: Number(scan.threatCount) || 0,
    skipped: Number(scan.skipped) || 0,
    truncated: Boolean(scan.truncated),
    errors: (scan.errors || []).slice(0, 3).map(error =>
      clip(error.message ? `${error.message} [${error.path || ""}]` : error.path || error, 200)
    ),
    signatureVersion: scan.signatureVersion || null
  };
}

function daysSince(iso) {
  const time = Date.parse(iso || "");
  if (!Number.isFinite(time)) return null;
  return (Date.now() - time) / (24 * 60 * 60 * 1000);
}

// Turns stored records into the exact facts the assistant is allowed to use.
// Nothing here is generated or estimated; missing data stays null.
function describeState({ devices = [], status = {}, scans = [], quarantine = [], platform = null, protection = null } = {}) {
  const openThreats = [];

  for (const scan of scans) {
    for (const threat of scan.threats || []) {
      if (threat.status !== "detected") continue;

      openThreats.push({
        scanId: scan.id,
        threatId: threat.id,
        name: clip(threat.name || "unknown file", 200),
        severity: clip(threat.severity || "UNKNOWN", 20),
        reasons: (threat.reasons || []).slice(0, 4).map(reason => clip(reason, 240)),
        filePath: clip(threat.filePath || "", 400),
        detectedAt: threat.detectedAt || null
      });

      if (openThreats.length >= MAX_OPEN_THREATS) break;
    }
    if (openThreats.length >= MAX_OPEN_THREATS) break;
  }

  const host = devices.find(device => device.id === "local-host") || devices[0] || null;
  const checks = Array.isArray(host?.checks) ? host.checks : [];
  const attentionChecks = checks
    .filter(check => check.status === "fail" || check.status === "warn")
    .map(check => ({
      id: check.id,
      title: clip(check.title, 120),
      severity: clip(check.severity, 20),
      detail: clip(check.detail, 300),
      recommendation: clip(check.recommendation, 300)
    }));

  const fileScans = scans.filter(scan => ["quick", "full", "custom"].includes(scan.scope));
  const lastScan = fileScans[0] || null;
  const preferences = status.preferences || {};

  return {
    generatedAt: new Date().toISOString(),
    platform,
    protection: protection || null,
    host: host
      ? {
          name: clip(host.name, 80),
          platform: host.platformLabel || null,
          score: Number.isFinite(host.score) ? host.score : null,
          grade: host.grade || null,
          checkedAt: host.checkedAt || null,
          summary: host.summary || null
        }
      : null,
    devices: devices.map(device => ({
      name: clip(device.name, 80),
      platform: device.platformLabel || null,
      kind: device.kind || null,
      score: Number.isFinite(device.score) ? device.score : null,
      grade: device.grade || null,
      source: device.source || null
    })),
    attentionChecks,
    scanner: {
      signatureVersion: status.signatureVersion || null,
      signatureCount: Number(status.signatureCount) || 0,
      realtime: Boolean(status.watch?.enabled),
      watchSupported: Boolean(status.watchSupported),
      scheduleEnabled: Boolean(preferences.schedule?.enabled),
      schedule: preferences.schedule
        ? {
            scope: preferences.schedule.scope,
            frequency: preferences.schedule.frequency,
            time: preferences.schedule.time,
            lastRunAt: preferences.schedule.lastRunAt || null
          }
        : null,
      exclusions: Array.isArray(preferences.exclusions) ? preferences.exclusions.length : 0,
      remoteFeed: Boolean(status.remoteFeed?.url),
      signatureWarnings: (status.signatureWarnings || []).slice(0, 3).map(warning => clip(warning, 200)),
      activeScan: status.active
        ? { id: status.active.id, scope: status.active.scope, filesScanned: status.active.filesScanned }
        : null
    },
    scans: scans.slice(0, 5).map(scanLite),
    lastScan: lastScan ? scanLite(lastScan) : null,
    lastScanAgeDays: lastScan ? daysSince(lastScan.finishedAt || lastScan.startedAt) : null,
    openThreats,
    quarantine: {
      count: quarantine.length,
      items: quarantine.slice(0, 5).map(item => ({
        name: clip(item.name, 200),
        severity: clip(item.severity, 20),
        quarantinedAt: item.quarantinedAt || null
      }))
    }
  };
}

// Every recommendation is derived from a stored fact. Order is by severity.
function recommendationsFor(state) {
  const recs = [];

  for (const threat of state.openThreats.slice(0, 3)) {
    recs.push({
      id: `threat-${threat.threatId}`,
      title: `Quarantine ${threat.name}`,
      detail:
        `The scanner flagged this ${threat.severity.toLowerCase()} risk` +
        (threat.reasons.length ? `: ${threat.reasons.join("; ")}` : "."),
      severity: threat.severity,
      action: { kind: "quarantine-threat", scanId: threat.scanId, threatId: threat.threatId }
    });
  }

  if (!state.host || !Number.isFinite(state.host.score)) {
    recs.push({
      id: "device-check",
      title: "Run a device check",
      detail: "No posture score exists yet. The check is read-only and reports settings as found.",
      severity: "info",
      action: { kind: "run-check" }
    });
  }

  for (const check of state.attentionChecks.slice(0, 3)) {
    recs.push({
      id: `check-${check.id}`,
      title: check.title || "Device setting needs attention",
      detail: check.recommendation || check.detail || "Review this setting on the device.",
      severity: check.severity === "critical" || check.severity === "high" ? "HIGH" : "MEDIUM",
      action: { kind: "open-protection", checkId: check.id }
    });
  }

  if (!state.scanner.realtime && state.scanner.watchSupported) {
    recs.push({
      id: "enable-watch",
      title: "Turn on real-time folder watching",
      detail: "Detections in Downloads, Desktop, and Documents are recorded as they appear.",
      severity: "info",
      action: { kind: "enable-watch" }
    });
  }

  if (!state.scanner.scheduleEnabled) {
    recs.push({
      id: "schedule-scan",
      title: "Schedule a regular scan",
      detail: "No automatic scan is scheduled, so nothing runs unless you start it.",
      severity: "info",
      action: { kind: "schedule-scan" }
    });
  }

  if (!state.lastScan || (state.lastScanAgeDays != null && state.lastScanAgeDays > 7)) {
    recs.push({
      id: "run-scan",
      title: state.lastScan ? "Run a fresh quick scan" : "Run your first quick scan",
      detail: state.lastScan
        ? `The last file scan finished ${Math.round(state.lastScanAgeDays)} day(s) ago.`
        : "No file scan has run on this server yet.",
      severity: "LOW",
      action: { kind: "run-scan" }
    });
  }

  if (state.scanner.signatureWarnings.length) {
    recs.push({
      id: "signatures",
      title: "Review signature warnings",
      detail: state.scanner.signatureWarnings.join(" · "),
      severity: "MEDIUM",
      action: { kind: "open-settings", section: "signatures" }
    });
  }

  const rank = { HIGH: 0, MEDIUM: 1, LOW: 2, info: 3 };
  return recs
    .sort((a, b) => (rank[a.severity] ?? 4) - (rank[b.severity] ?? 4))
    .slice(0, MAX_RECOMMENDATIONS);
}

function detectIntent(message) {
  const text = String(message || "").toLowerCase();

  if (
    /\b(run|start|perform|begin|do)\b[^.!?]{0,40}\b(security\s*test|scan|checkup|check-up|check)\b/.test(text) ||
    /\b(security\s*test|scan (my|this|the|a) (device|computer|mac|pc|system)|check (my|this|the) (device|computer|mac|pc|system))\b/.test(text)
  ) {
    return "run-security-test";
  }

  if (/\b(threat|threats|virus|malware|trojan|infected|quarantin\w*|detection)\b/.test(text)) {
    return "threats";
  }

  if (/\b(status|score|safe|protected|health|how am i|how.*doing|what.*state)\b/.test(text)) {
    return "status";
  }

  return "question";
}

function timeLabel(iso) {
  const time = Date.parse(iso || "");
  return Number.isFinite(time) ? new Date(time).toUTCString() : "unknown time";
}

function statusAnswer(state) {
  if (!state.host || !Number.isFinite(state.host.score)) {
    return [
      "No device check has run yet, so there is no safety score to report.",
      state.scanner.activeScan
        ? `A ${state.scanner.activeScan.scope} scan is running (${state.scanner.activeScan.filesScanned} files so far).`
        : "Ask me to run a security test and I will check this computer, then start a quick file scan.",
      "Everything I report comes from the real check output; I will not guess a score."
    ].join("\n\n");
  }

  const summary = state.host.summary || {};
  const lines = [
    `${state.host.name} scored ${state.host.score}/100 (${state.host.grade}) on ${timeLabel(state.host.checkedAt)}.`,
    `${summary.passed || 0} checks passed, ${summary.attention || 0} need attention, and ${summary.unverified || 0} could not be verified.`
  ];

  if (state.attentionChecks.length) {
    lines.push(
      "Needs attention: " +
        state.attentionChecks
          .slice(0, 3)
          .map(check => `${check.title} (${check.severity})`)
          .join(", ") +
        "."
    );
  }

  if (state.lastScan) {
    lines.push(
      `Last ${state.lastScan.scope} scan: ${state.lastScan.filesScanned} files, ` +
        `${state.lastScan.threatCount} detection(s), finished ${timeLabel(state.lastScan.finishedAt)}.`
    );
  } else {
    lines.push("No file scan has run on this server yet.");
  }

  lines.push(
    state.openThreats.length
      ? `${state.openThreats.length} open detection(s) still need a decision.`
      : `Recorded scans show no unhandled detection right now; ${state.quarantine.count} item(s) are in quarantine.`
  );

  return lines.join("\n\n");
}

function threatsAnswer(state) {
  if (!state.openThreats.length) {
    return [
      "No open detections are recorded in the most recent scans.",
      state.quarantine.count
        ? `${state.quarantine.count} item(s) are in quarantine. Open the threat queue to restore or delete them.`
        : "Quarantine is empty.",
      "That is a statement about recorded scan results, not a guarantee about every file on the device."
    ].join("\n\n");
  }

  const lines = [
    `${state.openThreats.length} open detection(s) waiting for a decision:`
  ];

  for (const threat of state.openThreats.slice(0, 5)) {
    lines.push(
      `- ${threat.name} (${threat.severity}) at ${threat.filePath || "unknown path"}` +
        (threat.reasons.length ? ` — ${threat.reasons.join("; ")}` : "")
    );
  }

  lines.push("Quarantining moves the file into the local vault. Nothing is uploaded.");
  return lines.join("\n");
}

function testStartedAnswer(run) {
  const lines = [];

  if (run.device && Number.isFinite(run.device.score)) {
    const summary = run.device.summary || {};
    lines.push(
      `Device check finished: ${run.device.score}/100 (${run.device.grade}). ` +
        `${summary.passed || 0} passed, ${summary.attention || 0} need attention, ` +
        `${summary.unverified || 0} unverified.`
    );
  } else {
    lines.push(
      run.check?.message ||
        "The device check could not run on this platform, so no posture score is shown."
    );
  }

  if (run.scan) {
    lines.push(
      `A ${run.scan.scope} file scan is running now (started ${timeLabel(run.scan.startedAt)}). ` +
        "I will show the real file count and detections as they are written."
    );
  } else {
    lines.push(run.scanError || "A file scan could not be started.");
  }

  lines.push("Scores and detections come from the local checks only; nothing is estimated.");
  return lines.join("\n");
}

function runSummary(state) {
  const scan = state.lastScan;

  if (!scan) {
    return "No file scan has been recorded on this server yet.";
  }

  const lines = [
    `${scan.scope} scan ${scan.status} at ${timeLabel(scan.finishedAt || scan.startedAt)}.`,
    `Scanned ${scan.filesScanned} files, found ${scan.threatCount} detection(s), skipped ${scan.skipped}` +
      (scan.truncated ? "; the scan hit its limit before finishing." : ".")
  ];

  if (state.openThreats.length) {
    lines.push(`Open detections: ${state.openThreats.slice(0, 5).map(threat => threat.name).join(", ")}.`);
  }

  if (scan.errors.length) {
    const blocked = scan.errors.filter(error =>
      /EPERM|EACCES|operation not permitted|permission denied/i.test(error)
    );
    const other = scan.errors.filter(error => !blocked.includes(error));

    if (blocked.length) {
      lines.push(
        `Folder access was blocked for ${blocked.length} location(s), so those files were not scanned. ` +
          "Grant the app permission (Full Disk Access on macOS) or scan a folder it can read."
      );
    }

    if (other.length) {
      lines.push(`Scanner errors: ${other.join("; ")}.`);
    }
  }

  if (state.host && Number.isFinite(state.host.score)) {
    lines.push(`Current device score: ${state.host.score}/100 (${state.host.grade}).`);
  }

  return lines.join("\n");
}

module.exports = {
  describeState,
  recommendationsFor,
  detectIntent,
  statusAnswer,
  threatsAnswer,
  testStartedAnswer,
  runSummary
};
