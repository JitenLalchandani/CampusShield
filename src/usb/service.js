"use strict";

// USB auto-scan service. When on, it notices removable drives that appear while CampusShield is
// watching, looks at the top of the drive for autorun tricks, and runs the normal file scanner on
// it. Records say exactly what was checked. Drives already plugged in when watching starts are
// listed but not scanned until you ask. Every side effect is injectable for tests.

const crypto = require("node:crypto");

const config = require("./config");
const { httpError } = require("../shield/config");
const { listRemovableDrives, isSupported } = require("./drives");
const { inspectDrive, maxSeverity } = require("./inspect");

const TOKEN_TTL_MS = 60 * 1000;
const ATTEMPT_WINDOW_MS = 10 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const EVENT_LIMIT = 200;
const MAX_THREATS = 50;
const SCAN_STATUSES = new Set(["scanning", "clean", "open", "incomplete", "removed", "dismissed"]);

const LIMITS = Object.freeze([
  "Detection polls for removable drives every few seconds, so a drive that is plugged in and removed within that time can be missed.",
  "Scanning uses the same signatures and heuristics as the file scanner. It is not a guarantee a drive is safe.",
  "CampusShield never runs, opens, or changes files on the drive. Quarantine moves a file off the drive only when you confirm it.",
  "Only the top of the drive is checked for autorun tricks. Deeper files are covered by the file scan."
]);

const realSleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function createUsbService({
  store,
  platform = process.platform,
  now = Date.now,
  runner,
  lister = listRemovableDrives,
  inspector = inspectDrive,
  scanner,
  audit = async () => {},
  onChange = () => {},
  onEvent = () => {},
  setTimer = setTimeout,
  clearTimer = clearTimeout,
  sleep = realSleep,
  pollMs = 4000,
  scanPollMs = 1000,
  busyRetryMs = 5000,
  busyMaxMs = 10 * 60 * 1000
}) {
  const supported = isSupported(platform);

  let settings = null;
  let known = new Map();
  let initialized = false;
  let listError = null;
  let lastPollAt = null;
  let pollTimer = null;
  let closed = false;
  let queue = Promise.resolve();

  const jobs = new Set();
  const activeScans = new Map();
  const tokens = new Map();
  const attempts = new Map();
  const iso = () => new Date(now()).toISOString();

  function enqueue(task) {
    const run = queue.then(task);
    queue = run.catch(() => {});
    return run;
  }

  async function record(entry) {
    try {
      await audit({ kind: "usb", ...entry });
    } catch {
      // An audit failure must not undo something that already happened.
    }
  }

  async function loadSettings() {
    const stored = await store.settings.get();
    settings = config.normalizeStored(stored.usb);
  }

  async function saveSettings(next) {
    await store.settings.save({ usb: next });
    settings = next;
  }

  const isIgnored = id => settings.ignoredDrives.includes(id);
  const detectedThreats = event => (event.threats || []).filter(threat => threat.status === "detected");
  const actionableFindings = event => (event.findings || []).filter(finding => finding.severity !== "low");

  function computeStatus(event) {
    if (event.status === "removed" || event.status === "dismissed") return event.status;
    if (event.status === "scanning" && !event.finished) return "scanning";
    if (detectedThreats(event).length || actionableFindings(event).length) return "open";
    if (event.scanFailed || (event.scan && event.scan.status !== "complete")) return "incomplete";
    if (event.inspect && !event.inspect.ok) return "incomplete";
    return "clean";
  }

  // ---- drive events ------------------------------------------------------------------------------

  async function startEvent(drive, trigger) {
    const event = {
      id: crypto.randomUUID(),
      driveId: drive.id,
      label: drive.label,
      mountPoint: drive.mountPoint,
      fsType: drive.fsType || null,
      sizeBytes: drive.sizeBytes || null,
      trigger,
      status: "scanning",
      severity: null,
      startedAt: iso(),
      updatedAt: iso(),
      findings: [],
      inspect: null,
      scan: null,
      threats: [],
      note: null,
      actions: []
    };

    const inspected = await inspector(drive.mountPoint);

    event.findings = inspected.findings || [];
    event.inspect = {
      ok: inspected.ok,
      entriesChecked: inspected.entriesChecked || 0,
      truncated: Boolean(inspected.truncated),
      reason: inspected.reason || null
    };

    await store.usbEvents.upsert(event);
    await store.usbEvents.prune(EVENT_LIMIT);
    await record({ message: `USB drive "${drive.label}" ${trigger === "insert" ? "inserted" : "scan requested"} (${drive.mountPoint}).`, severity: null });

    return event;
  }

  async function saveEvent(event, patch = {}) {
    const next = { ...event, ...patch, updatedAt: iso() };
    next.status = patch.status || computeStatus(next);
    next.severity = maxSeverity([...actionableFindings(next), ...detectedThreats(next)]);
    await store.usbEvents.upsert(next);
    return next;
  }

  async function finishScan(eventId, result) {
    return enqueue(async () => {
      const event = await store.usbEvents.get(eventId);
      if (!event) return null;

      const scan = result.scan;
      const patch = { note: result.note || null, finished: true, scanFailed: Boolean(result.failed) };

      if (scan) {
        patch.scan = {
          scanId: scan.id,
          status: scan.status,
          filesScanned: scan.filesScanned || 0,
          bytesScanned: scan.bytesScanned || 0,
          skipped: scan.skipped || 0,
          errorCount: (scan.errors || []).length,
          truncated: Boolean(scan.truncated),
          stopReason: scan.stopReason || null
        };
        patch.threats = (scan.threats || []).slice(0, MAX_THREATS).map(threat => ({
          id: threat.id,
          name: threat.name,
          severity: threat.severity,
          filePath: threat.filePath,
          status: threat.status || "detected"
        }));
      }

      // A drive that was pulled out keeps that fact; the scan facts are still saved.
      const saved = await saveEvent(event, event.status === "removed" ? { ...patch, status: "removed" } : patch);

      await record({
        message:
          `USB scan of "${saved.label}": ` +
          (scan
            ? `${patch.scan.filesScanned} files, ${detectedThreats(saved).length} threat${detectedThreats(saved).length === 1 ? "" : "s"}, ${saved.findings.length} autorun finding${saved.findings.length === 1 ? "" : "s"}` +
              `${scan.status !== "complete" ? ` (scan ${scan.status})` : ""}`
            : result.note || "no scan ran"),
        severity: saved.status === "open" ? "MEDIUM" : null,
        status: saved.status
      });

      if (saved.status === "open") onEvent(saved);
      await onChange();
      return saved;
    });
  }

  async function scanJob(eventId, mountPoint) {
    if (!scanner) return finishScan(eventId, { scan: null, failed: true, note: "The file scanner is not available." });

    const deadline = now() + busyMaxMs;
    let started = null;
    let waited = false;

    while (!started) {
      try {
        started = await scanner.startScan({ scope: "custom", target: mountPoint, trigger: "usb" });
      } catch (error) {
        if (error.statusCode === 409 && now() < deadline && !closed) {
          if (!waited) {
            waited = true;
            await enqueue(async () => {
              const event = await store.usbEvents.get(eventId);
              if (event) await saveEvent(event, { note: "Waiting for another scan to finish before this drive is scanned." });
            });
          }

          await sleep(busyRetryMs);
          continue;
        }

        return finishScan(eventId, {
          scan: null,
          failed: true,
          note: error.statusCode === 409 ? "Another scan kept running, so this drive was not scanned. Scan it again from Protection." : `The drive could not be scanned: ${error.message}`
        });
      }
    }

    activeScans.set(eventId, started.id);
    let current = started;

    while (current.status === "running" && !closed) {
      await sleep(scanPollMs);
      current = (await scanner.getScan(started.id)) || { ...started, status: "failed" };
    }

    activeScans.delete(eventId);

    return finishScan(eventId, {
      scan: current,
      note: current.status === "complete" ? null : `The scan ${current.status}, so results for this drive are partial.`
    });
  }

  function launch(event) {
    const job = scanJob(event.id, event.mountPoint).catch(error => console.error("USB scan job failed:", error.message));
    jobs.add(job);
    job.finally(() => jobs.delete(job));
    return job;
  }

  async function handleInserted(drive, trigger) {
    const event = await enqueue(() => startEvent(drive, trigger));

    if (trigger === "manual" || settings.autoScan) {
      launch(event);
    } else {
      await finishScan(event.id, { scan: null, note: "Auto-scan is off, so only the top of the drive was checked." });
    }

    return event;
  }

  async function markRemoved(driveId) {
    await enqueue(async () => {
      const events = await store.usbEvents.all(EVENT_LIMIT);
      let changed = false;

      for (const event of events) {
        if (event.driveId !== driveId || event.status === "removed" || event.status === "dismissed") continue;

        const scanId = activeScans.get(event.id);
        if (scanId) {
          try {
            scanner?.cancelScan(scanId);
          } catch {
            // The scan may have just finished.
          }
        }

        await saveEvent(event, { status: "removed", note: scanId ? "The drive was removed during the scan, so results are partial." : event.note });
        await record({ message: `USB drive "${event.label}" was removed.`, severity: null, status: "removed" });
        changed = true;
      }

      if (changed) await onChange();
    });
  }

  async function pollNow() {
    if (closed || !settings?.enabled || !supported) return;

    const result = await lister({ platform, runner });
    lastPollAt = iso();

    if (!result.ok) {
      listError = result.reason;
      return;
    }

    listError = null;
    const present = new Map(result.drives.map(drive => [drive.id, drive]));
    const first = !initialized;
    initialized = true;

    for (const drive of present.values()) {
      if (known.has(drive.id)) continue;
      known.set(drive.id, drive);
      if (!first && !isIgnored(drive.id)) await handleInserted(drive, "insert");
    }

    for (const [id] of [...known]) {
      if (present.has(id)) continue;
      known.delete(id);
      await markRemoved(id);
    }
  }

  function schedule() {
    if (closed || !settings?.enabled || !supported) return;

    pollTimer = setTimer(async () => {
      try {
        await pollNow();
      } catch (error) {
        listError = error.message;
      }

      schedule();
    }, pollMs);

    pollTimer?.unref?.();
  }

  function stopPolling() {
    if (pollTimer) clearTimer(pollTimer);
    pollTimer = null;
    known = new Map();
    initialized = false;
    listError = null;
  }

  async function startPolling() {
    stopPolling();
    if (!supported || !settings?.enabled) return;

    try {
      await pollNow();
    } catch (error) {
      listError = error.message;
    }

    schedule();
  }

  const ready = (async () => {
    await loadSettings();
    await startPolling();
  })().catch(error => {
    listError = `USB auto-scan could not start: ${error.message}`;
  });

  // ---- tokens and limits --------------------------------------------------------------------------

  function issueConfirmToken(eventId, callerKey) {
    for (const [token, entry] of tokens) if (entry.expiresAt <= now()) tokens.delete(token);
    while (tokens.size > 200) tokens.delete(tokens.keys().next().value);

    const token = crypto.randomBytes(24).toString("base64url");
    tokens.set(token, { eventId, callerKey, expiresAt: now() + TOKEN_TTL_MS });
    return { confirmToken: token, confirmExpiresInSec: TOKEN_TTL_MS / 1000 };
  }

  function consumeToken(token, eventId, callerKey) {
    const entry = typeof token === "string" ? tokens.get(token) : null;
    if (entry) tokens.delete(token);

    if (!entry || entry.expiresAt <= now() || entry.eventId !== eventId || entry.callerKey !== callerKey) {
      throw httpError("This confirmation is missing, expired, or was already used. Open the drive event again and confirm.", 403);
    }
  }

  function noteAttempt(eventId) {
    const cutoff = now() - ATTEMPT_WINDOW_MS;
    const recent = (attempts.get(eventId) || []).filter(time => time > cutoff);

    if (recent.length >= MAX_ATTEMPTS) {
      attempts.set(eventId, recent);
      throw httpError("Too many attempts for this drive. Wait a few minutes and try again.", 429);
    }

    recent.push(now());
    attempts.set(eventId, recent);
  }

  // ---- reads ---------------------------------------------------------------------------------------

  async function status() {
    await ready;
    const events = await store.usbEvents.all(EVENT_LIMIT);
    const latest = new Map();

    for (const event of events) if (!latest.has(event.driveId)) latest.set(event.driveId, event);

    return {
      supported,
      enabled: Boolean(settings?.enabled),
      running: Boolean(settings?.enabled && supported && !listError),
      autoScan: Boolean(settings?.autoScan),
      ignoredDrives: settings?.ignoredDrives || [],
      lastPollAt,
      error: listError,
      drives: [...known.values()].map(drive => ({
        ...drive,
        ignored: isIgnored(drive.id),
        latestEvent: latest.get(drive.id) ? { id: latest.get(drive.id).id, status: latest.get(drive.id).status } : null
      })),
      openEvents: events.filter(event => event.status === "open").length,
      limits: LIMITS,
      notes: [
        ...(supported ? [] : ["USB detection is not supported on this operating system."]),
        ...(platform === "win32" ? ["Windows drive detection has not been verified on a real machine."] : [])
      ]
    };
  }

  async function listEvents({ status: wanted = null, limit = 50 } = {}) {
    await ready;
    const max = Math.max(1, Math.min(Number.parseInt(limit, 10) || 50, EVENT_LIMIT));
    const all = await store.usbEvents.all(EVENT_LIMIT);
    return all.filter(event => !wanted || event.status === wanted).slice(0, max);
  }

  async function getEvent(id, callerKey = null) {
    await ready;
    const event = await store.usbEvents.get(id);
    if (!event) throw httpError("Drive event not found.", 404);

    return { event, ...(callerKey ? issueConfirmToken(id, callerKey) : {}) };
  }

  async function penaltyThreats() {
    await ready;
    const events = await store.usbEvents.all(EVENT_LIMIT);

    // File-scanner threats are already scored by the scanner. Only autorun findings are added here.
    return events
      .filter(event => event.status === "open" && actionableFindings(event).length)
      .map(event => ({ filePath: `usb:${event.driveId}`, severity: maxSeverity(actionableFindings(event)) }));
  }

  function postureCheck() {
    const base = { id: "usb-autoscan", title: "USB auto-scan", severity: "low" };

    if (!supported) return { ...base, status: "unknown", detail: "USB detection is not available on this platform.", recommendation: "Use CampusShield on macOS, Windows, or Linux." };
    if (!settings) return { ...base, status: "unknown", detail: "The USB auto-scan state has not loaded yet.", recommendation: "Run the check again." };

    if (!settings.enabled) {
      return { ...base, status: "warn", detail: "USB auto-scan is off, so drives you plug in are not checked automatically.", recommendation: "Turn on USB auto-scan in Protection." };
    }

    if (listError) return { ...base, status: "unknown", detail: listError, recommendation: "Check that the system tool for listing drives is available." };

    return { ...base, status: "pass", detail: "Watching for removable drives and scanning them when they appear.", recommendation: "No action needed." };
  }

  // ---- changes ---------------------------------------------------------------------------------------

  async function updateSettings(patch) {
    await ready;

    return enqueue(async () => {
      const next = config.applySettingsPatch(settings, patch);

      if (next.enabled && !supported) throw httpError("USB detection is not supported on this operating system.", 400);

      const toggled = next.enabled !== settings.enabled;
      await saveSettings(next);

      if (toggled) {
        await record({ message: next.enabled ? "USB auto-scan turned on." : "USB auto-scan turned off.", severity: null });
        await startPolling();
        await onChange();
      }

      return status();
    });
  }

  async function ignoreDrive(driveId, ignore = true, { callerLabel = "" } = {}) {
    await ready;
    if (typeof driveId !== "string" || !driveId || driveId.length > config.MAX_ID) throw httpError("Drive not found.", 404);

    return enqueue(async () => {
      const list = new Set(settings.ignoredDrives);
      if (ignore) list.add(driveId);
      else list.delete(driveId);

      await saveSettings(config.applySettingsPatch(settings, { ignoredDrives: [...list] }));
      await record({ message: `${ignore ? "Stopped" : "Resumed"} auto-scanning drive ${driveId}${callerLabel ? ` (${callerLabel})` : ""}.`, severity: null });
      return status();
    });
  }

  // Scans a drive that is mounted right now. Only drives the system lists as removable can be scanned.
  async function scanDrive(driveId, { callerLabel = "" } = {}) {
    await ready;
    if (!supported) throw httpError("USB detection is not supported on this operating system.", 400);

    const result = await lister({ platform, runner });
    if (!result.ok) throw httpError(`Drives could not be listed: ${result.reason}`, 502);

    const drive = result.drives.find(item => item.id === driveId);
    if (!drive) throw httpError("That drive is not connected.", 404);

    if (callerLabel) await record({ message: `Manual USB scan requested by ${callerLabel}.`, severity: null });

    return handleInserted(drive, "manual");
  }

  async function dismiss(eventId, { reason, callerLabel = "" } = {}) {
    await ready;

    return enqueue(async () => {
      const event = await store.usbEvents.get(eventId);
      if (!event) throw httpError("Drive event not found.", 404);
      if (event.status === "dismissed") return { event };
      if (event.status === "scanning") throw httpError("This drive is still being scanned.", 409);

      const saved = await saveEvent(event, {
        status: "dismissed",
        dismissedAt: iso(),
        dismissReason: typeof reason === "string" ? reason.trim().slice(0, 200) : ""
      });

      await record({ message: `USB event for "${event.label}" dismissed${callerLabel ? ` by ${callerLabel}` : ""}.`, severity: null, status: "dismissed" });
      await onChange();
      return { event: saved };
    });
  }

  async function quarantineAll(eventId, { confirmToken, callerKey, callerLabel = "" } = {}) {
    await ready;
    noteAttempt(eventId);

    try {
      consumeToken(confirmToken, eventId, callerKey);
    } catch (error) {
      await record({ message: `Quarantine refused for USB event ${eventId}: ${error.message}`, severity: "LOW" });
      throw error;
    }

    return enqueue(async () => {
      const event = await store.usbEvents.get(eventId);
      if (!event) throw httpError("Drive event not found.", 404);

      const targets = detectedThreats(event).filter(threat => threat.id);
      if (!targets.length) throw httpError("There is nothing to quarantine on this drive event.", 409);
      if (!event.scan?.scanId) throw httpError("This event has no scan to quarantine from.", 409);

      const results = [];

      for (const threat of targets) {
        try {
          await scanner.quarantineThreat(event.scan.scanId, threat.id);
          threat.status = "quarantined";
          results.push({ id: threat.id, name: threat.name, ok: true, message: "Moved to quarantine." });
        } catch (error) {
          results.push({ id: threat.id, name: threat.name, ok: false, message: error.message });
        }
      }

      const done = results.filter(item => item.ok).length;
      const saved = await saveEvent(event, {
        threats: event.threats,
        actions: [...event.actions, { type: "quarantine", at: iso(), by: callerLabel, ok: done === results.length, done, failed: results.length - done }]
      });

      await record({ message: `Quarantined ${done} of ${results.length} file${results.length === 1 ? "" : "s"} from USB drive "${event.label}"${callerLabel ? ` (${callerLabel})` : ""}.`, severity: "LOW", status: saved.status });
      await onChange();
      return { event: saved, results };
    });
  }

  async function close() {
    closed = true;
    if (pollTimer) clearTimer(pollTimer);
    pollTimer = null;
    await Promise.allSettled([...jobs]);
  }

  return {
    ready,
    status,
    listEvents,
    getEvent,
    penaltyThreats,
    postureCheck,
    updateSettings,
    ignoreDrive,
    scanDrive,
    dismiss,
    quarantineAll,
    pollNow,
    close,
    isSupported: () => supported
  };
}

module.exports = { createUsbService, LIMITS, SCAN_STATUSES };
