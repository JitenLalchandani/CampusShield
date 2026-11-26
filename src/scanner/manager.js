"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");

const { ENGINE_VERSION, LIMITS, scan, scanRoots, scanSingleFile, inspectFile } = require("./engine");
const { severityWeight } = require("./heuristics");
const { createQuarantine } = require("./quarantine");
const { DEFAULT_PREFERENCES, normalizePreferences, nextRunAt, isDue } = require("./preferences");
const { loadSignatures, refreshSignaturesFromUrl } = require("./signatures");
const { createWatcher } = require("./watcher");

const PENALTY_CAP = 45;
const REALTIME_SCAN_ID = "realtime";
const HISTORY_LIMIT = 50;
const SCHEDULER_INTERVAL_MS = 30 * 1000;
const CUSTOM_SCOPE = "custom";

function feedHost(url) {
  if (!url) return "";

  try {
    return new URL(url).hostname;
  } catch {
    return "invalid URL";
  }
}

// `extraThreats` lets another module (the ransomware shield) add open threats to the same penalty,
// so the weights and the cap stay in one place. Each item needs a filePath and a severity.
function createScannerService({ store, dataDir, audit, onThreatsChanged, extraThreats }) {
  const signatures = loadSignatures();
  const quarantine = createQuarantine(dataDir);
  const remoteFeed = {
    url: (process.env.CAMPUSSHIELD_SIGNATURES_URL || "").trim(),
    state: "off",
    added: 0,
    message: null,
    checkedAt: null
  };

  if (remoteFeed.url) {
    loadRemoteFeed().catch(error => {
      console.error("Signature feed refresh failed:", error.message);
    });
  }

  let preferences = normalizePreferences(DEFAULT_PREFERENCES);
  let preferencesReady = false;
  let scheduler = null;
  let active = null;
  let watcher = null;
  let watchRoots = [];
  let mutation = Promise.resolve();

  function watchSupported() {
    return process.platform === "darwin" || process.platform === "win32";
  }

  async function loadRemoteFeed() {
    remoteFeed.state = "pending";

    try {
      const result = await refreshSignaturesFromUrl(signatures, remoteFeed.url);
      remoteFeed.state = "loaded";
      remoteFeed.added = result.added;
      remoteFeed.message = null;
      remoteFeed.checkedAt = new Date().toISOString();
      return result;
    } catch (error) {
      remoteFeed.state = "error";
      remoteFeed.message = error.message;
      remoteFeed.checkedAt = new Date().toISOString();
      throw error;
    }
  }

  const ready = (async () => {
    try {
      const stored = typeof store.settings?.get === "function" ? await store.settings.get() : {};
      preferences = normalizePreferences(stored?.preferences, DEFAULT_PREFERENCES);
      preferencesReady = true;

      if (preferences.realtime && watchSupported()) {
        try {
          await startWatch();
        } catch (error) {
          // A stored preference can outlive the folder it watched; scans still work without the watcher.
          preferences = { ...preferences, realtime: false };
          await store.settings.save({ preferences });
          console.error("Real-time protection could not start:", error.message);
        }
      }
    } catch (error) {
      preferencesReady = true;
      console.error("Scanner settings load failed:", error.message);
    }
  })();

  async function runScheduledScan(now = new Date()) {
    await ready;

    const schedule = preferences.schedule;
    if (!isDue(schedule, now) || active) return null;

    preferences = {
      ...preferences,
      schedule: { ...schedule, lastRunAt: now.toISOString() }
    };
    await store.settings.save({ preferences });

    try {
      await startScan({ scope: schedule.scope, trigger: "schedule" });
    } catch (error) {
      if (error.statusCode === 409) return null;
      throw error;
    }

    await audit?.({
      kind: "scan",
      message: `Scheduled ${schedule.scope} scan started`,
      severity: null
    });

    return { scope: schedule.scope, startedAt: now.toISOString() };
  }

  function startScheduler() {
    if (scheduler) return;

    scheduler = setInterval(() => {
      runScheduledScan().catch(error => console.error("Scheduled scan failed:", error.message));
    }, SCHEDULER_INTERVAL_MS);

    scheduler.unref?.();
  }

  startScheduler();

  function enqueue(task) {
    const run = mutation.then(task);
    mutation = run.catch(() => {});
    return run;
  }

  function decorate(record) {
    if (!record) return null;

    if (active && active.id === record.id) {
      return {
        ...record,
        filesScanned: active.progress.filesScanned,
        bytesScanned: active.progress.bytesScanned,
        currentDirectory: active.progress.currentDirectory,
        threatCount: active.progress.threats
      };
    }

    return {
      ...record,
      threatCount: Array.isArray(record.threats) ? record.threats.length : 0
    };
  }

  async function listScans(limit = 20) {
    const scans = await store.scans.all(HISTORY_LIMIT);
    return scans.slice(0, limit).map(decorate);
  }

  async function getScan(id) {
    if (active && active.id === id) return decorate(active.record);
    return decorate(await store.scans.get(id));
  }

  async function allThreats() {
    const scans = await store.scans.all(200);
    const threats = [];

    for (const item of scans) {
      for (const threat of item.threats || []) threats.push(threat);
    }

    return threats;
  }

  // The same file can be flagged by a scan and by the watcher. One decision applies to all copies.
  async function updateThreatsForPath(filePath, patch) {
    const scans = await store.scans.all(200);

    for (const record of scans) {
      let changed = false;

      for (const threat of record.threats || []) {
        if (threat.filePath === filePath && threat.status === "detected") {
          Object.assign(threat, patch);
          changed = true;
        }
      }

      if (changed) await store.scans.upsert(record);
    }
  }

  async function penalty() {
    const extra = typeof extraThreats === "function" ? await extraThreats() : [];
    const open = [...(await allThreats()).filter(threat => threat.status === "detected"), ...extra];
    const byPath = new Map();

    for (const threat of open) {
      const weight = severityWeight(threat.severity);
      byPath.set(threat.filePath, Math.max(byPath.get(threat.filePath) || 0, weight));
    }

    const total = [...byPath.values()].reduce((sum, weight) => sum + weight, 0);
    return Math.min(total, PENALTY_CAP);
  }

  function preferencesView() {
    return {
      ...preferences,
      exclusions: [...preferences.exclusions],
      schedule: { ...preferences.schedule }
    };
  }

  function status() {
    return {
      available: true,
      engineVersion: ENGINE_VERSION,
      signatureVersion: signatures.version,
      signatureCount: signatures.count,
      signatureNote: signatures.note,
      signatureWarnings: signatures.warnings,
      remoteFeed: { ...remoteFeed, url: feedHost(remoteFeed.url) },
      limits: LIMITS,
      preferences: preferencesView(),
      preferencesReady,
      scheduleNextRunAt: nextRunAt(preferences.schedule),
      active: active
        ? {
            id: active.id,
            scope: active.scope,
            trigger: active.record.trigger,
            startedAt: active.record.startedAt,
            ...active.progress
          }
        : null,
      watch: watcher ? watcher.status() : { enabled: false, roots: [] },
      watchSupported: watchSupported(),
      realtimeScanId: REALTIME_SCAN_ID
    };
  }

  function scopeLabel(scope) {
    if (scope === "full") return "Full";
    if (scope === CUSTOM_SCOPE) return "Custom";
    return "Quick";
  }

  async function scanOneFile(filePath) {
    const startedAt = new Date().toISOString();
    const started = Date.now();
    const result = {
      engineVersion: ENGINE_VERSION,
      signatureVersion: signatures.version,
      signatureCount: signatures.count,
      scope: CUSTOM_SCOPE,
      roots: [filePath],
      startedAt,
      finishedAt: null,
      durationMs: 0,
      filesScanned: 1,
      bytesScanned: 0,
      skipped: 0,
      threats: [],
      errors: [],
      truncated: false,
      stopReason: null
    };

    try {
      const inspected = await inspectFile(filePath, signatures);

      if (inspected?.skipped) result.skipped = 1;
      if (inspected?.threat) result.threats.push(inspected.threat);
      if (inspected?.size) result.bytesScanned = inspected.size;
    } catch (error) {
      result.errors.push({ path: filePath, message: error.message });
    }

    result.finishedAt = new Date().toISOString();
    result.durationMs = Date.now() - started;
    return result;
  }

  async function startScan({ scope = "quick", target = null, trigger = "manual" } = {}) {
    if (scope !== CUSTOM_SCOPE && !LIMITS[scope]) {
      throw Object.assign(new Error("Scope must be quick, full, or custom."), { statusCode: 400 });
    }

    if (active) {
      throw Object.assign(
        new Error("A scan is already running. Wait for it to finish or cancel it."),
        { statusCode: 409 }
      );
    }

    await ready;

    let roots = scope === CUSTOM_SCOPE ? [] : scanRoots(scope);
    let targetStat = null;

    if (scope === CUSTOM_SCOPE) {
      if (typeof target !== "string" || !target.trim()) {
        throw Object.assign(new Error("Choose a folder or file to scan."), { statusCode: 400 });
      }

      const resolved = path.resolve(target.trim());

      try {
        targetStat = await fs.stat(resolved);
      } catch {
        throw Object.assign(new Error("That folder or file does not exist."), { statusCode: 400 });
      }

      if (!targetStat.isDirectory() && !targetStat.isFile()) {
        throw Object.assign(new Error("Only folders and files can be scanned."), { statusCode: 400 });
      }

      roots = [resolved];
    }

    const id = crypto.randomUUID();
    const controller = new AbortController();
    const record = {
      id,
      scope,
      trigger,
      status: "running",
      startedAt: new Date().toISOString(),
      finishedAt: null,
      durationMs: null,
      engineVersion: ENGINE_VERSION,
      signatureVersion: signatures.version,
      signatureCount: signatures.count,
      filesScanned: 0,
      bytesScanned: 0,
      skipped: 0,
      threats: [],
      errors: [],
      truncated: false,
      stopReason: null,
      roots
    };

    const excludePaths =
      scope === CUSTOM_SCOPE
        ? [quarantine.root]
        : [quarantine.root, ...preferences.exclusions];

    active = {
      id,
      scope,
      controller,
      record,
      progress: { filesScanned: 0, bytesScanned: 0, threats: 0, currentDirectory: null }
    };

    const run = (async () => {
      await store.scans.upsert(record);

      try {
        const result =
          scope === CUSTOM_SCOPE && targetStat.isFile()
            ? await scanOneFile(roots[0])
            : await scan({
                scope: scope === CUSTOM_SCOPE ? "quick" : scope,
                signatures,
                signal: controller.signal,
                excludePaths,
                roots,
                limits: scope === CUSTOM_SCOPE ? LIMITS.full : LIMITS[scope],
                onProgress: progress => {
                  if (active && active.id === id) active.progress = { ...active.progress, ...progress };
                }
              });

        const finished = {
          ...record,
          ...result,
          status: controller.signal.aborted ? "cancelled" : "complete",
          id,
          scope,
          trigger
        };

        await audit?.({
          kind: "scan",
          message:
            `${scopeLabel(scope)} file scan: ` +
            `${finished.filesScanned} files, ${finished.threats.length} threat${finished.threats.length === 1 ? "" : "s"}` +
            `${finished.truncated ? ` (stopped early: ${finished.stopReason})` : ""}`,
          severity: finished.threats.length ? "MEDIUM" : null
        });

        await store.scans.upsert(finished);

        // Keep the job "running" from the UI's point of view until the device row reflects the new
        // threats, so the first poll after completion never shows "complete" with a stale score.
        await onThreatsChanged?.();
        active = null;
      } catch (error) {
        const failed = {
          ...record,
          ...(active?.progress || {}),
          status: "failed",
          error: error.message,
          finishedAt: new Date().toISOString()
        };

        if (active && active.id === id) active = null;

        await store.scans.upsert(failed);
        await audit?.({ kind: "scan", message: `File scan failed: ${error.message}`, severity: "MEDIUM" });
      }
    })();

    run.catch(error => console.error("Scan job error:", error.message));

    return decorate(record);
  }

  function cancelScan(id = null) {
    if (!active) {
      throw Object.assign(new Error("No scan is running."), { statusCode: 409 });
    }

    if (id && active.id !== id) {
      throw Object.assign(new Error("That scan is not the one currently running."), { statusCode: 409 });
    }

    active.controller.abort();
    return { cancelled: true, id: active.id };
  }

  async function findThreat(scanId, threatId) {
    const record = await store.scans.get(scanId);
    const threat = record?.threats?.find(item => item.id === threatId);

    if (!record || !threat) {
      throw Object.assign(new Error("Threat not found."), { statusCode: 404 });
    }

    return { record, threat };
  }

  async function restoreThreatsForPath(filePath) {
    const scans = await store.scans.all(200);

    for (const record of scans) {
      let changed = false;

      for (const threat of record.threats || []) {
        if (threat.filePath === filePath && threat.status === "quarantined") {
          threat.status = "detected";
          threat.statusAt = new Date().toISOString();
          delete threat.quarantineId;
          changed = true;
        }
      }

      if (changed) await store.scans.upsert(record);
    }
  }

  function quarantineThreat(scanId, threatId) {
    return enqueue(async () => {
      const { record, threat } = await findThreat(scanId, threatId);

      if (threat.status === "quarantined") {
        return { scan: decorate(record), threat };
      }

      let stored;

      try {
        stored = await quarantine.moveIn(threat.filePath);
      } catch (error) {
        if (error.code === "ENOENT") {
          threat.status = "deleted";
          threat.statusAt = new Date().toISOString();
          await store.scans.upsert(record);
          await onThreatsChanged?.();
          throw Object.assign(new Error("The file is no longer at its original path."), { statusCode: 409 });
        }
        throw error;
      }

      const entry = {
        id: crypto.randomUUID(),
        scanId,
        threatId,
        name: threat.name,
        originalPath: threat.filePath,
        storedName: stored.storedName,
        sha256: threat.sha256,
        severity: threat.severity,
        size: stored.size,
        reasons: threat.reasons,
        quarantinedAt: new Date().toISOString()
      };

      await store.quarantine.upsert(entry);

      threat.status = "quarantined";
      threat.statusAt = entry.quarantinedAt;
      threat.quarantineId = entry.id;

      await store.scans.upsert(record);
      await updateThreatsForPath(threat.filePath, {
        status: "quarantined",
        statusAt: entry.quarantinedAt,
        quarantineId: entry.id
      });
      await audit({
        kind: "quarantine",
        message: `Quarantined ${threat.name} (${threat.severity}) from ${threat.filePath}`,
        severity: "LOW"
      });
      await onThreatsChanged?.();

      return { scan: decorate(record), threat, quarantine: entry };
    });
  }

  function deleteThreat(scanId, threatId) {
    return enqueue(async () => {
      const { record, threat } = await findThreat(scanId, threatId);

      if (threat.status === "quarantined" && threat.quarantineId) {
        const entry = await store.quarantine.get(threat.quarantineId);
        if (entry) await quarantine.remove(entry);
        await store.quarantine.remove(threat.quarantineId);
      } else {
        await fs.unlink(threat.filePath).catch(error => {
          if (error.code !== "ENOENT") throw error;
        });
      }

      threat.status = "deleted";
      threat.statusAt = new Date().toISOString();

      await store.scans.upsert(record);
      await updateThreatsForPath(threat.filePath, {
        status: "deleted",
        statusAt: threat.statusAt
      });
      await audit({
        kind: "quarantine",
        message: `Deleted ${threat.name} permanently`,
        severity: "LOW"
      });
      await onThreatsChanged?.();

      return { scan: decorate(record), threat };
    });
  }

  async function listQuarantine() {
    return store.quarantine.all();
  }

  function restoreQuarantine(id) {
    return enqueue(async () => {
      const entry = await store.quarantine.get(id);

      if (!entry) {
        throw Object.assign(new Error("Quarantine entry not found."), { statusCode: 404 });
      }

      const restoredTo = await quarantine.moveOut(entry);
      await store.quarantine.remove(id);

      const record = await store.scans.get(entry.scanId);
      const threat = record?.threats?.find(item => item.id === entry.threatId);

      if (threat) {
        // A restored file is back on disk, so it counts as an open threat again.
        threat.status = "detected";
        threat.statusAt = new Date().toISOString();
        threat.restoredAt = threat.statusAt;
        threat.restoredTo = restoredTo;
        delete threat.quarantineId;
        await store.scans.upsert(record);
      }

      await restoreThreatsForPath(entry.originalPath);

      await audit({
        kind: "quarantine",
        message: `Restored ${entry.name} to ${restoredTo}`,
        severity: "MEDIUM"
      });
      await onThreatsChanged?.();

      return { restoredTo, entry };
    });
  }

  function deleteQuarantine(id) {
    return enqueue(async () => {
      const entry = await store.quarantine.get(id);

      if (!entry) {
        throw Object.assign(new Error("Quarantine entry not found."), { statusCode: 404 });
      }

      await quarantine.remove(entry);
      await store.quarantine.remove(id);

      const record = await store.scans.get(entry.scanId);
      const threat = record?.threats?.find(item => item.id === entry.threatId);

      if (threat) {
        threat.status = "deleted";
        threat.statusAt = new Date().toISOString();
        await store.scans.upsert(record);
      }

      await audit({ kind: "quarantine", message: `Deleted quarantined file ${entry.name}` });
      await onThreatsChanged?.();

      return { removed: id };
    });
  }

  async function recordRealtimeThreat(threat) {
    return enqueue(async () => {
      const existing = await store.scans.get(REALTIME_SCAN_ID);
      const record = existing || {
        id: REALTIME_SCAN_ID,
        scope: "realtime",
        status: "watching",
        startedAt: new Date().toISOString(),
        finishedAt: null,
        durationMs: null,
        engineVersion: ENGINE_VERSION,
        signatureVersion: signatures.version,
        signatureCount: signatures.count,
        filesScanned: 0,
        bytesScanned: 0,
        skipped: 0,
        threats: [],
        errors: [],
        truncated: false,
        stopReason: null,
        roots: watchRoots
      };

      record.filesScanned += 1;
      record.threats.push(threat);
      record.roots = watchRoots;
      record.status = "watching";

      await store.scans.upsert(record);
      await onThreatsChanged?.();
    });
  }

  async function startWatch() {
    if (watcher) return watcher.status();

    if (!watchSupported()) {
      throw Object.assign(
        new Error("Real-time protection is available on macOS and Windows only."),
        { statusCode: 400 }
      );
    }

    const excludePaths = [quarantine.root, ...preferences.exclusions];
    const roots = scanRoots("quick").filter(Boolean);

    const instance = createWatcher({
      roots,
      excludePaths,
      onFile: async filePath => {
        const threat = await scanSingleFile(filePath, signatures);
        if (!threat) return null;
        await recordRealtimeThreat(threat);
        await audit?.({
          kind: "detection",
          message: `Real-time watcher flagged ${threat.name} (${threat.severity}) at ${threat.filePath}`,
          severity: "MEDIUM"
        });
        return threat;
      },
      onError: error => {
        console.error("Watcher error:", error.message);
      }
    });

    const watchStatus = instance.start();
    watcher = instance;
    watchRoots = roots;

    return watchStatus;
  }

  async function stopWatch({ persist = true } = {}) {
    if (watcher) {
      watcher.stop();
      watcher = null;
    }

    if (persist && preferences.realtime) {
      preferences = { ...preferences, realtime: false };
      await store.settings.save({ preferences });
    }

    return { enabled: false, roots: watchRoots };
  }

  async function configure(patch) {
    await ready;

    const next = normalizePreferences(patch, preferences);

    if (next.realtime && !watchSupported()) {
      throw Object.assign(
        new Error("Real-time protection is available on macOS and Windows only."),
        { statusCode: 400 }
      );
    }

    if (next.schedule.enabled && !next.schedule.lastRunAt) {
      next.schedule.lastRunAt = new Date().toISOString();
    }

    preferences = next;
    await store.settings.save({ preferences });

    if (preferences.realtime && !watcher) {
      try {
        await startWatch();
      } catch (error) {
        preferences = { ...preferences, realtime: false };
        await store.settings.save({ preferences });
        throw Object.assign(
          new Error(`Real-time protection could not start: ${error.message}`),
          { statusCode: error.statusCode || 500 }
        );
      }
    } else if (!preferences.realtime && watcher) {
      await stopWatch({ persist: false });
    }

    await audit?.({ kind: "settings", message: "Protection settings updated" });

    return preferencesView();
  }

  async function setRealtime(enabled) {
    const view = await configure({ realtime: Boolean(enabled) });

    return {
      enabled: Boolean(watcher),
      roots: watchRoots,
      preferences: view
    };
  }

  async function updateSignatures() {
    if (!remoteFeed.url) {
      throw Object.assign(
        new Error("No signature feed is configured. Set CAMPUSSHIELD_SIGNATURES_URL and restart."),
        { statusCode: 400 }
      );
    }

    try {
      const result = await loadRemoteFeed();

      await audit?.({
        kind: "signatures",
        message:
          `Signature update from ${feedHost(remoteFeed.url)}: ` +
          `${result.added} new hash${result.added === 1 ? "" : "es"} (${signatures.version})`,
        severity: null
      });

      return { ...status(), updated: result.added };
    } catch (error) {
      throw Object.assign(error, { statusCode: 502 });
    }
  }

  async function reset() {
    try {
      cancelScan();
    } catch {
      /* no scan running */
    }
    await stopWatch({ persist: false });
    preferences = normalizePreferences(DEFAULT_PREFERENCES);
    await store.settings.clear?.();
    await store.scans.clear();
    await store.quarantine.clear();
    await quarantine.clear();
    await onThreatsChanged?.();
  }

  async function close() {
    if (scheduler) {
      clearInterval(scheduler);
      scheduler = null;
    }

    await stopWatch({ persist: false });
  }

  return {
    status,
    configure,
    setRealtime,
    updateSignatures,
    runScheduledScan,
    listScans,
    getScan,
    startScan,
    cancelScan,
    quarantineThreat,
    deleteThreat,
    listQuarantine,
    restoreQuarantine,
    deleteQuarantine,
    startWatch,
    stopWatch,
    penalty,
    allThreats,
    reset,
    close
  };
}

module.exports = { createScannerService, PENALTY_CAP, REALTIME_SCAN_ID };
