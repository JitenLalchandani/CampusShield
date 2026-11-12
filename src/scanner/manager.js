"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs/promises");

const { ENGINE_VERSION, LIMITS, scan, scanRoots, scanSingleFile } = require("./engine");
const { severityWeight } = require("./heuristics");
const { createQuarantine } = require("./quarantine");
const { loadSignatures } = require("./signatures");
const { createWatcher } = require("./watcher");

const PENALTY_CAP = 45;
const REALTIME_SCAN_ID = "realtime";
const HISTORY_LIMIT = 50;

function createScannerService({ store, dataDir, audit, onThreatsChanged }) {
  const signatures = loadSignatures();
  const quarantine = createQuarantine(dataDir);

  let active = null;
  let watcher = null;
  let watchRoots = [];
  let mutation = Promise.resolve();

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
    const open = (await allThreats()).filter(threat => threat.status === "detected");
    const byPath = new Map();

    for (const threat of open) {
      const weight = severityWeight(threat.severity);
      byPath.set(threat.filePath, Math.max(byPath.get(threat.filePath) || 0, weight));
    }

    const total = [...byPath.values()].reduce((sum, weight) => sum + weight, 0);
    return Math.min(total, PENALTY_CAP);
  }

  function status() {
    return {
      available: true,
      engineVersion: ENGINE_VERSION,
      signatureVersion: signatures.version,
      signatureCount: signatures.count,
      signatureNote: signatures.note,
      signatureWarnings: signatures.warnings,
      limits: LIMITS,
      active: active
        ? {
            id: active.id,
            scope: active.scope,
            startedAt: active.record.startedAt,
            ...active.progress
          }
        : null,
      watch: watcher ? watcher.status() : { enabled: false, roots: [] },
      watchSupported: process.platform === "darwin" || process.platform === "win32",
      realtimeScanId: REALTIME_SCAN_ID
    };
  }

  function startScan({ scope = "quick" } = {}) {
    if (!LIMITS[scope]) {
      return Promise.reject(Object.assign(new Error("Scope must be quick or full."), { statusCode: 400 }));
    }

    if (active) {
      return Promise.reject(Object.assign(
        new Error("A scan is already running. Wait for it to finish or cancel it."),
        { statusCode: 409 }
      ));
    }

    const id = crypto.randomUUID();
    const controller = new AbortController();
    const record = {
      id,
      scope,
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
      roots: scanRoots(scope)
    };

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
        const result = await scan({
          scope,
          signatures,
          signal: controller.signal,
          excludePaths: [quarantine.root],
          onProgress: progress => {
            if (active && active.id === id) active.progress = { ...active.progress, ...progress };
          }
        });

        const finished = {
          ...record,
          ...result,
          status: controller.signal.aborted ? "cancelled" : "complete",
          id,
          scope
        };

        await audit({
          kind: "scan",
          message:
            `${scope === "full" ? "Full" : "Quick"} file scan: ` +
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
        await audit({ kind: "scan", message: `File scan failed: ${error.message}`, severity: "MEDIUM" });
      }
    })();

    run.catch(error => console.error("Scan job error:", error.message));

    return Promise.resolve(decorate(record));
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

  function startWatch() {
    if (watcher) {
      return Promise.resolve(watcher.status());
    }

    const excludePaths = [quarantine.root];
    const roots = scanRoots("quick").filter(Boolean);

    const instance = createWatcher({
      roots,
      excludePaths,
      onFile: async filePath => {
        const threat = await scanSingleFile(filePath, signatures);
        if (!threat) return null;
        await recordRealtimeThreat(threat);
        await audit({
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

    return Promise.resolve(watchStatus);
  }

  function stopWatch() {
    if (watcher) {
      watcher.stop();
      watcher = null;
    }

    return Promise.resolve({ enabled: false, roots: watchRoots });
  }

  async function reset() {
    try {
      cancelScan();
    } catch {
      /* no scan running */
    }
    await stopWatch();
    await store.scans.clear();
    await store.quarantine.clear();
    await quarantine.clear();
    await onThreatsChanged?.();
  }

  return {
    status,
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
    close: stopWatch
  };
}

module.exports = { createScannerService, PENALTY_CAP, REALTIME_SCAN_ID };
