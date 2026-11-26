"use strict";

// The ransomware shield service. It owns the settings, the watcher, the alert records, and the
// Contain / Undo / Dismiss actions. Every side effect (clock, OS commands, file watching,
// timers) is injectable so the whole thing can be tested without touching the computer.

const crypto = require("node:crypto");
const fsp = require("node:fs/promises");
const os = require("node:os");

const config = require("./config");
const { createDetector } = require("./detector");
const { createShieldEngine } = require("./engine");
const { sampleSuspect } = require("./suspects");
const { createProcessController, createNetworkController } = require("./controllers");
const { runCommand } = require("./exec");

const SUPPORTED_PLATFORMS = new Set(["darwin", "win32", "linux"]);
const ACTION_TYPES = ["stop-suspect", "isolate-network"];
const TOKEN_TTL_MS = 60 * 1000;
const ATTEMPT_WINDOW_MS = 10 * 60 * 1000;
const MAX_ATTEMPTS = 3;
const ALERT_LIMIT = 200;
const HEAD_BYTES = 8192;

const LIMITS = Object.freeze([
  "This is a heuristic, not a guarantee. Slow, low-volume encryption and programs that avoid the watched folders can go unnoticed.",
  "The shield reports and responds. It cannot block a program from writing files.",
  "The suspect is a best guess from the programs holding files open at that moment."
]);

async function readHeadFromDisk(file) {
  let handle;

  try {
    handle = await fsp.open(file, "r");
    const buffer = Buffer.alloc(HEAD_BYTES);
    const { bytesRead } = await handle.read(buffer, 0, HEAD_BYTES, 0);
    return buffer.subarray(0, bytesRead);
  } catch {
    return null;
  } finally {
    await handle?.close().catch(() => {});
  }
}

function isIsolationActive(alert) {
  return (alert.actions || []).some(
    action =>
      action.type === "isolate-network" &&
      !action.undoneAt &&
      (action.interfaces || []).some(item => item.ok && !item.restoredAt)
  );
}

function activeIsolation(alert) {
  return (alert.actions || [])
    .slice()
    .reverse()
    .find(
      action =>
        action.type === "isolate-network" &&
        !action.undoneAt &&
        (action.interfaces || []).some(item => item.ok && !item.restoredAt)
    );
}

function createShieldService({
  store,
  home = os.homedir(),
  platform = process.platform,
  now = Date.now,
  runner = runCommand,
  detector = null,
  processController = null,
  networkController = null,
  sampler = sampleSuspect,
  watchFn,
  readHead = readHeadFromDisk,
  audit = async () => {},
  onChange = () => {},
  onAlert = () => {},
  setTimer = setTimeout,
  clearTimer = clearTimeout
}) {
  const supported = SUPPORTED_PLATFORMS.has(platform);
  const detect =
    detector ||
    createDetector({ now, readHead });
  const processes = processController || createProcessController({ platform, runner });
  const network = networkController || createNetworkController({ platform, runner });

  let settings = null;
  let engine = null;
  let running = false;
  let watching = [];
  let failedFolders = [];
  let startError = null;
  let lastAlertAt = null;
  let closed = false;

  const timers = new Map();
  const tokens = new Map();
  const attempts = new Map();
  let queue = Promise.resolve();

  function enqueue(task) {
    const run = queue.then(task);
    queue = run.catch(() => {});
    return run;
  }

  const iso = () => new Date(now()).toISOString();

  function isIgnored(folder) {
    const until = settings?.ignoredFolders?.[folder];
    return Boolean(until) && Date.parse(until) > now();
  }

  async function record(entry) {
    try {
      await audit({ kind: "shield", ...entry });
    } catch {
      // An audit failure must not undo a containment that already happened.
    }
  }

  function view(alert) {
    if (!alert) return null;
    const isolation = activeIsolation(alert);

    return {
      ...alert,
      isolationActive: Boolean(isolation),
      restoreAt: isolation?.restoreAt || null,
      restoreDue: Boolean(isolation?.restoreAt && Date.parse(isolation.restoreAt) <= now())
    };
  }

  async function loadSettings() {
    const stored = await store.settings.get();
    settings = config.normalizeStored(stored.shield, { home });
  }

  async function saveSettings(next) {
    await store.settings.save({ shield: next });
    settings = next;
  }

  function stopEngine() {
    engine?.stop();
    engine = null;
    running = false;
    watching = [];
    failedFolders = [];
  }

  async function startEngine() {
    stopEngine();
    startError = null;

    if (!supported || !settings?.enabled) return;

    detect.setThresholds(settings.thresholds);

    engine = createShieldEngine({
      folders: settings.folders,
      exclusions: settings.exclusions,
      isIgnored,
      detector: detect,
      watchFn,
      onResult: handleResult,
      onError: (folder, error) => {
        startError = `Watching ${folder} failed: ${error.message}`;
      }
    });

    try {
      const result = await engine.start();
      watching = result.watching;
      failedFolders = result.failed;
      running = watching.length > 0;

      if (!running) startError = "None of the chosen folders could be watched.";
    } catch (error) {
      running = false;
      startError = error.message;
    }
  }

  function handleResult({ kind, alert }) {
    return enqueue(async () => {
      if (closed) return;

      const existing = await store.shieldAlerts.get(alert.id);
      const merged = existing
        ? {
            ...existing,
            evidence: alert.evidence,
            updatedAt: alert.updatedAt,
            severity: alert.severity,
            confidence: alert.confidence
          }
        : alert;

      await store.shieldAlerts.upsert(merged);
      lastAlertAt = merged.updatedAt;

      if (kind === "alert") {
        await store.shieldAlerts.prune(ALERT_LIMIT);

        await record({
          message: `Possible ransomware activity in ${merged.folder}: ${merged.evidence.filesTouched} files touched in ${merged.evidence.windowSec}s.`,
          severity: merged.severity
        });

        try {
          onAlert(view(merged));
        } catch {
          // a notification failure must not stop the alert from being saved
        }

        // Finding the program can take seconds, so it runs outside the queue.
        sampleAndAttach(merged.id, merged.folder);
      }

      onChange();
    }).catch(error => {
      console.error("Shield alert handling failed:", error.message);
    });
  }

  async function sampleAndAttach(id, folder) {
    try {
      const result = await sampler({ folder, platform, runner });

      await enqueue(async () => {
        const alert = await store.shieldAlerts.get(id);
        if (!alert) return;

        alert.suspect = result.suspect ? { ...result.suspect, method: result.method } : null;
        alert.suspectNote = result.suspect ? null : result.reason || "No suspect could be identified.";
        alert.suspectMethod = result.method || null;
        alert.updatedAt = iso();

        await store.shieldAlerts.upsert(alert);
        onChange();
      });
    } catch (error) {
      await enqueue(async () => {
        const alert = await store.shieldAlerts.get(id);
        if (!alert) return;

        alert.suspectNote = `The suspect check failed: ${error.message}`;
        await store.shieldAlerts.upsert(alert);
      });
    }
  }

  // ---- restore timer and reconciliation ------------------------------------------------------

  function clearRestoreTimer(id) {
    const timer = timers.get(id);
    if (timer) clearTimer(timer);
    timers.delete(id);
  }

  function scheduleRestore(id, restoreAt) {
    clearRestoreTimer(id);
    if (!restoreAt || closed) return;

    const delay = Math.max(0, Date.parse(restoreAt) - now());
    const timer = setTimer(() => {
      timers.delete(id);
      undo(id, { auto: true }).catch(() => {});
    }, delay);

    timer.unref?.();
    timers.set(id, timer);
  }

  // After a restart, an isolation that was never undone is not forgotten and not blindly undone.
  // The real state is read back first: if the connections are already on, the record is closed;
  // otherwise it stays visible so the host can restore it.
  async function reconcile() {
    const alerts = await store.shieldAlerts.all(ALERT_LIMIT);

    for (const alert of alerts) {
      if (alert.status === "open") detect.adopt(alert);
      if (!isIsolationActive(alert)) continue;

      const listed = await network.list();
      const action = activeIsolation(alert);

      if (listed.ok) {
        const stamp = iso();

        for (const item of action.interfaces) {
          const found = listed.interfaces.find(entry => entry.name === item.name);
          if (item.ok && !item.restoredAt && found?.enabled) {
            item.restoredAt = stamp;
            item.message = "Found back on after a restart; restored outside CampusShield.";
          }
        }

        if (action.interfaces.every(item => !item.ok || item.restoredAt)) action.undoneAt = stamp;
        await store.shieldAlerts.upsert(alert);
      }

      if (isIsolationActive(alert)) {
        await record({
          message: `Network isolation from a shield alert is still recorded as active after a restart (${alert.folder}).`,
          severity: "high"
        });

        const current = activeIsolation(alert);
        if (current?.restoreAt && Date.parse(current.restoreAt) > now()) scheduleRestore(alert.id, current.restoreAt);
      }
    }
  }

  const ready = (async () => {
    await loadSettings();
    await reconcile();
    await startEngine();
  })().catch(error => {
    startError = `The shield could not start: ${error.message}`;
  });

  // ---- confirm tokens and attempt limits ------------------------------------------------------

  function purgeTokens() {
    for (const [token, entry] of tokens) {
      if (entry.expiresAt <= now()) tokens.delete(token);
    }

    while (tokens.size > 200) tokens.delete(tokens.keys().next().value);
  }

  function issueConfirmToken(alertId, callerKey) {
    purgeTokens();
    const token = crypto.randomBytes(24).toString("base64url");
    tokens.set(token, { alertId, callerKey, expiresAt: now() + TOKEN_TTL_MS });
    return { confirmToken: token, confirmExpiresInSec: TOKEN_TTL_MS / 1000 };
  }

  function consumeToken(token, alertId, callerKey) {
    const entry = typeof token === "string" ? tokens.get(token) : null;
    if (entry) tokens.delete(token);

    if (!entry || entry.expiresAt <= now() || entry.alertId !== alertId || entry.callerKey !== callerKey) {
      throw config.httpError(
        "This confirmation is missing, expired, or was already used. Open the alert again and confirm.",
        403
      );
    }
  }

  function noteAttempt(alertId) {
    const cutoff = now() - ATTEMPT_WINDOW_MS;
    const recent = (attempts.get(alertId) || []).filter(time => time > cutoff);

    if (recent.length >= MAX_ATTEMPTS) {
      attempts.set(alertId, recent);
      throw config.httpError("Too many Contain attempts for this alert. Wait a few minutes and try again.", 429);
    }

    recent.push(now());
    attempts.set(alertId, recent);
  }

  // ---- reads -----------------------------------------------------------------------------------

  function platformNotes() {
    if (!supported) return ["The shield runs on macOS, Windows, and Linux computers."];
    if (platform === "win32") {
      return ["Windows support has not been tested end to end. Finding the program needs Sysinternals handle.exe, which CampusShield does not install."];
    }
    if (platform === "linux") return ["Linux support is best-effort."];
    return [];
  }

  async function status() {
    await ready;
    const alerts = await store.shieldAlerts.all(ALERT_LIMIT);

    return {
      supported,
      platform,
      enabled: Boolean(settings?.enabled),
      running,
      watching,
      failedFolders,
      folders: settings?.folders || [],
      exclusions: settings?.exclusions || [],
      thresholds: settings?.thresholds || { ...config.DEFAULT_THRESHOLDS },
      thresholdBounds: config.THRESHOLD_BOUNDS,
      allowRemoteContain: settings?.allowRemoteContain ?? true,
      autoRestoreMinutes: settings?.autoRestoreMinutes ?? config.DEFAULT_AUTO_RESTORE_MINUTES,
      openAlerts: alerts.filter(alert => alert.status === "open").length,
      isolatedAlerts: alerts.filter(isIsolationActive).length,
      lastAlertAt,
      error: startError,
      notes: platformNotes(),
      limits: LIMITS
    };
  }

  // The posture check that feeds the 100-point score. Off costs a little, running costs nothing,
  // and anything that could not be verified costs nothing and says so.
  function postureCheck() {
    const base = { id: "ransomware-shield", title: "Ransomware shield", severity: "low" };

    if (!supported) {
      return {
        ...base,
        status: "unknown",
        detail: "The shield is not available on this platform.",
        recommendation: "Use CampusShield on macOS, Windows, or Linux to enable the ransomware shield."
      };
    }

    if (!settings) {
      return { ...base, status: "unknown", detail: "The shield state has not loaded yet.", recommendation: "Run the check again." };
    }

    if (!settings.enabled) {
      return {
        ...base,
        status: "warn",
        detail: "The ransomware shield is off, so mass file encryption in your documents would not be flagged.",
        recommendation: "Turn on the ransomware shield in Protection."
      };
    }

    if (!running) {
      return {
        ...base,
        status: "unknown",
        detail: startError || "The shield is on but no folder could be watched.",
        recommendation: "Check the folders listed in the shield settings."
      };
    }

    return {
      ...base,
      status: "pass",
      detail: `Watching ${watching.length} folder${watching.length === 1 ? "" : "s"} for mass file encryption.`,
      recommendation: "No action needed."
    };
  }

  // Open alerts become scored threats through the scanner's existing penalty path, so the weights
  // and the cap stay in one place.
  async function penaltyThreats() {
    const alerts = await store.shieldAlerts.all(ALERT_LIMIT);

    return alerts
      .filter(alert => alert.status === "open")
      .map(alert => ({ filePath: alert.folder, severity: alert.severity }));
  }

  async function listAlerts({ status: wanted = null, limit = 50 } = {}) {
    await ready;
    const alerts = await store.shieldAlerts.all(ALERT_LIMIT);
    const cap = Math.max(1, Math.min(Number(limit) || 50, ALERT_LIMIT));

    return alerts
      .filter(alert => !wanted || alert.status === wanted)
      .slice(0, cap)
      .map(view);
  }

  async function getAlert(id, callerKey = null) {
    await ready;
    const alert = await store.shieldAlerts.get(id);
    if (!alert) throw config.httpError("Alert not found.", 404);

    const result = { alert: view(alert) };
    if (callerKey && alert.status !== "dismissed") Object.assign(result, issueConfirmToken(id, callerKey));
    return result;
  }

  // ---- settings --------------------------------------------------------------------------------

  function updateSettings(patch) {
    return enqueue(async () => {
      await ready;
      const next = config.applySettingsPatch(settings, patch, { home });

      if (next.enabled && !supported) {
        throw config.httpError("The shield cannot run on this platform.", 400);
      }

      const wasEnabled = settings.enabled;
      await saveSettings(next);
      await startEngine();

      if (wasEnabled !== next.enabled) {
        await record({ message: next.enabled ? "Ransomware shield turned on." : "Ransomware shield turned off." });
      } else {
        await record({ message: "Ransomware shield settings changed." });
      }

      onChange();
    }).then(() => status());
  }

  // ---- actions ---------------------------------------------------------------------------------

  function normalizeActions(actions) {
    if (!Array.isArray(actions) || !actions.length) {
      throw config.httpError('actions must list at least one of: "stop-suspect", "isolate-network".', 400);
    }

    const unique = [...new Set(actions)];

    for (const type of unique) {
      if (!ACTION_TYPES.includes(type)) throw config.httpError(`Unknown action: ${type}`, 400);
    }

    return unique;
  }

  async function isolate() {
    const listed = await network.list();

    if (!listed.ok) {
      return { ok: false, interfaces: [], message: `Network connections could not be read: ${listed.message}` };
    }

    const targets = listed.interfaces.filter(item => item.enabled).map(item => item.name);

    if (!targets.length) {
      return { ok: true, interfaces: [], message: "No active network connections needed turning off." };
    }

    const results = await network.disable(targets);
    const changed = results.filter(item => item.ok).length;

    return {
      ok: changed === results.length,
      partial: changed > 0 && changed < results.length,
      needsElevation: results.some(item => item.needsElevation),
      interfaces: results.map(item => ({
        name: item.name,
        priorEnabled: true,
        ok: item.ok,
        message: item.message,
        restoredAt: null
      })),
      message:
        changed === results.length
          ? `Turned off ${changed} network connection${changed === 1 ? "" : "s"}.`
          : `Turned off ${changed} of ${results.length} network connections.`
    };
  }

  function contain(id, { actions, confirmToken, callerKey, remote = false, callerLabel = "unknown caller" } = {}) {
    return enqueue(async () => {
      await ready;
      const wanted = normalizeActions(actions);
      const alert = await store.shieldAlerts.get(id);
      if (!alert) throw config.httpError("Alert not found.", 404);
      if (alert.status === "dismissed") throw config.httpError("This alert was dismissed.", 409);

      const finished = new Set(
        (alert.actions || []).filter(action => action.ok && !action.undoneAt).map(action => action.type)
      );

      if (alert.status === "contained" && wanted.every(type => finished.has(type))) {
        return { alert: view(alert), results: [], alreadyDone: true };
      }

      if (remote && !settings.allowRemoteContain) {
        await record({ message: `Remote Contain refused for ${alert.folder} (${callerLabel}): turned off on this computer.`, severity: "high" });
        throw config.httpError("Remote Contain is turned off on this computer. Use the protected computer.", 403);
      }

      try {
        noteAttempt(id);
        consumeToken(confirmToken, id, callerKey);
      } catch (error) {
        await record({ message: `Contain refused for ${alert.folder} (${callerLabel}): ${error.message}`, severity: "high" });
        throw error;
      }

      const results = [];
      alert.actions = alert.actions || [];
      alert.pendingApproval = (alert.pendingApproval || []).filter(type => !wanted.includes(type));

      for (const type of wanted) {
        if (finished.has(type)) continue;

        if (type === "stop-suspect") {
          const outcome = alert.suspect
            ? await processes.stop(alert.suspect)
            : { ok: false, message: "No suspect was identified, so nothing was stopped." };

          results.push({ type, ...outcome });
          alert.actions.push({ type, at: iso(), ok: Boolean(outcome.ok), message: outcome.message || null, by: callerLabel });
          continue;
        }

        if (remote) {
          // Turning the network off needs an administrator prompt, and that has to be answered on
          // the protected computer. Nothing is claimed as done.
          results.push({
            type,
            ok: false,
            pending: true,
            needsElevation: true,
            message: "Approve this on the protected computer."
          });
          alert.pendingApproval.push(type);
          continue;
        }

        const outcome = await isolate();
        const restoreAt =
          outcome.interfaces.some(item => item.ok) && settings.autoRestoreMinutes
            ? new Date(now() + settings.autoRestoreMinutes * 60000).toISOString()
            : null;

        results.push({ type, ...outcome, restoreAt });
        alert.actions.push({
          type,
          at: iso(),
          ok: Boolean(outcome.ok),
          partial: Boolean(outcome.partial),
          message: outcome.message,
          by: callerLabel,
          interfaces: outcome.interfaces,
          restoreAt,
          undoneAt: null
        });

        if (restoreAt) scheduleRestore(id, restoreAt);
      }

      const didSomething = alert.actions.some(action => (action.ok || action.partial) && !action.undoneAt);

      if (didSomething && alert.status === "open") {
        alert.status = "contained";
        alert.containedAt = iso();
        detect.close(alert.folder, now());
      }

      alert.updatedAt = iso();
      await store.shieldAlerts.upsert(alert);

      for (const result of results) {
        await record({
          message: `Contain (${result.type}) for ${alert.folder} by ${callerLabel}: ${result.message}`,
          severity: result.ok ? "medium" : "high"
        });
      }

      onChange();
      return { alert: view(alert), results };
    });
  }

  function undo(id, { action = "isolate-network", auto = false, callerLabel = "unknown caller" } = {}) {
    return enqueue(async () => {
      await ready;
      if (action !== "isolate-network") {
        throw config.httpError("Only isolate-network can be undone. A stopped program cannot be restarted by CampusShield.", 400);
      }

      const alert = await store.shieldAlerts.get(id);
      if (!alert) throw config.httpError("Alert not found.", 404);

      const isolation = activeIsolation(alert);

      if (!isolation) {
        return { alert: view(alert), result: { type: action, ok: true, interfaces: [], message: "There is nothing to restore." } };
      }

      const names = isolation.interfaces.filter(item => item.ok && !item.restoredAt).map(item => item.name);
      const results = await network.enable(names);
      const stamp = iso();

      for (const outcome of results) {
        const item = isolation.interfaces.find(entry => entry.name === outcome.name);
        if (outcome.ok && item) {
          item.restoredAt = stamp;
          item.message = "Connected again.";
        }
      }

      const allBack = results.every(outcome => outcome.ok);

      if (allBack) {
        isolation.undoneAt = stamp;
        clearRestoreTimer(id);
      }

      alert.updatedAt = stamp;
      await store.shieldAlerts.upsert(alert);

      const message = allBack
        ? "Network connections restored."
        : "Some connections could not be restored. Approve the administrator prompt on this computer, or use the recovery steps shown.";

      await record({
        message: `${auto ? "Auto-restore" : "Restore network"} for ${alert.folder} by ${auto ? "the restore timer" : callerLabel}: ${message}`,
        severity: allBack ? "medium" : "high"
      });

      onChange();

      return {
        alert: view(alert),
        result: { type: action, ok: allBack, interfaces: results, message }
      };
    });
  }

  function keepIsolated(id, { callerLabel = "unknown caller" } = {}) {
    return enqueue(async () => {
      await ready;
      const alert = await store.shieldAlerts.get(id);
      if (!alert) throw config.httpError("Alert not found.", 404);

      const isolation = activeIsolation(alert);
      if (!isolation) throw config.httpError("This alert has no active network isolation.", 409);

      isolation.restoreAt = null;
      clearRestoreTimer(id);
      alert.updatedAt = iso();
      await store.shieldAlerts.upsert(alert);
      await record({ message: `Auto-restore cancelled for ${alert.folder} by ${callerLabel}. The network stays off until restored.`, severity: "high" });
      onChange();

      return { alert: view(alert) };
    });
  }

  function dismiss(id, { reason = "", ignoreHours = 0, callerLabel = "unknown caller" } = {}) {
    return enqueue(async () => {
      await ready;
      const alert = await store.shieldAlerts.get(id);
      if (!alert) throw config.httpError("Alert not found.", 404);
      if (alert.status === "dismissed") return { alert: view(alert) };

      const hours = Number(ignoreHours) || 0;
      if (hours < 0 || hours > 168) throw config.httpError("ignoreHours must be between 0 and 168.", 400);

      alert.status = "dismissed";
      alert.dismissedAt = iso();
      alert.dismissReason = String(reason || "").slice(0, 200) || null;
      alert.updatedAt = alert.dismissedAt;
      await store.shieldAlerts.upsert(alert);
      detect.close(alert.folder, now());

      if (hours > 0) {
        const next = {
          ...settings,
          ignoredFolders: { ...settings.ignoredFolders, [alert.folder]: new Date(now() + hours * 3600000).toISOString() }
        };
        await saveSettings(next);
      }

      await record({
        message: `Alert for ${alert.folder} dismissed as a false alarm by ${callerLabel}${hours ? `; folder ignored for ${hours}h` : ""}.`
      });

      onChange();
      return { alert: view(alert) };
    });
  }

  function close() {
    closed = true;
    stopEngine();
    for (const id of [...timers.keys()]) clearRestoreTimer(id);
  }

  return {
    ready,
    status,
    postureCheck,
    penaltyThreats,
    updateSettings,
    listAlerts,
    getAlert,
    contain,
    undo,
    keepIsolated,
    dismiss,
    close,
    // exposed for tests and for the route layer
    isSupported: () => supported,
    allowRemoteContain: () => Boolean(settings?.allowRemoteContain)
  };
}

module.exports = { createShieldService, isIsolationActive, activeIsolation, LIMITS, ACTION_TYPES };
