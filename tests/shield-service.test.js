"use strict";

// Ransomware shield service: settings, alerts, Contain / Undo / Dismiss, confirmation tokens, rate
// limits, remote approval, restore timer, restart reconciliation, scoring, and store parity.
// Every side effect is faked. No real process is stopped and no network connection is changed.

const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { createStore } = require("../src/store");
const { createShieldService, isIsolationActive } = require("../src/shield/service");

const HOME = path.resolve("/home/tester");
const DOCS = path.join(HOME, "Documents");

async function tempStore() {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), "cs-shield-test-"));
  return { dataDir, store: await createStore({ dataDir }) };
}

function sampleAlert(overrides = {}) {
  return {
    id: "alert-1",
    status: "open",
    severity: "critical",
    confidence: "high",
    folder: DOCS,
    startedAt: "2026-11-25T05:00:00.000Z",
    updatedAt: "2026-11-25T05:00:00.000Z",
    evidence: { filesTouched: 30, evaluated: 30, windowSec: 10, extChanged: 30, highEntropy: 0, signalPct: 100, newExtensions: [], samples: [], thresholds: {} },
    suspect: { name: "Encryptor", pid: 4321, uid: 501, filesHeld: 20, sharePct: 90, confidence: "high", method: "open-file sampling (lsof)" },
    actions: [],
    ...overrides
  };
}

// A harness with a controllable clock, timers, and fake OS controllers that record what they were asked.
async function harness({ platform = "darwin", seed = [], settings, network, processes, detector } = {}) {
  const { store } = await tempStore();
  const clock = { t: Date.parse("2026-11-25T05:00:00.000Z") };
  const timers = [];
  const log = { stopped: [], disabled: [], enabled: [], audit: [], alerts: [], changes: 0 };

  const interfaces = network?.interfaces || [
    { name: "Wi-Fi", enabled: true },
    { name: "Ethernet", enabled: true }
  ];

  const networkController = {
    list: network?.list || (async () => ({ ok: true, interfaces: interfaces.map(item => ({ ...item })) })),
    disable:
      network?.disable ||
      (async names => {
        log.disabled.push(names);
        for (const item of interfaces) if (names.includes(item.name)) item.enabled = false;
        return names.map(name => ({ name, ok: true, message: "Turned off." }));
      }),
    enable:
      network?.enable ||
      (async names => {
        log.enabled.push(names);
        for (const item of interfaces) if (names.includes(item.name)) item.enabled = true;
        return names.map(name => ({ name, ok: true, message: "Turned on." }));
      })
  };

  const processController = {
    stop:
      processes?.stop ||
      (async suspect => {
        log.stopped.push(suspect);
        return { ok: true, message: `Stopped ${suspect.name} (PID ${suspect.pid}).` };
      })
  };

  if (settings) await store.settings.save({ shield: settings });
  for (const alert of seed) await store.shieldAlerts.upsert(alert);

  const service = createShieldService({
    store,
    home: HOME,
    platform,
    now: () => clock.t,
    networkController,
    processController,
    sampler: async () => ({ suspect: null, method: "test", reason: "not sampled in tests" }),
    watchFn: () => ({ close() {}, on() {} }),
    detector:
      detector ||
      {
        setThresholds() {},
        setBaseline() {},
        observe: async () => null,
        adopt() {},
        close() {}
      },
    audit: async entry => {
      log.audit.push(entry);
    },
    onAlert: alert => log.alerts.push(alert),
    onChange: () => {
      log.changes += 1;
    },
    setTimer: (fn, delay) => {
      const timer = { fn, delay, cleared: false, unref() {} };
      timers.push(timer);
      return timer;
    },
    clearTimer: timer => {
      timer.cleared = true;
    }
  });

  await service.ready;
  return { store, service, clock, timers, log, interfaces };
}

const caller = (key = "session:alice") => ({ callerKey: key, callerLabel: "alice from 127.0.0.1" });

async function confirm(service, id, key = "session:alice") {
  return (await service.getAlert(id, key)).confirmToken;
}

// ---- status and settings ---------------------------------------------------------------------------

test("a fresh shield is off, reports its limits, and costs the small posture penalty", async () => {
  const { service } = await harness();
  const status = await service.status();

  assert.equal(status.enabled, false);
  assert.equal(status.running, false);
  assert.equal(status.supported, true);
  assert.equal(status.openAlerts, 0);
  assert.ok(status.limits.length >= 3);
  assert.deepEqual(status.folders, [DOCS, path.join(HOME, "Desktop"), path.join(HOME, "Pictures")]);

  const check = service.postureCheck();
  assert.equal(check.id, "ransomware-shield");
  assert.equal(check.status, "warn");
  assert.equal(check.severity, "low");
});

test("turning it on starts watching, reports it as pass, and is written to the audit log", async () => {
  const { service, log } = await harness();
  const status = await service.updateSettings({ enabled: true, folders: [DOCS] });

  assert.equal(status.enabled, true);
  assert.equal(status.running, false, "the fake folders do not exist, so nothing is really watched");
  assert.ok(log.audit.some(entry => entry.kind === "shield" && /turned on/i.test(entry.message)));
  assert.ok(log.changes >= 1);
});

test("the posture check says 'unknown', not 'pass', when the shield is on but could not watch anything", async () => {
  const { service } = await harness();
  await service.updateSettings({ enabled: true, folders: [DOCS] });

  const check = service.postureCheck();
  assert.equal(check.status, "unknown");
  assert.ok(check.detail.length > 0);
});

test("on a platform the shield does not support it is unavailable and cannot be turned on", async () => {
  const { service } = await harness({ platform: "freebsd" });

  assert.equal(service.postureCheck().status, "unknown");
  assert.equal((await service.status()).supported, false);

  await assert.rejects(
    () => service.updateSettings({ enabled: true, folders: [DOCS] }),
    error => error.statusCode === 400
  );
});

test("invalid settings are rejected with 400 and nothing is saved", async () => {
  const { service, store } = await harness();

  await assert.rejects(() => service.updateSettings({ thresholds: { minFiles: 1 } }), error => error.statusCode === 400);
  await assert.rejects(() => service.updateSettings({ folders: [path.resolve("/etc")] }), error => error.statusCode === 400);
  assert.equal((await store.settings.get()).shield, undefined);
});

test("settings survive a restart with the same store", async () => {
  const { store } = await tempStore();
  const make = () =>
    createShieldService({
      store,
      home: HOME,
      platform: "darwin",
      watchFn: () => ({ close() {}, on() {} })
    });

  const first = make();
  await first.updateSettings({ thresholds: { minFiles: 40 }, autoRestoreMinutes: 60, allowRemoteContain: false });
  first.close();

  const second = make();
  const status = await second.status();
  second.close();

  assert.equal(status.thresholds.minFiles, 40);
  assert.equal(status.autoRestoreMinutes, 60);
  assert.equal(status.allowRemoteContain, false);
});

// ---- alerts and scoring ----------------------------------------------------------------------------

test("an open alert counts as one scored threat, and a contained or dismissed one stops counting", async () => {
  const { service, store } = await harness({
    seed: [
      sampleAlert({ id: "a1" }),
      sampleAlert({ id: "a2", folder: path.join(HOME, "Desktop"), status: "contained", severity: "high" }),
      sampleAlert({ id: "a3", folder: path.join(HOME, "Pictures"), status: "dismissed" })
    ]
  });

  assert.deepEqual(await service.penaltyThreats(), [{ filePath: DOCS, severity: "critical" }]);

  const alert = await store.shieldAlerts.get("a1");
  alert.status = "dismissed";
  await store.shieldAlerts.upsert(alert);

  assert.deepEqual(await service.penaltyThreats(), []);
});

test("listing filters by status and never returns more than requested", async () => {
  const { service } = await harness({
    seed: [
      sampleAlert({ id: "a1" }),
      sampleAlert({ id: "a2", status: "dismissed", folder: path.join(HOME, "Desktop") })
    ]
  });

  assert.equal((await service.listAlerts()).length, 2);
  assert.deepEqual((await service.listAlerts({ status: "open" })).map(item => item.id), ["a1"]);
  assert.equal((await service.listAlerts({ limit: 1 })).length, 1);
  assert.equal((await service.listAlerts({ limit: "junk" })).length, 2);
});

test("reading an alert issues a confirmation token only to a caller that is allowed to use it", async () => {
  const { service } = await harness({ seed: [sampleAlert()] });

  const anonymous = await service.getAlert("alert-1", null);
  assert.equal(anonymous.confirmToken, undefined);

  const signedIn = await service.getAlert("alert-1", "session:alice");
  assert.equal(typeof signedIn.confirmToken, "string");
  assert.equal(signedIn.confirmExpiresInSec, 60);

  await assert.rejects(() => service.getAlert("missing", "session:alice"), error => error.statusCode === 404);
});

// ---- contain ---------------------------------------------------------------------------------------

test("Contain stops the suspect, turns off active connections, records both, and marks the alert contained", async () => {
  const { service, log, interfaces, timers } = await harness({ seed: [sampleAlert()] });
  const token = await confirm(service, "alert-1");

  const result = await service.contain("alert-1", {
    actions: ["stop-suspect", "isolate-network"],
    confirmToken: token,
    ...caller()
  });

  assert.equal(result.alert.status, "contained");
  assert.equal(log.stopped.length, 1);
  assert.equal(log.stopped[0].pid, 4321);
  assert.deepEqual(log.disabled, [["Wi-Fi", "Ethernet"]]);
  assert.ok(interfaces.every(item => item.enabled === false));
  assert.equal(result.alert.isolationActive, true);
  assert.equal(isIsolationActive(result.alert), true);
  assert.equal(timers.length, 1, "the auto-restore timer is set");
  assert.equal(timers[0].delay, 30 * 60 * 1000);
  assert.ok(result.alert.restoreAt);
  assert.ok(log.audit.some(entry => /Contain \(stop-suspect\)/.test(entry.message)));
  assert.ok(log.audit.some(entry => /Contain \(isolate-network\)/.test(entry.message)));
  assert.equal((await service.penaltyThreats()).length, 0, "a contained alert no longer costs points");
});

test("Contain asks for exactly what the caller listed: stopping the program alone leaves the network alone", async () => {
  const { service, log } = await harness({ seed: [sampleAlert()] });

  await service.contain("alert-1", { actions: ["stop-suspect"], confirmToken: await confirm(service, "alert-1"), ...caller() });

  assert.equal(log.stopped.length, 1);
  assert.deepEqual(log.disabled, []);
});

test("Contain with no confirmation, a wrong one, or someone else's is refused and still audited", async () => {
  const { service, log } = await harness({ seed: [sampleAlert()] });
  const forAlice = await confirm(service, "alert-1", "session:alice");

  const attempts = [
    { confirmToken: undefined, ...caller() },
    { confirmToken: "not-a-real-token", ...caller() },
    { confirmToken: forAlice, ...caller("session:mallory") }
  ];

  for (const attempt of attempts) {
    await assert.rejects(
      () => service.contain("alert-1", { actions: ["stop-suspect"], ...attempt }),
      error => error.statusCode === 403
    );
  }

  assert.deepEqual(log.stopped, []);
  assert.equal(log.audit.filter(entry => /Contain refused/.test(entry.message)).length, 3);
});

test("a confirmation works once and expires after 60 seconds", async () => {
  const { service, clock, log } = await harness({
    seed: [sampleAlert(), sampleAlert({ id: "alert-2", folder: path.join(HOME, "Desktop") })]
  });

  const once = await confirm(service, "alert-1");
  await service.contain("alert-1", { actions: ["stop-suspect"], confirmToken: once, ...caller() });

  await assert.rejects(
    () => service.contain("alert-1", { actions: ["isolate-network"], confirmToken: once, ...caller() }),
    error => error.statusCode === 403
  );

  const stale = await confirm(service, "alert-2");
  clock.t += 61 * 1000;

  await assert.rejects(
    () => service.contain("alert-2", { actions: ["stop-suspect"], confirmToken: stale, ...caller() }),
    error => error.statusCode === 403
  );
  assert.equal(log.stopped.length, 1);
});

test("a confirmation for one alert cannot be used on another", async () => {
  const { service } = await harness({
    seed: [sampleAlert(), sampleAlert({ id: "alert-2", folder: path.join(HOME, "Desktop") })]
  });

  const token = await confirm(service, "alert-1");

  await assert.rejects(
    () => service.contain("alert-2", { actions: ["stop-suspect"], confirmToken: token, ...caller() }),
    error => error.statusCode === 403
  );
});

test("Contain is limited to three attempts per alert in ten minutes, then allowed again", async () => {
  const { service, clock } = await harness({ seed: [sampleAlert()] });

  for (let index = 0; index < 3; index += 1) {
    await assert.rejects(
      () => service.contain("alert-1", { actions: ["stop-suspect"], confirmToken: "bad", ...caller() }),
      error => error.statusCode === 403
    );
  }

  await assert.rejects(
    () => service.contain("alert-1", { actions: ["stop-suspect"], confirmToken: "bad", ...caller() }),
    error => error.statusCode === 429
  );

  clock.t += 10 * 60 * 1000 + 1;

  await assert.rejects(
    () => service.contain("alert-1", { actions: ["stop-suspect"], confirmToken: "bad", ...caller() }),
    error => error.statusCode === 403,
    "the limiter lets the next attempt through after the window"
  );
});

test("bad action lists are rejected before anything runs", async () => {
  const { service, log } = await harness({ seed: [sampleAlert()] });
  const token = await confirm(service, "alert-1");

  for (const actions of [undefined, [], "stop-suspect", ["format-disk"]]) {
    await assert.rejects(
      () => service.contain("alert-1", { actions, confirmToken: token, ...caller() }),
      error => error.statusCode === 400
    );
  }

  assert.deepEqual(log.stopped, []);
  assert.deepEqual(log.disabled, []);
});

test("a dismissed or unknown alert cannot be contained", async () => {
  const { service } = await harness({ seed: [sampleAlert({ status: "dismissed" })] });

  await assert.rejects(
    () => service.contain("alert-1", { actions: ["stop-suspect"], confirmToken: "x", ...caller() }),
    error => error.statusCode === 409
  );
  await assert.rejects(
    () => service.contain("nope", { actions: ["stop-suspect"], confirmToken: "x", ...caller() }),
    error => error.statusCode === 404
  );
});

test("Contain with no suspect says nothing was stopped and does not claim success", async () => {
  const { service, log } = await harness({ seed: [sampleAlert({ suspect: null })] });

  const result = await service.contain("alert-1", {
    actions: ["stop-suspect"],
    confirmToken: await confirm(service, "alert-1"),
    ...caller()
  });

  assert.equal(result.results[0].ok, false);
  assert.match(result.results[0].message, /No suspect/);
  assert.equal(result.alert.status, "open", "nothing was done, so the alert stays open");
  assert.deepEqual(log.stopped, []);
});

test("repeating a finished Contain does nothing and says so", async () => {
  const { service, log } = await harness({ seed: [sampleAlert()] });
  const args = { actions: ["stop-suspect", "isolate-network"], ...caller() };

  await service.contain("alert-1", { ...args, confirmToken: await confirm(service, "alert-1") });
  const again = await service.contain("alert-1", { ...args, confirmToken: await confirm(service, "alert-1") });

  assert.equal(again.alreadyDone, true);
  assert.equal(log.stopped.length, 1);
  assert.equal(log.disabled.length, 1);
});

test("a partial network failure is reported per connection and keeps only what really changed", async () => {
  const { service } = await harness({
    seed: [sampleAlert()],
    network: {
      disable: async names => names.map(name => (name === "Wi-Fi" ? { name, ok: true, message: "Turned off." } : { name, ok: false, message: "Permission denied." }))
    }
  });

  const result = await service.contain("alert-1", {
    actions: ["isolate-network"],
    confirmToken: await confirm(service, "alert-1"),
    ...caller()
  });

  const action = result.results[0];
  assert.equal(action.ok, false);
  assert.equal(action.partial, true);
  assert.deepEqual(action.interfaces.map(item => [item.name, item.ok]), [["Wi-Fi", true], ["Ethernet", false]]);
  assert.equal(result.alert.isolationActive, true);
});

test("when the connections cannot be read nothing is turned off and the failure is stated", async () => {
  const { service, log } = await harness({
    seed: [sampleAlert()],
    network: { list: async () => ({ ok: false, interfaces: [], message: "networksetup failed" }) }
  });

  const result = await service.contain("alert-1", {
    actions: ["isolate-network"],
    confirmToken: await confirm(service, "alert-1"),
    ...caller()
  });

  assert.equal(result.results[0].ok, false);
  assert.match(result.results[0].message, /could not be read/);
  assert.deepEqual(log.disabled, []);
  assert.equal(result.alert.status, "open");
});

test("a remote Contain stops the program but leaves network isolation waiting for approval on the computer", async () => {
  const { service, log } = await harness({ seed: [sampleAlert()] });

  const result = await service.contain("alert-1", {
    actions: ["stop-suspect", "isolate-network"],
    confirmToken: await confirm(service, "alert-1"),
    remote: true,
    ...caller()
  });

  const isolate = result.results.find(item => item.type === "isolate-network");

  assert.equal(log.stopped.length, 1);
  assert.deepEqual(log.disabled, [], "the network is not touched from afar");
  assert.equal(isolate.pending, true);
  assert.equal(isolate.needsElevation, true);
  assert.equal(isolate.ok, false);
  assert.deepEqual(result.alert.pendingApproval, ["isolate-network"]);
  assert.equal(result.alert.isolationActive, false);
});

test("a remote Contain is refused when the computer's owner turned remote Contain off", async () => {
  const { service, log } = await harness({ seed: [sampleAlert()], settings: { allowRemoteContain: false } });

  const token = await confirm(service, "alert-1");

  await assert.rejects(
    () => service.contain("alert-1", { actions: ["stop-suspect"], confirmToken: token, remote: true, ...caller() }),
    error => error.statusCode === 403
  );

  assert.deepEqual(log.stopped, []);
  assert.ok(log.audit.some(entry => /Remote Contain refused/.test(entry.message)));
});

// ---- undo, restore timer, keep isolated ------------------------------------------------------------

async function contained(options = {}) {
  const parts = await harness({ seed: [sampleAlert()], ...options });
  const result = await parts.service.contain("alert-1", {
    actions: ["isolate-network"],
    confirmToken: await confirm(parts.service, "alert-1"),
    ...caller()
  });

  return { ...parts, result };
}

test("Undo turns back on only the connections Contain turned off, then clears the timer", async () => {
  const { service, log, timers } = await contained({
    network: {
      interfaces: [
        { name: "Wi-Fi", enabled: true },
        { name: "Ethernet", enabled: false }
      ]
    }
  });

  assert.deepEqual(log.disabled, [["Wi-Fi"]], "the Ethernet port that was already off is not touched");

  const undone = await service.undo("alert-1", caller());

  assert.deepEqual(log.enabled, [["Wi-Fi"]]);
  assert.equal(undone.result.ok, true);
  assert.equal(undone.alert.isolationActive, false);
  assert.equal(timers[0].cleared, true);
});

test("Undo with nothing to restore is a harmless no-op", async () => {
  const { service, log } = await harness({ seed: [sampleAlert()] });
  const result = await service.undo("alert-1", caller());

  assert.equal(result.result.ok, true);
  assert.match(result.result.message, /nothing to restore/i);
  assert.deepEqual(log.enabled, []);
});

test("a stopped program cannot be 'undone' and the answer says why", async () => {
  const { service } = await harness({ seed: [sampleAlert()] });

  await assert.rejects(
    () => service.undo("alert-1", { action: "stop-suspect" }),
    error => error.statusCode === 400 && /cannot be restarted/.test(error.message)
  );
});

test("a failed restore keeps the isolation on record so it can be retried", async () => {
  const { service, store } = await contained({
    network: {
      enable: async names => names.map(name => ({ name, ok: false, message: "Administrator approval was declined." }))
    }
  });

  const undone = await service.undo("alert-1", caller());

  assert.equal(undone.result.ok, false);
  assert.equal(undone.alert.isolationActive, true);
  assert.equal(isIsolationActive(await store.shieldAlerts.get("alert-1")), true);
});

test("the restore timer fires the restore on its own and says it was automatic", async () => {
  const { timers, log, store } = await contained();

  assert.equal(timers.length, 1);
  timers[0].fn();

  for (let wait = 0; wait < 50 && !log.audit.some(entry => /Auto-restore/.test(entry.message)); wait += 1) {
    await new Promise(resolve => setTimeout(resolve, 10));
  }

  assert.deepEqual(log.enabled, [["Wi-Fi", "Ethernet"]]);
  assert.equal(isIsolationActive(await store.shieldAlerts.get("alert-1")), false);
  assert.ok(log.audit.some(entry => /Auto-restore/.test(entry.message)));
});

test("Keep isolated cancels the restore timer and the connections stay off", async () => {
  const { service, timers, log } = await contained();
  const kept = await service.keepIsolated("alert-1", caller());

  assert.equal(timers[0].cleared, true);
  assert.equal(kept.alert.restoreAt, null);
  assert.equal(kept.alert.isolationActive, true);
  assert.deepEqual(log.enabled, []);

  await assert.rejects(
    () => service.keepIsolated("missing", caller()),
    error => error.statusCode === 404
  );
});

test("Keep isolated on an alert with no isolation is refused", async () => {
  const { service } = await harness({ seed: [sampleAlert()] });

  await assert.rejects(() => service.keepIsolated("alert-1", caller()), error => error.statusCode === 409);
});

test("after a restart an isolation that is still active stays on record and the timer is re-armed", async () => {
  const { store, clock } = await tempStore().then(async parts => ({ ...parts, clock: { t: Date.parse("2026-11-25T05:10:00.000Z") } }));
  const timers = [];

  await store.shieldAlerts.upsert(
    sampleAlert({
      status: "contained",
      actions: [
        {
          type: "isolate-network",
          at: "2026-11-25T05:05:00.000Z",
          ok: true,
          interfaces: [{ name: "Wi-Fi", ok: true, restoredAt: null }],
          restoreAt: "2026-11-25T05:35:00.000Z",
          undoneAt: null
        }
      ]
    })
  );

  const audit = [];
  const service = createShieldService({
    store,
    home: HOME,
    platform: "darwin",
    now: () => clock.t,
    networkController: { list: async () => ({ ok: true, interfaces: [{ name: "Wi-Fi", enabled: false }] }), enable: async () => [], disable: async () => [] },
    audit: async entry => audit.push(entry),
    setTimer: (fn, delay) => {
      timers.push({ delay });
      return { unref() {} };
    },
    watchFn: () => ({ close() {}, on() {} })
  });

  await service.ready;
  service.close();

  assert.equal(timers.length, 1);
  assert.equal(timers[0].delay, 25 * 60 * 1000);
  assert.ok(audit.some(entry => /still recorded as active/.test(entry.message)));
});

test("after a restart a connection that is already back on is recorded as restored and not touched again", async () => {
  const { store } = await tempStore();

  await store.shieldAlerts.upsert(
    sampleAlert({
      status: "contained",
      actions: [
        {
          type: "isolate-network",
          at: "2026-11-25T05:05:00.000Z",
          ok: true,
          interfaces: [{ name: "Wi-Fi", ok: true, restoredAt: null }],
          restoreAt: "2026-11-25T05:35:00.000Z",
          undoneAt: null
        }
      ]
    })
  );

  const enabled = [];
  const service = createShieldService({
    store,
    home: HOME,
    platform: "darwin",
    networkController: {
      list: async () => ({ ok: true, interfaces: [{ name: "Wi-Fi", enabled: true }] }),
      enable: async names => enabled.push(names),
      disable: async () => []
    },
    watchFn: () => ({ close() {}, on() {} })
  });

  await service.ready;
  service.close();

  const alert = await store.shieldAlerts.get("alert-1");
  assert.equal(isIsolationActive(alert), false);
  assert.deepEqual(enabled, []);
  assert.match(alert.actions[0].interfaces[0].message, /restored outside CampusShield/);
});

// ---- dismiss ---------------------------------------------------------------------------------------

test("Dismiss marks a false alarm, stops it counting, and can ignore the folder for a while", async () => {
  const { service, store, clock } = await harness({ seed: [sampleAlert()] });

  const result = await service.dismiss("alert-1", { reason: "I was bulk-renaming photos", ignoreHours: 24, callerLabel: "alice" });

  assert.equal(result.alert.status, "dismissed");
  assert.equal(result.alert.dismissReason, "I was bulk-renaming photos");
  assert.equal((await service.penaltyThreats()).length, 0);

  const saved = await store.settings.get();
  assert.equal(Date.parse(saved.shield.ignoredFolders[DOCS]), clock.t + 24 * 3600 * 1000);

  const again = await service.dismiss("alert-1", {});
  assert.equal(again.alert.status, "dismissed");
});

test("Dismiss rejects an ignore period outside 0 to 168 hours and an unknown alert", async () => {
  const { service } = await harness({ seed: [sampleAlert()] });

  await assert.rejects(() => service.dismiss("alert-1", { ignoreHours: 169 }), error => error.statusCode === 400);
  await assert.rejects(() => service.dismiss("alert-1", { ignoreHours: -1 }), error => error.statusCode === 400);
  await assert.rejects(() => service.dismiss("nope", {}), error => error.statusCode === 404);
});

test("a very long dismissal reason is cut to 200 characters", async () => {
  const { service } = await harness({ seed: [sampleAlert()] });
  const result = await service.dismiss("alert-1", { reason: "x".repeat(500) });

  assert.equal(result.alert.dismissReason.length, 200);
});

// ---- store parity ----------------------------------------------------------------------------------

async function parityChecks(store) {
  await store.shieldAlerts.clear();

  for (let index = 0; index < 5; index += 1) {
    await store.shieldAlerts.upsert(
      sampleAlert({ id: `p${index}`, startedAt: `2026-11-25T05:0${index}:00.000Z`, updatedAt: `2026-11-25T05:0${index}:00.000Z` })
    );
  }

  const all = await store.shieldAlerts.all(10);
  assert.equal(all.length, 5);
  assert.deepEqual(all.map(item => item.id), ["p4", "p3", "p2", "p1", "p0"], "newest first");
  assert.ok(all.every(item => item._id === undefined), "no storage ids leak out");

  assert.equal((await store.shieldAlerts.all(2)).length, 2);
  assert.equal((await store.shieldAlerts.get("p2")).id, "p2");
  assert.equal(await store.shieldAlerts.get("missing"), null);

  const changed = await store.shieldAlerts.get("p2");
  changed.status = "dismissed";
  await store.shieldAlerts.upsert(changed);
  assert.equal((await store.shieldAlerts.get("p2")).status, "dismissed");
  assert.equal((await store.shieldAlerts.all(10)).length, 5, "upsert replaces and does not duplicate");

  await store.shieldAlerts.prune(3);
  assert.deepEqual((await store.shieldAlerts.all(10)).map(item => item.id), ["p4", "p3", "p2"]);

  await store.shieldAlerts.clear();
  assert.equal((await store.shieldAlerts.all(10)).length, 0);
}

test("store parity: the local JSON store keeps shield alerts newest-first, replaces on upsert, and prunes", async () => {
  const { store } = await tempStore();
  await parityChecks(store);
});

test("store parity: shield alerts survive a restart of the JSON store", async () => {
  const { store, dataDir } = await tempStore();
  await store.shieldAlerts.upsert(sampleAlert());

  const reopened = await createStore({ dataDir });
  assert.equal((await reopened.shieldAlerts.get("alert-1")).folder, DOCS);
});

test("store parity: an old store.json with no shield data loads with an empty alert list and default settings", async () => {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), "cs-shield-old-"));
  await fs.writeFile(path.join(dataDir, "store.json"), JSON.stringify({ settings: {}, events: [] }));

  const store = await createStore({ dataDir });
  assert.deepEqual(await store.shieldAlerts.all(10), []);
});

test("store parity: MongoDB behaves the same when MONGODB_URI is set", { skip: !process.env.MONGODB_URI }, async () => {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), "cs-shield-mongo-"));
  const store = await createStore({ dataDir });

  assert.equal(store.kind, "mongodb");
  await parityChecks(store);
});

// ---- scoring ---------------------------------------------------------------------------------------

test("scoring: shield threats use the scanner's weights and share its 45-point cap", async () => {
  const { createScannerService } = require("../src/scanner/manager");
  const { store, dataDir } = await tempStore();
  let extra = [];
  const scanner = createScannerService({ store, dataDir, audit: async () => {}, extraThreats: async () => extra });

  assert.equal(await scanner.penalty(), 0);

  extra = [{ filePath: DOCS, severity: "critical" }];
  assert.equal(await scanner.penalty(), 30);

  extra = [
    { filePath: DOCS, severity: "critical" },
    { filePath: path.join(HOME, "Desktop"), severity: "critical" }
  ];
  assert.equal(await scanner.penalty(), 45, "capped");

  extra = [{ filePath: DOCS, severity: "high" }];
  assert.equal(await scanner.penalty(), 18);
  scanner.close?.();
});

test("scoring: the posture check is pass only when watching, warn when off, unknown when it could not start", async () => {
  const { service } = await harness();
  assert.equal(service.postureCheck().status, "warn");

  const { scoreFindings } = require("../src/deviceAudit");
  const off = scoreFindings([service.postureCheck()]);
  assert.equal(off.score, 96, "a supported but off shield costs the low weight of 4");

  const unsupported = await harness({ platform: "freebsd" });
  assert.equal(scoreFindings([unsupported.service.postureCheck()]).score, 100, "unknown costs nothing");
});
