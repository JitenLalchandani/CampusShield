"use strict";

// Ransomware shield: the pure rules. Nothing here touches the real file system watcher, a real
// process, or the network. Time, file bytes, and OS commands are all injected.

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const path = require("node:path");
const test = require("node:test");

const config = require("../src/shield/config");
const { shannonEntropy, looksEncrypted } = require("../src/shield/entropy");
const { createDetector, isNoisePath } = require("../src/shield/detector");
const {
  parseLsofFields,
  parseHandleOutput,
  chooseSuspect,
  isProtectedProcess,
  sampleSuspect
} = require("../src/shield/suspects");
const { createProcessController, createNetworkController, sameProgram } = require("../src/shield/controllers");
const { createShieldEngine, collectExtensions } = require("../src/shield/engine");

const HOME = path.resolve("/home/tester");
const DOCS = path.join(HOME, "Documents");

// ---- settings ------------------------------------------------------------------------------------

test("defaults are off, watch three folders in home, and use the approved thresholds", () => {
  const settings = config.defaultSettings(HOME);

  assert.equal(settings.enabled, false);
  assert.deepEqual(settings.folders, [DOCS, path.join(HOME, "Desktop"), path.join(HOME, "Pictures")]);
  assert.deepEqual(settings.thresholds, { minFiles: 25, windowSec: 10, minSignalPct: 60 });
  assert.equal(settings.autoRestoreMinutes, 30);
  assert.equal(settings.allowRemoteContain, true);
});

test("a settings patch is merged and the current settings are not changed", () => {
  const current = config.defaultSettings(HOME);
  const next = config.applySettingsPatch(current, { enabled: true, thresholds: { minFiles: 40 } }, { home: HOME });

  assert.equal(next.enabled, true);
  assert.equal(next.thresholds.minFiles, 40);
  assert.equal(next.thresholds.windowSec, 10);
  assert.equal(current.enabled, false);
  assert.equal(current.thresholds.minFiles, 25);
});

test("invalid settings are rejected with a 400 instead of being corrected", () => {
  const current = config.defaultSettings(HOME);
  const bad = [
    { enabled: "yes" },
    { allowRemoteContain: 1 },
    { thresholds: { minFiles: 9 } },
    { thresholds: { minFiles: 501 } },
    { thresholds: { windowSec: 2 } },
    { thresholds: { minSignalPct: 101 } },
    { thresholds: { minFiles: 25.5 } },
    { thresholds: { nonsense: 1 } },
    { autoRestoreMinutes: 4 },
    { autoRestoreMinutes: 241 },
    { folders: "Documents" },
    { folders: ["relative/path"] },
    { folders: [path.resolve("/etc")] },
    { folders: [HOME] },
    { exclusions: [`${DOCS}\0evil`] },
    { unknownKey: true }
  ];

  for (const patch of bad) {
    assert.throws(
      () => config.applySettingsPatch(current, patch, { home: HOME }),
      error => error.statusCode === 400,
      JSON.stringify(patch)
    );
  }

  assert.throws(() => config.applySettingsPatch(current, null, { home: HOME }), /object/);
});

test("folder rules: a path that climbs out of home is refused, duplicates collapse, and limits hold", () => {
  const current = config.defaultSettings(HOME);

  assert.throws(
    () => config.applySettingsPatch(current, { folders: [path.join(DOCS, "..", "..", "etc")] }, { home: HOME }),
    /inside your home folder/
  );

  const dupes = config.applySettingsPatch(current, { folders: [DOCS, DOCS, `${DOCS}/`] }, { home: HOME });
  assert.deepEqual(dupes.folders, [DOCS]);

  const eleven = Array.from({ length: 11 }, (_, index) => path.join(HOME, `f${index}`));
  assert.throws(() => config.applySettingsPatch(current, { folders: eleven }, { home: HOME }), /at most 10/);

  const fiftyOne = Array.from({ length: 51 }, (_, index) => path.join(DOCS, `x${index}`));
  assert.throws(() => config.applySettingsPatch(current, { exclusions: fiftyOne }, { home: HOME }), /at most 50/);
});

test("the shield cannot be turned on with no folders", () => {
  const current = config.defaultSettings(HOME);

  assert.throws(
    () => config.applySettingsPatch(current, { folders: [], enabled: true }, { home: HOME }),
    /at least one folder/
  );
  assert.equal(config.applySettingsPatch(current, { folders: [] }, { home: HOME }).enabled, false);
});

test("stored settings load leniently: missing key gives defaults, bad fields fall back one by one", () => {
  assert.deepEqual(config.normalizeStored(undefined, { home: HOME }), config.defaultSettings(HOME));
  assert.deepEqual(config.normalizeStored("junk", { home: HOME }), config.defaultSettings(HOME));

  const stored = config.normalizeStored(
    {
      enabled: true,
      folders: [path.resolve("/somewhere/else")],
      thresholds: { minFiles: 5 },
      autoRestoreMinutes: 60,
      ignoredFolders: { [DOCS]: "2030-01-01T00:00:00.000Z", [HOME]: "not a date" }
    },
    { home: HOME }
  );

  assert.equal(stored.enabled, true);
  assert.deepEqual(stored.folders, config.defaultFolders(HOME));
  assert.equal(stored.thresholds.minFiles, 25);
  assert.equal(stored.autoRestoreMinutes, 60);
  assert.deepEqual(Object.keys(stored.ignoredFolders), [DOCS]);
});

// ---- entropy -------------------------------------------------------------------------------------

test("entropy: plain text is low, random bytes are high, and short data is not judged", () => {
  const text = Buffer.from("The quick brown fox jumps over the lazy dog. ".repeat(40));
  const random = crypto.randomBytes(4096);

  assert.ok(shannonEntropy(text) < 5);
  assert.ok(shannonEntropy(random) > 7.5);
  assert.equal(looksEncrypted(text), false);
  assert.equal(looksEncrypted(random), true);
  assert.equal(looksEncrypted(Buffer.alloc(10, 1)), null);
  assert.equal(looksEncrypted(null), null);
  assert.equal(shannonEntropy(Buffer.alloc(0)), 0);
});

// ---- detector ------------------------------------------------------------------------------------

function makeDetector({ baseline = ["txt", "docx", "pdf"].map(ext => `.${ext}`), heads = {}, ...options } = {}) {
  const clock = { t: 1_000_000 };
  const detector = createDetector({
    now: () => clock.t,
    readHead: async file => heads[file] || null,
    evalThrottleMs: 0,
    ...options
  });

  if (baseline) detector.setBaseline(DOCS, baseline);
  return { detector, clock };
}

async function burst(detector, clock, { count, spacingMs = 100, ext = ".locked", prefix = "f" }) {
  let last = null;

  for (let index = 0; index < count; index += 1) {
    clock.t += spacingMs;
    const result = await detector.observe(DOCS, path.join(DOCS, `${prefix}${index}${ext}`));
    if (result) last = result;
  }

  return last;
}

test("detector: 24 files stay quiet and the 25th unfamiliar-extension file raises a critical alert", async () => {
  const { detector, clock } = makeDetector();

  assert.equal(await burst(detector, clock, { count: 24 }), null);

  clock.t += 100;
  const result = await detector.observe(DOCS, path.join(DOCS, "f24.locked"));

  assert.equal(result.kind, "alert");
  assert.equal(result.alert.severity, "critical");
  assert.equal(result.alert.confidence, "high");
  assert.equal(result.alert.folder, DOCS);
  assert.equal(result.alert.evidence.extChanged, 25);
  assert.deepEqual(result.alert.evidence.newExtensions, [{ ext: ".locked", count: 25 }]);
  assert.deepEqual(result.alert.evidence.thresholds, { minFiles: 25, windowSec: 10, minSignalPct: 60 });
});

test("detector: files spread over more than the window never count together", async () => {
  const { detector, clock } = makeDetector();

  // 25 files, but 1 second apart: only about 10 are ever inside a 10 second window.
  assert.equal(await burst(detector, clock, { count: 25, spacingMs: 1000 }), null);

  const fast = makeDetector();
  // 25 files in 9 seconds fires, which proves the window is what stopped the slow run.
  assert.ok(await burst(fast.detector, fast.clock, { count: 25, spacingMs: 360 }));
});

test("detector: the signal share must reach the threshold (56% is quiet, 60% fires)", async () => {
  const limits = { minFiles: 25, windowSec: 60, minSignalPct: 60 };

  async function run(unfamiliar, prefix) {
    const { detector, clock } = makeDetector({ thresholds: limits });
    let fired = null;

    for (let index = 0; index < 25; index += 1) {
      clock.t += 10;
      const ext = index < unfamiliar ? ".locked" : ".txt";
      fired = (await detector.observe(DOCS, path.join(DOCS, `${prefix}${index}${ext}`))) || fired;
    }

    return fired;
  }

  assert.equal(await run(14, "a"), null, "14 of 25 is 56%");

  const fired = await run(15, "b");
  assert.ok(fired, "15 of 25 is exactly 60%");
  assert.equal(fired.alert.evidence.signalPct, 60);
});

test("detector: a folder with no known baseline never uses the extension signal", async () => {
  const { detector, clock } = makeDetector({ baseline: null });

  assert.equal(await burst(detector, clock, { count: 40 }), null);

  const emptyBaseline = makeDetector({ baseline: [] });
  assert.equal(await burst(emptyBaseline.detector, emptyBaseline.clock, { count: 40 }), null);
});

test("detector: high-entropy plain-text files alone give a medium-confidence, high-severity alert", async () => {
  const heads = {};

  for (let index = 0; index < 30; index += 1) heads[path.join(DOCS, `n${index}.txt`)] = crypto.randomBytes(2048);

  const { detector, clock } = makeDetector({ heads });
  const result = await burst(detector, clock, { count: 30, ext: ".txt", prefix: "n" });

  assert.equal(result.alert.severity, "high");
  assert.equal(result.alert.confidence, "medium");
  assert.equal(result.alert.evidence.extChanged, 0);
  assert.ok(result.alert.evidence.highEntropy >= 18);
});

test("detector: many ordinary saves (known extensions, normal text) never fire", async () => {
  const heads = {};

  for (let index = 0; index < 60; index += 1) {
    heads[path.join(DOCS, `ok${index}.txt`)] = Buffer.from("plain notes about the semester ".repeat(30));
  }

  const { detector, clock } = makeDetector({ heads });
  assert.equal(await burst(detector, clock, { count: 60, ext: ".txt", prefix: "ok" }), null);
});

test("detector: noise folders and files are ignored", async () => {
  assert.equal(isNoisePath(path.join(DOCS, "proj", "node_modules", "a.js")), true);
  assert.equal(isNoisePath(path.join(DOCS, ".git", "objects", "ab")), true);
  assert.equal(isNoisePath(path.join(DOCS, ".DS_Store")), true);
  assert.equal(isNoisePath(path.join(DOCS, "essay.docx")), false);

  const { detector, clock } = makeDetector();

  for (let index = 0; index < 60; index += 1) {
    clock.t += 50;
    assert.equal(await detector.observe(DOCS, path.join(DOCS, "node_modules", `m${index}.locked`)), null);
  }
});

test("detector: one open alert per folder, later bursts only update it, and cooldown follows a close", async () => {
  const { detector, clock } = makeDetector();
  const first = await burst(detector, clock, { count: 25 });

  assert.equal(first.kind, "alert");
  const again = await burst(detector, clock, { count: 5, prefix: "g" });
  assert.equal(again.kind, "update");
  assert.equal(again.alert.id, first.alert.id);

  detector.close(DOCS, clock.t);
  assert.equal(await burst(detector, clock, { count: 30, prefix: "h" }), null, "inside the cooldown");

  clock.t += 5 * 60 * 1000 + 1;
  const afterCooldown = await burst(detector, clock, { count: 25, prefix: "i" });
  assert.equal(afterCooldown.kind, "alert");
  assert.notEqual(afterCooldown.alert.id, first.alert.id);
});

test("detector: an alert that was open at restart is adopted, so it is updated and not duplicated", async () => {
  const { detector, clock } = makeDetector();
  const existing = {
    id: "restored-1",
    status: "open",
    severity: "critical",
    confidence: "high",
    folder: DOCS,
    startedAt: new Date(clock.t).toISOString(),
    updatedAt: new Date(clock.t).toISOString(),
    evidence: { filesTouched: 30 },
    actions: []
  };

  detector.adopt(existing);
  const result = await burst(detector, clock, { count: 30 });

  assert.equal(result.kind, "update");
  assert.equal(result.alert.id, "restored-1");
});

test("detector: thresholds can be changed and the new values are shown in the evidence", async () => {
  const { detector, clock } = makeDetector();
  detector.setThresholds({ minFiles: 10, windowSec: 10, minSignalPct: 60 });

  const result = await burst(detector, clock, { count: 12 });
  assert.equal(result.alert.evidence.thresholds.minFiles, 10);
});

// ---- suspects ------------------------------------------------------------------------------------

test("lsof field output is parsed into programs with the number of files each holds", () => {
  const output = ["p100", "cEncryptor", "u501", "n/a/1", "n/a/2", "p200", "cPages", "u501", "n/a/3", "p300", "cidle", "u501"].join("\n");
  const parsed = parseLsofFields(output);

  assert.deepEqual(parsed, [
    { pid: 100, name: "Encryptor", uid: 501, files: 2 },
    { pid: 200, name: "Pages", uid: 501, files: 1 }
  ]);
  assert.deepEqual(parseLsofFields(""), []);
  assert.deepEqual(parseLsofFields("garbage\npx\n"), []);
});

test("handle.exe output is parsed per process", () => {
  const output = [
    "Nthandle v5.0",
    "",
    "evil.exe           pid: 4242   type: File           1C: C:\\Users\\t\\Documents\\a.docx",
    "   2C: File          C:\\Users\\t\\Documents\\a.docx",
    "   30: File          C:\\Users\\t\\Documents\\b.docx",
    "notepad.exe        pid: 77   type: File           10: C:\\Users\\t\\Documents\\c.txt"
  ].join("\r\n");

  const parsed = parseHandleOutput(output);
  const evil = parsed.find(entry => entry.pid === 4242);

  assert.ok(evil);
  assert.equal(evil.name, "evil.exe");
  assert.equal(evil.files, 2);
});

test("suspect choice: confidence follows the share of open files, and protected programs are skipped", () => {
  const options = { selfPid: 1, parentPid: 1 };
  const high = chooseSuspect(
    [
      { pid: 100, name: "Encryptor", uid: 1, files: 20 },
      { pid: 200, name: "Pages", uid: 1, files: 2 }
    ],
    options
  );

  assert.equal(high.suspect.name, "Encryptor");
  assert.equal(high.suspect.confidence, "high");
  assert.equal(high.suspect.sharePct, 91);

  const medium = chooseSuspect(
    [
      { pid: 100, name: "A", uid: 1, files: 4 },
      { pid: 200, name: "B", uid: 1, files: 3 },
      { pid: 300, name: "C", uid: 1, files: 3 }
    ],
    options
  );
  assert.equal(medium.suspect.confidence, "medium");

  const lowShare = chooseSuspect(
    [
      { pid: 100, name: "A", uid: 1, files: 3 },
      { pid: 200, name: "B", uid: 1, files: 3 },
      { pid: 300, name: "C", uid: 1, files: 3 },
      { pid: 400, name: "D", uid: 1, files: 3 }
    ],
    options
  );
  assert.equal(lowShare.suspect.confidence, "low");

  const systemOnly = chooseSuspect([{ pid: 50, name: "launchd", uid: 0, files: 40 }], options);
  assert.equal(systemOnly.suspect, null);
  assert.match(systemOnly.reason, /system programs/);

  const skipsSystem = chooseSuspect(
    [
      { pid: 50, name: "launchd", uid: 0, files: 40 },
      { pid: 60, name: "Encryptor", uid: 1, files: 10 }
    ],
    options
  );
  assert.equal(skipsSystem.suspect.name, "Encryptor");

  assert.equal(chooseSuspect([], options).suspect, null);
});

test("protected programs include init, this process, and its parent", () => {
  assert.equal(isProtectedProcess({ pid: 1, name: "x" }), true);
  assert.equal(isProtectedProcess({ pid: 999, name: "Finder" }, { selfPid: 5, parentPid: 6 }), true);
  assert.equal(isProtectedProcess({ pid: 5, name: "node" }, { selfPid: 5, parentPid: 6 }), true);
  assert.equal(isProtectedProcess({ pid: 6, name: "bash" }, { selfPid: 5, parentPid: 6 }), true);
  assert.equal(isProtectedProcess({ pid: 999, name: "Encryptor" }, { selfPid: 5, parentPid: 6 }), false);
  assert.equal(isProtectedProcess({ pid: "12", name: "x" }), true);
});

test("sampling: Windows without handle.exe says so and never claims a suspect", async () => {
  const runner = async () => ({ ok: false, stdout: "", stderr: "", message: "not found" });
  const result = await sampleSuspect({ folder: DOCS, platform: "win32", runner });

  assert.equal(result.suspect, null);
  assert.match(result.reason, /does not download/);
});

test("sampling: lsof exiting non-zero with output still counts, and with no output gives a reason", async () => {
  const lsofOutput = "p100\ncEncryptor\nu501\nn/a\nn/b\nn/c\nn/d\nn/e\n";
  const withOutput = await sampleSuspect({
    folder: DOCS,
    platform: "linux",
    runner: async () => ({ ok: false, stdout: lsofOutput, stderr: "", message: "exit 1" }),
    selfPid: 1,
    parentPid: 1
  });

  assert.equal(withOutput.suspect.name, "Encryptor");
  assert.equal(withOutput.suspect.confidence, "high");

  const empty = await sampleSuspect({
    folder: DOCS,
    platform: "linux",
    runner: async () => ({ ok: false, stdout: "", stderr: "", message: "lsof missing" })
  });

  assert.equal(empty.suspect, null);
  assert.match(empty.reason, /lsof/);
});

// ---- controllers ---------------------------------------------------------------------------------

function killRecorder({ alivePids = new Set(), onSignal } = {}) {
  const calls = [];
  const kill = (pid, signal) => {
    calls.push([pid, signal]);
    if (signal === 0) {
      if (!alivePids.has(pid)) throw Object.assign(new Error("gone"), { code: "ESRCH" });
      return true;
    }
    onSignal?.(pid, signal, alivePids);
    return true;
  };

  return { calls, kill };
}

const instant = async () => {};

test("stop: a protected program is never signalled", async () => {
  const { calls, kill } = killRecorder();
  const controller = createProcessController({
    platform: "linux",
    runner: async () => ({ ok: true, stdout: "launchd" }),
    kill,
    sleep: instant,
    selfUid: 1,
    selfPid: 5,
    parentPid: 6
  });

  const result = await controller.stop({ pid: 200, name: "launchd", uid: 1 });

  assert.equal(result.ok, false);
  assert.match(result.message, /protected/);
  assert.deepEqual(calls, []);
});

test("stop: this app and its parent are never signalled", async () => {
  const { calls, kill } = killRecorder();
  const controller = createProcessController({
    platform: "linux",
    runner: async () => ({ ok: true, stdout: "node" }),
    kill,
    sleep: instant,
    selfUid: 1,
    selfPid: 5,
    parentPid: 6
  });

  assert.equal((await controller.stop({ pid: 5, name: "node", uid: 1 })).ok, false);
  assert.equal((await controller.stop({ pid: 6, name: "bash", uid: 1 })).ok, false);
  assert.deepEqual(calls, []);
});

test("stop: a program owned by another user needs an administrator and is left alone", async () => {
  const { calls, kill } = killRecorder();
  const controller = createProcessController({
    platform: "linux",
    runner: async () => ({ ok: true, stdout: "Encryptor" }),
    kill,
    sleep: instant,
    selfUid: 501,
    selfPid: 5,
    parentPid: 6
  });

  const result = await controller.stop({ pid: 300, name: "Encryptor", uid: 0 });

  assert.equal(result.ok, false);
  assert.equal(result.needsElevation, true);
  assert.deepEqual(calls, []);
});

test("stop: a reused process number that now belongs to another program is not killed", async () => {
  const { calls, kill } = killRecorder();
  const controller = createProcessController({
    platform: "linux",
    runner: async () => ({ ok: true, stdout: "/usr/bin/postgres\n" }),
    kill,
    sleep: instant,
    selfUid: 1,
    selfPid: 5,
    parentPid: 6
  });

  const result = await controller.stop({ pid: 300, name: "Encryptor", uid: 1 });

  assert.equal(result.ok, false);
  assert.match(result.message, /different program/);
  assert.deepEqual(calls, []);
});

test("stop: a program that already exited is reported as gone, not as stopped by us", async () => {
  const { calls, kill } = killRecorder();
  const controller = createProcessController({
    platform: "linux",
    runner: async () => ({ ok: false, stdout: "", message: "no such process" }),
    kill,
    sleep: instant,
    selfUid: 1,
    selfPid: 5,
    parentPid: 6
  });

  const result = await controller.stop({ pid: 300, name: "Encryptor", uid: 1 });

  assert.equal(result.ok, true);
  assert.match(result.message, /no longer running/);
  assert.deepEqual(calls, []);
});

test("stop: SIGTERM first, and SIGKILL only if the program is still alive afterwards", async () => {
  const polite = new Set([300]);
  const first = killRecorder({ alivePids: polite, onSignal: (pid, signal, alive) => signal === "SIGTERM" && alive.delete(pid) });
  const controller = createProcessController({
    platform: "linux",
    runner: async () => ({ ok: true, stdout: "Encryptor" }),
    kill: first.kill,
    sleep: instant,
    selfUid: 1,
    selfPid: 5,
    parentPid: 6
  });

  const done = await controller.stop({ pid: 300, name: "Encryptor", uid: 1 });
  assert.equal(done.ok, true);
  assert.ok(first.calls.some(([, signal]) => signal === "SIGTERM"));
  assert.ok(!first.calls.some(([, signal]) => signal === "SIGKILL"));

  const stubborn = new Set([301]);
  const second = killRecorder({ alivePids: stubborn, onSignal: (pid, signal, alive) => signal === "SIGKILL" && alive.delete(pid) });
  const hard = createProcessController({
    platform: "linux",
    runner: async () => ({ ok: true, stdout: "Encryptor" }),
    kill: second.kill,
    sleep: instant,
    selfUid: 1,
    selfPid: 5,
    parentPid: 6
  });

  const forced = await hard.stop({ pid: 301, name: "Encryptor", uid: 1 });
  assert.equal(forced.ok, true);
  assert.match(forced.message, /Force-stopped/);
  assert.ok(second.calls.some(([, signal]) => signal === "SIGKILL"));

  const stuck = killRecorder({ alivePids: new Set([302]) });
  const never = createProcessController({
    platform: "linux",
    runner: async () => ({ ok: true, stdout: "Encryptor" }),
    kill: stuck.kill,
    sleep: instant,
    selfUid: 1,
    selfPid: 5,
    parentPid: 6
  });

  const failed = await never.stop({ pid: 302, name: "Encryptor", uid: 1 });
  assert.equal(failed.ok, false);
  assert.match(failed.message, /did not stop/);
});

test("stop: a missing or malformed suspect is refused", async () => {
  const controller = createProcessController({ platform: "linux", runner: async () => ({ ok: true }), kill: () => {}, sleep: instant });

  assert.equal((await controller.stop(null)).ok, false);
  assert.equal((await controller.stop({ pid: "12", name: "x" })).ok, false);
});

test("sameProgram tolerates lsof's shortened names and full paths", () => {
  assert.equal(sameProgram("/Applications/Encryptor.app/Contents/MacOS/Encryptor", "Encryptor"), true);
  assert.equal(sameProgram("Encryptor", "Encrypt"), true);
  assert.equal(sameProgram("postgres", "Encryptor"), false);
  assert.equal(sameProgram("", "x"), false);
});

test("network controller: names that could carry shell syntax are refused before any command runs", async () => {
  const calls = [];
  const controller = createNetworkController({
    platform: "darwin",
    runner: async (command, args) => {
      calls.push([command, args]);
      return { ok: true, stdout: "" };
    }
  });

  const results = await controller.disable(['Wi-Fi"; rm -rf ~; "', "$(reboot)"]);

  assert.equal(results.length, 2);
  assert.ok(results.every(item => item.ok === false));
  assert.deepEqual(calls, []);
});

// ---- engine --------------------------------------------------------------------------------------

function fakeWatch() {
  const watchers = new Map();

  const watchFn = (folder, options, listener) => {
    const watcher = { closed: false, listener, close() { this.closed = true; } };
    watchers.set(folder, watcher);
    return watcher;
  };

  return { watchers, watchFn };
}

test("engine: watches each folder, reports only files that still exist, and honours exclusions", async () => {
  const { watchers, watchFn } = fakeWatch();
  const seen = [];
  const existing = new Set([path.join(DOCS, "new.locked")]);

  const engine = createShieldEngine({
    folders: [DOCS],
    exclusions: [path.join(DOCS, "Skip")],
    isIgnored: () => false,
    detector: {
      setBaseline() {},
      observe: async (folder, file) => {
        seen.push(file);
        return null;
      },
      close() {}
    },
    onResult: () => {},
    onError: () => {},
    watchFn,
    statFn: async file => {
      if (file !== DOCS && !existing.has(file)) throw Object.assign(new Error("gone"), { code: "ENOENT" });
      return { isFile: () => true, isDirectory: () => true, isSymbolicLink: () => false };
    },
    readdirFn: async () => [],
    debounceMs: 0
  });

  const started = await engine.start();
  assert.deepEqual(started.watching, [DOCS], JSON.stringify(started.failed));
  assert.deepEqual(started.failed, []);

  const watcher = watchers.get(DOCS);
  watcher.listener("rename", "new.locked");
  watcher.listener("rename", "old-name.docx"); // deleted: must be skipped
  watcher.listener("change", path.join("Skip", "inside.locked")); // excluded
  await new Promise(resolve => setTimeout(resolve, 20));

  assert.deepEqual(seen, [path.join(DOCS, "new.locked")]);

  engine.stop();
  assert.equal(watcher.closed, true);
});

test("engine: a folder that cannot be watched is reported as failed, not as watched", async () => {
  const engine = createShieldEngine({
    folders: [DOCS],
    exclusions: [],
    isIgnored: () => false,
    detector: { setBaseline() {}, observe: async () => null, close() {} },
    onResult: () => {},
    onError: () => {},
    watchFn: () => {
      throw Object.assign(new Error("no such folder"), { code: "ENOENT" });
    },
    readdirFn: async () => [],
    debounceMs: 0
  });

  const started = await engine.start();

  assert.deepEqual(started.watching, []);
  assert.equal(started.failed.length, 1);
  assert.equal(started.failed[0].folder, DOCS);
  engine.stop();
});

test("baseline walk collects extensions, skips noise folders, and respects the depth limit", async () => {
  const tree = {
    [DOCS]: [
      { name: "a.docx", isDirectory: () => false, isFile: () => true },
      { name: "node_modules", isDirectory: () => true, isFile: () => false },
      { name: "sub", isDirectory: () => true, isFile: () => false }
    ],
    [path.join(DOCS, "sub")]: [{ name: "b.PDF", isDirectory: () => false, isFile: () => true }],
    [path.join(DOCS, "node_modules")]: [{ name: "c.js", isDirectory: () => false, isFile: () => true }]
  };

  const extensions = await collectExtensions(DOCS, { readdirFn: async dir => tree[dir] || [] });

  assert.deepEqual([...extensions].sort(), [".docx", ".pdf"]);
});
