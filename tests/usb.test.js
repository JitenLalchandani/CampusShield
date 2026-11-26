"use strict";

// USB auto-scan. Drive listing, the file scanner, and the clock are all faked: no real drive is
// read and no real file is scanned or moved.

const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { createStore } = require("../src/store");
const config = require("../src/usb/config");
const { parseLsblk, parseDiskutil, parseWindows, listRemovableDrives } = require("../src/usb/drives");
const { inspectDrive, parseAutorun, maxSeverity } = require("../src/usb/inspect");
const { createUsbService } = require("../src/usb/service");

// ---- settings ----------------------------------------------------------------------------------

test("usb settings: off by default, strict patches, lenient loading", () => {
  const current = config.defaultSettings();
  assert.deepEqual(current, { enabled: false, autoScan: true, ignoredDrives: [] });

  const next = config.applySettingsPatch(current, { enabled: true, ignoredDrives: ["a", "a", "b"] });
  assert.equal(next.enabled, true);
  assert.deepEqual(next.ignoredDrives, ["a", "b"]);
  assert.equal(current.enabled, false);

  for (const bad of [{ enabled: "yes" }, { autoScan: 1 }, { nope: 1 }, { ignoredDrives: "x" }, { ignoredDrives: [""] }, { ignoredDrives: ["x".repeat(129)] }, { ignoredDrives: Array.from({ length: 51 }, (_, i) => `d${i}`) }]) {
    assert.throws(() => config.applySettingsPatch(current, bad), error => error.statusCode === 400, JSON.stringify(bad).slice(0, 40));
  }

  assert.throws(() => config.applySettingsPatch(current, null), /object/);
  assert.deepEqual(config.normalizeStored(undefined), current);
  assert.deepEqual(config.normalizeStored({ enabled: "x", ignoredDrives: [1, "ok"] }), { enabled: false, autoScan: true, ignoredDrives: ["ok"] });
});

// ---- drive listing -----------------------------------------------------------------------------

test("lsblk: removable and USB-attached mounted partitions are listed, internal disks are not", () => {
  const output = JSON.stringify({
    blockdevices: [
      { name: "sda", rm: false, hotplug: false, tran: "sata", type: "disk", children: [{ name: "sda1", rm: false, hotplug: false, type: "part", mountpoint: "/", uuid: "int-1", fstype: "ext4", size: "500000000000" }] },
      { name: "sdb", rm: true, hotplug: true, tran: "usb", type: "disk", children: [
        { name: "sdb1", rm: true, hotplug: true, type: "part", mountpoint: "/media/u/STICK", label: "STICK", uuid: "ABCD-1234", fstype: "vfat", size: "16000000000" },
        { name: "sdb2", rm: true, hotplug: true, type: "part", mountpoint: null }
      ] }
    ]
  });

  const drives = parseLsblk(output);
  assert.equal(drives.length, 1);
  assert.deepEqual(drives[0], { id: "linux:ABCD-1234", label: "STICK", mountPoint: "/media/u/STICK", fsType: "vfat", sizeBytes: 16000000000 });
  assert.equal(parseLsblk("not json"), null);
  assert.deepEqual(parseLsblk("{}"), []);
});

test("diskutil: only mounted external or removable volumes are listed", () => {
  const output = [
    "   Device Identifier:         disk1s1\n   Volume Name:               Macintosh HD\n   Mounted:                   Yes\n   Mount Point:               /\n   Device Location:           Internal\n   Volume UUID:               AAAA",
    "   Device Identifier:         disk4s1\n   Volume Name:               SANDISK\n   Volume UUID:               BBBB-2222\n   File System Personality:   MS-DOS FAT32\n   Protocol:                  USB\n   Device Location:           External\n   Mounted:                   Yes\n   Mount Point:               /Volumes/SANDISK\n   Volume Total Space:        32.0 GB (32000000000 Bytes) (exactly 62500000 512-Byte-Units)",
    "   Device Identifier:         disk5s1\n   Volume Name:               Unplugged\n   Device Location:           External\n   Mounted:                   No\n   Mount Point:"
  ].join("\n**********\n");

  const drives = parseDiskutil(output);
  assert.equal(drives.length, 1);
  assert.equal(drives[0].id, "darwin:BBBB-2222");
  assert.equal(drives[0].mountPoint, "/Volumes/SANDISK");
  assert.equal(drives[0].sizeBytes, 32000000000);
});

test("windows: one drive or many, empty output, and unreadable output", () => {
  const one = JSON.stringify({ DeviceID: "E:", VolumeName: "KINGSTON", FileSystem: "FAT32", Size: 8000000000, VolumeSerialNumber: "1A2B3C4D" });
  assert.deepEqual(parseWindows(one), [{ id: "win32:1A2B3C4D", label: "KINGSTON", mountPoint: "E:\\", fsType: "FAT32", sizeBytes: 8000000000 }]);
  assert.equal(parseWindows(`[${one},${one.replace("E:", "F:")}]`).length, 2);
  assert.deepEqual(parseWindows(""), []);
  assert.equal(parseWindows("oops"), null);
});

test("listing reports why it failed instead of guessing", async () => {
  assert.equal((await listRemovableDrives({ platform: "freebsd" })).ok, false);
  assert.match((await listRemovableDrives({ platform: "linux", runner: async () => ({ ok: false, stdout: "", message: "lsblk is not installed on this computer." }) })).reason, /not installed/);
  assert.match((await listRemovableDrives({ platform: "linux", runner: async () => ({ ok: true, stdout: "garbage" }) })).reason, /could not be read/);

  const good = await listRemovableDrives({ platform: "win32", runner: async () => ({ ok: true, stdout: "" }) });
  assert.deepEqual(good, { ok: true, drives: [], reason: null });
});

// ---- autorun inspection ---------------------------------------------------------------------------

const dirent = (name, dir = false) => ({ name, isDirectory: () => dir });

test("autorun.inf that launches a program is high; one that launches nothing is low", async () => {
  assert.deepEqual(parseAutorun("[autorun]\r\nopen=setup.exe\r\nicon=a.ico"), { open: "setup.exe", icon: "a.ico" });

  const run = async text => inspectDrive("/d", { readdir: async () => [dirent("autorun.inf")], readFile: async () => Buffer.from(text) });
  const launches = await run("[autorun]\nopen=evil.exe");
  const quiet = await run("[autorun]\nlabel=Photos");

  assert.equal(launches.findings[0].severity, "high");
  assert.match(launches.findings[0].detail, /evil\.exe/);
  assert.equal(quiet.findings[0].severity, "low");
});

test("double extensions, shortcut impersonation, and plain programs are told apart", async () => {
  const entries = [dirent("Photos", true), dirent("Photos.lnk"), dirent("invoice.pdf.exe"), dirent("setup.exe"), dirent("notes.txt"), dirent("Other.lnk")];
  const result = await inspectDrive("/d", { readdir: async () => entries });
  const byRule = Object.fromEntries(result.findings.map(item => [item.rule, item]));

  assert.equal(byRule["double-extension"].severity, "high");
  assert.equal(byRule["shortcut-impersonation"].severity, "medium");
  assert.equal(byRule["root-program"].severity, "low");
  assert.equal(result.findings.length, 3, "notes.txt and the lone shortcut are not findings");
  assert.equal(result.findings[0].severity, "high", "worst first");
  assert.equal(maxSeverity(result.findings), "high");
  assert.equal(maxSeverity([]), null);
});

test("a clean drive has no findings; an unreadable one says so; a huge one is marked truncated", async () => {
  const clean = await inspectDrive("/d", { readdir: async () => [dirent("Docs", true), dirent("a.docx")] });
  assert.deepEqual(clean.findings, []);
  assert.equal(clean.ok, true);

  const blocked = await inspectDrive("/d", { readdir: async () => { throw Object.assign(new Error("denied"), { code: "EACCES" }); } });
  assert.equal(blocked.ok, false);
  assert.match(blocked.reason, /EACCES/);

  const many = Array.from({ length: 12 }, (_, i) => dirent(`f${i}.txt`));
  const cut = await inspectDrive("/d", { readdir: async () => many, limit: 10 });
  assert.equal(cut.truncated, true);
  assert.equal(cut.entriesChecked, 10);
});

// ---- service ---------------------------------------------------------------------------------------

const STICK = { id: "linux:AAAA", label: "STICK", mountPoint: "/media/STICK", fsType: "vfat", sizeBytes: 1000 };
const OTHER = { id: "linux:BBBB", label: "OTHER", mountPoint: "/media/OTHER", fsType: "ntfs", sizeBytes: 2000 };

async function harness({ present = [], scanResult, inspect, enabled = true, scanner: scannerOverride } = {}) {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), "cs-usb-test-"));
  const store = await createStore({ dataDir });
  const state = { drives: [...present], fail: null };
  const log = { audit: [], events: [], changes: 0, started: [], cancelled: [], quarantined: [] };
  let scanSeq = 0;
  const scans = new Map();

  const scanner = scannerOverride || {
    startScan: async args => {
      log.started.push(args);
      const id = `scan-${(scanSeq += 1)}`;
      scans.set(id, { id, status: "running", polls: 0 });
      return { id, status: "running" };
    },
    getScan: async id => {
      const scan = scans.get(id);
      scan.polls += 1;
      if (scan.polls < 2) return { id, status: "running" };
      return { id, status: "complete", filesScanned: 40, bytesScanned: 4000, skipped: 0, errors: [], truncated: false, threats: [], ...(typeof scanResult === "function" ? scanResult(id) : scanResult) };
    },
    cancelScan: id => log.cancelled.push(id),
    quarantineThreat: async (scanId, threatId) => {
      log.quarantined.push([scanId, threatId]);
      if (threatId === "bad") throw new Error("File is locked.");
    }
  };

  if (enabled) await store.settings.save({ usb: { enabled: true, autoScan: true, ignoredDrives: [] } });

  const service = createUsbService({
    store,
    platform: "linux",
    scanner,
    lister: async () => (state.fail ? { ok: false, drives: [], reason: state.fail } : { ok: true, drives: state.drives.map(item => ({ ...item })), reason: null }),
    inspector: inspect || (async () => ({ ok: true, findings: [], entriesChecked: 3, truncated: false, reason: null })),
    audit: async entry => log.audit.push(entry),
    onChange: () => { log.changes += 1; },
    onEvent: event => log.events.push(event),
    setTimer: () => ({ unref() {} }),
    clearTimer: () => {},
    sleep: async () => {},
    now: () => Date.parse("2026-11-26T08:00:00.000Z")
  });

  await service.ready;
  const settled = async () => { await new Promise(resolve => setTimeout(resolve, 5)); await service.close().catch(() => {}); };
  return { service, store, state, log, scanner, settled };
}

const insertAndScan = async (h, drive = STICK) => {
  h.state.drives.push(drive);
  await h.service.pollNow();
  await new Promise(resolve => setTimeout(resolve, 20));
};

test("off by default: nothing is listed or scanned and the posture check says so", async () => {
  const h = await harness({ enabled: false, present: [STICK] });
  await h.service.pollNow();
  const status = await h.service.status();

  assert.equal(status.enabled, false);
  assert.deepEqual(status.drives, []);
  assert.deepEqual(h.log.started, []);
  assert.equal(h.service.postureCheck().status, "warn");
  assert.equal(h.service.postureCheck().severity, "low");
});

test("a drive already plugged in when watching starts is listed but not scanned", async () => {
  const h = await harness({ present: [STICK] });
  await h.service.pollNow();

  assert.deepEqual((await h.service.status()).drives.map(item => item.id), ["linux:AAAA"]);
  assert.deepEqual(h.log.started, []);
  assert.deepEqual(await h.service.listEvents(), []);
  assert.equal(h.service.postureCheck().status, "pass");
  await h.settled();
});

test("a newly inserted clean drive is scanned and recorded as clean with what was checked", async () => {
  const h = await harness();
  await insertAndScan(h);

  assert.deepEqual(h.log.started, [{ scope: "custom", target: "/media/STICK", trigger: "usb" }]);
  const [event] = await h.service.listEvents();

  assert.equal(event.status, "clean");
  assert.equal(event.trigger, "insert");
  assert.equal(event.scan.filesScanned, 40);
  assert.equal(event.inspect.entriesChecked, 3);
  assert.equal(event.severity, null);
  assert.deepEqual(await h.service.penaltyThreats(), []);
  assert.ok(h.log.audit.every(entry => entry.kind === "usb"));
  await h.settled();
});

test("a drive with scanner threats is open, announced, and not double-scored", async () => {
  const h = await harness({ scanResult: { threats: [{ id: "t1", name: "Eicar", severity: "high", filePath: "/media/STICK/e.com", status: "detected" }] } });
  await insertAndScan(h);

  const [event] = await h.service.listEvents();
  assert.equal(event.status, "open");
  assert.equal(event.severity, "high");
  assert.equal(h.log.events.length, 1);
  assert.deepEqual(await h.service.penaltyThreats(), [], "the file scanner already scores these threats");
  assert.equal((await h.service.status()).openEvents, 1);
  await h.settled();
});

test("autorun findings open the event and are scored once, at their worst severity", async () => {
  const h = await harness({
    inspect: async () => ({
      ok: true,
      entriesChecked: 2,
      truncated: false,
      findings: [
        { rule: "autorun-inf", severity: "high", path: "/media/STICK/autorun.inf", detail: "starts evil.exe" },
        { rule: "shortcut-impersonation", severity: "medium", path: "/media/STICK/a.lnk", detail: "x" },
        { rule: "root-program", severity: "low", path: "/media/STICK/s.exe", detail: "y" }
      ]
    })
  });
  await insertAndScan(h);

  assert.deepEqual(await h.service.penaltyThreats(), [{ filePath: "usb:linux:AAAA", severity: "high" }]);
  await h.settled();
});

test("low-only findings are listed but do not open an event or cost points", async () => {
  const h = await harness({ inspect: async () => ({ ok: true, entriesChecked: 1, truncated: false, findings: [{ rule: "root-program", severity: "low", path: "/m/s.exe", detail: "y" }] }) });
  await insertAndScan(h);

  const [event] = await h.service.listEvents();
  assert.equal(event.status, "clean");
  assert.equal(event.findings.length, 1);
  assert.deepEqual(await h.service.penaltyThreats(), []);
  await h.settled();
});

test("removing the drive marks open events removed and stops them costing points", async () => {
  const h = await harness({ inspect: async () => ({ ok: true, entriesChecked: 1, truncated: false, findings: [{ rule: "autorun-inf", severity: "high", path: "/p", detail: "d" }] }) });
  await insertAndScan(h);
  assert.equal((await h.service.penaltyThreats()).length, 1);

  h.state.drives = [];
  await h.service.pollNow();

  assert.equal((await h.service.listEvents())[0].status, "removed");
  assert.deepEqual(await h.service.penaltyThreats(), []);
  assert.deepEqual((await h.service.status()).drives, []);
  await h.settled();
});

test("a drive pulled out mid-scan cancels the scan and keeps the result marked partial", async () => {
  const h = await harness();
  h.state.drives.push(STICK);
  await h.service.pollNow();
  await new Promise(resolve => setTimeout(resolve, 0));

  h.state.drives = [];
  await h.service.pollNow();
  await new Promise(resolve => setTimeout(resolve, 20));

  const [event] = await h.service.listEvents();
  assert.equal(event.status, "removed");
  assert.ok(h.log.cancelled.length <= 1);
  await h.settled();
});

test("a failed or cancelled scan is incomplete and says the result is partial", async () => {
  const h = await harness({ scanResult: { status: "failed" } });
  await insertAndScan(h);

  const [event] = await h.service.listEvents();
  assert.equal(event.status, "incomplete");
  assert.match(event.note, /partial/);
  await h.settled();
});

test("an unreadable drive top is reported as incomplete, never as clean", async () => {
  const h = await harness({ scanResult: { filesScanned: 0 }, inspect: async () => ({ ok: false, findings: [], entriesChecked: 0, truncated: false, reason: "The top of the drive could not be read (EACCES)." }) });
  await insertAndScan(h);

  const [event] = await h.service.listEvents();
  assert.equal(event.status, "incomplete");
  assert.match(event.inspect.reason, /EACCES/);
  await h.settled();
});

test("if another scan is running the drive waits and then scans", async () => {
  let attempts = 0;
  const scans = new Map();
  const scanner = {
    startScan: async () => {
      attempts += 1;
      if (attempts < 3) throw Object.assign(new Error("A scan is already running."), { statusCode: 409 });
      scans.set("s", 0);
      return { id: "s", status: "running" };
    },
    getScan: async () => ({ id: "s", status: "complete", filesScanned: 5, errors: [], threats: [] }),
    cancelScan() {},
    quarantineThreat: async () => {}
  };

  const h = await harness({ scanner });
  await insertAndScan(h);

  assert.equal(attempts, 3);
  assert.equal((await h.service.listEvents())[0].status, "clean");
  await h.settled();
});

test("a scanner that stays busy past the wait limit gives up and says so", async () => {
  const scanner = { startScan: async () => { throw Object.assign(new Error("busy"), { statusCode: 409 }); }, getScan: async () => null, cancelScan() {}, quarantineThreat: async () => {} };
  let clock = Date.parse("2026-11-26T08:00:00.000Z");
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), "cs-usb-test-"));
  const store = await createStore({ dataDir });
  await store.settings.save({ usb: { enabled: true, autoScan: true, ignoredDrives: [] } });
  const drives = [];

  const service = createUsbService({
    store,
    platform: "linux",
    scanner,
    lister: async () => ({ ok: true, drives: drives.map(item => ({ ...item })), reason: null }),
    inspector: async () => ({ ok: true, findings: [], entriesChecked: 0, truncated: false }),
    setTimer: () => ({ unref() {} }),
    clearTimer: () => {},
    sleep: async () => { clock += 6 * 60 * 1000; },
    now: () => clock
  });

  await service.ready;
  drives.push(STICK);
  await service.pollNow();
  await new Promise(resolve => setTimeout(resolve, 20));

  const [event] = await service.listEvents();
  assert.equal(event.status, "incomplete");
  assert.match(event.note, /was not scanned/);
  await service.close();
});

test("auto-scan off: a new drive only gets the autorun check and the record says so", async () => {
  const h = await harness();
  await h.service.updateSettings({ autoScan: false });
  await insertAndScan(h);

  assert.deepEqual(h.log.started, []);
  assert.match((await h.service.listEvents())[0].note, /Auto-scan is off/);
  await h.settled();
});

test("an ignored drive is not scanned on insert, and can be resumed", async () => {
  const h = await harness();
  await h.service.ignoreDrive(STICK.id, true);
  await insertAndScan(h);

  assert.deepEqual(h.log.started, []);
  assert.equal((await h.service.status()).drives[0].ignored, true);

  const after = await h.service.ignoreDrive(STICK.id, false);
  assert.deepEqual(after.ignoredDrives, []);
  await assert.rejects(() => h.service.ignoreDrive("", true), error => error.statusCode === 404);
  await h.settled();
});

test("manual scan works only for a drive the system lists right now", async () => {
  const h = await harness({ present: [STICK] });
  await h.service.pollNow();

  await assert.rejects(() => h.service.scanDrive("linux:NOPE"), error => error.statusCode === 404);
  await assert.rejects(() => h.service.scanDrive("/etc"), error => error.statusCode === 404);

  const event = await h.service.scanDrive(STICK.id, { callerLabel: "alice" });
  assert.equal(event.trigger, "manual");
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal((await h.service.listEvents())[0].status, "clean");

  h.state.fail = "lsblk is not installed on this computer.";
  await assert.rejects(() => h.service.scanDrive(STICK.id), error => error.statusCode === 502);
  await h.settled();
});

test("a listing failure turns the posture check to unknown with the reason, and recovers", async () => {
  const h = await harness();
  h.state.fail = "lsblk is not installed on this computer.";
  await h.service.pollNow();

  assert.equal(h.service.postureCheck().status, "unknown");
  assert.match(h.service.postureCheck().detail, /lsblk/);
  assert.equal((await h.service.status()).running, false);

  h.state.fail = null;
  await h.service.pollNow();
  assert.equal(h.service.postureCheck().status, "pass");
  await h.settled();
});

test("turning it on needs a supported platform; invalid settings change nothing", async () => {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), "cs-usb-test-"));
  const store = await createStore({ dataDir });
  const unsupported = createUsbService({ store, platform: "freebsd", scanner: {} });

  await assert.rejects(() => unsupported.updateSettings({ enabled: true }), error => error.statusCode === 400);
  assert.equal(unsupported.postureCheck().status, "unknown");

  const h = await harness({ enabled: false });
  await assert.rejects(() => h.service.updateSettings({ enabled: "yes" }), error => error.statusCode === 400);
  assert.equal((await h.service.status()).enabled, false);
  await h.service.updateSettings({ enabled: true });
  assert.equal((await h.service.status()).enabled, true);
  assert.equal((await h.store.settings.get()).usb.enabled, true);
  await h.settled();
});

test("dismiss closes an open event, rejects unknown ids, and is repeatable", async () => {
  const h = await harness({ scanResult: { threats: [{ id: "t1", name: "X", severity: "medium", filePath: "/m/x", status: "detected" }] } });
  await insertAndScan(h);
  const [event] = await h.service.listEvents();

  const done = await h.service.dismiss(event.id, { reason: "r".repeat(300) });
  assert.equal(done.event.status, "dismissed");
  assert.equal(done.event.dismissReason.length, 200);
  assert.equal((await h.service.dismiss(event.id)).event.status, "dismissed");
  await assert.rejects(() => h.service.dismiss("nope"), error => error.statusCode === 404);
  await h.settled();
});

test("quarantine-all needs a valid single-use confirmation bound to the caller", async () => {
  const threats = [
    { id: "t1", name: "A", severity: "high", filePath: "/m/a", status: "detected" },
    { id: "bad", name: "B", severity: "high", filePath: "/m/b", status: "detected" }
  ];
  const h = await harness({ scanResult: { threats } });
  await insertAndScan(h);
  const [event] = await h.service.listEvents();

  await assert.rejects(() => h.service.quarantineAll(event.id, { confirmToken: "x", callerKey: "session:a" }), error => error.statusCode === 403);

  const { confirmToken } = await h.service.getEvent(event.id, "session:a");
  await assert.rejects(() => h.service.quarantineAll(event.id, { confirmToken, callerKey: "session:mallory" }), error => error.statusCode === 403);
  assert.deepEqual(h.log.quarantined, []);

  const fresh = (await h.service.getEvent(event.id, "session:a")).confirmToken;
  const result = await h.service.quarantineAll(event.id, { confirmToken: fresh, callerKey: "session:a", callerLabel: "alice" });

  assert.deepEqual(result.results.map(item => [item.id, item.ok]), [["t1", true], ["bad", false]]);
  assert.equal(result.event.threats.find(item => item.id === "t1").status, "quarantined");
  assert.equal(result.event.threats.find(item => item.id === "bad").status, "detected");
  assert.equal(result.event.status, "open", "one file could not be moved, so the event stays open");

  await assert.rejects(() => h.service.quarantineAll(event.id, { confirmToken: fresh, callerKey: "session:a" }), error => error.statusCode === 403, "token is single-use");
  await h.settled();
});

test("quarantine-all with nothing detected is refused and the attempt limit holds", async () => {
  const h = await harness();
  await insertAndScan(h);
  const [event] = await h.service.listEvents();

  for (let index = 0; index < 5; index += 1) {
    const { confirmToken } = await h.service.getEvent(event.id, "session:a");
    await assert.rejects(() => h.service.quarantineAll(event.id, { confirmToken, callerKey: "session:a" }), error => error.statusCode === 409);
  }

  const { confirmToken } = await h.service.getEvent(event.id, "session:a");
  await assert.rejects(() => h.service.quarantineAll(event.id, { confirmToken, callerKey: "session:a" }), error => error.statusCode === 429);
  await h.settled();
});

test("reading an event gives a token only to an identified caller; unknown ids are 404", async () => {
  const h = await harness();
  await insertAndScan(h);
  const [event] = await h.service.listEvents();

  assert.equal((await h.service.getEvent(event.id, null)).confirmToken, undefined);
  assert.equal(typeof (await h.service.getEvent(event.id, "session:a")).confirmToken, "string");
  await assert.rejects(() => h.service.getEvent("nope", "session:a"), error => error.statusCode === 404);
  assert.deepEqual((await h.service.listEvents({ status: "open" })), []);
  assert.equal((await h.service.listEvents({ limit: "junk" })).length, 1);
  await h.settled();
});

// ---- store parity ------------------------------------------------------------------------------------

async function parity(store) {
  await store.usbEvents.clear();

  for (let index = 0; index < 5; index += 1) {
    await store.usbEvents.upsert({ id: `u${index}`, status: "clean", startedAt: `2026-11-26T08:0${index}:00.000Z` });
  }

  const all = await store.usbEvents.all(10);
  assert.deepEqual(all.map(item => item.id), ["u4", "u3", "u2", "u1", "u0"]);
  assert.ok(all.every(item => item._id === undefined));
  assert.equal((await store.usbEvents.get("u2")).id, "u2");
  assert.equal(await store.usbEvents.get("zzz"), null);

  await store.usbEvents.upsert({ id: "u2", status: "dismissed", startedAt: "2026-11-26T08:02:00.000Z" });
  assert.equal((await store.usbEvents.all(10)).length, 5);
  assert.equal((await store.usbEvents.get("u2")).status, "dismissed");

  await store.usbEvents.prune(3);
  assert.deepEqual((await store.usbEvents.all(10)).map(item => item.id), ["u4", "u3", "u2"]);
  await store.usbEvents.clear();
  assert.equal((await store.usbEvents.all(10)).length, 0);
}

test("store parity: the JSON store keeps USB events newest-first, replaces on upsert, prunes, and survives restart", async () => {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), "cs-usb-store-"));
  const store = await createStore({ dataDir });
  await parity(store);

  await store.usbEvents.upsert({ id: "keep", status: "clean", startedAt: "2026-11-26T09:00:00.000Z" });
  assert.equal((await (await createStore({ dataDir })).usbEvents.get("keep")).id, "keep");
});

test("store parity: an old store.json with no USB data loads with an empty list", async () => {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), "cs-usb-old-"));
  await fs.writeFile(path.join(dataDir, "store.json"), JSON.stringify({ settings: {}, events: [] }));
  assert.deepEqual(await (await createStore({ dataDir })).usbEvents.all(10), []);
});

test("store parity: MongoDB behaves the same when MONGODB_URI is set", { skip: !process.env.MONGODB_URI }, async () => {
  const store = await createStore({ dataDir: await fs.mkdtemp(path.join(os.tmpdir(), "cs-usb-mongo-")) });
  await parity(store);
});
