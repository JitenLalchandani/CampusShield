"use strict";

const fs = require("node:fs/promises");
const path = require("node:path");

class DuplicateIdError extends Error {
  constructor(id) {
    super(`Event ID already exists: ${id}`);
    this.name = "DuplicateIdError";
    this.code = 11000;
  }
}

function copy(value) {
  return value == null ? value : JSON.parse(JSON.stringify(value));
}

function byTimeDesc(a, b) {
  return Date.parse(b.time || 0) - Date.parse(a.time || 0);
}

async function createStore({ mongoUri, dataDir }) {
  const store = mongoUri ? createMongoStore(mongoUri) : createJsonStore(dataDir);
  await store.init();
  return store;
}

function createJsonStore(dir) {
  const file = path.join(dir, "store.json");
  const state = {
    events: [],
    actions: [],
    audit: [],
    devices: [],
    scans: [],
    quarantine: [],
    settings: {}
  };
  let loading = null;
  let writes = Promise.resolve();

  async function load() {
    if (loading) return loading;

    loading = (async () => {
      await fs.mkdir(dir, { recursive: true });

      try {
        const raw = await fs.readFile(file, "utf8");
        const parsed = JSON.parse(raw);

        if (parsed && typeof parsed === "object") {
          state.events = Array.isArray(parsed.events) ? parsed.events : [];
          state.actions = Array.isArray(parsed.actions) ? parsed.actions : [];
          state.audit = Array.isArray(parsed.audit) ? parsed.audit : [];
          state.devices = Array.isArray(parsed.devices) ? parsed.devices : [];
          state.scans = Array.isArray(parsed.scans) ? parsed.scans : [];
          state.quarantine = Array.isArray(parsed.quarantine) ? parsed.quarantine : [];
          state.settings =
            parsed.settings && typeof parsed.settings === "object" && !Array.isArray(parsed.settings)
              ? parsed.settings
              : {};
        }
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
    })();

    return loading;
  }

  function persist() {
    const next = writes.then(async () => {
      const temp = `${file}.tmp`;
      await fs.writeFile(temp, JSON.stringify(state, null, 2));
      await fs.rename(temp, file);
    });

    writes = next.catch(() => {});
    return next;
  }

  return {
    kind: "local-json",
    location: file,

    async init() {
      await load();
    },

    events: {
      async all() {
        await load();
        return state.events.slice().sort(byTimeDesc).map(copy);
      },
      async get(id) {
        await load();
        return copy(state.events.find(event => event.id === id) || null);
      },
      async insert(doc) {
        await load();
        if (state.events.some(event => event.id === doc.id)) {
          throw new DuplicateIdError(doc.id);
        }
        state.events.push(copy(doc));
        await persist();
        return copy(doc);
      },
      async clear() {
        await load();
        const deleted = state.events.length;
        state.events = [];
        await persist();
        return deleted;
      }
    },

    actions: {
      async all() {
        await load();
        return state.actions.map(copy);
      },
      async upsert(record) {
        await load();
        const index = state.actions.findIndex(item => item.eventId === record.eventId);

        if (index === -1) state.actions.push(copy(record));
        else state.actions[index] = copy(record);

        await persist();
        return copy(record);
      },
      async clear() {
        await load();
        const deleted = state.actions.length;
        state.actions = [];
        await persist();
        return deleted;
      }
    },

    audit: {
      async all(limit = 200, offset = 0, kind = null) {
        await load();
        return state.audit
          .filter(entry => !kind || entry.kind === kind)
          .sort(byTimeDesc)
          .slice(offset, offset + limit)
          .map(copy);
      },
      async forEvent(eventId) {
        await load();
        return state.audit
          .filter(entry => entry.eventId === eventId)
          .sort((a, b) => Date.parse(a.time || 0) - Date.parse(b.time || 0))
          .map(copy);
      },
      async count(kind = null) {
        await load();
        return state.audit.filter(entry => !kind || entry.kind === kind).length;
      },
      async append(record) {
        await load();
        state.audit.push(copy(record));
        await persist();
        return copy(record);
      },
      async clear() {
        await load();
        const deleted = state.audit.length;
        state.audit = [];
        await persist();
        return deleted;
      }
    },

    devices: {
      async all() {
        await load();
        return state.devices
          .map(copy)
          .sort((a, b) => Date.parse(b.lastSeen || 0) - Date.parse(a.lastSeen || 0));
      },
      async get(id) {
        await load();
        return copy(state.devices.find(device => device.id === id) || null);
      },
      async upsert(record) {
        await load();
        const index = state.devices.findIndex(device => device.id === record.id);

        if (index === -1) state.devices.push(copy(record));
        else state.devices[index] = copy(record);

        await persist();
        return copy(record);
      },
      async remove(id) {
        await load();
        const index = state.devices.findIndex(device => device.id === id);
        if (index === -1) return false;
        state.devices.splice(index, 1);
        await persist();
        return true;
      },
      async clear() {
        await load();
        const deleted = state.devices.length;
        state.devices = [];
        await persist();
        return deleted;
      }
    },

    scans: {
      async all(limit = 50) {
        await load();
        return state.scans
          .slice()
          .sort((a, b) => Date.parse(b.startedAt || 0) - Date.parse(a.startedAt || 0))
          .slice(0, limit)
          .map(copy);
      },
      async get(id) {
        await load();
        return copy(state.scans.find(scan => scan.id === id) || null);
      },
      async upsert(record) {
        await load();
        const index = state.scans.findIndex(scan => scan.id === record.id);

        if (index === -1) state.scans.push(copy(record));
        else state.scans[index] = copy(record);

        await persist();
        return copy(record);
      },
      async remove(id) {
        await load();
        const index = state.scans.findIndex(scan => scan.id === id);
        if (index === -1) return false;
        state.scans.splice(index, 1);
        await persist();
        return true;
      },
      async clear() {
        await load();
        const deleted = state.scans.length;
        state.scans = [];
        await persist();
        return deleted;
      }
    },

    quarantine: {
      async all() {
        await load();
        return state.quarantine
          .slice()
          .sort((a, b) => Date.parse(b.quarantinedAt || 0) - Date.parse(a.quarantinedAt || 0))
          .map(copy);
      },
      async get(id) {
        await load();
        return copy(state.quarantine.find(item => item.id === id) || null);
      },
      async upsert(record) {
        await load();
        const index = state.quarantine.findIndex(item => item.id === record.id);

        if (index === -1) state.quarantine.push(copy(record));
        else state.quarantine[index] = copy(record);

        await persist();
        return copy(record);
      },
      async remove(id) {
        await load();
        const index = state.quarantine.findIndex(item => item.id === id);
        if (index === -1) return false;
        state.quarantine.splice(index, 1);
        await persist();
        return true;
      },
      async clear() {
        await load();
        const deleted = state.quarantine.length;
        state.quarantine = [];
        await persist();
        return deleted;
      }
    },

    settings: {
      async get() {
        await load();
        return copy(state.settings);
      },
      async save(patch) {
        await load();
        state.settings = { ...state.settings, ...copy(patch) };
        await persist();
        return copy(state.settings);
      },
      async clear() {
        await load();
        state.settings = {};
        await persist();
        return true;
      }
    },

    async close() {}
  };
}

function createMongoStore(uri) {
  const { MongoClient } = require("mongodb");
  let client;
  let events;
  let actions;
  let audit;
  let devices;
  let scans;
  let quarantine;
  let settings;

  return {
    kind: "mongodb",
    location: "MongoDB Atlas",

    async init() {
      client = new MongoClient(uri, {
        appName: "CampusShield",
        serverSelectionTimeoutMS: 12000
      });

      await client.connect();

      const db = client.db();
      events = db.collection("events");
      actions = db.collection("actions");
      audit = db.collection("audit");
      devices = db.collection("devices");
      scans = db.collection("scans");
      quarantine = db.collection("quarantine");
      settings = db.collection("settings");

      await Promise.all([
        events.createIndex({ id: 1 }, { unique: true }),
        actions.createIndex({ eventId: 1 }, { unique: true }),
        audit.createIndex({ time: -1 }),
        devices.createIndex({ id: 1 }, { unique: true }),
        devices.createIndex({ lastSeen: -1 }),
        scans.createIndex({ id: 1 }, { unique: true }),
        scans.createIndex({ startedAt: -1 }),
        quarantine.createIndex({ id: 1 }, { unique: true }),
        quarantine.createIndex({ quarantinedAt: -1 })
      ]);
    },

    events: {
      async all() {
        return events.find({}).sort({ time: -1 }).toArray();
      },
      async get(id) {
        return events.findOne({ id });
      },
      async insert(doc) {
        await events.insertOne(doc);
        return doc;
      },
      async clear() {
        const result = await events.deleteMany({});
        return result.deletedCount;
      }
    },

    actions: {
      async all() {
        return actions.find({}).toArray();
      },
      async upsert(record) {
        await actions.updateOne(
          { eventId: record.eventId },
          { $set: record },
          { upsert: true }
        );
        return record;
      },
      async clear() {
        const result = await actions.deleteMany({});
        return result.deletedCount;
      }
    },

    audit: {
      async all(limit = 200, offset = 0, kind = null) {
        const filter = kind ? { kind } : {};
        return audit
          .find(filter)
          .sort({ time: -1 })
          .skip(offset)
          .limit(limit)
          .toArray();
      },
      async forEvent(eventId) {
        return audit.find({ eventId }).sort({ time: 1 }).toArray();
      },
      async count(kind = null) {
        return audit.countDocuments(kind ? { kind } : {});
      },
      async append(record) {
        await audit.insertOne(record);
        return record;
      },
      async clear() {
        const result = await audit.deleteMany({});
        return result.deletedCount;
      }
    },

    devices: {
      async all() {
        return devices.find({}).sort({ lastSeen: -1 }).toArray();
      },
      async get(id) {
        return devices.findOne({ id });
      },
      async upsert(record) {
        await devices.updateOne(
          { id: record.id },
          { $set: record },
          { upsert: true }
        );
        return record;
      },
      async remove(id) {
        const result = await devices.deleteOne({ id });
        return result.deletedCount > 0;
      },
      async clear() {
        const result = await devices.deleteMany({});
        return result.deletedCount;
      }
    },

    scans: {
      async all(limit = 50) {
        return scans.find({}).sort({ startedAt: -1 }).limit(limit).toArray();
      },
      async get(id) {
        return scans.findOne({ id });
      },
      async upsert(record) {
        await scans.updateOne(
          { id: record.id },
          { $set: record },
          { upsert: true }
        );
        return record;
      },
      async remove(id) {
        const result = await scans.deleteOne({ id });
        return result.deletedCount > 0;
      },
      async clear() {
        const result = await scans.deleteMany({});
        return result.deletedCount;
      }
    },

    quarantine: {
      async all() {
        return quarantine.find({}).sort({ quarantinedAt: -1 }).toArray();
      },
      async get(id) {
        return quarantine.findOne({ id });
      },
      async upsert(record) {
        await quarantine.updateOne(
          { id: record.id },
          { $set: record },
          { upsert: true }
        );
        return record;
      },
      async remove(id) {
        const result = await quarantine.deleteOne({ id });
        return result.deletedCount > 0;
      },
      async clear() {
        const result = await quarantine.deleteMany({});
        return result.deletedCount;
      }
    },

    settings: {
      async get() {
        const doc = await settings.findOne({ _id: "scanner" });
        if (!doc) return {};
        const { _id, ...rest } = doc;
        return rest;
      },
      async save(patch) {
        await settings.updateOne(
          { _id: "scanner" },
          { $set: patch },
          { upsert: true }
        );
        return this.get();
      },
      async clear() {
        await settings.deleteOne({ _id: "scanner" });
        return true;
      }
    },

    async close() {
      if (client) await client.close();
    }
  };
}

module.exports = { createStore, DuplicateIdError };
