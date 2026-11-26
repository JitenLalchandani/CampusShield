"use strict";

// The app must only show real data. The old "Contained (demo)" action changed a label and nothing
// else, so it was removed. These tests keep it from coming back and check that events say where
// they came from.

const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { createStore } = require("../src/store");
const { createApp } = require("../src/server");

async function withApp(run) {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), "cs-realdata-test-"));
  const store = await createStore({ dataDir });
  const app = createApp({ store, dataDir });
  const server = await new Promise(resolve => {
    const instance = app.listen(0, "127.0.0.1", () => resolve(instance));
  });
  const base = `http://127.0.0.1:${server.address().port}`;

  const call = async (method, url, body) => {
    const response = await fetch(`${base}${url}`, {
      method,
      headers: { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    return { status: response.status, json: await response.json() };
  };

  try {
    await run({ store, call });
  } finally {
    server.close();
    await store.close();
    await fs.rm(dataDir, { recursive: true, force: true });
  }
}

test("Contain is rejected for queued events", () =>
  withApp(async ({ call }) => {
    await call("POST", "/api/events", {
      id: "evt-1",
      group: "Library",
      type: "login_failure",
      source: "test-feed",
      count: 6
    });

    const contain = await call("POST", "/api/alerts/evt-1/action", { action: "Contain" });
    assert.equal(contain.status, 400);
    assert.match(contain.json.error, /never touched a device|not available/i);

    const investigate = await call("POST", "/api/alerts/evt-1/action", { action: "Investigate" });
    assert.equal(investigate.status, 200);
    assert.equal(investigate.json.event.status, "Under review");
    assert.match(investigate.json.note, /did not change any device/);
  }));

test("a stored demo containment reads as Open and is flagged, never as contained", () =>
  withApp(async ({ store, call }) => {
    await call("POST", "/api/events", {
      id: "evt-2",
      group: "Hostel",
      type: "malicious_domain",
      source: "test-feed",
      count: 1
    });

    await store.actions.upsert({
      eventId: "evt-2",
      action: "Contain",
      status: "Contained (demo)",
      actor: "Analyst (local)",
      time: new Date().toISOString()
    });

    const detail = await call("GET", "/api/events/evt-2");
    assert.equal(detail.json.event.status, "Open");
    assert.equal(detail.json.event.legacyDemoAction, true);

    const summary = await call("GET", "/api/summary");
    assert.equal("contained" in summary.json, false);
    assert.equal("Contained (demo)" in summary.json.statusCounts, false);
    assert.equal(summary.json.open, 1);
  }));

test("events say where they came from", () =>
  withApp(async ({ store, call }) => {
    const ingested = await call("POST", "/api/events", {
      id: "evt-3",
      group: "Admin",
      type: "unpatched_endpoint",
      source: "asset-inventory",
      count: 2
    });
    assert.equal(ingested.status, 201);
    assert.match(ingested.json.event.originLabel, /events API.*not verified/);

    // An event stored before origins were recorded must not claim a source it cannot prove.
    await store.events.insert({
      id: "evt-old",
      time: new Date().toISOString(),
      group: "Admin",
      type: "login_failure",
      source: "macOS Unified Log",
      count: 5,
      detail: "older record"
    });

    const old = await call("GET", "/api/events/evt-old");
    assert.match(old.json.event.originLabel, /Source not recorded/);
  }));
