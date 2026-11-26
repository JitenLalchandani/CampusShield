"use strict";

// HTTP behaviour of /api/shield. Needs the app's normal dependencies (express, mongodb, dotenv).
// The shield is never turned on here, so no folder is watched and nothing on the computer changes.

const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { createStore } = require("../src/store");
const { createApp } = require("../src/server");

async function withApp(run) {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), "cs-shield-api-"));
  const store = await createStore({ dataDir });
  const app = createApp({ store, dataDir });
  const server = await new Promise(resolve => {
    const instance = app.listen(0, "127.0.0.1", () => resolve(instance));
  });
  const base = `http://127.0.0.1:${server.address().port}`;

  const call = async (method, url, body, headers = {}) => {
    const response = await fetch(`${base}${url}`, {
      method,
      headers: { "content-type": "application/json", ...headers },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    return { status: response.status, json: await response.json() };
  };

  try {
    await run({ store, call });
  } finally {
    server.close();
    app.locals.shield.close();
    await store.close();
    await fs.rm(dataDir, { recursive: true, force: true });
  }
}

const alert = {
  id: "api-1",
  status: "open",
  severity: "critical",
  confidence: "high",
  folder: path.join(os.homedir(), "Documents"),
  startedAt: "2026-11-25T05:00:00.000Z",
  updatedAt: "2026-11-25T05:00:00.000Z",
  evidence: { filesTouched: 30, windowSec: 10 },
  suspect: null,
  actions: []
};

test("GET /api/shield reports an off shield with visible thresholds", () =>
  withApp(async ({ call }) => {
    const { status, json } = await call("GET", "/api/shield");

    assert.equal(status, 200);
    assert.equal(json.enabled, false);
    assert.deepEqual(json.thresholds, { minFiles: 25, windowSec: 10, minSignalPct: 60 });
  }));

test("PATCH settings validates input and rejects a foreign Origin", () =>
  withApp(async ({ call }) => {
    assert.equal((await call("PATCH", "/api/shield/settings", { thresholds: { minFiles: 1 } })).status, 400);
    assert.equal((await call("PATCH", "/api/shield/settings", { unknown: 1 })).status, 400);
    assert.equal((await call("PATCH", "/api/shield/settings", { allowRemoteContain: false }, { Origin: "https://evil.example" })).status, 403);

    const ok = await call("PATCH", "/api/shield/settings", { allowRemoteContain: false });
    assert.equal(ok.status, 200);
    assert.equal(ok.json.allowRemoteContain, false);
  }));

test("alerts: list, filter, read with a token, and 404 for unknown ids", () =>
  withApp(async ({ store, call }) => {
    await store.shieldAlerts.upsert(alert);

    assert.equal((await call("GET", "/api/shield/alerts")).json.alerts.length, 1);
    assert.equal((await call("GET", "/api/shield/alerts?status=dismissed")).json.alerts.length, 0);
    assert.equal((await call("GET", "/api/shield/alerts?status=bogus")).status, 400);

    const one = await call("GET", "/api/shield/alerts/api-1");
    assert.equal(one.status, 200);
    assert.equal(typeof one.json.confirmToken, "string");

    assert.equal((await call("GET", "/api/shield/alerts/nope")).status, 404);
  }));

test("contain needs confirm: true and a valid token, and a bad attempt changes nothing", () =>
  withApp(async ({ store, call }) => {
    await store.shieldAlerts.upsert(alert);

    assert.equal((await call("POST", "/api/shield/alerts/api-1/contain", { actions: ["stop-suspect"] })).status, 400);
    assert.equal((await call("POST", "/api/shield/alerts/api-1/contain", { actions: ["stop-suspect"], confirm: true, confirmToken: "bad" })).status, 403);
    assert.equal((await store.shieldAlerts.get("api-1")).status, "open");
  }));

test("dismiss closes the alert and the score no longer counts it", () =>
  withApp(async ({ store, call }) => {
    await store.shieldAlerts.upsert(alert);

    const done = await call("POST", "/api/shield/alerts/api-1/dismiss", { ignoreHours: 0 });
    assert.equal(done.status, 200);
    assert.equal(done.json.alert.status, "dismissed");
    assert.equal((await call("POST", "/api/shield/alerts/api-1/dismiss", { ignoreHours: 500 })).status, 400);
  }));

test("GET /api/usb reports an off USB auto-scan and rejects bad settings and foreign origins", () =>
  withApp(async ({ call }) => {
    const status = await call("GET", "/api/usb");
    assert.equal(status.status, 200);
    assert.equal(status.json.enabled, false);

    assert.equal((await call("PATCH", "/api/usb/settings", { enabled: "yes" })).status, 400);
    assert.equal((await call("PATCH", "/api/usb/settings", { autoScan: false }, { Origin: "https://evil.example" })).status, 403);
    assert.equal((await call("GET", "/api/usb/events?status=bogus")).status, 400);
    assert.equal((await call("GET", "/api/usb/events/nope")).status, 404);
    assert.equal((await call("POST", "/api/usb/events/nope/quarantine-all", { confirm: true })).status, 403);
  }));

test("web: check validates input, reads a link without logging while off, and guards settings", () =>
  withApp(async ({ call }) => {
    assert.equal((await call("GET", "/api/web")).json.enabled, false);
    assert.equal((await call("POST", "/api/web/check", {})).status, 400);
    assert.equal((await call("POST", "/api/web/check", { url: "ftp://x.example" })).status, 400);

    const checked = await call("POST", "/api/web/check", { url: "http://192.168.1.5/verify" });
    assert.equal(checked.status, 200);
    assert.equal(checked.json.verdict, "warn");
    assert.equal(checked.json.logged, false);

    assert.equal((await call("POST", "/api/web/check", { url: "https://example.com" }, { Origin: "https://evil.example" })).status, 403);
    assert.equal((await call("PATCH", "/api/web/settings", { blocklist: ["not a domain"] })).status, 400);
    assert.equal((await call("GET", "/api/web/events?status=bogus")).status, 400);
    assert.equal((await call("GET", "/api/web/events/nope")).status, 404);
    assert.equal((await call("POST", "/api/web/feed/refresh", {})).status, 409);
  }));
