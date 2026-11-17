"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const assistant = require("../src/assistant");
const { createStore } = require("../src/store");
const { createApp } = require("../src/server");

function state(overrides = {}) {
  return assistant.describeState({
    devices: [
      {
        id: "local-host",
        name: "Meets-MacBook-Pro",
        platformLabel: "macOS",
        kind: "computer",
        score: 78,
        grade: "Needs attention",
        checkedAt: "2026-11-18T09:00:00.000Z",
        summary: { passed: 9, attention: 1, unverified: 1 },
        checks: [
          { id: "firewall", title: "Firewall", status: "fail", severity: "high", detail: "Off", recommendation: "Turn it on." },
          { id: "disk-encryption", title: "Disk encryption", status: "pass", severity: "info", detail: "On" }
        ]
      }
    ],
    status: {
      signatureVersion: "2026.11.1",
      signatureCount: 48,
      watch: { enabled: false },
      watchSupported: true,
      preferences: { exclusions: [], schedule: { enabled: false, scope: "quick", frequency: "weekly", time: "09:00" } },
      signatureWarnings: []
    },
    scans: [
      {
        id: "scan-1",
        scope: "quick",
        status: "complete",
        startedAt: "2026-11-18T09:10:00.000Z",
        finishedAt: "2026-11-18T09:11:00.000Z",
        filesScanned: 4210,
        skipped: 3,
        truncated: false,
        errors: [],
        threats: [
          {
            id: "threat-1",
            name: "invoice.scr",
            severity: "HIGH",
            status: "detected",
            filePath: "/Users/me/Downloads/invoice.scr",
            reasons: ["Executable in Downloads"],
            detectedAt: "2026-11-18T09:10:30.000Z"
          }
        ]
      }
    ],
    quarantine: [],
    platform: "macOS",
    ...overrides
  });
}

test("describeState keeps only stored facts", () => {
  const snapshot = state();

  assert.equal(snapshot.host.score, 78);
  assert.equal(snapshot.openThreats.length, 1);
  assert.equal(snapshot.openThreats[0].name, "invoice.scr");
  assert.equal(snapshot.attentionChecks.length, 1);
  assert.equal(snapshot.attentionChecks[0].id, "firewall");
  assert.equal(snapshot.lastScan.filesScanned, 4210);
  assert.equal(snapshot.scanner.scheduleEnabled, false);
});

test("recommendations follow real findings", () => {
  const recs = assistant.recommendationsFor(state());

  assert.equal(recs[0].action.kind, "quarantine-threat");
  assert.equal(recs[0].action.threatId, "threat-1");
  assert.ok(recs.some(rec => rec.id === "check-firewall"));
  assert.ok(recs.some(rec => rec.id === "enable-watch"));
  assert.ok(recs.some(rec => rec.id === "schedule-scan"));
  assert.ok(!recs.some(rec => rec.id === "device-check"));
});

test("recommendations ask for a device check when nothing was checked", () => {
  const recs = assistant.recommendationsFor(state({ devices: [] }));
  assert.ok(recs.some(rec => rec.id === "device-check"));
});

test("detects security-test and status intents", () => {
  assert.equal(assistant.detectIntent("Please run a security test"), "run-security-test");
  assert.equal(assistant.detectIntent("scan my device"), "run-security-test");
  assert.equal(assistant.detectIntent("What is my status?"), "status");
  assert.equal(assistant.detectIntent("Are there any threats?"), "threats");
  assert.equal(assistant.detectIntent("Tell me a joke"), "question");
});

test("answers report stored numbers and avoid clean-device claims", () => {
  const statusReply = assistant.statusAnswer(state());
  assert.match(statusReply, /78\/100/);
  assert.match(statusReply, /4210 files/);
  assert.match(statusReply, /1 open detection/);
  assert.doesNotMatch(statusReply, /device is clean/i);

  const threatReply = assistant.threatsAnswer(state());
  assert.match(threatReply, /invoice\.scr/);
  assert.match(threatReply, /Downloads/);

  const emptyReply = assistant.threatsAnswer(state({ scans: [], devices: [], quarantine: [] }));
  assert.match(emptyReply, /No open detections/);
  assert.match(emptyReply, /not a guarantee/);
});

test("test summary never invents a score", () => {
  const reply = assistant.testStartedAnswer({
    device: null,
    check: { supported: false, message: "Device checks run on macOS and Windows only." },
    scan: { id: "scan-2", scope: "quick", startedAt: new Date().toISOString() },
    scanError: null
  });

  assert.match(reply, /Device checks run on macOS and Windows only/);
  assert.match(reply, /quick file scan is running/);
  assert.doesNotMatch(reply, /\/100/);
});

function mockProvider(received) {
  return new Promise(resolve => {
    const server = http.createServer((req, res) => {
      let body = "";
      req.on("data", chunk => (body += chunk));
      req.on("end", () => {
        received.push(JSON.parse(body));
        res.setHeader("content-type", "application/json");
        res.end(
          JSON.stringify({
            model: "mock-model",
            choices: [{ message: { content: "Provider reply from the snapshot." } }]
          })
        );
      });
    });

    server.listen(0, "127.0.0.1", () => {
      resolve({ server, baseUrl: `http://127.0.0.1:${server.address().port}/v1` });
    });
  });
}

test("assistant endpoints answer from stored data", async () => {
  const received = [];
  const provider = await mockProvider(received);
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), "cs-assistant-test-"));
  const store = await createStore({ dataDir });

  await store.devices.upsert({
    id: "local-host",
    name: "Test-Mac",
    kind: "computer",
    platform: "darwin",
    platformLabel: "macOS",
    source: "electron",
    role: "host",
    score: 78,
    postureScore: 88,
    scanPenalty: 10,
    grade: "Needs attention",
    checkedAt: new Date().toISOString(),
    lastSeen: new Date().toISOString(),
    summary: { passed: 9, attention: 1, unverified: 1 },
    checks: []
  });

  await store.scans.upsert({
    id: "scan-1",
    scope: "quick",
    status: "complete",
    startedAt: new Date().toISOString(),
    finishedAt: new Date().toISOString(),
    filesScanned: 4210,
    skipped: 0,
    truncated: false,
    errors: [],
    threats: [
      {
        id: "threat-1",
        name: "invoice.scr",
        severity: "HIGH",
        status: "detected",
        filePath: "/Users/me/Downloads/invoice.scr",
        reasons: ["Executable in Downloads"]
      }
    ]
  });

  const app = createApp({ store, dataDir });
  const server = await new Promise(resolve => {
    const instance = app.listen(0, "127.0.0.1", () => resolve(instance));
  });
  const base = `http://127.0.0.1:${server.address().port}`;

  const post = async (url, body = {}) => {
    const response = await fetch(`${base}${url}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body)
    });
    return { status: response.status, json: await response.json() };
  };

  try {
    const plain = await post("/api/assistant/suggest");
    assert.equal(plain.status, 200);
    assert.equal(plain.json.ai.available, false);
    assert.ok(plain.json.aiSetup.includes("OpenAI-compatible"));
    assert.ok(plain.json.recommendations.some(rec => rec.action.kind === "quarantine-threat"));

    const withAi = await post("/api/assistant/suggest", {
      ai: { baseUrl: provider.baseUrl, model: "mock", apiKey: "secret-key" }
    });
    assert.equal(withAi.json.ai.available, true);
    assert.equal(withAi.json.ai.reply, "Provider reply from the snapshot.");
    assert.ok(JSON.stringify(received[0].messages).includes("invoice.scr"));
    assert.ok(!JSON.stringify(received[0].messages).includes("secret-key"));

    const chat = await post("/api/assistant/chat", { message: "What is my status?" });
    assert.equal(chat.json.intent, "status");
    assert.match(chat.json.reply, /78\/100/);
    assert.match(chat.json.reply, /4210 files/);

    const summary = await post("/api/assistant/run-summary");
    assert.match(summary.json.summary, /Scanned 4210 files/);
    assert.match(summary.json.summary, /invoice\.scr/);
    assert.equal(summary.json.ai.available, false);

    const unsafe = await post("/api/assistant/suggest", {
      ai: { baseUrl: "http://provider.example.com/v1", model: "mock" }
    });
    assert.equal(unsafe.status, 400);
  } finally {
    server.close();
    provider.server.close();
    await store.close();
    await fs.rm(dataDir, { recursive: true, force: true });
  }
});
