"use strict";

require("dotenv").config();

const express = require("express");
const path = require("node:path");
const crypto = require("node:crypto");
const { createStore } = require("./store");

const PUBLIC_DIR = path.join(__dirname, "..", "public");
const ACTIONS = ["Investigate", "Contain", "Reopen"];
const DEVICE_PLATFORMS = ["darwin", "win32", "linux", "ios", "android", "web"];
const DEVICE_KINDS = ["computer", "phone", "tablet", "browser"];
const DEVICE_SOURCES = ["web", "native", "electron"];
const PLATFORM_LABELS = {
  darwin: "macOS",
  win32: "Windows",
  linux: "Linux",
  ios: "iOS",
  android: "Android",
  web: "Web"
};
const HOST_DEVICE_ID = "local-host";
const { auditHost, gradeFor, RULES_VERSION } = require("./deviceAudit");

function platformLabel(platform) {
  return PLATFORM_LABELS[platform] || platform || "Unknown";
}

function deviceAuditAvailable() {
  return process.platform === "darwin";
}

function detect(event, action = null) {
  let severity = "LOW";
  let rule = "No high-risk rule matched";
  let recommendation = "Continue monitoring";

  if (event.type === "login_failure" && event.count >= 5) {
    severity = event.count >= 8 ? "HIGH" : "MEDIUM";
    rule = "Repeated authentication failures";
    recommendation =
      "Review authentication logs and verify the activity";
  } else if (event.type === "malicious_domain") {
    severity = "HIGH";
    rule = "Threat-intelligence indicator match";
    recommendation =
      "Validate the indicator and investigate DNS/proxy logs";
  } else if (event.type === "outbound_spike" && event.count >= 3) {
    severity = "MEDIUM";
    rule = "Outbound traffic deviation";
    recommendation = "Compare traffic with the asset baseline";
  } else if (event.type === "unpatched_endpoint") {
    severity = "MEDIUM";
    rule = "Missing critical patch";
    recommendation = "Verify the asset and plan an approved patch";
  }

  return {
    ...event,
    severity,
    rule,
    recommendation,
    status: action ? action.status : "Open",
    statusUpdatedAt: action ? action.time : null
  };
}

function publicDoc(doc) {
  if (!doc) return null;
  const { _id, ...rest } = doc;
  return rest;
}

function dataSourceLabel(store) {
  const storage = store.kind === "mongodb" ? "MongoDB" : "local JSON store";
  return `${storage}; no live SIEM source connected`;
}

function storageLabel(store) {
  return store.kind === "mongodb" ? "MongoDB Atlas" : "Local JSON store";
}

function paging(query, defaultLimit, maxLimit) {
  const rawLimit = Number.parseInt(query.limit, 10);
  const rawOffset = Number.parseInt(query.offset, 10);
  const limit = Number.isFinite(rawLimit)
    ? Math.min(Math.max(rawLimit, 1), maxLimit)
    : defaultLimit;
  const offset = Number.isFinite(rawOffset) && rawOffset > 0 ? rawOffset : 0;
  return { limit, offset };
}

function text(value, max = 120) {
  return String(value ?? "").trim().slice(0, max);
}

function buildDaily(alerts) {
  const days = [];
  const now = new Date();

  for (let index = 6; index >= 0; index -= 1) {
    const day = new Date(
      Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - index)
    );
    const key = day.toISOString().slice(0, 10);
    days.push({
      date: key,
      label: day.toLocaleDateString("en-US", { weekday: "short", timeZone: "UTC" }),
      count: 0
    });
  }

  const byDate = new Map(days.map(day => [day.date, day]));

  for (const alert of alerts) {
    const key = String(alert.time || "").slice(0, 10);
    const day = byDate.get(key);
    if (day) day.count += 1;
  }

  return days;
}

function auditEntry(store, entry) {
  return store.audit.append({
    id: crypto.randomUUID(),
    time: new Date().toISOString(),
    kind: entry.kind,
    message: entry.message,
    eventId: entry.eventId || null,
    severity: entry.severity || null,
    status: entry.status || null
  });
}

async function loadAlerts(store) {
  const [events, actions] = await Promise.all([
    store.events.all(),
    store.actions.all()
  ]);

  const actionByEvent = new Map(
    actions.map(action => [action.eventId, action])
  );

  return events
    .map(event => detect(publicDoc(event), actionByEvent.get(event.id)))
    .sort((a, b) => Date.parse(b.time || 0) - Date.parse(a.time || 0));
}

function protectionSummary(devices) {
  const checked = devices.filter(device => Number.isFinite(device.score));
  const average = checked.length
    ? Math.round(
        checked.reduce((sum, device) => sum + device.score, 0) / checked.length
      )
    : null;
  const weakest = checked
    .slice()
    .sort((a, b) => a.score - b.score)[0] || null;

  return {
    total: devices.length,
    checked: checked.length,
    average,
    grade: gradeFor(average),
    weakest: weakest
      ? { id: weakest.id, name: weakest.name, score: weakest.score }
      : null
  };
}

function createApp({ store }) {
  const app = express();
  const version = require("../package.json").version;

  app.disable("x-powered-by");
  app.use(express.json({ limit: "1mb" }));

  // Allow the Capacitor shells (and configured hosts) to call the API.
  const allowedOrigins = new Set(
    (process.env.CORS_ORIGIN || "")
      .split(",")
      .map(origin => origin.trim())
      .filter(Boolean)
  );

  app.use((req, res, next) => {
    const origin = req.headers.origin;

    if (origin) {
      const isLocalShell =
        origin === "capacitor://localhost" ||
        origin === "ionic://localhost" ||
        origin === "http://localhost" ||
        origin === "https://localhost" ||
        /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/.test(origin);

      if (isLocalShell || allowedOrigins.has(origin)) {
        res.setHeader("Access-Control-Allow-Origin", origin);
        res.setHeader("Vary", "Origin");
        res.setHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
        res.setHeader("Access-Control-Allow-Headers", "Content-Type");
      }
    }

    if (req.method === "OPTIONS") return res.sendStatus(204);
    return next();
  });

  app.use((_req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("X-Frame-Options", "DENY");
    next();
  });

  app.get("/api/health", (_req, res) => {
    res.json({
      status: "ok",
      database: store.kind === "mongodb" ? "connected" : "local",
      storage: storageLabel(store),
      app: "CampusShield",
      version,
      platform: process.platform,
      platformLabel: platformLabel(process.platform),
      scannerAvailable: process.platform === "darwin",
      deviceAuditAvailable: deviceAuditAvailable(),
      rulesVersion: RULES_VERSION,
      uptimeSeconds: Math.round(process.uptime()),
      dataSource: dataSourceLabel(store)
    });
  });

  app.get("/api/summary", async (_req, res) => {
    const [alerts, auditTotal, devices] = await Promise.all([
      loadAlerts(store),
      store.audit.count(),
      store.devices.all()
    ]);

    const severity = { HIGH: 0, MEDIUM: 0, LOW: 0 };
    const statusCounts = { Open: 0, "Under review": 0, "Contained (demo)": 0 };

    for (const alert of alerts) {
      severity[alert.severity] = (severity[alert.severity] || 0) + 1;
      statusCounts[alert.status] = (statusCounts[alert.status] || 0) + 1;
    }

    res.json({
      devicesReporting: devices.length,
      protection: protectionSummary(devices),
      eventsTotal: alerts.length,
      highPriority: alerts.filter(
        alert => alert.severity === "HIGH" && alert.status === "Open"
      ).length,
      underReview: statusCounts["Under review"],
      contained: statusCounts["Contained (demo)"],
      open: statusCounts.Open,
      severity,
      statusCounts,
      daily: buildDaily(alerts),
      lastEventTime: alerts[0] ? alerts[0].time : null,
      auditTotal,
      storage: storageLabel(store),
      platform: process.platform,
      platformLabel: platformLabel(process.platform),
      scannerAvailable: process.platform === "darwin",
      deviceAuditAvailable: deviceAuditAvailable(),
      rulesVersion: RULES_VERSION,
      dataSource: dataSourceLabel(store)
    });
  });

  app.get("/api/protection", async (_req, res) => {
    const devices = (await store.devices.all()).map(publicDoc);

    res.json({
      devices,
      summary: protectionSummary(devices),
      rulesVersion: RULES_VERSION,
      auditAvailable: deviceAuditAvailable(),
      platform: process.platform,
      platformLabel: platformLabel(process.platform),
      storage: storageLabel(store)
    });
  });

  // Runs read-only checks on the server host. Nothing is changed on the device.
  app.post("/api/protection/scan", async (_req, res) => {
    let audit;

    try {
      audit = await auditHost();
    } catch (error) {
      console.error("Device check failed:", error.message);
      return res.status(500).json({
        message: "Device check failed before it could finish.",
        error: error.message
      });
    }

    if (!audit.supported) {
      return res.status(501).json({
        supported: false,
        platform: audit.platform,
        message: audit.message
      });
    }

    const existing = await store.devices.get(HOST_DEVICE_ID);
    const checkedAt = audit.checkedAt || new Date().toISOString();

    const device = {
      id: HOST_DEVICE_ID,
      name: audit.hostname || "This computer",
      kind: "computer",
      platform: audit.platform,
      platformLabel: audit.platformLabel,
      source: "electron",
      role: "host",
      model: audit.model || null,
      score: audit.score,
      grade: audit.grade,
      rulesVersion: audit.rulesVersion,
      checkedAt,
      lastSeen: checkedAt,
      createdAt: existing ? existing.createdAt : checkedAt,
      checks: audit.checks,
      summary: {
        passed: audit.passed,
        attention: audit.attention,
        unverified: audit.unverified
      }
    };

    await store.devices.upsert(device);

    await auditEntry(store, {
      kind: "device",
      message:
        `Device check on ${device.name}: ${device.score}/100 (${device.grade}) · ` +
        `${audit.passed} passed · ${audit.attention} need attention · ` +
        `${audit.unverified} unverified`,
      severity: audit.attention > 0 ? "MEDIUM" : null
    });

    const devices = (await store.devices.all()).map(publicDoc);

    return res.json({
      device,
      summary: protectionSummary(devices),
      note:
        "Checks are read-only. Settings are reported as found and were not changed."
    });
  });

  app.get("/api/devices", async (_req, res) => {
    const devices = (await store.devices.all()).map(publicDoc);
    res.json({ devices, summary: protectionSummary(devices) });
  });

  // Register another device in the household. Its score stays "Not checked"
  // until that device runs its own native check.
  app.post("/api/devices", async (req, res) => {
    const name = text(req.body?.name, 60);
    const kind = text(req.body?.kind, 20) || "phone";
    const platform = text(req.body?.platform, 20) || "web";
    const source = text(req.body?.source, 20) || "web";

    if (!name) {
      return res.status(400).json({ error: "Provide a device name" });
    }
    if (!DEVICE_KINDS.includes(kind)) {
      return res.status(400).json({
        error: `Kind must be one of: ${DEVICE_KINDS.join(", ")}`
      });
    }
    if (!DEVICE_PLATFORMS.includes(platform)) {
      return res.status(400).json({
        error: `Platform must be one of: ${DEVICE_PLATFORMS.join(", ")}`
      });
    }
    if (!DEVICE_SOURCES.includes(source)) {
      return res.status(400).json({
        error: `Source must be one of: ${DEVICE_SOURCES.join(", ")}`
      });
    }

    const now = new Date().toISOString();
    const device = {
      id: crypto.randomUUID(),
      name,
      kind,
      platform,
      platformLabel: platformLabel(platform),
      source,
      role: "linked",
      model: null,
      score: null,
      grade: "Not checked",
      rulesVersion: null,
      checkedAt: null,
      lastSeen: now,
      createdAt: now,
      checks: [],
      summary: null
    };

    await store.devices.upsert(device);

    await auditEntry(store, {
      kind: "device",
      message: `Linked ${kind} "${name}" (${platformLabel(platform)}) · score not checked`
    });

    const devices = (await store.devices.all()).map(publicDoc);

    return res.status(201).json({
      device,
      summary: protectionSummary(devices),
      note:
        "Linked devices appear in the cross-device score once that device runs its own check."
    });
  });

  app.delete("/api/devices/:id", async (req, res) => {
    const removed = await store.devices.remove(req.params.id);

    if (!removed) {
      return res.status(404).json({ error: "Device not found" });
    }

    await auditEntry(store, {
      kind: "device",
      message: `Removed device ${req.params.id} from the cross-device score`
    });

    const devices = (await store.devices.all()).map(publicDoc);

    return res.json({
      removed: req.params.id,
      devices,
      summary: protectionSummary(devices)
    });
  });

  app.get("/api/events", async (req, res) => {
    const { limit, offset } = paging(req.query, 25, 200);
    const severityFilter = text(req.query.severity, 20);
    const statusFilter = text(req.query.status, 30);
    const typeFilter = text(req.query.type);
    const groupFilter = text(req.query.group);
    const search = text(req.query.q).toLowerCase();
    const sort = text(req.query.sort, 20) || "newest";

    let alerts = await loadAlerts(store);
    const allTotal = alerts.length;
    const facets = {
      types: [...new Set(alerts.map(alert => alert.type))].sort(),
      groups: [...new Set(alerts.map(alert => alert.group))].sort()
    };

    if (severityFilter && severityFilter !== "all") {
      alerts = alerts.filter(alert => alert.severity === severityFilter);
    }
    if (statusFilter && statusFilter !== "all") {
      alerts = alerts.filter(alert => alert.status === statusFilter);
    }
    if (typeFilter && typeFilter !== "all") {
      alerts = alerts.filter(alert => alert.type === typeFilter);
    }
    if (groupFilter && groupFilter !== "all") {
      alerts = alerts.filter(alert => alert.group === groupFilter);
    }
    if (search) {
      alerts = alerts.filter(alert =>
        [alert.id, alert.type, alert.group, alert.source, alert.detail, alert.rule]
          .some(value => String(value || "").toLowerCase().includes(search))
      );
    }

    if (sort === "oldest") {
      alerts.sort((a, b) => Date.parse(a.time || 0) - Date.parse(b.time || 0));
    } else if (sort === "severity") {
      const rank = { HIGH: 0, MEDIUM: 1, LOW: 2 };
      alerts.sort(
        (a, b) =>
          (rank[a.severity] ?? 3) - (rank[b.severity] ?? 3) ||
          Date.parse(b.time || 0) - Date.parse(a.time || 0)
      );
    }

    const total = alerts.length;
    const page = alerts.slice(offset, offset + limit);

    res.json({
      events: page,
      count: page.length,
      total,
      allTotal,
      limit,
      offset,
      facets,
      dataSource: dataSourceLabel(store)
    });
  });

  app.get("/api/events/:id", async (req, res) => {
    const event = await store.events.get(req.params.id);

    if (!event) {
      return res.status(404).json({ error: "Event not found" });
    }

    const [actions, history] = await Promise.all([
      store.actions.all(),
      store.audit.forEvent(event.id)
    ]);

    const action = actions.find(item => item.eventId === event.id);

    return res.json({
      event: detect(publicDoc(event), action),
      history: history.map(publicDoc),
      dataSource: dataSourceLabel(store)
    });
  });

  app.get("/api/activity", async (req, res) => {
    const { limit, offset } = paging(req.query, 50, 200);
    const kind = text(req.query.kind, 20);

    const [activity, total] = await Promise.all([
      store.audit.all(limit, offset, kind || null),
      store.audit.count(kind || null)
    ]);

    res.json({
      activity: activity.map(publicDoc),
      count: activity.length,
      total,
      limit,
      offset
    });
  });

  // Accept events from an approved source. This endpoint does not
  // independently verify that submitted events are genuine.
  app.post("/api/events", async (req, res) => {
    const { id, group, type, source, count, detail } = req.body || {};

    if (
      !id || !group || !type || !source ||
      !Number.isFinite(count) || count < 0
    ) {
      return res.status(400).json({
        error: "Provide id, group, type, source, and a non-negative numeric count"
      });
    }

    const event = {
      id: String(id).slice(0, 200),
      time: new Date().toISOString(),
      group: String(group).slice(0, 120),
      type: String(type).slice(0, 120),
      source: String(source).slice(0, 120),
      count,
      detail: detail ? String(detail).slice(0, 500) : "Event received"
    };

    try {
      await store.events.insert(event);
      const alert = detect(event);

      await auditEntry(store, {
        kind: "ingest",
        message: `Ingested ${alert.type} event for ${alert.group} from ${alert.source}`,
        eventId: event.id,
        severity: alert.severity
      });

      return res.status(201).json({ event: alert });
    } catch (error) {
      if (error.code === 11000) {
        return res.status(409).json({ error: "Event ID already exists" });
      }
      throw error;
    }
  });

  // Scan recent macOS logs and persist matching indicators.
  app.post("/api/scan", async (_req, res) => {
    if (process.platform !== "darwin") {
      return res.status(501).json({
        message: "Local log scanning is only available when the server runs on macOS."
      });
    }

    try {
      const { scanMacLogs } = require("./localScanner");
      const result = await scanMacLogs();
      let saved = 0;
      let duplicates = 0;

      for (const finding of result.findings) {
        const event = {
          id: finding.id,
          time: finding.timestamp,
          group: finding.group,
          type: finding.type,
          source: finding.source,
          count: finding.count,
          detail: finding.description
        };

        try {
          await store.events.insert(event);
          saved += 1;

          await auditEntry(store, {
            kind: "detection",
            message: `Detected ${finding.type} on ${finding.group}`,
            eventId: finding.id,
            severity: "LOW"
          });
        } catch (error) {
          if (error.code === 11000) duplicates += 1;
          else throw error;
        }
      }

      await auditEntry(store, {
        kind: "scan",
        message:
          `Scanned the macOS unified log (last ${result.windowMinutes} min): ` +
          `${result.entriesMatched} indicators, ${saved} new events`
      });

      return res.json({
        message: "Local macOS log scan completed.",
        scanner: "macOS Unified Log",
        windowMinutes: result.windowMinutes,
        indicatorsMatched: result.entriesMatched,
        newEventsSaved: saved,
        duplicatesSkipped: duplicates,
        findings: result.findings,
        note: "Log phrase matches are indicators for review, not proof of an attack."
      });
    } catch (error) {
      console.error("Local scan failed:", error.message);
      return res.status(500).json({
        message: "Local scan failed. Check scanner permissions and log output.",
        error: error.message
      });
    }
  });

  app.post("/api/alerts/:id/action", async (req, res) => {
    const { action } = req.body || {};

    if (!ACTIONS.includes(action)) {
      return res.status(400).json({
        error: `Action must be one of: ${ACTIONS.join(", ")}`
      });
    }

    const event = await store.events.get(req.params.id);

    if (!event) {
      return res.status(404).json({ error: "Event not found" });
    }

    const status = action === "Contain"
      ? "Contained (demo)"
      : action === "Investigate"
        ? "Under review"
        : "Open";

    const actionRecord = {
      eventId: event.id,
      action,
      status,
      actor: "Analyst (local)",
      time: new Date().toISOString()
    };

    await store.actions.upsert(actionRecord);

    const alert = detect(publicDoc(event), actionRecord);

    await auditEntry(store, {
      kind: "action",
      message: `${action} · ${event.type} · ${event.group} (status: ${status})`,
      eventId: event.id,
      severity: alert.severity,
      status
    });

    return res.json({
      event: alert,
      note: status === "Open"
        ? "Event reopened for review."
        : "Action history saved. This prototype has not changed or contained any real device or account."
    });
  });

  app.delete("/api/events", async (_req, res) => {
    const [deletedEvents, deletedActions, deletedAudit, deletedDevices] =
      await Promise.all([
        store.events.clear(),
        store.actions.clear(),
        store.audit.clear(),
        store.devices.clear()
      ]);

    await auditEntry(store, {
      kind: "admin",
      message:
        `Cleared all data (${deletedEvents} events, ` +
        `${deletedActions} actions, ${deletedDevices} devices, ` +
        `${deletedAudit} history entries)`
    });

    res.json({
      message: "Events, actions, devices, and audit history cleared",
      total: 0,
      deletedEvents,
      deletedActions,
      deletedDevices,
      deletedAudit
    });
  });

  app.use("/api", (_req, res) => {
    res.status(404).json({ error: "API route not found" });
  });

  app.use(
    express.static(PUBLIC_DIR, {
      setHeaders(res, filePath) {
        if (filePath.endsWith(".html") || filePath.endsWith("sw.js")) {
          res.setHeader("Cache-Control", "no-cache");
        }
      }
    })
  );

  app.get("*", (_req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, "index.html"));
  });

  app.use((err, _req, res, _next) => {
    if (res.headersSent) return;

    if (err.type === "entity.parse.failed") {
      return res.status(400).json({ error: "Request body must be valid JSON" });
    }

    console.error("Request failed:", err.message);
    return res.status(500).json({ error: "Internal server error" });
  });

  return app;
}

async function start(options = {}) {
  const dataDir =
    options.dataDir ||
    process.env.CAMPUSSHIELD_DATA_DIR ||
    path.join(__dirname, "..", "data");

  const store = await createStore({
    mongoUri: process.env.MONGODB_URI,
    dataDir
  });

  const app = createApp({ store });
  const port = options.port ?? Number(process.env.PORT || 3000);

  const server = await new Promise((resolve, reject) => {
    const instance = app.listen(port, options.host, () => resolve(instance));
    instance.on("error", reject);
  });

  const actualPort = server.address().port;

  if (!options.quiet) {
    console.log(`CampusShield running at http://localhost:${actualPort}`);
    console.log(
      `Storage: ${storageLabel(store)}${store.location ? ` (${store.location})` : ""}`
    );
    console.log(
      process.platform === "darwin"
        ? "Local macOS log scanning and device checks: available"
        : "Local macOS log scanning and device checks: unavailable on this platform"
    );
    console.log("No sample events are loaded. No live SIEM is connected.");
  }

  return { app, server, store, port: actualPort };
}

if (require.main === module) {
  start()
    .then(({ server, store }) => {
      const shutdown = async () => {
        server.close();
        await store.close();
        process.exit(0);
      };

      process.on("SIGINT", shutdown);
      process.on("SIGTERM", shutdown);
    })
    .catch(error => {
      console.error("CampusShield startup failed:", error.message);
      process.exit(1);
    });
}

module.exports = { createApp, start, detect };
