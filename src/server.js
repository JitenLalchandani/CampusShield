require("dotenv").config();

const express = require("express");
const path = require("path");
const crypto = require("node:crypto");
const { MongoClient } = require("mongodb");

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;

app.use(express.json());
app.use(express.static(path.join(__dirname, "..", "public")));

let db;
let eventsCollection;
let actionsCollection;

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
    _id: undefined,
    severity,
    rule,
    recommendation,
    status: action ? action.status : "Open"
  };
}

function publicEvent(event) {
  const { _id, ...safeEvent } = event;
  return safeEvent;
}

app.get("/api/health", async (_req, res) => {
  try {
    await db.command({ ping: 1 });

    res.json({
      status: "ok",
      database: "connected",
      app: "CampusShield",
      dataSource: "MongoDB Atlas; no live SIEM source connected"
    });
  } catch (error) {
    console.error("Health check failed:", error.message);
    res.status(503).json({
      status: "error",
      database: "unavailable",
      app: "CampusShield"
    });
  }
});

app.get("/api/events", async (_req, res) => {
  const [events, actions] = await Promise.all([
    eventsCollection.find({}).sort({ time: -1 }).toArray(),
    actionsCollection.find({}).toArray()
  ]);

  const actionByEvent = new Map(
    actions.map(action => [action.eventId, action])
  );

  res.json({
    events: events.map(event =>
      detect(publicEvent(event), actionByEvent.get(event.id))
    ),
    total: events.length,
    dataSource: "MongoDB Atlas; no live SIEM source connected"
  });
});

app.get("/api/summary", async (_req, res) => {
  const [events, actions] = await Promise.all([
    eventsCollection.find({}).toArray(),
    actionsCollection.find({}).toArray()
  ]);

  const actionByEvent = new Map(
    actions.map(action => [action.eventId, action])
  );

  const alerts = events.map(event =>
    detect(publicEvent(event), actionByEvent.get(event.id))
  );

  res.json({
    devicesReporting: null,
    eventsTotal: events.length,
    highPriority: alerts.filter(
      event => event.severity === "HIGH" && event.status === "Open"
    ).length,
    underReview: actions.filter(
      action => action.status === "Under review"
    ).length,
    contained: actions.filter(
      action => action.status === "Contained (demo)"
    ).length,
    dataSource: "MongoDB Atlas; no live SIEM source connected"
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
    id: String(id),
    time: new Date().toISOString(),
    group: String(group),
    type: String(type),
    source: String(source),
    count,
    detail: detail ? String(detail) : "Event received"
  };

  try {
    await eventsCollection.insertOne(event);
    return res.status(201).json({ event: detect(event) });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({ error: "Event ID already exists" });
    }
    throw error;
  }
});

// Scan recent macOS logs and persist matching indicators in MongoDB.
app.post("/api/scan", async (_req, res) => {
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
        await eventsCollection.insertOne(event);
        saved++;
      } catch (error) {
        if (error.code === 11000) {
          duplicates++;
        } else {
          throw error;
        }
      }
    }

    res.json({
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
    res.status(500).json({
      message: "Local scan failed. Check scanner permissions and log output.",
      error: error.message
    });
  }
});

app.post("/api/alerts/:id/action", async (req, res) => {
  const { action } = req.body || {};

  if (!["Investigate", "Contain"].includes(action)) {
    return res.status(400).json({
      error: "Action must be Investigate or Contain"
    });
  }

  const event = await eventsCollection.findOne({ id: req.params.id });

  if (!event) {
    return res.status(404).json({ error: "Event not found" });
  }

  const status = action === "Contain"
    ? "Contained (demo)"
    : "Under review";

  const actionRecord = {
    eventId: event.id,
    status,
    time: new Date().toISOString()
  };

  await actionsCollection.updateOne(
    { eventId: event.id },
    { $set: actionRecord },
    { upsert: true }
  );

  return res.json({
    event: detect(publicEvent(event), actionRecord),
    note: "Action history saved in MongoDB. This prototype has not changed or contained any real device or account."
  });
});

app.delete("/api/events", async (_req, res) => {
  const [eventsResult, actionsResult] = await Promise.all([
    eventsCollection.deleteMany({}),
    actionsCollection.deleteMany({})
  ]);

  res.json({
    message: "Events and action history cleared",
    total: 0,
    deletedEvents: eventsResult.deletedCount,
    deletedActions: actionsResult.deletedCount
  });
});

app.use((err, _req, res, _next) => {
  console.error("Request failed:", err.message);
  res.status(500).json({ error: "Internal server error" });
});

async function start() {
  if (!MONGODB_URI) {
    throw new Error("MONGODB_URI is missing from the .env file");
  }

  const client = new MongoClient(MONGODB_URI, {
    serverSelectionTimeoutMS: 10000
  });

  await client.connect();

  db = client.db();
  eventsCollection = db.collection("events");
  actionsCollection = db.collection("actions");

  await Promise.all([
    eventsCollection.createIndex({ id: 1 }, { unique: true }),
    actionsCollection.createIndex({ eventId: 1 }, { unique: true })
  ]);

  console.log("MongoDB Atlas connected successfully.");

  app.listen(PORT, () => {
    console.log(`CampusShield running at http://localhost:${PORT}`);
    console.log("No sample events are loaded.");
    console.log("No live SIEM scanner is connected.");
  });
}

start().catch(error => {
  console.error("CampusShield startup failed:", error);
  process.exit(1);
});
