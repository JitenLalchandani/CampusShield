"use strict";

// HTTP routes for web & phishing protection. Same guards as the shield and USB routes. A check can
// write a log entry, so it needs a signed-in account or the admin token, like every change.

const { httpError } = require("../shield/config");
const { createGuards } = require("../shield/routes");

const EVENT_STATUSES = new Set(["open", "dismissed"]);

function registerWebRoutes(app, { web, isAllowedOrigin }) {
  const { requireMutation, handle } = createGuards(isAllowedOrigin);

  const idParam = req => {
    const id = String(req.params.id || "");
    if (!id || id.length > 64) throw httpError("Not found.", 404);
    return id;
  };

  app.get("/api/web", handle(async (_req, res) => res.json(await web.status())));

  app.patch(
    "/api/web/settings",
    handle(async (req, res) => {
      const caller = requireMutation(req);
      res.json(await web.updateSettings(req.body || {}, { callerLabel: caller.label }));
    })
  );

  app.post(
    "/api/web/check",
    handle(async (req, res) => {
      const caller = requireMutation(req);
      const url = (req.body || {}).url;
      if (typeof url !== "string") throw httpError("Send the link as text in url.", 400);

      res.json(await web.check(url, { callerKey: caller.key, callerLabel: caller.label }));
    })
  );

  app.post(
    "/api/web/feed/refresh",
    handle(async (req, res) => {
      requireMutation(req);
      res.json({ feed: await web.refreshFeed() });
    })
  );

  app.get(
    "/api/web/events",
    handle(async (req, res) => {
      const status = req.query.status ? String(req.query.status) : null;
      if (status && !EVENT_STATUSES.has(status)) throw httpError("Unknown status.", 400);

      res.json({ events: await web.listEvents({ status, limit: req.query.limit }) });
    })
  );

  app.get("/api/web/events/:id", handle(async (req, res) => res.json(await web.getEvent(idParam(req)))));

  app.post(
    "/api/web/events/:id/dismiss",
    handle(async (req, res) => {
      const caller = requireMutation(req);
      res.json(await web.dismiss(idParam(req), { callerLabel: caller.label }));
    })
  );
}

module.exports = { registerWebRoutes };
