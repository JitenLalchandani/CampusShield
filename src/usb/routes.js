"use strict";

// HTTP routes for USB auto-scan. Same guards as the ransomware shield: reading needs a normal
// sign-in or token; anything that changes settings or acts on files needs a signed-in account or
// the admin token and passes the Origin check. Quarantine also needs a single-use confirmation.

const { httpError } = require("../shield/config");
const { createGuards } = require("../shield/routes");

const EVENT_STATUSES = new Set(["scanning", "clean", "open", "incomplete", "removed", "dismissed"]);

function registerUsbRoutes(app, { usb, isAllowedOrigin }) {
  const { identify, requireMutation, handle } = createGuards(isAllowedOrigin);

  const idParam = req => {
    const id = String(req.params.id || "");
    if (!id || id.length > 128) throw httpError("Not found.", 404);
    return id;
  };

  app.get("/api/usb", handle(async (_req, res) => res.json(await usb.status())));

  app.patch(
    "/api/usb/settings",
    handle(async (req, res) => {
      requireMutation(req);
      res.json(await usb.updateSettings(req.body || {}));
    })
  );

  app.get(
    "/api/usb/events",
    handle(async (req, res) => {
      const status = req.query.status ? String(req.query.status) : null;
      if (status && !EVENT_STATUSES.has(status)) throw httpError("Unknown status.", 400);

      res.json({ events: await usb.listEvents({ status, limit: req.query.limit }) });
    })
  );

  app.get(
    "/api/usb/events/:id",
    handle(async (req, res) => {
      const caller = identify(req);
      res.json(await usb.getEvent(idParam(req), caller ? caller.key : null));
    })
  );

  app.post(
    "/api/usb/drives/:id/scan",
    handle(async (req, res) => {
      const caller = requireMutation(req);
      res.status(202).json({ event: await usb.scanDrive(idParam(req), { callerLabel: caller.label }) });
    })
  );

  app.post(
    "/api/usb/drives/:id/ignore",
    handle(async (req, res) => {
      const caller = requireMutation(req);
      const ignore = (req.body || {}).ignore;
      if (ignore !== undefined && typeof ignore !== "boolean") throw httpError("ignore must be true or false.", 400);

      res.json(await usb.ignoreDrive(idParam(req), ignore !== false, { callerLabel: caller.label }));
    })
  );

  app.post(
    "/api/usb/events/:id/dismiss",
    handle(async (req, res) => {
      const caller = requireMutation(req);
      res.json(await usb.dismiss(idParam(req), { reason: (req.body || {}).reason, callerLabel: caller.label }));
    })
  );

  app.post(
    "/api/usb/events/:id/quarantine-all",
    handle(async (req, res) => {
      const caller = requireMutation(req);
      const body = req.body || {};

      if (body.confirm !== true) throw httpError("Send confirm: true to quarantine files from a drive.", 400);

      res.json(
        await usb.quarantineAll(idParam(req), {
          confirmToken: body.confirmToken,
          callerKey: caller.key,
          callerLabel: caller.label
        })
      );
    })
  );
}

module.exports = { registerUsbRoutes };
