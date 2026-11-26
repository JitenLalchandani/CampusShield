"use strict";

// HTTP routes for the ransomware shield. Reading needs a normal sign-in or token. Anything that
// changes settings or acts on the computer needs a signed-in account or the admin token, passes an
// Origin check, and (for Contain) a single-use confirmation that was issued when the alert was
// opened. The viewer token can read but can never change anything.

const { httpError } = require("./config");

const ALERT_STATUSES = new Set(["open", "contained", "dismissed"]);

function isLoopback(address) {
  return /^(::1$|127\.|::ffff:127\.)/.test(String(address || ""));
}

function registerShieldRoutes(app, { shield, isAllowedOrigin }) {
  // Who is calling, and whether they may change things. Returns null when they may not.
  function identify(req) {
    const address = req.socket?.remoteAddress || "unknown";
    const remote = !isLoopback(address);
    let key = null;

    if (req.session?.id) key = `session:${req.session.id}`;
    else if (req.apiRole === "admin") key = "admin-token";
    else if (req.apiRole === undefined && !remote) key = "local-open";

    if (!key) return null;

    const who = req.user?.username || req.user?.email || (key === "admin-token" ? "admin token" : "this computer");
    return { key, remote, label: `${who} from ${address}` };
  }

  function sameOrigin(origin, req) {
    try {
      return new URL(origin).host === req.headers.host;
    } catch {
      return false;
    }
  }

  function requireMutation(req) {
    const origin = req.headers.origin;

    if (origin && !(isAllowedOrigin(origin) || sameOrigin(origin, req))) {
      throw httpError("This request came from an origin that is not allowed.", 403);
    }

    const caller = identify(req);

    if (!caller) {
      throw httpError(
        "Sign in with an account or use the admin token to change the shield or contain an alert.",
        403
      );
    }

    return caller;
  }

  const handle = fn => async (req, res) => {
    try {
      await fn(req, res);
    } catch (error) {
      const code = error.statusCode || 500;
      if (code === 500) console.error("Shield request failed:", error.message);
      res.status(code).json({ error: code === 500 ? "Internal server error" : error.message });
    }
  };

  const alertId = req => {
    const id = String(req.params.id || "");
    if (!id || id.length > 64) throw httpError("Alert not found.", 404);
    return id;
  };

  app.get("/api/shield", handle(async (_req, res) => res.json(await shield.status())));

  app.patch(
    "/api/shield/settings",
    handle(async (req, res) => {
      requireMutation(req);
      res.json(await shield.updateSettings(req.body || {}));
    })
  );

  app.get(
    "/api/shield/alerts",
    handle(async (req, res) => {
      const status = req.query.status ? String(req.query.status) : null;
      if (status && !ALERT_STATUSES.has(status)) throw httpError("status must be open, contained, or dismissed.", 400);

      res.json({ alerts: await shield.listAlerts({ status, limit: req.query.limit }) });
    })
  );

  app.get(
    "/api/shield/alerts/:id",
    handle(async (req, res) => {
      // A confirmation token is only issued to a caller that is allowed to use it.
      const caller = identify(req);
      res.json(await shield.getAlert(alertId(req), caller ? caller.key : null));
    })
  );

  app.post(
    "/api/shield/alerts/:id/contain",
    handle(async (req, res) => {
      const caller = requireMutation(req);
      const body = req.body || {};

      if (body.confirm !== true) throw httpError("Send confirm: true to contain an alert.", 400);

      res.json(
        await shield.contain(alertId(req), {
          actions: body.actions,
          confirmToken: body.confirmToken,
          callerKey: caller.key,
          callerLabel: caller.label,
          remote: caller.remote
        })
      );
    })
  );

  app.post(
    "/api/shield/alerts/:id/undo",
    handle(async (req, res) => {
      const caller = requireMutation(req);
      res.json(await shield.undo(alertId(req), { action: (req.body || {}).action, callerLabel: caller.label }));
    })
  );

  app.post(
    "/api/shield/alerts/:id/keep-isolated",
    handle(async (req, res) => {
      const caller = requireMutation(req);
      res.json(await shield.keepIsolated(alertId(req), { callerLabel: caller.label }));
    })
  );

  app.post(
    "/api/shield/alerts/:id/dismiss",
    handle(async (req, res) => {
      const caller = requireMutation(req);
      const body = req.body || {};

      res.json(
        await shield.dismiss(alertId(req), {
          reason: body.reason,
          ignoreHours: body.ignoreHours,
          callerLabel: caller.label
        })
      );
    })
  );
}

module.exports = { registerShieldRoutes, isLoopback };
