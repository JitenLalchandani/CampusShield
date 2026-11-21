"use strict";

const crypto = require("node:crypto");

const SESSION_COOKIE = "cs_session";
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const SESSION_TOUCH_MS = 60 * 60 * 1000;
const PASSWORD_MIN = 10;
const PASSWORD_MAX = 200;
const KEY_LENGTH = 64;
const SCRYPT_OPTIONS = { N: 16384, r: 8, p: 1, maxmem: 96 * 1024 * 1024 };
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const USERNAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{2,31}$/;

function authError(message, statusCode = 400) {
  return Object.assign(new Error(message), { statusCode });
}

function normalizeEmail(raw) {
  return String(raw || "").trim().toLowerCase().slice(0, 254);
}

function validateEmail(raw) {
  const email = normalizeEmail(raw);
  if (!EMAIL_PATTERN.test(email)) throw authError("Enter a valid email address.");
  return email;
}

function normalizeName(raw) {
  const name = String(raw || "").trim().replace(/\s+/g, " ").slice(0, 60);
  if (name.length < 2) throw authError("Enter a name of at least 2 characters.");
  return name;
}

function normalizeUsername(raw) {
  return String(raw || "").trim().slice(0, 32);
}

function validateUsername(raw) {
  const username = normalizeUsername(raw);
  if (!USERNAME_PATTERN.test(username)) {
    throw authError(
      "Choose a username of 3-32 characters: letters, numbers, dots, dashes, or underscores."
    );
  }
  return username;
}

function validatePassword(raw) {
  const password = String(raw || "");
  if (password.length < PASSWORD_MIN) {
    throw authError(`Use at least ${PASSWORD_MIN} characters. A short sentence works well.`);
  }
  if (password.length > PASSWORD_MAX) {
    throw authError(`Keep the password under ${PASSWORD_MAX} characters.`);
  }
  return password;
}

function scrypt(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, KEY_LENGTH, SCRYPT_OPTIONS, (error, derived) => {
      if (error) reject(error);
      else resolve(derived);
    });
  });
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const derived = await scrypt(password, salt);
  return { salt, hash: derived.toString("hex") };
}

async function verifyPassword(password, record = {}) {
  const expected = Buffer.from(String(record.hash || ""), "hex");
  if (!record.salt || expected.length !== KEY_LENGTH) return false;

  const derived = await scrypt(String(password || ""), record.salt);
  return crypto.timingSafeEqual(derived, expected);
}

// Login for an unknown email still pays the scrypt cost, so response time
// does not reveal whether the account exists.
let dummyRecord = null;
async function dummyPasswordRecord() {
  if (!dummyRecord) dummyRecord = hashPassword("campusshield-dummy-password");
  return dummyRecord;
}

function createSessionToken() {
  return crypto.randomBytes(32).toString("base64url");
}

function hashToken(token) {
  return crypto.createHash("sha256").update(String(token)).digest("hex");
}

function parseCookies(header) {
  const cookies = {};

  for (const part of String(header || "").split(";")) {
    const index = part.indexOf("=");
    if (index === -1) continue;

    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    if (name) cookies[name] = decodeURIComponent(value);
  }

  return cookies;
}

function sessionCookie(token, { secure = false, maxAgeSeconds = SESSION_TTL_MS / 1000 } = {}) {
  const parts = [
    `${SESSION_COOKIE}=${token}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${Math.round(maxAgeSeconds)}`
  ];

  if (secure) parts.push("Secure");
  return parts.join("; ");
}

function expiredSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
}

function isSecureRequest(req) {
  const forwarded = String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim();
  return req.secure || forwarded === "https";
}

function sessionToken(req) {
  const fromCookie = parseCookies(req.headers.cookie)[SESSION_COOKIE];
  if (fromCookie) return fromCookie;

  const bearer = String(req.headers.authorization || "").match(/^Bearer\s+(.+)$/i);
  if (bearer) return bearer[1].trim();

  return "";
}

function publicUser(user) {
  if (!user) return null;

  return {
    id: user.id,
    email: user.email,
    username: user.username || null,
    name: user.name,
    role: user.role,
    createdAt: user.createdAt || null,
    lastLoginAt: user.lastLoginAt || null
  };
}

function createLoginLimiter({ maxAttempts = 8, windowMs = 15 * 60 * 1000, now = () => Date.now() } = {}) {
  const entries = new Map();

  function entry(key) {
    const current = entries.get(key);
    if (current && current.resetAt > now()) return current;

    const fresh = { count: 0, resetAt: now() + windowMs };
    entries.set(key, fresh);
    return fresh;
  }

  return {
    retryAfterSeconds(key) {
      const current = entry(key);
      return current.count >= maxAttempts
        ? Math.max(1, Math.ceil((current.resetAt - now()) / 1000))
        : 0;
    },
    fail(key) {
      entry(key).count += 1;
    },
    succeed(key) {
      entries.delete(key);
    },
    clear() {
      entries.clear();
    }
  };
}

async function resolveSession(req, store) {
  const token = sessionToken(req);
  if (!token) return null;

  const session = await store.sessions.findByToken(hashToken(token));
  if (!session) return null;

  if (!session.expiresAt || Date.parse(session.expiresAt) <= Date.now()) {
    await store.sessions.remove(session.id);
    return null;
  }

  const user = await store.users.get(session.userId);
  if (!user) {
    await store.sessions.remove(session.id);
    return null;
  }

  if (!session.lastSeenAt || Date.now() - Date.parse(session.lastSeenAt) > SESSION_TOUCH_MS) {
    const lastSeenAt = new Date().toISOString();
    await store.sessions.update(session.id, { lastSeenAt });
    session.lastSeenAt = lastSeenAt;
  }

  return { session, user };
}

function registerAuthRoutes(app, { store, audit, limiter = createLoginLimiter() }) {
  const log = typeof audit === "function" ? audit : async () => {};

  function setSessionCookie(req, res, token) {
    res.setHeader("Set-Cookie", sessionCookie(token, { secure: isSecureRequest(req) }));
  }

  async function startSession(req, res, user) {
    const token = createSessionToken();
    const now = new Date();
    const session = {
      id: crypto.randomUUID(),
      userId: user.id,
      tokenHash: hashToken(token),
      createdAt: now.toISOString(),
      lastSeenAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + SESSION_TTL_MS).toISOString()
    };

    await store.sessions.insert(session);
    setSessionCookie(req, res, token);
    return { token, expiresAt: session.expiresAt };
  }

  function sendAuthError(res, error, next) {
    if (error && error.statusCode) {
      return res.status(error.statusCode).json({ error: error.message });
    }

    return next(error);
  }

  async function requireUser(req) {
    const resolved = await resolveSession(req, store);
    if (!resolved) throw authError("Sign in to continue.", 401);
    return resolved.user;
  }

  async function requireOwner(req) {
    const user = await requireUser(req);
    if (user.role !== "owner") throw authError("Only the account owner can manage people.", 403);
    return user;
  }

  app.get("/api/auth/status", async (req, res, next) => {
    try {
      const [accounts, resolved] = await Promise.all([
        store.users.count(),
        resolveSession(req, store)
      ]);

      res.json({
        signupOpen: accounts === 0,
        hasAccount: accounts > 0,
        user: resolved ? publicUser(resolved.user) : null
      });
    } catch (error) {
      next(error);
    }
  });

  // The first account created on this server becomes the owner.
  app.post("/api/auth/signup", async (req, res, next) => {
    try {
      if (await store.users.count() > 0) {
        return res.status(409).json({
          error: "This server already has an account. Sign in instead.",
          hasAccount: true
        });
      }

      const email = validateEmail(req.body?.email);
      const name = normalizeName(req.body?.name);
      const username = validateUsername(req.body?.username);
      const password = validatePassword(req.body?.password);
      const { salt, hash } = await hashPassword(password);
      const now = new Date().toISOString();

      const user = {
        id: crypto.randomUUID(),
        email,
        name,
        username,
        usernameLower: username.toLowerCase(),
        role: "owner",
        passwordSalt: salt,
        passwordHash: hash,
        createdAt: now,
        lastLoginAt: now,
        passwordUpdatedAt: now
      };

      await store.users.insert(user);
      const session = await startSession(req, res, user);
      await log({ kind: "auth", message: `Owner account created for ${username} <${email}>` });

      return res.status(201).json({
        user: publicUser(user),
        token: session.token,
        expiresAt: session.expiresAt,
        signupOpen: false
      });
    } catch (error) {
      return sendAuthError(res, error, next);
    }
  });

  app.post("/api/auth/login", async (req, res, next) => {
    try {
      const identifier = String(req.body?.identifier ?? req.body?.email ?? "").trim().toLowerCase();
      const password = String(req.body?.password || "");
      const limitKey = `${req.ip || "unknown"}|${identifier}`;
      const wait = limiter.retryAfterSeconds(limitKey);

      if (wait) {
        res.setHeader("Retry-After", String(wait));
        return res.status(429).json({
          error: `Too many sign-in attempts. Try again in ${Math.ceil(wait / 60)} minute(s).`
        });
      }

      const user = identifier ? await store.users.findByLogin(identifier) : null;
      const record = user
        ? { salt: user.passwordSalt, hash: user.passwordHash }
        : await dummyPasswordRecord();
      const matches = await verifyPassword(password, record);

      if (!user || !matches) {
        limiter.fail(limitKey);
        return res.status(401).json({ error: "Username, email, or password is incorrect." });
      }

      limiter.succeed(limitKey);

      const lastLoginAt = new Date().toISOString();
      await store.users.update(user.id, { lastLoginAt });
      const session = await startSession(req, res, user);

      return res.json({
        user: publicUser({ ...user, lastLoginAt }),
        token: session.token,
        expiresAt: session.expiresAt
      });
    } catch (error) {
      return sendAuthError(res, error, next);
    }
  });

  app.post("/api/auth/logout", async (req, res, next) => {
    try {
      const token = sessionToken(req);

      if (token) {
        const session = await store.sessions.findByToken(hashToken(token));
        if (session) await store.sessions.remove(session.id);
      }

      res.setHeader("Set-Cookie", expiredSessionCookie());
      return res.json({ ok: true });
    } catch (error) {
      return next(error);
    }
  });

  app.get("/api/auth/me", async (req, res, next) => {
    try {
      return res.json({ user: publicUser(await requireUser(req)) });
    } catch (error) {
      return sendAuthError(res, error, next);
    }
  });

  app.post("/api/auth/password", async (req, res, next) => {
    try {
      const user = await requireUser(req);
      const currentPassword = String(req.body?.currentPassword || "");
      const newPassword = validatePassword(req.body?.newPassword);

      const matches = await verifyPassword(currentPassword, {
        salt: user.passwordSalt,
        hash: user.passwordHash
      });

      if (!matches) throw authError("The current password is incorrect.", 403);

      const { salt, hash } = await hashPassword(newPassword);
      await store.users.update(user.id, {
        passwordSalt: salt,
        passwordHash: hash,
        passwordUpdatedAt: new Date().toISOString()
      });

      // Sign out every other device; this browser keeps its session.
      const resolved = await resolveSession(req, store);
      await store.sessions.removeForUser(user.id, resolved?.session?.id || null);

      await log({ kind: "auth", message: `Password changed for ${user.email}` });
      return res.json({ ok: true });
    } catch (error) {
      return sendAuthError(res, error, next);
    }
  });

  app.get("/api/auth/users", async (req, res, next) => {
    try {
      await requireOwner(req);
      const users = await store.users.all();
      return res.json({ users: users.map(publicUser) });
    } catch (error) {
      return sendAuthError(res, error, next);
    }
  });

  app.post("/api/auth/users", async (req, res, next) => {
    try {
      await requireOwner(req);

      const email = validateEmail(req.body?.email);
      const name = normalizeName(req.body?.name);
      const username = validateUsername(req.body?.username);
      const password = validatePassword(req.body?.password);

      if (await store.users.find(email)) {
        return res.status(409).json({ error: "Someone already uses that email on this server." });
      }
      if (await store.users.findByLogin(username)) {
        return res.status(409).json({ error: "Someone already uses that username on this server." });
      }

      const { salt, hash } = await hashPassword(password);
      const user = {
        id: crypto.randomUUID(),
        email,
        name,
        username,
        usernameLower: username.toLowerCase(),
        role: "member",
        passwordSalt: salt,
        passwordHash: hash,
        createdAt: new Date().toISOString(),
        lastLoginAt: null,
        passwordUpdatedAt: new Date().toISOString()
      };

      await store.users.insert(user);
      await log({ kind: "auth", message: `Member account created for ${username} <${email}>` });
      return res.status(201).json({ user: publicUser(user) });
    } catch (error) {
      return sendAuthError(res, error, next);
    }
  });

  app.delete("/api/auth/users/:id", async (req, res, next) => {
    try {
      const owner = await requireOwner(req);
      const target = await store.users.get(req.params.id);

      if (!target) return res.status(404).json({ error: "That account does not exist." });
      if (target.id === owner.id) {
        return res.status(400).json({ error: "You cannot remove the account you are signed in with." });
      }

      if (target.role === "owner") {
        const owners = (await store.users.all()).filter(user => user.role === "owner");
        if (owners.length <= 1) {
          return res.status(400).json({ error: "Keep at least one owner account on this server." });
        }
      }

      await store.users.remove(target.id);
      await store.sessions.removeForUser(target.id);
      await log({ kind: "auth", message: `Account removed for ${target.email}` });
      return res.json({ ok: true });
    } catch (error) {
      return sendAuthError(res, error, next);
    }
  });

  return limiter;
}

module.exports = {
  SESSION_COOKIE,
  SESSION_TTL_MS,
  PASSWORD_MIN,
  normalizeEmail,
  validateEmail,
  normalizeName,
  normalizeUsername,
  validateUsername,
  validatePassword,
  hashPassword,
  verifyPassword,
  createSessionToken,
  hashToken,
  parseCookies,
  sessionCookie,
  expiredSessionCookie,
  sessionToken,
  publicUser,
  createLoginLimiter,
  resolveSession,
  registerAuthRoutes
};
