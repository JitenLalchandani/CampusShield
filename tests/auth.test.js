"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const auth = require("../src/auth");
const { createStore } = require("../src/store");
const { createApp } = require("../src/server");

async function withServer(run) {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), "cs-auth-test-"));
  const store = await createStore({ dataDir });
  const app = createApp({ store, dataDir });
  const server = await new Promise(resolve => {
    const instance = app.listen(0, "127.0.0.1", () => resolve(instance));
  });
  const base = `http://127.0.0.1:${server.address().port}`;

  const call = async (method, url, { body, token, cookie } = {}) => {
    const headers = {};
    if (body) headers["content-type"] = "application/json";
    if (token) headers.authorization = `Bearer ${token}`;
    if (cookie) headers.cookie = cookie;

    const response = await fetch(`${base}${url}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined
    });

    const text = await response.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      /* plain text */
    }

    return { status: response.status, json, text, headers: response.headers };
  };

  try {
    await run({ call, store, app });
  } finally {
    server.close();
    await store.close();
    await fs.rm(dataDir, { recursive: true, force: true });
  }
}

test("hashes and verifies passwords with scrypt", async () => {
  const first = await auth.hashPassword("correct horse battery");
  const second = await auth.hashPassword("correct horse battery");

  assert.notEqual(first.salt, second.salt);
  assert.notEqual(first.hash, second.hash);
  assert.equal(await auth.verifyPassword("correct horse battery", first), true);
  assert.equal(await auth.verifyPassword("wrong password", first), false);
  assert.equal(await auth.verifyPassword("anything", {}), false);
});

test("rejects weak account details", () => {
  assert.throws(() => auth.validateEmail("not-an-email"), /valid email/);
  assert.throws(() => auth.validatePassword("short"), /at least 10/);
  assert.throws(() => auth.normalizeName(" "), /name/);

  assert.equal(auth.validateEmail("  Owner@Example.COM "), "owner@example.com");
  assert.equal(auth.validatePassword("a long passphrase"), "a long passphrase");
});

test("parses and serializes session cookies", () => {
  const cookies = auth.parseCookies("theme=dark; cs_session=abc123; empty=");
  assert.equal(cookies.cs_session, "abc123");
  assert.equal(cookies.theme, "dark");

  const cookie = auth.sessionCookie("token-value", { secure: true, maxAgeSeconds: 60 });
  assert.match(cookie, /cs_session=token-value/);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Lax/);
  assert.match(cookie, /Max-Age=60/);
  assert.match(cookie, /Secure/);
  assert.doesNotMatch(auth.sessionCookie("t"), /Secure/);
});

test("login limiter blocks after repeated failures", () => {
  let clock = 0;
  const limiter = auth.createLoginLimiter({ maxAttempts: 3, windowMs: 1000, now: () => clock });

  limiter.fail("ip|user");
  limiter.fail("ip|user");
  assert.equal(limiter.retryAfterSeconds("ip|user"), 0);

  limiter.fail("ip|user");
  assert.equal(limiter.retryAfterSeconds("ip|user"), 1);

  limiter.succeed("ip|user");
  assert.equal(limiter.retryAfterSeconds("ip|user"), 0);
});

test("signup opens the API, then sessions are required", async () => {
  await withServer(async ({ call }) => {
    const before = await call("GET", "/api/protection");
    assert.equal(before.status, 200);

    const signup = await call("POST", "/api/auth/signup", {
      body: { email: "owner@example.com", name: "Owner Person", password: "a long passphrase" }
    });

    assert.equal(signup.status, 201);
    assert.equal(signup.json.user.role, "owner");
    assert.equal(typeof signup.json.token, "string");

    const locked = await call("GET", "/api/protection");
    assert.equal(locked.status, 401);
    assert.equal(locked.json.code, "auth_required");

    const token = signup.json.token;
    const allowed = await call("GET", "/api/protection", { token });
    assert.equal(allowed.status, 200);

    const cookie = String(signup.headers.get("set-cookie") || "").split(";")[0];
    const me = await call("GET", "/api/auth/me", { cookie });
    assert.equal(me.status, 200);
    assert.equal(me.json.user.email, "owner@example.com");

    const again = await call("POST", "/api/auth/signup", {
      body: { email: "second@example.com", name: "Second Person", password: "another passphrase" }
    });
    assert.equal(again.status, 409);
  });
});

test("login, logout, and password change behave", async () => {
  await withServer(async ({ call }) => {
    const signup = await call("POST", "/api/auth/signup", {
      body: { email: "owner@example.com", name: "Owner Person", password: "a long passphrase" }
    });
    const ownerToken = signup.json.token;

    const wrong = await call("POST", "/api/auth/login", {
      body: { email: "owner@example.com", password: "not the password" }
    });
    assert.equal(wrong.status, 401);

    const login = await call("POST", "/api/auth/login", {
      body: { email: "owner@example.com", password: "a long passphrase" }
    });
    assert.equal(login.status, 200);
    assert.equal(login.json.user.lastLoginAt !== null, true);

    const member = await call("POST", "/api/auth/users", {
      token: ownerToken,
      body: { email: "member@example.com", name: "Member Person", password: "member passphrase" }
    });
    assert.equal(member.status, 201);
    assert.equal(member.json.user.role, "member");

    const memberLogin = await call("POST", "/api/auth/login", {
      body: { email: "member@example.com", password: "member passphrase" }
    });
    const memberToken = memberLogin.json.token;

    const memberList = await call("GET", "/api/auth/users", { token: memberToken });
    assert.equal(memberList.status, 403);

    const changed = await call("POST", "/api/auth/password", {
      token: memberToken,
      body: { currentPassword: "member passphrase", newPassword: "a new passphrase" }
    });
    assert.equal(changed.status, 200);

    const stale = await call("POST", "/api/auth/login", {
      body: { email: "member@example.com", password: "member passphrase" }
    });
    assert.equal(stale.status, 401);

    const fresh = await call("POST", "/api/auth/login", {
      body: { email: "member@example.com", password: "a new passphrase" }
    });
    assert.equal(fresh.status, 200);

    const logout = await call("POST", "/api/auth/logout", { token: fresh.json.token });
    assert.equal(logout.status, 200);

    const after = await call("GET", "/api/auth/me", { token: fresh.json.token });
    assert.equal(after.status, 401);

    const removed = await call("DELETE", `/api/auth/users/${member.json.user.id}`, {
      token: ownerToken
    });
    assert.equal(removed.status, 200);
  });
});

test("unknown emails still pay the password hash cost", async () => {
  await withServer(async ({ call }) => {
    await call("POST", "/api/auth/signup", {
      body: { email: "owner@example.com", name: "Owner Person", password: "a long passphrase" }
    });

    const started = Date.now();
    const missing = await call("POST", "/api/auth/login", {
      body: { email: "ghost@example.com", password: "whatever password" }
    });

    assert.equal(missing.status, 401);
    assert.equal(missing.json.error, "Email or password is incorrect.");
    assert.ok(Date.now() - started >= 20, "dummy hash verification ran");
  });
});
