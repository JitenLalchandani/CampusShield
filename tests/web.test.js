"use strict";

// Web & phishing protection. No network is used: the feed is a fake fetch, and links are only ever
// read as text.

const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { createStore } = require("../src/store");
const config = require("../src/web/config");
const { parseUrl, registrableDomain } = require("../src/web/url");
const { analyze, editDistance, deconfuse } = require("../src/web/heuristics");
const { createWebService, parseFeed, listMatch } = require("../src/web/service");

const score = input => {
  const parsed = parseUrl(input);
  assert.equal(parsed.ok, true, input);
  return analyze(parsed);
};

const ids = input => score(input).signals.map(signal => signal.id);

// ---- settings ----------------------------------------------------------------------------------

test("web settings: off by default, strict patches, lenient loading", () => {
  const current = config.defaultSettings();
  assert.deepEqual(current, { enabled: false, blocklist: [], allowlist: [], feedEnabled: false, feedUrl: "", warnScore: 40 });

  const next = config.applySettingsPatch(current, { enabled: true, blocklist: ["Evil.Example", "*.bad.example", "evil.example"] });
  assert.deepEqual(next.blocklist, ["evil.example", "bad.example"]);
  assert.equal(current.enabled, false);

  const bad = [
    { enabled: "yes" }, { blocklist: "x" }, { blocklist: ["not a domain"] }, { blocklist: ["http://x.com/a"] }, { allowlist: ["a@b.com"] },
    { blocklist: Array.from({ length: 201 }, (_, i) => `d${i}.example`) }, { warnScore: 9 }, { warnScore: 91 }, { warnScore: 40.5 },
    { feedUrl: "http://plain.example/list.txt" }, { feedUrl: "https://someone:pass@feed.example/x" }, { feedEnabled: true }, { unknown: 1 }
  ];

  for (const patch of bad) {
    assert.throws(() => config.applySettingsPatch(current, patch), error => error.statusCode === 400, JSON.stringify(patch).slice(0, 50));
  }

  const withFeed = config.applySettingsPatch(current, { feedUrl: "https://feed.example/list.txt", feedEnabled: true });
  assert.equal(withFeed.feedEnabled, true);

  assert.deepEqual(config.normalizeStored(undefined), current);
  assert.deepEqual(config.normalizeStored({ blocklist: ["ok.example", "bad domain"], warnScore: 5, feedEnabled: true }), { ...current, blocklist: ["ok.example"], feedEnabled: false });
});

test("domain normalisation accepts real domains and refuses anything else", () => {
  assert.equal(config.normalizeDomain(" Example.COM. "), "example.com");
  assert.equal(config.normalizeDomain("münchen.example"), "xn--mnchen-3ya.example");
  for (const bad of ["", "localhost", "a b.com", "a/b.com", "-a.com", "a-.com", "x".repeat(64) + ".com", 5, null]) {
    assert.equal(config.normalizeDomain(bad), null, String(bad));
  }
});

// ---- URL reading -------------------------------------------------------------------------------

test("links are read without a scheme, and unreadable or oversized ones are refused", () => {
  const plain = parseUrl("example.com/login?x=1");
  assert.equal(plain.ok, true);
  assert.equal(plain.schemeAdded, true);
  assert.equal(plain.host, "example.com");

  assert.equal(parseUrl("localhost:8080/x").host, "localhost");
  assert.equal(parseUrl("").ok, false);
  assert.equal(parseUrl("ftp://x.example").ok, false);
  assert.equal(parseUrl("https://").ok, false);
  assert.equal(parseUrl("a\nb.com").ok, false);
  assert.equal(parseUrl(`https://x.example/${"a".repeat(2100)}`).ok, false);
  assert.equal(parseUrl(undefined).ok, false);
});

test("registrable domain handles two-part endings and numeric hosts", () => {
  assert.equal(registrableDomain("a.b.example.com"), "example.com");
  assert.equal(registrableDomain("login.shop.example.co.uk"), "example.co.uk");
  assert.equal(registrableDomain("mail.sbi.co.in"), "sbi.co.in");
  assert.equal(registrableDomain("example.com"), "example.com");
  assert.equal(parseUrl("http://192.168.1.5/x").registrable, "192.168.1.5");
  assert.equal(parseUrl("http://[::1]/x").isIp, true);
});

test("a decimal or hex IP written as a hostname is still seen as a numeric address", () => {
  assert.ok(ids("http://2130706433/").includes("ip-host"));
  assert.ok(ids("http://0x7f.0.0.1/").includes("ip-host"));
});

// ---- heuristics: safe links ----------------------------------------------------------------------

test("ordinary and brand-owned links score zero", () => {
  for (const url of [
    "https://www.google.com/search?q=cats", "https://mail.google.com", "https://docs.github.com/en", "https://login.microsoftonline.com",
    "https://example.com", "https://www.amazon.co.uk/orders", "https://sbi.co.in", "https://en.wikipedia.org/wiki/Phishing", "https://accounts.google.com/signin"
  ]) {
    assert.equal(score(url).score, 0, url);
  }
});

test("login words alone do not make a link suspicious", () => {
  assert.equal(score("https://example.com/login/verify/account").score, 0);
});

// ---- heuristics: suspicious links -----------------------------------------------------------------

test("numeric address plus http plus a sensitive word adds up and explains each part", () => {
  const result = score("http://192.168.1.5/verify");
  assert.deepEqual(result.signals.map(item => item.id).sort(), ["ip-host", "no-tls", "sensitive-words"]);
  assert.equal(result.score, 60);
  assert.ok(result.signals.every(item => item.detail.length > 10));
});

test("lookalikes of known brands are flagged, the real domains are not", () => {
  assert.ok(ids("https://paypa1.com/login").includes("brand-lookalike"));
  assert.ok(ids("https://paypal.net").includes("brand-lookalike"));
  assert.ok(ids("https://rnicrosoft.com").includes("brand-lookalike"));
  assert.ok(ids("https://amazom.com").includes("brand-lookalike"));
  assert.deepEqual(ids("https://paypal.com"), []);
  assert.deepEqual(ids("https://paypal.me"), []);
});

test("a brand name used as a subdomain or hyphen part of someone else's domain is flagged", () => {
  assert.ok(ids("https://accounts.google.com.evil.example/login").includes("brand-in-name"));
  assert.ok(ids("https://microsoft.com.attacker.in").includes("brand-in-name"));
  assert.ok(ids("https://my-paypal-secure-login.example.com/verify").includes("brand-in-name"));
  assert.deepEqual(ids("https://notpaypalatall.example"), []);
});

test("a name before an @ is flagged and the real host is named", () => {
  const result = score("https://www.google.com@evil.example/");
  const signal = result.signals.find(item => item.id === "userinfo");
  assert.ok(signal);
  assert.match(signal.detail, /evil\.example/);
});

test("mixed-script and non-Latin names are told apart", () => {
  assert.ok(ids("https://xn--pple-43d.com/").includes("mixed-script"));
  assert.ok(ids("https://gооgle.com").includes("mixed-script"));
  const allCyrillic = ids("https://пример.рф");
  assert.ok(allCyrillic.includes("non-latin"));
  assert.ok(!allCyrillic.includes("mixed-script"));
});

test("shorteners say the destination is hidden and was not followed", () => {
  const result = score("https://bit.ly/3abc");
  assert.equal(result.signals[0].id, "shortener");
  assert.match(result.signals[0].detail, /does not follow redirects/);
});

test("structure signs: many subdomains, long host, many hyphens, confusing endings, long links", () => {
  assert.ok(ids("https://a.b.c.d.example.com").includes("many-subdomains"));
  assert.ok(ids(`https://${"a".repeat(61)}.example.com`).includes("long-host"));
  assert.ok(ids("https://a-b-c-d.example.com").includes("many-hyphens"));
  assert.ok(!ids("https://xn--pple-43d.com").includes("many-hyphens"), "punycode's own hyphens do not count");
  assert.ok(ids("https://invoice.zip").includes("confusing-tld"));
  assert.ok(ids(`https://example.com/${"a".repeat(220)}`).includes("long-url"));
});

test("code-running links are 100 and never treated as websites", () => {
  for (const url of ["javascript:alert(1)", "data:text/html,<b>1</b>", "vbscript:msgbox(1)"]) {
    const parsed = parseUrl(url);
    assert.equal(parsed.runsCode, true);
    assert.equal(analyze(parsed).score, 100);
  }
});

test("the score never goes above 100", () => {
  assert.equal(score("http://someone:pass@a.b.c.d.paypa1-login-verify-now.zip/verify/secure/update").score <= 100, true);
});

test("helpers: edit distance and letter-swap undoing", () => {
  assert.equal(editDistance("paypal", "paypa1"), 1);
  assert.equal(editDistance("paypal", "paypal"), 0);
  assert.equal(editDistance("abc", "abcdef"), 2);
  assert.equal(deconfuse("paypa1"), "paypal");
  assert.equal(deconfuse("rnicrosoft"), "microsoft");
});

// ---- feed and lists ----------------------------------------------------------------------------------

test("feeds parse plain lists and hosts files, skip comments, and cap size", () => {
  const set = parseFeed("# header\nbad.example\n0.0.0.0 worse.example # note\n127.0.0.1 localhost\n\nnot a domain\n1.2.3.4 only-ip.example\n");
  assert.deepEqual([...set].sort(), ["bad.example", "worse.example"]);
  assert.equal(parseFeed("").size, 0);
});

test("list matching covers the domain and its subdomains, not look-alike suffixes", () => {
  assert.equal(listMatch("a.bad.example", ["bad.example"]), "bad.example");
  assert.equal(listMatch("bad.example", ["bad.example"]), "bad.example");
  assert.equal(listMatch("notbad.example", ["bad.example"]), null);
  assert.equal(listMatch("bad.example.org", ["bad.example"]), null);
});

// ---- service -------------------------------------------------------------------------------------------

async function harness({ enabled = true, settings = {}, fetchFn } = {}) {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), "cs-web-test-"));
  const store = await createStore({ dataDir });
  const log = { audit: [], changes: 0 };
  let clock = Date.parse("2026-11-26T10:00:00.000Z");

  if (enabled) await store.settings.save({ web: { ...config.defaultSettings(), enabled: true, ...settings } });

  const service = createWebService({
    store,
    fetchFn,
    now: () => clock,
    audit: async entry => log.audit.push(entry),
    onChange: () => { log.changes += 1; }
  });

  await service.ready;
  return { service, store, log, advance: ms => { clock += ms; } };
}

test("off by default: a check still reads the link but uses no lists, logs nothing, and says so", async () => {
  const h = await harness({ enabled: false });
  const result = await h.service.check("http://192.168.1.5/verify");

  assert.equal(result.verdict, "warn");
  assert.equal(result.listsInUse, false);
  assert.equal(result.logged, false);
  assert.deepEqual(await h.service.listEvents(), []);
  assert.equal(h.service.postureCheck().status, "warn");
  assert.equal(h.service.postureCheck().severity, "low");
});

test("no warning signs is worded as no signs, never 'safe', and lists what was not checked", async () => {
  const h = await harness();
  const result = await h.service.check("https://example.com/");

  assert.equal(result.verdict, "no-signs");
  assert.equal(result.score, 0);
  assert.ok(result.notChecked.length >= 3);
  assert.ok(result.notChecked.some(line => /not opened/.test(line)));
  assert.match(result.approximate, /best guess/);
  assert.deepEqual(await h.service.listEvents(), [], "clean checks are never logged");
});

test("a warned link is logged by host only, with no path or query kept", async () => {
  const h = await harness();
  const result = await h.service.check("http://192.168.1.5/verify?ref=PRIVATE-VALUE&user=me#frag");

  assert.equal(result.verdict, "warn");
  assert.equal(result.logged, true);

  const [event] = await h.service.listEvents();
  assert.equal(event.host, "192.168.1.5");
  assert.equal(event.status, "open");
  assert.equal(event.severity, "medium");
  assert.doesNotMatch(JSON.stringify(event), /PRIVATE-VALUE|frag|\/verify\?/);
  assert.ok(h.log.audit.every(entry => entry.kind === "web"));
  assert.doesNotMatch(JSON.stringify(h.log.audit), /PRIVATE-VALUE/);
});

test("repeat checks of the same host within ten minutes add to one event; later ones start a new one", async () => {
  const h = await harness();

  await h.service.check("http://192.168.1.5/a");
  await h.service.check("http://192.168.1.5/b");
  assert.equal((await h.service.listEvents()).length, 1);
  assert.equal((await h.service.listEvents())[0].count, 2);

  h.advance(11 * 60 * 1000);
  await h.service.check("http://192.168.1.5/c");
  assert.equal((await h.service.listEvents()).length, 2);
});

test("your block list blocks, your allow list wins over it, and lists are ignored while off", async () => {
  const h = await harness({ settings: { blocklist: ["bad.example"], allowlist: ["ok.bad.example"] } });

  const blocked = await h.service.check("https://bad.example/x");
  assert.equal(blocked.verdict, "block");
  assert.deepEqual(blocked.list, { kind: "blocklist", entry: "bad.example" });
  assert.equal((await h.service.listEvents())[0].severity, "high");

  const allowed = await h.service.check("https://ok.bad.example/x");
  assert.equal(allowed.verdict, "allowed");
  assert.deepEqual(allowed.list, { kind: "allowlist", entry: "ok.bad.example" });

  await h.service.updateSettings({ enabled: false });
  assert.equal((await h.service.check("https://bad.example/x")).verdict, "no-signs");
});

test("code-running links are blocked and logged without any host", async () => {
  const h = await harness();
  const result = await h.service.check("javascript:alert(document.title)");

  assert.equal(result.verdict, "block");
  assert.equal(result.host, "");
  const [event] = await h.service.listEvents();
  assert.equal(event.host, "(runs code)");
  assert.doesNotMatch(JSON.stringify(event), /document\.title/);
});

test("the warn threshold is the person's to change and is respected", async () => {
  const h = await harness();
  assert.equal((await h.service.check("https://bit.ly/x")).verdict, "no-signs", "15 is under the default 40");

  await h.service.updateSettings({ warnScore: 10 });
  assert.equal((await h.service.check("https://bit.ly/x")).verdict, "warn");
});

test("a feed adds known-bad domains, is shown with its host and count, and a failed refresh keeps the last good list", async () => {
  let mode = "ok";
  const fetchFn = async () => {
    if (mode === "ok") return { ok: true, text: async () => "feedbad.example\n# c\n" };
    if (mode === "big") return { ok: true, text: async () => "a.example\n".repeat(200000) };
    return { ok: false, status: 503, text: async () => "" };
  };

  const h = await harness({ fetchFn });
  await h.service.updateSettings({ feedUrl: "https://feed.example/list.txt", feedEnabled: true });

  let status = await h.service.status();
  assert.equal(status.feed.count, 1);
  assert.equal(status.feed.host, "feed.example");
  assert.equal(status.feed.error, null);

  const hit = await h.service.check("https://sub.feedbad.example/");
  assert.equal(hit.verdict, "block");
  assert.deepEqual(hit.list, { kind: "feed", entry: "feedbad.example" });

  mode = "down";
  await h.service.refreshFeed();
  status = await h.service.status();
  assert.match(status.feed.error, /503/);
  assert.equal(status.feed.count, 1, "the last good list is kept");
  assert.equal((await h.service.check("https://feedbad.example/")).verdict, "block");

  mode = "big";
  await h.service.refreshFeed();
  assert.match((await h.service.status()).feed.error, /larger than 1 MB/);
});

test("a feed that times out says so instead of pretending it loaded", async () => {
  const h = await harness({ fetchFn: async () => { throw Object.assign(new Error("aborted"), { name: "AbortError" }); } });
  await h.service.updateSettings({ feedUrl: "https://feed.example/list.txt", feedEnabled: true });

  const status = await h.service.status();
  assert.match(status.feed.error, /did not answer in time/);
  assert.equal(status.feed.count, 0);
  assert.equal(status.feed.fetchedAt, null);
});

test("refreshing the feed needs the feed to be on", async () => {
  const h = await harness();
  await assert.rejects(() => h.service.refreshFeed(), error => error.statusCode === 409);
});

test("bad input to a check is a 400 and checks are limited to 30 a minute per caller", async () => {
  const h = await harness();

  for (const bad of ["", "ftp://x.example", "x".repeat(2100), "a\nb"]) {
    await assert.rejects(() => h.service.check(bad, { callerKey: "u1" }), error => error.statusCode === 400);
  }

  const fresh = await harness();
  for (let index = 0; index < 30; index += 1) await fresh.service.check("https://example.com", { callerKey: "u" });
  await assert.rejects(() => fresh.service.check("https://example.com", { callerKey: "u" }), error => error.statusCode === 429);
  await fresh.service.check("https://example.com", { callerKey: "someone-else" });

  fresh.advance(61 * 1000);
  await fresh.service.check("https://example.com", { callerKey: "u" });
});

test("dismiss closes an event, is repeatable, and unknown ids are 404", async () => {
  const h = await harness();
  await h.service.check("http://192.168.1.5/");
  const [event] = await h.service.listEvents();

  assert.equal((await h.service.dismiss(event.id, { callerLabel: "alice" })).event.status, "dismissed");
  assert.equal((await h.service.dismiss(event.id)).event.status, "dismissed");
  await assert.rejects(() => h.service.dismiss("nope"), error => error.statusCode === 404);
  await assert.rejects(() => h.service.getEvent("nope"), error => error.statusCode === 404);
  assert.deepEqual(await h.service.listEvents({ status: "open" }), []);

  await h.service.check("http://192.168.1.5/");
  assert.equal((await h.service.listEvents({ status: "open" })).length, 1, "a dismissed event is not reopened");
});

test("settings: invalid ones change nothing; turning on and off is audited; the posture check follows", async () => {
  const h = await harness({ enabled: false });

  await assert.rejects(() => h.service.updateSettings({ blocklist: ["not a domain"] }), error => error.statusCode === 400);
  assert.deepEqual((await h.service.status()).blocklist, []);

  await h.service.updateSettings({ enabled: true });
  assert.equal(h.service.postureCheck().status, "pass");
  assert.ok(h.log.audit.some(entry => /turned on/.test(entry.message)));
  assert.ok(h.log.changes >= 1);

  await h.service.updateSettings({ enabled: false });
  assert.equal(h.service.postureCheck().status, "warn");
  assert.equal((await h.store.settings.get()).web.enabled, false);
});

// ---- store parity ------------------------------------------------------------------------------------------

async function parity(store) {
  await store.webEvents.clear();

  for (let index = 0; index < 5; index += 1) await store.webEvents.upsert({ id: `w${index}`, status: "open", startedAt: `2026-11-26T10:0${index}:00.000Z` });

  const all = await store.webEvents.all(10);
  assert.deepEqual(all.map(item => item.id), ["w4", "w3", "w2", "w1", "w0"]);
  assert.ok(all.every(item => item._id === undefined));
  assert.equal(await store.webEvents.get("zzz"), null);

  await store.webEvents.upsert({ id: "w2", status: "dismissed", startedAt: "2026-11-26T10:02:00.000Z" });
  assert.equal((await store.webEvents.all(10)).length, 5);
  assert.equal((await store.webEvents.get("w2")).status, "dismissed");

  await store.webEvents.prune(3);
  assert.deepEqual((await store.webEvents.all(10)).map(item => item.id), ["w4", "w3", "w2"]);
  await store.webEvents.clear();
  assert.equal((await store.webEvents.all(10)).length, 0);
}

test("store parity: the JSON store keeps web events newest-first, replaces on upsert, prunes, and survives restart", async () => {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), "cs-web-store-"));
  const store = await createStore({ dataDir });
  await parity(store);

  await store.webEvents.upsert({ id: "keep", status: "open", startedAt: "2026-11-26T11:00:00.000Z" });
  assert.equal((await (await createStore({ dataDir })).webEvents.get("keep")).id, "keep");
});

test("store parity: an old store.json with no web data loads with an empty list", async () => {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), "cs-web-old-"));
  await fs.writeFile(path.join(dataDir, "store.json"), JSON.stringify({ settings: {}, events: [] }));
  assert.deepEqual(await (await createStore({ dataDir })).webEvents.all(10), []);
});

test("store parity: MongoDB behaves the same when MONGODB_URI is set", { skip: !process.env.MONGODB_URI }, async () => {
  await parity(await createStore({ dataDir: await fs.mkdtemp(path.join(os.tmpdir(), "cs-web-mongo-")) }));
});
