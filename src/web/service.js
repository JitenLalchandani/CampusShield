"use strict";

// Web & phishing protection service. It checks a link you give it against your own block and allow
// lists, an optional feed you choose, and explainable phishing signs. It never opens the page,
// never follows redirects, and never watches your browsing. Only the website name of a warned or
// blocked link is kept, not the path, query, or anything after it.

const crypto = require("node:crypto");

const config = require("./config");
const { httpError } = require("../shield/config");
const { parseUrl } = require("./url");
const { analyze } = require("./heuristics");

const EVENT_LIMIT = 200;
const DEDUPE_MS = 10 * 60 * 1000;
const CHECK_WINDOW_MS = 60 * 1000;
const MAX_CHECKS = 30;
const FEED_MAX_BYTES = 1024 * 1024;
const FEED_MAX_ENTRIES = 50000;
const FEED_TIMEOUT_MS = 10000;

const NOT_CHECKED = Object.freeze([
  "The page itself was not opened, so its content was not looked at.",
  "Redirects were not followed, so a shortened or forwarding link's real destination is unknown.",
  "No outside reputation service was asked about this link."
]);

const LIMITS = Object.freeze([
  "This checks only links you paste here. It does not watch your browser or block pages for you.",
  "A result of \"no warning signs\" is not a promise a site is safe. The checks read the text of the link only.",
  "Heuristics can be wrong in both directions: a new phishing site with a plain name will not be flagged, and an unusual real site can be.",
  "Block and allow lists are yours. A feed is used only if you add one, and it is the only source of known-bad domains.",
  "Only the website name of a warned or blocked link is saved, never the full address."
]);

function listMatch(host, entries) {
  return entries.find(entry => host === entry || host.endsWith(`.${entry}`)) || null;
}

function parseFeed(text) {
  const out = new Set();

  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, "").trim();
    if (!line) continue;

    // "0.0.0.0 bad.example" (hosts format) or "bad.example".
    const parts = line.split(/\s+/);
    const candidate = parts.length > 1 && /^(0\.0\.0\.0|127\.0\.0\.1)$/.test(parts[0]) ? parts[1] : parts[0];
    const domain = config.normalizeDomain(candidate);

    if (domain) out.add(domain);
    if (out.size >= FEED_MAX_ENTRIES) break;
  }

  return out;
}

function createWebService({
  store,
  now = Date.now,
  fetchFn = globalThis.fetch,
  audit = async () => {},
  onChange = () => {}
}) {
  let settings = null;
  let feed = new Set();
  let feedMeta = { count: 0, fetchedAt: null, host: null, error: null };
  let queue = Promise.resolve();
  let closed = false;

  const attempts = new Map();
  const iso = () => new Date(now()).toISOString();

  function enqueue(task) {
    const run = queue.then(task);
    queue = run.catch(() => {});
    return run;
  }

  async function record(entry) {
    try {
      await audit({ kind: "web", ...entry });
    } catch {
      // An audit failure must not hide a result that was already produced.
    }
  }

  async function saveSettings(next) {
    await store.settings.save({ web: next });
    settings = next;
  }

  async function refreshFeed() {
    if (!settings?.feedEnabled || !settings.feedUrl) return feedMeta;

    const url = new URL(settings.feedUrl);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FEED_TIMEOUT_MS);

    try {
      const response = await fetchFn(settings.feedUrl, { signal: controller.signal, redirect: "error", headers: { accept: "text/plain" } });
      if (!response.ok) throw new Error(`The feed answered ${response.status}.`);

      const text = await response.text();
      if (Buffer.byteLength(text) > FEED_MAX_BYTES) throw new Error("The feed is larger than 1 MB, so it was not used.");

      feed = parseFeed(text);
      feedMeta = { count: feed.size, fetchedAt: iso(), host: url.host, error: feed.size ? null : "The feed had no readable domains." };
    } catch (error) {
      // Keep the last good list; say plainly that this refresh failed.
      feedMeta = { ...feedMeta, host: url.host, error: error.name === "AbortError" ? "The feed did not answer in time." : error.message };
    } finally {
      clearTimeout(timer);
    }

    await record({ message: `Phishing feed refresh from ${url.host}: ${feedMeta.error || `${feedMeta.count} domains`}.`, severity: feedMeta.error ? "LOW" : null });
    return feedMeta;
  }

  const ready = (async () => {
    const stored = await store.settings.get();
    settings = config.normalizeStored(stored.web);
    if (settings.enabled && settings.feedEnabled) await refreshFeed();
  })().catch(error => {
    feedMeta = { ...feedMeta, error: `Web protection could not start: ${error.message}` };
  });

  function limit(callerKey) {
    const cutoff = now() - CHECK_WINDOW_MS;
    const recent = (attempts.get(callerKey) || []).filter(time => time > cutoff);

    if (recent.length >= MAX_CHECKS) {
      attempts.set(callerKey, recent);
      throw httpError("Too many checks in a minute. Wait a moment and try again.", 429);
    }

    recent.push(now());
    attempts.set(callerKey, recent);
  }

  // The verdict for one link. Pure apart from reading settings and the feed.
  function judge(parsed) {
    const base = { notChecked: NOT_CHECKED, approximate: "The registrable domain is a best guess from a short built-in list of two-part endings." };

    if (parsed.runsCode) {
      const { score, signals } = analyze(parsed);
      return { ...base, verdict: "block", score, signals, list: null, host: "", registrable: "" };
    }

    const lists = settings.enabled ? settings : { blocklist: [], allowlist: [] };
    const allowed = listMatch(parsed.host, lists.allowlist);
    const blocked = listMatch(parsed.host, lists.blocklist);
    const fed = settings.enabled && settings.feedEnabled ? [...feedMatches(parsed.host)][0] : null;
    const { score, signals } = analyze(parsed);

    const common = { ...base, score, signals, host: parsed.host, registrable: parsed.registrable };

    // The person's own allow list wins over everything, including their block list.
    if (allowed) return { ...common, verdict: "allowed", list: { kind: "allowlist", entry: allowed } };
    if (blocked) return { ...common, verdict: "block", list: { kind: "blocklist", entry: blocked } };
    if (fed) return { ...common, verdict: "block", list: { kind: "feed", entry: fed } };
    if (score >= settings.warnScore) return { ...common, verdict: "warn", list: null };

    return { ...common, verdict: "no-signs", list: null };
  }

  function* feedMatches(host) {
    let candidate = host;

    while (candidate.includes(".")) {
      if (feed.has(candidate)) yield candidate;
      candidate = candidate.slice(candidate.indexOf(".") + 1);
    }
  }

  async function logVerdict(result, callerLabel) {
    const host = result.host || "(runs code)";
    const events = await store.webEvents.all(EVENT_LIMIT);
    const existing = events.find(
      event => event.host === host && event.verdict === result.verdict && event.status === "open" && Date.parse(event.lastSeen) > now() - DEDUPE_MS
    );

    const severity = result.verdict === "block" ? "high" : "medium";
    const signals = result.signals.map(({ id, points, detail }) => ({ id, points, detail }));

    if (existing) {
      const updated = { ...existing, count: existing.count + 1, lastSeen: iso(), updatedAt: iso(), score: result.score, signals };
      await store.webEvents.upsert(updated);
      return updated;
    }

    const event = {
      id: crypto.randomUUID(),
      host,
      registrable: result.registrable,
      verdict: result.verdict,
      severity,
      status: "open",
      score: result.score,
      signals,
      list: result.list,
      count: 1,
      source: "manual",
      startedAt: iso(),
      firstSeen: iso(),
      lastSeen: iso(),
      updatedAt: iso()
    };

    await store.webEvents.upsert(event);
    await store.webEvents.prune(EVENT_LIMIT);
    await record({ message: `Web check ${result.verdict === "block" ? "blocked" : "warned about"} ${host}${callerLabel ? ` (${callerLabel})` : ""}.`, severity: result.verdict === "block" ? "MEDIUM" : "LOW", status: "open" });
    return event;
  }

  async function check(input, { callerKey = "anonymous", callerLabel = "" } = {}) {
    await ready;
    limit(callerKey);

    const parsed = parseUrl(input);
    if (!parsed.ok) throw httpError(parsed.error, 400);

    const result = judge(parsed);
    const response = {
      verdict: result.verdict,
      score: result.score,
      warnScore: settings.warnScore,
      host: result.host,
      registrable: result.registrable,
      schemeAdded: parsed.schemeAdded,
      signals: result.signals,
      list: result.list,
      notChecked: result.notChecked,
      approximate: result.approximate,
      listsInUse: settings.enabled,
      logged: false
    };

    if (settings.enabled && (result.verdict === "warn" || result.verdict === "block")) {
      await enqueue(() => logVerdict(result, callerLabel));
      response.logged = true;
    }

    return response;
  }

  async function status() {
    await ready;
    const events = await store.webEvents.all(EVENT_LIMIT);

    return {
      enabled: settings.enabled,
      blocklist: settings.blocklist,
      allowlist: settings.allowlist,
      feedEnabled: settings.feedEnabled,
      feedUrl: settings.feedUrl,
      feed: feedMeta,
      warnScore: settings.warnScore,
      warnBounds: config.WARN_BOUNDS,
      openEvents: events.filter(event => event.status === "open").length,
      limits: LIMITS,
      notes: []
    };
  }

  async function listEvents({ status: wanted = null, limit: max = 50 } = {}) {
    await ready;
    const count = Math.max(1, Math.min(Number.parseInt(max, 10) || 50, EVENT_LIMIT));
    return (await store.webEvents.all(EVENT_LIMIT)).filter(event => !wanted || event.status === wanted).slice(0, count);
  }

  async function getEvent(id) {
    await ready;
    const event = await store.webEvents.get(id);
    if (!event) throw httpError("Web event not found.", 404);
    return { event };
  }

  async function dismiss(id, { callerLabel = "" } = {}) {
    await ready;

    return enqueue(async () => {
      const event = await store.webEvents.get(id);
      if (!event) throw httpError("Web event not found.", 404);
      if (event.status === "dismissed") return { event };

      const saved = { ...event, status: "dismissed", dismissedAt: iso(), updatedAt: iso() };
      await store.webEvents.upsert(saved);
      await record({ message: `Web event for ${event.host} dismissed${callerLabel ? ` by ${callerLabel}` : ""}.`, severity: null, status: "dismissed" });
      return { event: saved };
    });
  }

  async function updateSettings(patch, { callerLabel = "" } = {}) {
    await ready;

    return enqueue(async () => {
      const next = config.applySettingsPatch(settings, patch);
      const before = settings;
      await saveSettings(next);

      if (next.enabled !== before.enabled) {
        await record({ message: next.enabled ? "Web protection turned on." : "Web protection turned off.", severity: null });
        await onChange();
      }

      if (next.enabled && next.feedEnabled && (!before.feedEnabled || before.feedUrl !== next.feedUrl || !before.enabled)) await refreshFeed();
      if (!next.feedEnabled || !next.enabled) feed = new Set();

      if (before.blocklist.length !== next.blocklist.length || before.allowlist.length !== next.allowlist.length) {
        await record({ message: `Web block/allow lists changed${callerLabel ? ` by ${callerLabel}` : ""}.`, severity: null });
      }

      return status();
    });
  }

  async function refreshFeedNow() {
    await ready;
    if (!settings.enabled || !settings.feedEnabled) throw httpError("Turn on web protection and the feed first.", 409);
    return enqueue(refreshFeed);
  }

  function postureCheck() {
    const base = { id: "web-protection", title: "Web & phishing link checker", severity: "low" };

    if (!settings) return { ...base, status: "unknown", detail: "The web protection state has not loaded yet.", recommendation: "Run the check again." };

    if (!settings.enabled) {
      return { ...base, status: "warn", detail: "Link checking is not turned on, so warned and blocked links are not logged and your lists are not used.", recommendation: "Turn on web protection in Protection." };
    }

    return { ...base, status: "pass", detail: "Links you check here are compared with your lists and phishing signs. It does not watch your browser.", recommendation: "No action needed." };
  }

  function close() {
    closed = true;
  }

  return { ready, status, check, listEvents, getEvent, dismiss, updateSettings, refreshFeed: refreshFeedNow, postureCheck, close, judgeForTest: judge, isClosed: () => closed };
}

module.exports = { createWebService, parseFeed, listMatch, LIMITS, NOT_CHECKED };
