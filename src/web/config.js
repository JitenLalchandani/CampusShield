"use strict";

// Web & phishing protection settings. Off by default. A missing or damaged stored value falls back
// to defaults, one field at a time.

const { domainToASCII } = require("node:url");
const { httpError } = require("../shield/config");

const MAX_LIST = 200;
const WARN_BOUNDS = { min: 10, max: 90 };
const DEFAULT_WARN_SCORE = 40;
const KEYS = new Set(["enabled", "blocklist", "allowlist", "feedEnabled", "feedUrl", "warnScore"]);

function defaultSettings() {
  return { enabled: false, blocklist: [], allowlist: [], feedEnabled: false, feedUrl: "", warnScore: DEFAULT_WARN_SCORE };
}

// Returns a lowercase ASCII domain, or null when the text is not a plausible domain.
function normalizeDomain(value) {
  let text = String(value ?? "").trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
  if (!text || text.length > 253 || /[\s/\\@:?#]/.test(text)) return null;

  text = domainToASCII(text);
  if (!text || !/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(text)) return null;
  // A name never ends in a number. This also refuses IP addresses, which are not domains.
  if (/^\d+$/.test(text.slice(text.lastIndexOf(".") + 1))) return null;
  if (text.split(".").some(label => !label || label.length > 63 || label.startsWith("-") || label.endsWith("-"))) return null;

  return text;
}

function cleanList(value, name, strict) {
  if (!Array.isArray(value)) {
    if (strict) throw httpError(`${name} must be a list of domains.`, 400);
    return [];
  }

  const out = [];

  for (const item of value) {
    const domain = normalizeDomain(item);

    if (!domain) {
      if (strict) throw httpError(`"${String(item).slice(0, 60)}" is not a valid domain in ${name}.`, 400);
      continue;
    }

    if (!out.includes(domain)) out.push(domain);
  }

  if (out.length > MAX_LIST) {
    if (strict) throw httpError(`${name} can hold at most ${MAX_LIST} domains.`, 400);
    return out.slice(0, MAX_LIST);
  }

  return out;
}

function cleanFeedUrl(value, strict) {
  if (value === "" || value === null || value === undefined) return "";

  try {
    const url = new URL(String(value));
    if (url.protocol !== "https:" || url.username || url.password || String(value).length > 300) throw new Error("bad");
    return url.toString();
  } catch {
    if (strict) throw httpError("The feed address must be a plain https:// URL without a username or password.", 400);
    return "";
  }
}

function applySettingsPatch(current, patch) {
  if (!patch || typeof patch !== "object" || Array.isArray(patch)) throw httpError("Send a JSON object of settings to change.", 400);

  for (const key of Object.keys(patch)) {
    if (!KEYS.has(key)) throw httpError(`Unknown setting: ${key}.`, 400);
  }

  const next = { ...current, blocklist: [...current.blocklist], allowlist: [...current.allowlist] };

  for (const key of ["enabled", "feedEnabled"]) {
    if (patch[key] === undefined) continue;
    if (typeof patch[key] !== "boolean") throw httpError(`${key} must be true or false.`, 400);
    next[key] = patch[key];
  }

  if (patch.blocklist !== undefined) next.blocklist = cleanList(patch.blocklist, "blocklist", true);
  if (patch.allowlist !== undefined) next.allowlist = cleanList(patch.allowlist, "allowlist", true);
  if (patch.feedUrl !== undefined) next.feedUrl = cleanFeedUrl(patch.feedUrl, true);

  if (patch.warnScore !== undefined) {
    const value = patch.warnScore;
    if (!Number.isInteger(value) || value < WARN_BOUNDS.min || value > WARN_BOUNDS.max) {
      throw httpError(`warnScore must be a whole number from ${WARN_BOUNDS.min} to ${WARN_BOUNDS.max}.`, 400);
    }
    next.warnScore = value;
  }

  if (next.feedEnabled && !next.feedUrl) throw httpError("Add a feed address before turning the feed on.", 400);

  return next;
}

function normalizeStored(stored) {
  const base = defaultSettings();
  if (!stored || typeof stored !== "object" || Array.isArray(stored)) return base;

  const feedUrl = cleanFeedUrl(stored.feedUrl, false);

  return {
    enabled: typeof stored.enabled === "boolean" ? stored.enabled : base.enabled,
    blocklist: cleanList(stored.blocklist, "blocklist", false),
    allowlist: cleanList(stored.allowlist, "allowlist", false),
    feedEnabled: typeof stored.feedEnabled === "boolean" && feedUrl ? stored.feedEnabled : false,
    feedUrl,
    warnScore:
      Number.isInteger(stored.warnScore) && stored.warnScore >= WARN_BOUNDS.min && stored.warnScore <= WARN_BOUNDS.max
        ? stored.warnScore
        : base.warnScore
  };
}

module.exports = { MAX_LIST, WARN_BOUNDS, DEFAULT_WARN_SCORE, defaultSettings, applySettingsPatch, normalizeStored, normalizeDomain };
