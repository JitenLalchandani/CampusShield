"use strict";

// USB auto-scan settings. Off by default. A missing or damaged stored value falls back to defaults.

const { httpError } = require("../shield/config");

const MAX_IGNORED = 50;
const MAX_ID = 128;
const KEYS = new Set(["enabled", "autoScan", "ignoredDrives"]);

function defaultSettings() {
  return { enabled: false, autoScan: true, ignoredDrives: [] };
}

function cleanIds(value, strict) {
  if (!Array.isArray(value)) {
    if (strict) throw httpError("ignoredDrives must be a list.", 400);
    return [];
  }

  const ids = [];

  for (const item of value) {
    const id = typeof item === "string" ? item.trim() : "";

    if (!id || id.length > MAX_ID || /[\0\r\n]/.test(id)) {
      if (strict) throw httpError("Each ignored drive must be a short text id.", 400);
      continue;
    }

    if (!ids.includes(id)) ids.push(id);
  }

  if (ids.length > MAX_IGNORED) {
    if (strict) throw httpError(`Ignore at most ${MAX_IGNORED} drives.`, 400);
    return ids.slice(0, MAX_IGNORED);
  }

  return ids;
}

function applySettingsPatch(current, patch) {
  if (!patch || typeof patch !== "object" || Array.isArray(patch)) {
    throw httpError("Send a JSON object of settings to change.", 400);
  }

  for (const key of Object.keys(patch)) {
    if (!KEYS.has(key)) throw httpError(`Unknown setting: ${key}.`, 400);
  }

  const next = { ...current, ignoredDrives: [...current.ignoredDrives] };

  for (const key of ["enabled", "autoScan"]) {
    if (patch[key] === undefined) continue;
    if (typeof patch[key] !== "boolean") throw httpError(`${key} must be true or false.`, 400);
    next[key] = patch[key];
  }

  if (patch.ignoredDrives !== undefined) next.ignoredDrives = cleanIds(patch.ignoredDrives, true);

  return next;
}

function normalizeStored(stored) {
  const base = defaultSettings();
  if (!stored || typeof stored !== "object" || Array.isArray(stored)) return base;

  return {
    enabled: typeof stored.enabled === "boolean" ? stored.enabled : base.enabled,
    autoScan: typeof stored.autoScan === "boolean" ? stored.autoScan : base.autoScan,
    ignoredDrives: cleanIds(stored.ignoredDrives, false)
  };
}

module.exports = { MAX_IGNORED, MAX_ID, defaultSettings, applySettingsPatch, normalizeStored };
