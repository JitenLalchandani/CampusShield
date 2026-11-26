"use strict";

// Ransomware shield settings: defaults, bounds, and validation. Pure functions, so they can be
// tested without touching the disk or the OS.

const os = require("node:os");
const path = require("node:path");

const DEFAULT_THRESHOLDS = Object.freeze({
  minFiles: 25,
  windowSec: 10,
  minSignalPct: 60
});

const THRESHOLD_BOUNDS = Object.freeze({
  minFiles: { min: 10, max: 500 },
  windowSec: { min: 3, max: 120 },
  minSignalPct: { min: 30, max: 100 }
});

const DEFAULT_FOLDER_NAMES = Object.freeze(["Documents", "Desktop", "Pictures"]);
const MAX_FOLDERS = 10;
const MAX_EXCLUSIONS = 50;
const DEFAULT_AUTO_RESTORE_MINUTES = 30;
const AUTO_RESTORE_BOUNDS = Object.freeze({ min: 5, max: 240 });

function httpError(message, statusCode = 400) {
  return Object.assign(new Error(message), { statusCode });
}

function isInside(candidate, parent) {
  const relative = path.relative(parent, candidate);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function defaultFolders(home = os.homedir()) {
  return DEFAULT_FOLDER_NAMES.map(name => path.join(home, name));
}

function defaultSettings(home = os.homedir()) {
  return {
    enabled: false,
    folders: defaultFolders(home),
    exclusions: [],
    thresholds: { ...DEFAULT_THRESHOLDS },
    allowRemoteContain: true,
    autoRestoreMinutes: DEFAULT_AUTO_RESTORE_MINUTES,
    ignoredFolders: {}
  };
}

// A folder must be an absolute path strictly inside the home directory. Watching the whole home
// folder is refused because it is noisy and would hide the signal.
function checkFolder(value, home, label) {
  if (typeof value !== "string" || !value.trim() || value.includes("\0")) {
    throw httpError(`${label} must be a non-empty path.`);
  }

  if (!path.isAbsolute(value.trim())) {
    throw httpError(`${label} must be an absolute path: ${value}`);
  }

  const resolved = path.resolve(value.trim());

  if (!isInside(resolved, home)) {
    throw httpError(`${label} must be inside your home folder: ${resolved}`);
  }

  if (resolved === path.resolve(home)) {
    throw httpError(`${label} cannot be the whole home folder. Choose a subfolder.`);
  }

  return resolved;
}

function checkList(value, { max, home, label }) {
  if (!Array.isArray(value)) throw httpError(`${label} must be a list of paths.`);
  if (value.length > max) throw httpError(`${label} can hold at most ${max} paths.`);

  const seen = new Set();
  const out = [];

  for (const item of value) {
    const resolved = checkFolder(item, home, `Each entry in ${label}`);
    if (!seen.has(resolved)) {
      seen.add(resolved);
      out.push(resolved);
    }
  }

  return out;
}

function checkThresholds(value, current) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw httpError("thresholds must be an object.");
  }

  const next = { ...current };

  for (const [key, bounds] of Object.entries(THRESHOLD_BOUNDS)) {
    if (!(key in value)) continue;
    const number = value[key];

    if (!Number.isInteger(number) || number < bounds.min || number > bounds.max) {
      throw httpError(`${key} must be a whole number from ${bounds.min} to ${bounds.max}.`);
    }

    next[key] = number;
  }

  for (const key of Object.keys(value)) {
    if (!(key in THRESHOLD_BOUNDS)) throw httpError(`Unknown threshold: ${key}`);
  }

  return next;
}

// Validates a PATCH body against the current settings and returns the merged result. Anything
// invalid is rejected instead of silently corrected, so the UI never shows a value that was not
// applied.
function applySettingsPatch(current, patch, { home = os.homedir() } = {}) {
  if (!patch || typeof patch !== "object" || Array.isArray(patch)) {
    throw httpError("Send an object with the settings to change.");
  }

  const allowed = ["enabled", "folders", "exclusions", "thresholds", "allowRemoteContain", "autoRestoreMinutes"];

  for (const key of Object.keys(patch)) {
    if (!allowed.includes(key)) throw httpError(`Unknown setting: ${key}`);
  }

  const next = { ...current };

  if ("enabled" in patch) {
    if (typeof patch.enabled !== "boolean") throw httpError("enabled must be true or false.");
    next.enabled = patch.enabled;
  }

  if ("allowRemoteContain" in patch) {
    if (typeof patch.allowRemoteContain !== "boolean") {
      throw httpError("allowRemoteContain must be true or false.");
    }
    next.allowRemoteContain = patch.allowRemoteContain;
  }

  if ("folders" in patch) {
    next.folders = checkList(patch.folders, { max: MAX_FOLDERS, home, label: "folders" });
  }

  if ("exclusions" in patch) {
    next.exclusions = checkList(patch.exclusions, { max: MAX_EXCLUSIONS, home, label: "exclusions" });
  }

  if ("thresholds" in patch) {
    next.thresholds = checkThresholds(patch.thresholds, current.thresholds || DEFAULT_THRESHOLDS);
  }

  if ("autoRestoreMinutes" in patch) {
    const minutes = patch.autoRestoreMinutes;

    if (
      !Number.isInteger(minutes) ||
      minutes < AUTO_RESTORE_BOUNDS.min ||
      minutes > AUTO_RESTORE_BOUNDS.max
    ) {
      throw httpError(
        `autoRestoreMinutes must be a whole number from ${AUTO_RESTORE_BOUNDS.min} to ${AUTO_RESTORE_BOUNDS.max}.`
      );
    }

    next.autoRestoreMinutes = minutes;
  }

  if (next.enabled && next.folders.length === 0) {
    throw httpError("Choose at least one folder to protect before turning the shield on.");
  }

  return next;
}

// Reads stored settings leniently: a missing key means defaults, and a stored value that no longer
// validates (for example a folder outside home after a move) falls back to the default for that
// field instead of stopping the server.
function normalizeStored(stored, { home = os.homedir() } = {}) {
  const base = defaultSettings(home);
  if (!stored || typeof stored !== "object") return base;

  const result = { ...base };

  if (typeof stored.enabled === "boolean") result.enabled = stored.enabled;
  if (typeof stored.allowRemoteContain === "boolean") result.allowRemoteContain = stored.allowRemoteContain;

  for (const field of ["folders", "exclusions"]) {
    if (!Array.isArray(stored[field])) continue;

    try {
      result[field] = checkList(stored[field], {
        max: field === "folders" ? MAX_FOLDERS : MAX_EXCLUSIONS,
        home,
        label: field
      });
    } catch {
      // keep the default
    }
  }

  try {
    if (stored.thresholds) result.thresholds = checkThresholds(stored.thresholds, base.thresholds);
  } catch {
    // keep the default
  }

  if (
    Number.isInteger(stored.autoRestoreMinutes) &&
    stored.autoRestoreMinutes >= AUTO_RESTORE_BOUNDS.min &&
    stored.autoRestoreMinutes <= AUTO_RESTORE_BOUNDS.max
  ) {
    result.autoRestoreMinutes = stored.autoRestoreMinutes;
  }

  if (stored.ignoredFolders && typeof stored.ignoredFolders === "object") {
    result.ignoredFolders = {};

    for (const [folder, until] of Object.entries(stored.ignoredFolders)) {
      if (typeof until === "string" && Number.isFinite(Date.parse(until))) {
        result.ignoredFolders[folder] = until;
      }
    }
  }

  return result;
}

module.exports = {
  DEFAULT_THRESHOLDS,
  THRESHOLD_BOUNDS,
  MAX_FOLDERS,
  MAX_EXCLUSIONS,
  AUTO_RESTORE_BOUNDS,
  DEFAULT_AUTO_RESTORE_MINUTES,
  defaultFolders,
  defaultSettings,
  applySettingsPatch,
  normalizeStored,
  isInside,
  httpError
};
