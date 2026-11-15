"use strict";

const path = require("node:path");

const MAX_EXCLUSIONS = 50;
const MAX_PATH_LENGTH = 1024;

const DEFAULT_PREFERENCES = {
  realtime: false,
  notify: true,
  exclusions: [],
  schedule: {
    enabled: false,
    scope: "quick",
    frequency: "daily",
    weekday: 1,
    time: "09:00",
    lastRunAt: null
  }
};

function normalizeTime(value, fallback) {
  if (typeof value !== "string") return fallback;

  const match = /^(\d{1,2}):(\d{2})$/.exec(value.trim());
  if (!match) return fallback;

  const hours = Number(match[1]);
  const minutes = Number(match[2]);

  if (hours > 23 || minutes > 59) return fallback;

  return `${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}`;
}

function normalizeExclusions(list) {
  if (!Array.isArray(list)) return [];

  const seen = new Set();
  const exclusions = [];

  for (const item of list) {
    if (typeof item !== "string") continue;

    const trimmed = item.trim();
    if (!trimmed || trimmed.length > MAX_PATH_LENGTH) continue;

    const resolved = path.resolve(trimmed);
    if (seen.has(resolved)) continue;

    seen.add(resolved);
    exclusions.push(resolved);

    if (exclusions.length >= MAX_EXCLUSIONS) break;
  }

  return exclusions;
}

function normalizeLastRun(value, fallback) {
  if (value === null) return null;
  if (typeof value !== "string") return fallback;

  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? fallback : new Date(parsed).toISOString();
}

function normalizeSchedule(input, previous = DEFAULT_PREFERENCES.schedule) {
  const source = input && typeof input === "object" ? input : {};
  const base = { ...DEFAULT_PREFERENCES.schedule, ...previous };

  return {
    enabled: source.enabled === undefined ? Boolean(base.enabled) : Boolean(source.enabled),
    scope:
      source.scope === "full"
        ? "full"
        : source.scope === "quick"
          ? "quick"
          : base.scope === "full"
            ? "full"
            : "quick",
    frequency:
      source.frequency === "weekly"
        ? "weekly"
        : source.frequency === "daily"
          ? "daily"
          : base.frequency === "weekly"
            ? "weekly"
            : "daily",
    weekday:
      Number.isInteger(source.weekday) && source.weekday >= 0 && source.weekday <= 6
        ? source.weekday
        : Number.isInteger(base.weekday) && base.weekday >= 0 && base.weekday <= 6
          ? base.weekday
          : DEFAULT_PREFERENCES.schedule.weekday,
    time: normalizeTime(source.time, normalizeTime(base.time, DEFAULT_PREFERENCES.schedule.time)),
    lastRunAt:
      "lastRunAt" in source
        ? normalizeLastRun(source.lastRunAt, base.lastRunAt ?? null)
        : normalizeLastRun(base.lastRunAt, null)
  };
}

function normalizePreferences(input, previous = DEFAULT_PREFERENCES) {
  const source = input && typeof input === "object" ? input : {};
  const base = { ...DEFAULT_PREFERENCES, ...previous };

  return {
    realtime: source.realtime === undefined ? Boolean(base.realtime) : Boolean(source.realtime),
    notify: source.notify === undefined ? Boolean(base.notify) : Boolean(source.notify),
    exclusions:
      source.exclusions === undefined
        ? normalizeExclusions(base.exclusions)
        : normalizeExclusions(source.exclusions),
    schedule: normalizeSchedule(source.schedule, base.schedule)
  };
}

function atTime(day, time) {
  const [hours, minutes] = time.split(":").map(Number);
  const date = new Date(day);
  date.setHours(hours, minutes, 0, 0);
  return date;
}

function nextRunAt(schedule, from = new Date()) {
  if (!schedule || !schedule.enabled) return null;

  const base = from instanceof Date ? from : new Date(from);
  if (Number.isNaN(base.getTime())) return null;

  for (let offset = 0; offset <= 8; offset += 1) {
    const day = new Date(base);
    day.setDate(day.getDate() + offset);

    if (schedule.frequency === "weekly" && day.getDay() !== schedule.weekday) continue;

    const candidate = atTime(day, schedule.time);
    if (candidate.getTime() > base.getTime()) return candidate.toISOString();
  }

  return null;
}

function isDue(schedule, now = new Date()) {
  if (!schedule || !schedule.enabled || !schedule.lastRunAt) return false;

  const last = new Date(schedule.lastRunAt);
  if (Number.isNaN(last.getTime())) return false;

  const next = nextRunAt(schedule, last);
  if (!next) return false;

  const at = now instanceof Date ? now : new Date(now);
  return at.getTime() >= new Date(next).getTime();
}

function isExcluded(target, exclusions) {
  return exclusions.some(excluded => {
    const relative = path.relative(excluded, target);
    return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
  });
}

module.exports = {
  DEFAULT_PREFERENCES,
  MAX_EXCLUSIONS,
  normalizeExclusions,
  normalizePreferences,
  normalizeSchedule,
  nextRunAt,
  isDue,
  isExcluded
};
