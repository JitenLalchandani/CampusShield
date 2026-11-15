"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");

const {
  DEFAULT_PREFERENCES,
  isDue,
  isExcluded,
  nextRunAt,
  normalizeExclusions,
  normalizePreferences,
  normalizeSchedule
} = require("../src/scanner/preferences");

function localDate(year, month, day, hours = 0, minutes = 0) {
  return new Date(year, month - 1, day, hours, minutes, 0, 0);
}

test("fills defaults for an empty configuration", () => {
  const prefs = normalizePreferences(undefined);

  assert.equal(prefs.realtime, DEFAULT_PREFERENCES.realtime);
  assert.equal(prefs.notify, DEFAULT_PREFERENCES.notify);
  assert.deepEqual(prefs.exclusions, []);
  assert.equal(prefs.schedule.enabled, false);
  assert.equal(prefs.schedule.scope, "quick");
  assert.equal(prefs.schedule.time, "09:00");
});

test("normalizes times and rejects impossible values", () => {
  assert.equal(normalizeSchedule({ time: "7:05" }).time, "07:05");
  assert.equal(normalizeSchedule({ time: "24:00" }).time, "09:00");
  assert.equal(normalizeSchedule({ time: "noon" }).time, "09:00");
  assert.equal(normalizeSchedule({ scope: "everything" }).scope, "quick");
});

test("keeps previous schedule fields when a patch omits them", () => {
  const previous = normalizeSchedule({ enabled: true, scope: "full", time: "22:15" });
  const patched = normalizeSchedule({ enabled: false }, previous);

  assert.equal(patched.enabled, false);
  assert.equal(patched.scope, "full");
  assert.equal(patched.time, "22:15");
});

test("resolves, dedupes, and caps exclusions", () => {
  const relative = "some/relative/folder";
  const list = normalizeExclusions([relative, relative, "  ", 42, "/tmp/ok"]);

  assert.equal(list.length, 2);
  assert.equal(list[0], path.resolve(relative));
  assert.ok(list.includes(path.resolve("/tmp/ok")));
});

test("detects whether a path sits inside an exclusion", () => {
  const exclusions = [path.resolve("/tmp/campusshield-vendor")];

  assert.equal(isExcluded(path.resolve("/tmp/campusshield-vendor/a/b.sh"), exclusions), true);
  assert.equal(isExcluded(path.resolve("/tmp/campusshield-vendor"), exclusions), true);
  assert.equal(isExcluded(path.resolve("/tmp/other/a.sh"), exclusions), false);
});

test("daily schedules become due after the next occurrence", () => {
  const schedule = normalizeSchedule({
    enabled: true,
    frequency: "daily",
    time: "09:00",
    lastRunAt: localDate(2026, 1, 5, 9, 0).toISOString()
  });

  assert.equal(isDue(schedule, localDate(2026, 1, 5, 23, 0)), false);
  assert.equal(isDue(schedule, localDate(2026, 1, 6, 8, 59)), false);
  assert.equal(isDue(schedule, localDate(2026, 1, 6, 9, 0)), true);
  assert.equal(
    nextRunAt(schedule, localDate(2026, 1, 5, 9, 0)),
    localDate(2026, 1, 6, 9, 0).toISOString()
  );
});

test("weekly schedules only fire on the chosen weekday", () => {
  const schedule = normalizeSchedule({
    enabled: true,
    frequency: "weekly",
    weekday: 1,
    time: "08:30",
    lastRunAt: localDate(2026, 1, 5, 8, 30).toISOString()
  });

  assert.equal(isDue(schedule, localDate(2026, 1, 11, 9, 0)), false);
  assert.equal(isDue(schedule, localDate(2026, 1, 12, 8, 30)), true);
});

test("a disabled or never-run schedule is never due", () => {
  const disabled = normalizeSchedule({ enabled: false, time: "09:00", lastRunAt: null });
  const neverRun = normalizeSchedule({ enabled: true, time: "09:00", lastRunAt: null });

  assert.equal(isDue(disabled, localDate(2027, 1, 1, 12, 0)), false);
  assert.equal(isDue(neverRun, localDate(2027, 1, 1, 12, 0)), false);
  assert.equal(nextRunAt(disabled), null);
});
