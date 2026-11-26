"use strict";

// Ransomware trigger logic. It receives "this file was touched" observations and decides whether
// a burst looks like mass encryption. Everything that touches the outside world (the clock and
// reading file bytes) is injected, so the rules can be tested exactly.
//
// A burst fires only when BOTH hold within one watched folder:
//   1. at least `minFiles` distinct files were touched within `windowSec` seconds, and
//   2. at least `minSignalPct` percent of them carry a content signal: a file extension never
//      seen in that folder before, or a normally-plain-text file whose bytes now look encrypted.

const crypto = require("node:crypto");
const path = require("node:path");

const { DEFAULT_THRESHOLDS } = require("./config");
const { LOW_ENTROPY_EXTENSIONS, looksEncrypted } = require("./entropy");

const NOISE_SEGMENTS = new Set([".git", "node_modules", ".Trash", "Caches", "__pycache__", ".cache"]);
const NOISE_FILES = new Set([".ds_store", "thumbs.db", "desktop.ini"]);
const MAX_TRACKED = 5000;
const MAX_EVALUATED = 300;
const SAMPLE_LIMIT = 25;
const COOLDOWN_MS = 5 * 60 * 1000;

function isNoisePath(filePath) {
  const parts = String(filePath || "").split(/[\\/]/);
  if (parts.some(part => NOISE_SEGMENTS.has(part))) return true;
  return NOISE_FILES.has((parts[parts.length - 1] || "").toLowerCase());
}

function extensionOf(filePath) {
  return path.extname(String(filePath || "")).toLowerCase();
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function createDetector({
  thresholds = DEFAULT_THRESHOLDS,
  now = Date.now,
  readHead = async () => null,
  evalThrottleMs = 250,
  cooldownMs = COOLDOWN_MS
} = {}) {
  let limits = { ...DEFAULT_THRESHOLDS, ...thresholds };
  const folders = new Map();

  function stateFor(folder) {
    let state = folders.get(folder);

    if (!state) {
      state = {
        touched: new Map(),
        baseline: new Set(),
        baselineKnown: false,
        open: null,
        closedAt: 0,
        lastEval: 0,
        evaluating: false
      };
      folders.set(folder, state);
    }

    return state;
  }

  function prune(state, t) {
    const cutoff = t - limits.windowSec * 1000;

    for (const [file, entry] of state.touched) {
      if (entry.t >= cutoff) break;
      state.touched.delete(file);
    }

    while (state.touched.size > MAX_TRACKED) {
      state.touched.delete(state.touched.keys().next().value);
    }
  }

  async function evaluate(folder, state, t) {
    const entries = [...state.touched.entries()].slice(-MAX_EVALUATED);
    let extCount = 0;
    let entropyCount = 0;
    const newExtensions = new Map();
    const samples = [];

    for (const [file, entry] of entries) {
      // Without a known baseline for this folder there is nothing to compare an extension with,
      // so the extension signal is simply unavailable. It is never guessed.
      const extensionSignal = state.baselineKnown && Boolean(entry.ext) && !state.baseline.has(entry.ext);
      let entropySignal = false;

      if (extensionSignal) {
        extCount += 1;
        newExtensions.set(entry.ext, (newExtensions.get(entry.ext) || 0) + 1);
      } else if (LOW_ENTROPY_EXTENSIONS.has(entry.ext)) {
        entropySignal = looksEncrypted(await readHead(file)) === true;
        if (entropySignal) entropyCount += 1;
      }

      if ((extensionSignal || entropySignal) && samples.length < SAMPLE_LIMIT) {
        samples.push(path.relative(folder, file) || file);
      }
    }

    const evaluated = entries.length;
    const signalPct = evaluated ? Math.round((100 * (extCount + entropyCount)) / evaluated) : 0;

    if (signalPct < limits.minSignalPct) return null;

    const extPct = evaluated ? (100 * extCount) / evaluated : 0;
    const high = extPct >= limits.minSignalPct;
    const iso = new Date(t).toISOString();

    const evidence = {
      filesTouched: state.touched.size,
      evaluated,
      windowSec: limits.windowSec,
      extChanged: extCount,
      highEntropy: entropyCount,
      signalPct,
      newExtensions: [...newExtensions.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([ext, count]) => ({ ext, count })),
      samples,
      thresholds: { ...limits }
    };

    if (state.open) {
      state.open.updatedAt = iso;
      state.open.evidence = {
        ...evidence,
        filesTouched: Math.max(evidence.filesTouched, state.open.evidence.filesTouched || 0)
      };

      if (high) {
        state.open.severity = "critical";
        state.open.confidence = "high";
      }

      return { kind: "update", alert: clone(state.open) };
    }

    if (state.closedAt && t - state.closedAt < cooldownMs) return null;

    state.open = {
      id: crypto.randomUUID(),
      status: "open",
      severity: high ? "critical" : "high",
      confidence: high ? "high" : "medium",
      folder,
      startedAt: iso,
      updatedAt: iso,
      evidence,
      suspect: null,
      actions: []
    };

    return { kind: "alert", alert: clone(state.open) };
  }

  return {
    setThresholds(next) {
      limits = { ...DEFAULT_THRESHOLDS, ...next };
    },

    // The extensions already present in a folder before watching starts. An empty set means the
    // baseline is unknown, not that every extension is new.
    setBaseline(folder, extensions) {
      const state = stateFor(folder);
      state.baseline = new Set(extensions);
      state.baselineKnown = state.baseline.size > 0;
    },

    async observe(folder, filePath) {
      if (isNoisePath(filePath)) return null;

      const state = stateFor(folder);
      const t = now();

      state.touched.delete(filePath);
      state.touched.set(filePath, { t, ext: extensionOf(filePath) });
      prune(state, t);

      if (state.touched.size < limits.minFiles) return null;
      if (state.evaluating) return null;
      if (evalThrottleMs > 0 && t - state.lastEval < evalThrottleMs) return null;

      state.lastEval = t;
      state.evaluating = true;

      try {
        return await evaluate(folder, state, t);
      } finally {
        state.evaluating = false;
      }
    },

    // Re-attach an alert that was still open when the server restarted.
    adopt(alert) {
      stateFor(alert.folder).open = clone(alert);
    },

    // Called when an alert is contained or dismissed. The cooldown stops an alert storm.
    close(folder, at = now()) {
      const state = stateFor(folder);
      state.open = null;
      state.closedAt = at;
      state.touched.clear();
    },

    reset() {
      folders.clear();
    }
  };
}

module.exports = { createDetector, isNoisePath, extensionOf, COOLDOWN_MS, MAX_TRACKED };
