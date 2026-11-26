"use strict";

// Connects real file-system events to the detector. It only reads: it watches folders, stats the
// changed file, and hands the result to the detector. It never changes, moves, or deletes a file.

const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");

const { isInside } = require("./config");
const { isNoisePath, extensionOf } = require("./detector");

const BASELINE_FILE_LIMIT = 5000;
const BASELINE_DEPTH_LIMIT = 6;

// The file extensions already present in a folder, so a later burst of unfamiliar extensions
// stands out. The walk is bounded in both depth and file count.
async function collectExtensions(folder, { readdirFn = fsp.readdir } = {}) {
  const extensions = new Set();
  const queue = [{ dir: folder, depth: 0 }];
  let files = 0;

  while (queue.length && files < BASELINE_FILE_LIMIT) {
    const { dir, depth } = queue.shift();
    let entries;

    try {
      entries = await readdirFn(dir, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (isNoisePath(full)) continue;

      if (entry.isDirectory()) {
        if (depth < BASELINE_DEPTH_LIMIT) queue.push({ dir: full, depth: depth + 1 });
      } else if (entry.isFile()) {
        files += 1;
        const ext = extensionOf(entry.name);
        if (ext) extensions.add(ext);
        if (files >= BASELINE_FILE_LIMIT) break;
      }
    }
  }

  return extensions;
}

function createShieldEngine({
  folders,
  exclusions = [],
  isIgnored = () => false,
  detector,
  onResult,
  onError = () => {},
  watchFn = fs.watch,
  statFn = fsp.lstat,
  readdirFn = fsp.readdir,
  debounceMs = 100
}) {
  const watchers = [];
  const timers = new Map();
  let running = false;

  async function inspect(folder, full) {
    let stat;

    try {
      stat = await statFn(full);
    } catch {
      // The file is gone (deleted or renamed away). Deletions alone are not a signal.
      return;
    }

    if (!stat.isFile() || stat.isSymbolicLink()) return;

    try {
      const result = await detector.observe(folder, full);
      if (result) onResult(result);
    } catch (error) {
      onError(folder, error);
    }
  }

  function handle(folder, filename) {
    if (!running || !filename) return;

    const full = path.join(folder, filename.toString());

    if (isNoisePath(full)) return;
    if (exclusions.some(excluded => isInside(full, excluded))) return;
    if (isIgnored(folder)) return;
    if (timers.has(full)) return;

    const timer = setTimeout(() => {
      timers.delete(full);
      inspect(folder, full);
    }, debounceMs);

    timer.unref?.();
    timers.set(full, timer);
  }

  return {
    // Starts one recursive watcher per folder. A folder that cannot be watched is reported, not
    // hidden, so the status shows exactly what is and is not protected.
    async start() {
      running = true;
      const watching = [];
      const failed = [];

      for (const folder of folders) {
        try {
          const stat = await statFn(folder);
          if (!stat.isDirectory()) throw new Error("This path is not a folder.");

          detector.setBaseline(folder, await collectExtensions(folder, { readdirFn }));

          const watcher = watchFn(folder, { recursive: true, persistent: false }, (_type, filename) =>
            handle(folder, filename)
          );

          watcher.on?.("error", error => onError(folder, error));
          watchers.push(watcher);
          watching.push(folder);
        } catch (error) {
          failed.push({
            folder,
            message: error.code === "ENOENT" ? "This folder does not exist." : error.message
          });
        }
      }

      return { watching, failed };
    },

    stop() {
      running = false;

      for (const watcher of watchers.splice(0)) {
        try {
          watcher.close();
        } catch {
          // already closed
        }
      }

      for (const timer of timers.values()) clearTimeout(timer);
      timers.clear();
    }
  };
}

module.exports = { createShieldEngine, collectExtensions };
