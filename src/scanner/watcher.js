"use strict";

const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");

const DEBOUNCE_MS = 700;
const MAX_FILE_SIZE = 64 * 1024 * 1024;
const SKIP_DIRECTORIES = new Set([".git", ".Trash", "Caches", "DerivedData", "Logs", "node_modules"]);

function isInside(candidate, parent) {
  if (!parent) return false;
  const relative = path.relative(parent, candidate);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function createWatcher({ roots, excludePaths = [], onFile, onError }) {
  const watchers = [];
  const timers = new Map();
  const recent = new Set();
  const inFlight = new Set();
  let startedAt = null;
  let eventsSeen = 0;
  let alerts = 0;
  let closed = false;

  function shouldSkip(fullPath) {
    const parts = fullPath.split(path.sep);

    if (parts.some(part => SKIP_DIRECTORIES.has(part))) return true;
    return excludePaths.some(excluded => isInside(fullPath, excluded));
  }

  async function processFile(fullPath) {
    if (closed || inFlight.has(fullPath)) return;

    inFlight.add(fullPath);

    try {
      const stat = await fsp.lstat(fullPath);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size > MAX_FILE_SIZE) return;

      const key = `${fullPath}:${stat.size}:${stat.mtimeMs}`;
      if (recent.has(key)) return;

      recent.add(key);
      if (recent.size > 500) recent.delete(recent.values().next().value);

      const threat = await onFile(fullPath);

      if (threat) alerts += 1;
    } catch (error) {
      if (error.code !== "ENOENT" && error.code !== "EACCES" && error.code !== "EPERM") {
        onError?.(error);
      }
    } finally {
      setTimeout(() => inFlight.delete(fullPath), 1500);
    }
  }

  function schedule(fullPath) {
    if (closed || shouldSkip(fullPath)) return;

    const existing = timers.get(fullPath);
    if (existing) clearTimeout(existing);

    timers.set(
      fullPath,
      setTimeout(() => {
        timers.delete(fullPath);
        processFile(fullPath);
      }, DEBOUNCE_MS)
    );
  }

  function start() {
    startedAt = new Date().toISOString();

    for (const root of roots) {
      try {
        const watcher = fs.watch(root, { recursive: true }, (_event, filename) => {
          eventsSeen += 1;
          if (!filename) return;
          schedule(path.join(root, filename.toString()));
        });

        watcher.on("error", error => onError?.(error));
        watchers.push(watcher);
      } catch (error) {
        onError?.(error);
      }
    }

    if (!watchers.length) {
      throw new Error("No folders could be watched. Check folder permissions.");
    }

    return status();
  }

  function stop() {
    closed = true;

    for (const timer of timers.values()) clearTimeout(timer);
    timers.clear();

    for (const watcher of watchers) {
      try {
        watcher.close();
      } catch {
        /* already closed */
      }
    }

    watchers.length = 0;
  }

  function status() {
    return {
      enabled: !closed && watchers.length > 0,
      startedAt,
      roots,
      eventsSeen,
      alerts
    };
  }

  return { start, stop, status };
}

module.exports = { createWatcher };
