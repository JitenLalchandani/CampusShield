"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const { createReadStream } = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
  analyzeFile,
  isTextLike,
  SCRIPT_EXTENSIONS
} = require("./heuristics");

const ENGINE_VERSION = "2026.11.1";
const MAX_FILE_SIZE = 64 * 1024 * 1024;
const HEAD_BYTES = 8 * 1024;
const SCRIPT_BYTES = 64 * 1024;

const LIMITS = {
  quick: { maxFiles: 12000, timeMs: 3 * 60 * 1000 },
  full: { maxFiles: 60000, timeMs: 15 * 60 * 1000 }
};

const SKIP_DIRECTORIES = new Set([
  ".git", ".Trash", "Caches", "DerivedData", "Logs", "node_modules"
]);

function homePath(...parts) {
  return path.join(os.homedir(), ...parts);
}

function scanRoots(scope) {
  const platform = process.platform;

  if (platform === "win32") {
    const appData = process.env.APPDATA || path.join(os.homedir(), "AppData", "Roaming");

    return scope === "full"
      ? [
          os.homedir(),
          process.env.ProgramFiles || "C:\\Program Files",
          process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)",
          process.env.ProgramData || "C:\\ProgramData",
          os.tmpdir()
        ]
      : [
          homePath("Downloads"),
          homePath("Desktop"),
          homePath("Documents"),
          path.join(appData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
        ];
  }

  if (platform === "linux") {
    return scope === "full"
      ? [os.homedir(), "/usr/local/bin", "/opt", "/etc/cron.d", os.tmpdir()]
      : [
          homePath("Downloads"),
          homePath("Desktop"),
          homePath("Documents"),
          homePath(".config", "autostart")
        ];
  }

  if (scope === "full") {
    return [
      os.homedir(),
      "/Applications",
      "/Library/LaunchAgents",
      "/Library/LaunchDaemons",
      "/tmp"
    ];
  }

  return [
    homePath("Downloads"),
    homePath("Desktop"),
    homePath("Documents"),
    homePath("Library", "LaunchAgents")
  ];
}

function isInside(candidate, parent) {
  const relative = path.relative(parent, candidate);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function shouldSkipDirectory(fullPath, name, excludePaths) {
  if (SKIP_DIRECTORIES.has(name)) return true;
  if (fullPath === path.join(os.homedir(), "Library", "Caches")) return true;
  return excludePaths.some(excluded => isInside(fullPath, excluded));
}

async function readHead(filePath, size) {
  const length = Math.min(size, SCRIPT_BYTES);
  if (length <= 0) return Buffer.alloc(0);

  const handle = await fs.open(filePath, "r");

  try {
    const buffer = Buffer.alloc(length);
    const { bytesRead } = await handle.read(buffer, 0, length, 0);
    return buffer.subarray(0, bytesRead);
  } finally {
    await handle.close();
  }
}

async function hashFile(filePath) {
  const hash = crypto.createHash("sha256");
  const stream = createReadStream(filePath);

  for await (const chunk of stream) hash.update(chunk);

  return hash.digest("hex");
}

async function inspectFile(filePath, signatures, options = {}) {
  const stat = await fs.lstat(filePath);

  if (!stat.isFile() || stat.isSymbolicLink()) return null;

  const name = path.basename(filePath);
  const ext = path.extname(name).toLowerCase();
  const maxSize = options.maxFileSize || MAX_FILE_SIZE;

  if (stat.size > maxSize) {
    return { skipped: true, reason: "too-large", size: stat.size, name };
  }

  let head;

  try {
    head = await readHead(filePath, Math.min(stat.size, SCRIPT_BYTES));
  } catch (error) {
    return { skipped: true, reason: "unreadable", size: stat.size, name, error: error.message };
  }

  const shebang = head.subarray(0, 2).toString("latin1") === "#!";
  const isScriptContent = SCRIPT_EXTENSIONS.has(ext) || shebang;

  let sha256 = null;

  try {
    sha256 = await hashFile(filePath);
  } catch (error) {
    if (error.code === "EACCES" || error.code === "EPERM") {
      return { skipped: true, reason: "unreadable", size: stat.size, name, error: error.message };
    }
    throw error;
  }

  const signature = sha256 ? signatures.byHash.get(sha256) || null : null;
  const analysis = analyzeFile({
    filePath,
    name,
    head,
    signature,
    isScriptContent
  });

  if (!analysis) {
    return { threat: null, sha256, size: stat.size, name };
  }

  return {
    threat: {
      id: crypto.randomUUID(),
      detectedAt: new Date().toISOString(),
      size: stat.size,
      sha256,
      status: "detected",
      ...analysis
    },
    sha256,
    size: stat.size,
    name
  };
}

async function scan({
  scope = "quick",
  signatures,
  onProgress,
  signal,
  excludePaths = [],
  roots: customRoots = null,
  limits = LIMITS[scope] || LIMITS.quick
}) {
  if (!signatures?.byHash) throw new Error("Signature database is not loaded.");

  const startedAt = new Date().toISOString();
  const started = Date.now();
  const roots = (customRoots || scanRoots(scope)).filter(Boolean);
  const queue = roots.slice();
  const threats = [];
  const errors = [];
  const seen = new Set();
  let filesScanned = 0;
  let bytesScanned = 0;
  let skipped = 0;
  let truncated = false;
  let stopReason = null;
  let lastReport = 0;

  while (queue.length) {
    if (signal?.aborted) {
      truncated = true;
      stopReason = "cancelled";
      break;
    }

    if (Date.now() - started >= limits.timeMs) {
      truncated = true;
      stopReason = "time-limit";
      break;
    }

    if (filesScanned >= limits.maxFiles) {
      truncated = true;
      stopReason = "file-limit";
      break;
    }

    const current = queue.shift();
    let directory;

    try {
      directory = await fs.opendir(current);
    } catch (error) {
      if (errors.length < 20) errors.push({ path: current, message: error.message });
      continue;
    }

    try {
      for await (const entry of directory) {
        const fullPath = path.join(current, entry.name);

        if (entry.isSymbolicLink()) continue;

        if (entry.isDirectory()) {
          if (!shouldSkipDirectory(fullPath, entry.name, excludePaths) && !seen.has(fullPath)) {
            seen.add(fullPath);
            queue.push(fullPath);
          }
          continue;
        }

        if (!entry.isFile()) continue;

        filesScanned += 1;

        try {
          const result = await inspectFile(fullPath, signatures);

          if (result?.skipped) {
            skipped += 1;
          } else if (result?.threat) {
            threats.push(result.threat);
          }

          if (result?.size) bytesScanned += result.size;
        } catch (error) {
          if (errors.length < 20) errors.push({ path: fullPath, message: error.message });
        }

        const now = Date.now();

        if (now - lastReport > 250) {
          lastReport = now;
          onProgress?.({
            filesScanned,
            bytesScanned,
            threats: threats.length,
            currentDirectory: current
          });
        }
      }
    } catch (error) {
      if (errors.length < 20) errors.push({ path: current, message: error.message });
    }

    if (Date.now() - lastReport > 250) {
      lastReport = Date.now();
      onProgress?.({
        filesScanned,
        bytesScanned,
        threats: threats.length,
        currentDirectory: current
      });
    }
  }

  onProgress?.({ filesScanned, bytesScanned, threats: threats.length, currentDirectory: null });

  return {
    engineVersion: ENGINE_VERSION,
    signatureVersion: signatures.version,
    signatureCount: signatures.count,
    scope,
    roots,
    startedAt,
    finishedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    filesScanned,
    bytesScanned,
    skipped,
    threats,
    errors,
    truncated,
    stopReason
  };
}

async function scanSingleFile(filePath, signatures) {
  const result = await inspectFile(filePath, signatures, { maxFileSize: MAX_FILE_SIZE });
  return result?.threat || null;
}

module.exports = {
  ENGINE_VERSION,
  LIMITS,
  scan,
  scanRoots,
  scanSingleFile,
  inspectFile,
  isTextLike
};
