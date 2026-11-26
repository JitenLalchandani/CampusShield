"use strict";

// Best-effort guess at which process is touching the files in a folder. The file-system watcher
// does not report a process, so this samples which programs hold files open there. It is a
// guess and is always presented as one: a suspect with a confidence level and the method used.

const { runCommand } = require("./exec");

// Programs that must never be offered as a suspect, whatever they appear to be doing.
const PROTECTED_NAMES = new Set([
  "launchd", "kernel_task", "systemd", "init", "finder", "windowserver", "loginwindow", "mds",
  "mdworker", "mds_stores", "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
  "services.exe", "lsass.exe", "svchost.exe", "explorer.exe", "dwm.exe", "winlogon.exe"
]);

function isProtectedProcess({ pid, name }, { selfPid = process.pid, parentPid = process.ppid } = {}) {
  if (!Number.isInteger(pid) || pid <= 1) return true;
  if (pid === selfPid || pid === parentPid) return true;
  return PROTECTED_NAMES.has(String(name || "").toLowerCase());
}

// lsof -F output: one field per line, "p" starts a process, then c (command), u (user id), and
// one "n" per open file.
function parseLsofFields(stdout) {
  const processes = new Map();
  let current = null;

  for (const line of String(stdout || "").split("\n")) {
    if (!line) continue;
    const tag = line[0];
    const value = line.slice(1);

    if (tag === "p") {
      const pid = Number.parseInt(value, 10);
      current = Number.isInteger(pid) ? { pid, name: "", uid: null, files: 0 } : null;
      if (current) processes.set(pid, current);
    } else if (current && tag === "c") {
      current.name = value;
    } else if (current && tag === "u") {
      const uid = Number.parseInt(value, 10);
      current.uid = Number.isInteger(uid) ? uid : null;
    } else if (current && tag === "n") {
      current.files += 1;
    }
  }

  return [...processes.values()].filter(entry => entry.files > 0);
}

// Sysinternals handle.exe groups its output by process: a header line, then one line per handle.
function parseHandleOutput(stdout) {
  const processes = [];
  let current = null;

  for (const line of String(stdout || "").split(/\r?\n/)) {
    const header = line.match(/^(\S.*?)\s+pid:\s*(\d+)\s+/i);

    if (header) {
      current = { pid: Number.parseInt(header[2], 10), name: header[1].trim(), uid: null, files: 0 };
      processes.push(current);
      continue;
    }

    if (current && /^\s+[0-9A-Fa-f]+:\s+File\s/.test(line)) current.files += 1;
  }

  return processes.filter(entry => entry.files > 0);
}

// Picks the program holding the most files open and says how sure that is. Share is its portion
// of all files held open in the folder.
function chooseSuspect(candidates, options = {}) {
  const total = candidates.reduce((sum, entry) => sum + entry.files, 0);

  if (!total) return { suspect: null, reason: "No program was holding files open in the folder when it was checked." };

  const eligible = candidates
    .filter(entry => !isProtectedProcess(entry, options))
    .sort((a, b) => b.files - a.files);

  if (!eligible.length) {
    return { suspect: null, reason: "Only system programs were holding files open, and those are never offered as a suspect." };
  }

  const top = eligible[0];
  const share = top.files / total;
  const confidence = share >= 0.6 && top.files >= 5 ? "high" : share >= 0.35 ? "medium" : "low";

  return {
    suspect: {
      name: top.name || "unknown",
      pid: top.pid,
      uid: top.uid,
      filesHeld: top.files,
      sharePct: Math.round(share * 100),
      confidence
    },
    reason: null
  };
}

async function sampleSuspect({ folder, platform = process.platform, runner = runCommand, ...options }) {
  if (platform === "win32") {
    const result = await runner("handle.exe", ["-accepteula", "-nobanner", folder], { timeoutMs: 15000 });

    if (!result.ok) {
      return {
        suspect: null,
        method: "Sysinternals handle.exe",
        reason:
          "Finding the program on Windows needs Sysinternals handle.exe, which is not installed. " +
          "CampusShield does not download it. The alert is still valid."
      };
    }

    return { ...chooseSuspect(parseHandleOutput(result.stdout), options), method: "Sysinternals handle.exe" };
  }

  const result = await runner("lsof", ["-nP", "-F", "pcun", "+D", folder], { timeoutMs: 15000 });
  const parsed = parseLsofFields(result.stdout);

  // lsof exits non-zero when nothing matches, so output decides, not the exit code.
  if (!result.ok && !parsed.length) {
    return {
      suspect: null,
      method: "open-file sampling (lsof)",
      reason: result.message || "lsof could not read the open files for this folder."
    };
  }

  return { ...chooseSuspect(parsed, options), method: "open-file sampling (lsof)" };
}

module.exports = {
  PROTECTED_NAMES,
  isProtectedProcess,
  parseLsofFields,
  parseHandleOutput,
  chooseSuspect,
  sampleSuspect
};
