"use strict";

// Looks at the top of a drive for the classic USB-worm signs. Read-only: it lists names and reads
// the first 4 KB of autorun.inf. It never opens, runs, changes, or deletes anything on the drive.
// File contents are not judged here; the normal file scanner does that.

const fs = require("node:fs/promises");
const path = require("node:path");

const MAX_ENTRIES = 2000;
const EXECUTABLE = new Set([".exe", ".scr", ".com", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".ps1", ".msi", ".pif", ".hta", ".jar", ".lnk", ".command", ".app"]);
const DOCUMENT = new Set([".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".zip", ".rtf"]);
const SEVERITY_ORDER = { low: 1, medium: 2, high: 3, critical: 4 };

function extensionOf(name) {
  return path.extname(name).toLowerCase();
}

function parseAutorun(text) {
  const keys = {};

  for (const line of String(text).split(/\r?\n/)) {
    const match = line.match(/^\s*(open|shellexecute|shell\\[^=]+\\command|icon|label|action)\s*=\s*(.*)$/i);
    if (match) keys[match[1].toLowerCase()] = match[2].trim().slice(0, 200);
  }

  return keys;
}

async function inspectDrive(mountPoint, { readdir = fs.readdir, readFile = fs.readFile, limit = MAX_ENTRIES } = {}) {
  const findings = [];
  let entries;

  try {
    entries = await readdir(mountPoint, { withFileTypes: true });
  } catch (error) {
    return { ok: false, findings, entriesChecked: 0, truncated: false, reason: `The top of the drive could not be read (${error.code || error.message}).` };
  }

  const truncated = entries.length > limit;
  const top = entries.slice(0, limit);
  const folders = new Set(top.filter(entry => entry.isDirectory()).map(entry => entry.name.toLowerCase()));

  for (const entry of top) {
    const name = entry.name;
    const lower = name.toLowerCase();
    const ext = extensionOf(name);
    const where = path.join(mountPoint, name);

    if (lower === "autorun.inf" && !entry.isDirectory()) {
      let keys = {};
      let readable = true;

      try {
        keys = parseAutorun((await readFile(where)).subarray(0, 4096).toString("utf8"));
      } catch {
        readable = false;
      }

      const launches = keys.open || keys.shellexecute || Object.entries(keys).find(([key]) => key.startsWith("shell"))?.[1];

      findings.push({
        rule: "autorun-inf",
        severity: launches ? "high" : "low",
        path: where,
        detail: launches
          ? `autorun.inf tries to start "${launches}" when the drive is opened.`
          : readable
            ? "autorun.inf is present but does not start a program."
            : "autorun.inf is present but could not be read."
      });
      continue;
    }

    if (entry.isDirectory()) continue;

    // "report.pdf.exe": a program dressed as a document.
    const inner = extensionOf(path.basename(name, ext));

    if (EXECUTABLE.has(ext) && ext !== ".lnk" && DOCUMENT.has(inner)) {
      findings.push({ rule: "double-extension", severity: "high", path: where, detail: `"${name}" is a program that looks like a ${inner.slice(1)} file.` });
      continue;
    }

    // "Photos.lnk" next to a folder called "Photos": a shortcut standing in for the real folder.
    if (ext === ".lnk" && folders.has(path.basename(name, ext).toLowerCase())) {
      findings.push({ rule: "shortcut-impersonation", severity: "medium", path: where, detail: `"${name}" is a shortcut with the same name as the folder next to it.` });
      continue;
    }

    if (EXECUTABLE.has(ext) && ext !== ".lnk") {
      findings.push({ rule: "root-program", severity: "low", path: where, detail: `"${name}" is a program at the top of the drive.` });
    }
  }

  findings.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);

  return { ok: true, findings, entriesChecked: top.length, truncated, reason: truncated ? `Only the first ${limit} items at the top of the drive were checked.` : null };
}

function maxSeverity(items) {
  let best = null;

  for (const item of items) {
    if (!best || (SEVERITY_ORDER[item.severity] || 0) > (SEVERITY_ORDER[best] || 0)) best = item.severity;
  }

  return best;
}

module.exports = { inspectDrive, parseAutorun, maxSeverity, SEVERITY_ORDER };
