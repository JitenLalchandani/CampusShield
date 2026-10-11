
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");
const crypto = require("node:crypto");

const execFileAsync = promisify(execFile);

async function scanMacLogs() {
  const predicate =
    '(eventMessage CONTAINS[c] "authentication failed" OR ' +
    'eventMessage CONTAINS[c] "invalid password") AND ' +
    'NOT eventMessage CONTAINS[c] "localScanner.js"';

  const { stdout } = await execFileAsync(
    "/usr/bin/log",
    [
      "show",
      "--last", "15m",
      "--style", "json",
      "--predicate", predicate
    ],
    {
      timeout: 30000,
      maxBuffer: 10 * 1024 * 1024
    }
  );

  let parsed;

  try {
    parsed = JSON.parse(stdout || "[]");
  } catch {
    throw new Error("macOS returned logs in an unexpected format.");
  }

  const rows = Array.isArray(parsed) ? parsed : [parsed];

  const findings = rows
    .filter(row => row && typeof row === "object")
    .filter(row => {
      const message = String(row.eventMessage || "").toLowerCase();

      return (
        message.includes("authentication failed") ||
        message.includes("invalid password")
      );
    })
    .filter(row => {
      const message = String(row.eventMessage || "").toLowerCase();

      return !message.includes("localscanner.js");
    })
    .slice(0, 100)
    .map(row => {
      const message = String(row.eventMessage || "");
      const timestamp = row.timestamp || new Date().toISOString();

      const id = crypto
        .createHash("sha256")
        .update(`${timestamp}|${message}`)
        .digest("hex")
        .slice(0, 24);

      return {
        id,
        source: "macOS Unified Log",
        type: "Authentication failure indicator",
        group: "macOS",
        severity: "LOW",
        count: 1,
        timestamp,
        description: message.slice(0, 500),
        status: "New",
        rule: "Authentication-related phrase detected; investigation required",
        recommendation:
          "Verify the process, user, and surrounding logs before classifying this as a threat."
      };
    });

  return {
    scannedAt: new Date().toISOString(),
    windowMinutes: 15,
    entriesMatched: findings.length,
    findings
  };
}

module.exports = { scanMacLogs };

