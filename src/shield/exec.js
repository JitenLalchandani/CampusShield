"use strict";

// One place that runs OS commands. It uses execFile with an argument array, never a shell, so a
// value cannot turn into extra commands. Tests replace this with a fake runner.

const { execFile } = require("node:child_process");

function runCommand(command, args = [], { timeoutMs = 8000 } = {}) {
  return new Promise(resolve => {
    execFile(
      command,
      args,
      { timeout: timeoutMs, maxBuffer: 2 * 1024 * 1024, windowsHide: true },
      (error, stdout, stderr) => {
        if (error) {
          resolve({
            ok: false,
            stdout: String(stdout || ""),
            stderr: String(stderr || ""),
            code: error.code ?? null,
            message:
              error.code === "ENOENT"
                ? `${command} is not installed on this computer.`
                : String(stderr || error.message || "The command failed.").trim().slice(0, 300)
          });
          return;
        }

        resolve({ ok: true, stdout: String(stdout || ""), stderr: String(stderr || ""), code: 0, message: null });
      }
    );
  });
}

module.exports = { runCommand };
