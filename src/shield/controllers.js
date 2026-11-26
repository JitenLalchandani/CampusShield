"use strict";

// The two actions behind "Contain": stop a suspect program and turn off network connections.
// Both change the computer, so they are conservative:
//   - protected system programs and CampusShield itself are never stopped,
//   - the program is re-checked right before it is stopped, so a reused process number cannot
//     stop an unrelated program,
//   - names passed to the OS are validated against a strict pattern and never go through a shell,
//   - every network change is verified by reading the state back, and reported per connection.
// Tests inject fakes for the runner, the kill function, and the clock; nothing here runs in them.

const path = require("node:path");

const { runCommand } = require("./exec");
const { isProtectedProcess } = require("./suspects");

const SAFE_NAME_MAC = /^[A-Za-z0-9 ._()\-/]{1,64}$/;
const SAFE_NAME_WIN = /^[A-Za-z0-9 ._()-]{1,64}$/;
const SAFE_DEVICE_LINUX = /^[A-Za-z0-9_.:-]{1,32}$/;

const defaultSleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function sameProgram(currentName, expected) {
  const current = path.basename(String(currentName || "")).toLowerCase();
  const wanted = String(expected || "").toLowerCase();
  if (!current || !wanted) return false;
  // lsof truncates command names, so a prefix match in either direction counts.
  return current.startsWith(wanted) || wanted.startsWith(current);
}

async function currentProgramName(pid, { platform, runner }) {
  if (platform === "win32") {
    const result = await runner("tasklist", ["/FI", `PID eq ${pid}`, "/FO", "CSV", "/NH"]);
    const match = String(result.stdout || "").match(/^"([^"]+)"/m);
    return match ? match[1] : null;
  }

  const result = await runner("ps", ["-p", String(pid), "-o", "comm="]);
  return result.ok ? result.stdout.trim() || null : null;
}

function createProcessController({
  platform = process.platform,
  runner = runCommand,
  kill = (pid, signal) => process.kill(pid, signal),
  sleep = defaultSleep,
  selfUid = typeof process.getuid === "function" ? process.getuid() : null,
  selfPid = process.pid,
  parentPid = process.ppid
} = {}) {
  function alive(pid) {
    try {
      kill(pid, 0);
      return true;
    } catch (error) {
      return error.code === "EPERM";
    }
  }

  async function stop(suspect) {
    if (!suspect || !Number.isInteger(suspect.pid)) {
      return { ok: false, message: "There is no suspect to stop." };
    }

    if (isProtectedProcess(suspect, { selfPid, parentPid })) {
      return { ok: false, message: "This program is protected and will not be stopped." };
    }

    if (platform !== "win32" && suspect.uid != null && selfUid != null && suspect.uid !== selfUid) {
      return {
        ok: false,
        needsElevation: true,
        message: "This program belongs to another user. Stop it from an administrator account."
      };
    }

    const name = await currentProgramName(suspect.pid, { platform, runner });

    if (!name) {
      return { ok: true, message: `${suspect.name || "The program"} (PID ${suspect.pid}) is no longer running.` };
    }

    if (!sameProgram(name, suspect.name)) {
      return {
        ok: false,
        message: `PID ${suspect.pid} now belongs to a different program (${path.basename(name)}), so nothing was stopped.`
      };
    }

    if (platform === "win32") {
      const result = await runner("taskkill", ["/PID", String(suspect.pid), "/F"]);
      return result.ok
        ? { ok: true, message: `Stopped ${suspect.name} (PID ${suspect.pid}).` }
        : { ok: false, needsElevation: /access is denied/i.test(result.message || ""), message: result.message };
    }

    try {
      kill(suspect.pid, "SIGTERM");
    } catch (error) {
      if (error.code === "ESRCH") return { ok: true, message: `${suspect.name} is no longer running.` };
      if (error.code === "EPERM") {
        return { ok: false, needsElevation: true, message: "You are not allowed to stop this program." };
      }
      return { ok: false, message: error.message };
    }

    for (let attempt = 0; attempt < 6; attempt += 1) {
      await sleep(500);
      if (!alive(suspect.pid)) return { ok: true, message: `Stopped ${suspect.name} (PID ${suspect.pid}).` };
    }

    try {
      kill(suspect.pid, "SIGKILL");
    } catch (error) {
      if (error.code !== "ESRCH") return { ok: false, message: error.message };
    }

    await sleep(500);

    return alive(suspect.pid)
      ? { ok: false, message: `${suspect.name} (PID ${suspect.pid}) did not stop.` }
      : { ok: true, message: `Force-stopped ${suspect.name} (PID ${suspect.pid}).` };
  }

  return { stop };
}

function createNetworkController({ platform = process.platform, runner = runCommand } = {}) {
  async function list() {
    if (platform === "darwin") {
      const result = await runner("networksetup", ["-listallnetworkservices"]);
      if (!result.ok) return { ok: false, interfaces: [], message: result.message };

      const interfaces = result.stdout
        .split("\n")
        .map(line => line.trimEnd())
        .filter(line => line && !line.startsWith("An asterisk"))
        .map(line => (line.startsWith("*") ? { name: line.slice(1).trim(), enabled: false } : { name: line.trim(), enabled: true }));

      return { ok: true, interfaces };
    }

    if (platform === "linux") {
      const result = await runner("nmcli", ["-t", "-f", "DEVICE,TYPE,STATE", "device"]);
      if (!result.ok) return { ok: false, interfaces: [], message: result.message };

      const interfaces = result.stdout
        .split("\n")
        .map(line => line.split(":"))
        .filter(parts => parts.length >= 3 && parts[0] && parts[1] !== "loopback")
        .map(([name, , state]) => ({ name, enabled: state.startsWith("connected") }));

      return { ok: true, interfaces };
    }

    if (platform === "win32") {
      const result = await runner("powershell", [
        "-NoProfile", "-NonInteractive", "-Command",
        "Get-NetAdapter | Select-Object Name,Status | ConvertTo-Json -Compress"
      ]);
      if (!result.ok) return { ok: false, interfaces: [], message: result.message };

      let parsed;

      try {
        parsed = JSON.parse(result.stdout || "[]");
      } catch {
        return { ok: false, interfaces: [], message: "The adapter list could not be read." };
      }

      const rows = Array.isArray(parsed) ? parsed : [parsed];

      return {
        ok: true,
        interfaces: rows.filter(row => row?.Name).map(row => ({ name: String(row.Name), enabled: row.Status === "Up" }))
      };
    }

    return { ok: false, interfaces: [], message: "Network control is not supported on this platform." };
  }

  function nameAllowed(name) {
    if (platform === "darwin") return SAFE_NAME_MAC.test(name);
    if (platform === "win32") return SAFE_NAME_WIN.test(name);
    return SAFE_DEVICE_LINUX.test(name);
  }

  async function apply(name, enable) {
    if (platform === "darwin") {
      // The name was validated against SAFE_NAME_MAC, so it holds no quote or backslash.
      const script = `do shell script "networksetup -setnetworkserviceenabled '${name}' ${enable ? "on" : "off"}" with administrator privileges`;
      return runner("osascript", ["-e", script], { timeoutMs: 90000 });
    }

    if (platform === "linux") {
      return runner("pkexec", ["nmcli", "device", enable ? "connect" : "disconnect", name], { timeoutMs: 90000 });
    }

    const verb = enable ? "Enable" : "Disable";

    return runner(
      "powershell",
      [
        "-NoProfile", "-NonInteractive", "-Command",
        `Start-Process powershell -Verb RunAs -Wait -WindowStyle Hidden -ArgumentList '-NoProfile','-Command','${verb}-NetAdapter -Name ''${name}'' -Confirm:$false'`
      ],
      { timeoutMs: 90000 }
    );
  }

  // Changes each connection on its own and reads the state back, so the result says what is true
  // now rather than what was attempted.
  async function change(names, enable) {
    const results = [];

    for (const name of names) {
      if (!nameAllowed(name)) {
        results.push({
          name,
          ok: false,
          needsElevation: false,
          message: "The name contains characters CampusShield will not pass to the system, so it was left alone."
        });
        continue;
      }

      const attempt = await apply(name, enable);
      const after = await list();
      const found = after.interfaces.find(item => item.name === name);

      if (found && found.enabled === enable) {
        results.push({ name, ok: true, needsElevation: false, message: enable ? "Connected again." : "Turned off." });
      } else {
        const cancelled = /cancel|denied|not authori|dismissed/i.test(attempt.message || "");
        results.push({
          name,
          ok: false,
          needsElevation: cancelled || !attempt.ok,
          message:
            attempt.message ||
            (found ? "The state did not change. Approve the administrator prompt on this computer." : "The connection could not be found afterwards.")
        });
      }
    }

    return results;
  }

  return {
    list,
    disable: names => change(names, false),
    enable: names => change(names, true)
  };
}

module.exports = {
  createProcessController,
  createNetworkController,
  sameProgram,
  SAFE_NAME_MAC,
  SAFE_NAME_WIN,
  SAFE_DEVICE_LINUX
};
