"use strict";

// Finds removable drives that are mounted right now. Read-only: it lists, it never mounts,
// unmounts, or writes. Each parser takes the raw command output so tests can feed real samples.

const { runCommand } = require("../shield/exec");

function driveId(platform, parts) {
  const key = parts.find(Boolean) || "unknown";
  return `${platform}:${String(key).trim().slice(0, 100)}`;
}

// Linux: lsblk -J -b -o NAME,RM,HOTPLUG,TRAN,MOUNTPOINT,LABEL,UUID,FSTYPE,SIZE,TYPE
function parseLsblk(output) {
  let data;

  try {
    data = JSON.parse(output);
  } catch {
    return null;
  }

  const drives = [];

  const walk = (node, inherited) => {
    const removable =
      inherited ||
      node.rm === true || node.rm === "1" || node.rm === 1 ||
      node.hotplug === true || node.hotplug === "1" || node.hotplug === 1 ||
      String(node.tran || "").toLowerCase() === "usb";
    const mounts = [node.mountpoint, ...(Array.isArray(node.mountpoints) ? node.mountpoints : [])].filter(Boolean);

    if (removable && mounts.length) {
      drives.push({
        id: driveId("linux", [node.uuid, node.label, node.name]),
        label: node.label || node.name || "USB drive",
        mountPoint: mounts[0],
        fsType: node.fstype || null,
        sizeBytes: Number(node.size) || null
      });
    }

    for (const child of node.children || []) walk(child, removable);
  };

  for (const node of data.blockdevices || []) walk(node, false);
  return drives;
}

// macOS: diskutil info -all (text blocks separated by a line of asterisks)
function parseDiskutil(output) {
  const drives = [];

  for (const block of String(output).split(/\*{5,}/)) {
    const field = name => {
      const match = block.match(new RegExp(`^\\s*${name}:\\s*(.*)$`, "m"));
      return match ? match[1].trim() : "";
    };

    const mountPoint = field("Mount Point");
    const external = /external/i.test(field("Device Location")) || /removable/i.test(field("Removable Media")) || /usb/i.test(field("Protocol"));

    if (!mountPoint || /^not mounted$/i.test(mountPoint) || !external) continue;
    if (/^yes$/i.test(field("Mounted")) === false && field("Mounted")) continue;

    const bytes = block.match(/\((\d+) Bytes\)/);

    drives.push({
      id: driveId("darwin", [field("Volume UUID"), field("Disk / Partition UUID"), field("Volume Name"), mountPoint]),
      label: field("Volume Name") || "USB drive",
      mountPoint,
      fsType: field("File System Personality") || null,
      sizeBytes: bytes ? Number(bytes[1]) : null
    });
  }

  return drives;
}

// Windows: Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2" | ConvertTo-Json
function parseWindows(output) {
  const text = String(output).trim();
  if (!text) return [];

  let data;

  try {
    data = JSON.parse(text);
  } catch {
    return null;
  }

  return (Array.isArray(data) ? data : [data])
    .filter(item => item && item.DeviceID)
    .map(item => ({
      id: driveId("win32", [item.VolumeSerialNumber, item.DeviceID]),
      label: item.VolumeName || `Drive ${item.DeviceID}`,
      mountPoint: `${item.DeviceID}\\`,
      fsType: item.FileSystem || null,
      sizeBytes: Number(item.Size) || null
    }));
}

const COMMANDS = {
  linux: ["lsblk", ["-J", "-b", "-o", "NAME,RM,HOTPLUG,TRAN,MOUNTPOINT,LABEL,UUID,FSTYPE,SIZE,TYPE"], parseLsblk],
  darwin: ["diskutil", ["info", "-all"], parseDiskutil],
  win32: [
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-Command", "Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2' | Select-Object DeviceID,VolumeName,FileSystem,Size,VolumeSerialNumber | ConvertTo-Json -Compress"],
    parseWindows
  ]
};

function isSupported(platform) {
  return Boolean(COMMANDS[platform]);
}

async function listRemovableDrives({ platform = process.platform, runner = runCommand } = {}) {
  const entry = COMMANDS[platform];
  if (!entry) return { ok: false, drives: [], reason: "USB detection is not supported on this operating system." };

  const [command, args, parse] = entry;
  const result = await runner(command, args, { timeoutMs: 10000 });

  if (!result.ok && !result.stdout) {
    return { ok: false, drives: [], reason: result.message || `${command} failed.` };
  }

  const drives = parse(result.stdout);

  if (drives === null) return { ok: false, drives: [], reason: `${command} returned output that could not be read.` };

  return { ok: true, drives, reason: null };
}

module.exports = { parseLsblk, parseDiskutil, parseWindows, listRemovableDrives, isSupported, driveId };
