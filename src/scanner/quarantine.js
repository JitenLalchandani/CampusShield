"use strict";

const crypto = require("node:crypto");
const { constants } = require("node:fs");
const fs = require("node:fs/promises");
const path = require("node:path");

function safeStoredName(value) {
  const name = String(value || "");
  return name && path.basename(name) === name && !name.startsWith(".") ? name : null;
}

function createQuarantine(dataDir) {
  const root = path.join(dataDir, "quarantine");

  async function ensureRoot() {
    await fs.mkdir(root, { recursive: true });
  }

  async function moveIn(filePath) {
    const stat = await fs.lstat(filePath);

    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new Error("Only regular files can be quarantined.");
    }

    await ensureRoot();

    const storedName = `${crypto.randomUUID()}.quarantine`;
    const destination = path.join(root, storedName);

    try {
      await fs.rename(filePath, destination);
    } catch (error) {
      if (error.code !== "EXDEV") throw error;

      await fs.copyFile(filePath, destination, constants.COPYFILE_EXCL);
      await fs.unlink(filePath);
    }

    await fs.chmod(destination, 0o600).catch(() => {});

    return { storedName, size: stat.size };
  }

  async function moveOut(record) {
    const storedName = safeStoredName(record?.storedName);
    if (!storedName) throw new Error("Quarantine record is invalid.");

    const source = path.join(root, storedName);

    try {
      await fs.access(source);
    } catch {
      throw new Error("The quarantined file is no longer on disk.");
    }

    let destination = path.resolve(String(record.originalPath || ""));
    const base = path.dirname(destination);

    try {
      await fs.access(destination);
      destination = path.join(
        base,
        `${path.basename(destination)}.restored-${Date.now()}`
      );
    } catch {
      /* original path is free */
    }

    await fs.mkdir(base, { recursive: true });

    try {
      await fs.rename(source, destination);
    } catch (error) {
      if (error.code !== "EXDEV") throw error;

      await fs.copyFile(source, destination);
      await fs.unlink(source);
    }

    return destination;
  }

  async function remove(record) {
    const storedName = safeStoredName(record?.storedName);
    if (!storedName) return false;

    try {
      await fs.unlink(path.join(root, storedName));
      return true;
    } catch (error) {
      if (error.code === "ENOENT") return false;
      throw error;
    }
  }

  async function clear() {
    let names = [];

    try {
      names = await fs.readdir(root);
    } catch (error) {
      if (error.code === "ENOENT") return 0;
      throw error;
    }

    let deleted = 0;

    for (const name of names) {
      if (!name.endsWith(".quarantine")) continue;

      try {
        await fs.unlink(path.join(root, name));
        deleted += 1;
      } catch {
        /* best effort */
      }
    }

    return deleted;
  }

  return { root, moveIn, moveOut, remove, clear };
}

module.exports = { createQuarantine };
