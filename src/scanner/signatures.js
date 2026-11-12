"use strict";

const fs = require("node:fs");
const path = require("node:path");

const BUILTIN = require("./signatures.json");
const SEVERITIES = new Set(["critical", "high", "medium", "low"]);

function normalizeEntry(entry) {
  const sha256 = String(entry?.sha256 || "").trim().toLowerCase();

  if (!/^[a-f0-9]{64}$/.test(sha256)) return null;
  if (!entry?.name) return null;

  return {
    sha256,
    name: String(entry.name).slice(0, 120),
    severity: SEVERITIES.has(entry.severity) ? entry.severity : "high",
    kind: entry.kind ? String(entry.kind).slice(0, 40) : "signature",
    note: entry.note ? String(entry.note).slice(0, 300) : null
  };
}

function readFeed(file) {
  const raw = fs.readFileSync(file, "utf8");
  const parsed = JSON.parse(raw);
  const list = Array.isArray(parsed) ? parsed : parsed?.entries;

  if (!Array.isArray(list)) {
    throw new Error("Signature feed must be an array or an object with an entries array.");
  }

  return {
    version: parsed?.version ? String(parsed.version).slice(0, 40) : path.basename(file),
    entries: list.map(normalizeEntry).filter(Boolean)
  };
}

function loadSignatures(feedPath = process.env.CAMPUSSHIELD_SIGNATURES) {
  const byHash = new Map();
  const warnings = [];

  for (const entry of BUILTIN.entries) {
    const normalized = normalizeEntry(entry);
    if (normalized) byHash.set(normalized.sha256, normalized);
  }

  let version = BUILTIN.version;

  if (feedPath) {
    try {
      const feed = readFeed(path.resolve(feedPath));

      for (const entry of feed.entries) byHash.set(entry.sha256, entry);

      version = `${BUILTIN.version}+${feed.version}`;
    } catch (error) {
      warnings.push(`Signature feed ignored: ${error.message}`);
    }
  }

  return {
    version,
    entries: [...byHash.values()],
    byHash,
    count: byHash.size,
    note: BUILTIN.note,
    warnings
  };
}

module.exports = { loadSignatures, normalizeEntry };
