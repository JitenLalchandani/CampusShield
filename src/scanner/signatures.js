"use strict";

const fs = require("node:fs");
const http = require("node:http");
const https = require("node:https");
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
    baseVersion: version,
    entries: [...byHash.values()],
    byHash,
    count: byHash.size,
    note: BUILTIN.note,
    warnings
  };
}

function isLocalUrl(url) {
  return ["localhost", "127.0.0.1", "::1", "[::1]"].includes(url.hostname);
}

function fetchText(rawUrl, { timeoutMs = 10000, maxBytes = 5 * 1024 * 1024 } = {}) {
  return new Promise((resolve, reject) => {
    let url;

    try {
      url = new URL(rawUrl);
    } catch {
      reject(new Error("Signature feed URL is not valid."));
      return;
    }

    if (url.protocol !== "https:" && !(url.protocol === "http:" && isLocalUrl(url))) {
      reject(new Error("Signature feed must use HTTPS (HTTP is allowed for localhost only)."));
      return;
    }

    const client = url.protocol === "https:" ? https : http;

    const request = client.get(
      url,
      {
        timeout: timeoutMs,
        headers: { accept: "application/json", "user-agent": "CampusShield/1.0" }
      },
      response => {
        if (response.statusCode !== 200) {
          response.resume();
          reject(new Error(`Signature feed returned HTTP ${response.statusCode}.`));
          return;
        }

        const chunks = [];
        let size = 0;

        response.on("data", chunk => {
          size += chunk.length;

          if (size > maxBytes) {
            request.destroy(new Error("Signature feed is larger than 5 MB."));
            return;
          }

          chunks.push(chunk);
        });

        response.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
        response.on("error", reject);
      }
    );

    request.on("timeout", () => request.destroy(new Error("Signature feed timed out.")));
    request.on("error", reject);
  });
}

async function refreshSignaturesFromUrl(signatures, rawUrl, options = {}) {
  const raw = await fetchText(rawUrl, options);
  const parsed = JSON.parse(raw);
  const list = Array.isArray(parsed) ? parsed : parsed?.entries;

  if (!Array.isArray(list)) {
    throw new Error("Signature feed must be an array or an object with an entries array.");
  }

  let added = 0;

  for (const entry of list) {
    const normalized = normalizeEntry(entry);
    if (!normalized || signatures.byHash.has(normalized.sha256)) continue;

    signatures.byHash.set(normalized.sha256, normalized);
    added += 1;
  }

  signatures.entries = [...signatures.byHash.values()];
  signatures.count = signatures.byHash.size;

  const feedVersion =
    parsed?.version ? String(parsed.version).slice(0, 40) : new URL(rawUrl).hostname;
  signatures.version = `${signatures.baseVersion}+${feedVersion}`;

  return { added, version: signatures.version, count: signatures.count };
}

module.exports = { loadSignatures, normalizeEntry, refreshSignaturesFromUrl };
