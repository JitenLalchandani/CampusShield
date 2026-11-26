"use strict";

// Reads a pasted link without opening it. Nothing here touches the network.

const net = require("node:net");
const { domainToUnicode } = require("node:url");

const MAX_URL = 2048;
const CODE_SCHEMES = new Set(["javascript:", "data:", "vbscript:"]);

// Two-part public suffixes the "registrable domain" guess must respect. This is a short built-in
// list, not the full public suffix list, and the result says "approximate".
const TWO_PART_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "ac.in", "gov.in", "nic.in", "org.in", "net.in", "res.in", "edu.in",
  "com.au", "net.au", "org.au", "edu.au", "co.jp", "ne.jp", "co.nz", "co.za", "com.br", "com.cn", "com.sg", "com.my", "com.pk", "com.bd", "co.id"
]);

function registrableDomain(host) {
  const labels = host.split(".");
  if (labels.length <= 2) return host;
  const lastTwo = labels.slice(-2).join(".");
  return TWO_PART_SUFFIXES.has(lastTwo) ? labels.slice(-3).join(".") : lastTwo;
}

function parseUrl(input) {
  let text = String(input ?? "").trim();

  if (!text) return { ok: false, error: "Paste a link to check." };
  if (text.length > MAX_URL) return { ok: false, error: `Links longer than ${MAX_URL} characters are not checked.` };
  if (/[\0\r\n]/.test(text)) return { ok: false, error: "That does not look like a single link." };

  // "example.com/login" with no scheme is treated as https:// for the check only.
  const schemeless = !/^[a-z][a-z0-9+.-]*:/i.test(text) || /^[^/]+:\d+(\/|$)/.test(text);
  if (schemeless) text = `https://${text}`;

  let url;

  try {
    url = new URL(text);
  } catch {
    return { ok: false, error: "That is not a link CampusShield can read." };
  }

  if (CODE_SCHEMES.has(url.protocol)) {
    return { ok: true, url, scheme: url.protocol, runsCode: true, host: "", unicodeHost: "", registrable: "", schemeAdded: false };
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { ok: false, error: `Only http and https links are checked, not ${url.protocol}` };
  }

  const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (!host) return { ok: false, error: "That link has no website name." };

  const isIp = net.isIP(host) !== 0;

  return {
    ok: true,
    url,
    scheme: url.protocol,
    runsCode: false,
    host,
    unicodeHost: isIp ? host : domainToUnicode(host) || host,
    isIp,
    registrable: isIp ? host : registrableDomain(host),
    schemeAdded: schemeless
  };
}

module.exports = { parseUrl, registrableDomain, MAX_URL };
