"use strict";

const { execFile } = require("node:child_process");
const { promisify } = require("node:util");

const execFileAsync = promisify(execFile);

const COMMAND_TIMEOUT_MS = 8000;
const MAX_SERVICES = 80;

// Common ports are named only to make the list readable. A name is not a
// verdict: the exposure and the process are the facts, the label is a hint.
const SERVICE_NAMES = new Map([
  [20, "FTP data"],
  [21, "FTP"],
  [22, "SSH"],
  [23, "Telnet"],
  [25, "SMTP"],
  [53, "DNS"],
  [80, "HTTP"],
  [110, "POP3"],
  [139, "NetBIOS"],
  [143, "IMAP"],
  [443, "HTTPS"],
  [445, "SMB"],
  [587, "SMTP submission"],
  [631, "CUPS printing"],
  [1433, "SQL Server"],
  [1521, "Oracle"],
  [2049, "NFS"],
  [3000, "Development web server"],
  [3306, "MySQL"],
  [3389, "Remote Desktop"],
  [4000, "Development web server"],
  [5000, "Development web server"],
  [5432, "PostgreSQL"],
  [5900, "VNC"],
  [5984, "CouchDB"],
  [6379, "Redis"],
  [8000, "Development web server"],
  [8080, "HTTP proxy / development"],
  [8443, "HTTPS alternative"],
  [8888, "Jupyter"],
  [9200, "Elasticsearch"],
  [9300, "Elasticsearch transport"],
  [11211, "Memcached"],
  [27017, "MongoDB"],
  [2375, "Docker API"],
  [2376, "Docker API (TLS)"]
]);

// Ports that are routinely probed and attacked when reachable from another
// machine. Exposure is still reported, never turned into a fake detection.
const SENSITIVE_PORTS = new Map([
  [21, "FTP sends credentials in clear text."],
  [23, "Telnet sends credentials in clear text."],
  [445, "SMB file sharing is a common lateral-movement target."],
  [1433, "A database is reachable from other machines."],
  [2375, "The Docker API is unauthenticated on this port."],
  [3306, "A database is reachable from other machines."],
  [3389, "Remote Desktop is reachable from the network."],
  [5432, "A database is reachable from other machines."],
  [5900, "VNC screen sharing is reachable from the network."],
  [5984, "CouchDB is reachable from other machines."],
  [6379, "Redis has no authentication by default."],
  [9200, "Elasticsearch has no authentication by default."],
  [11211, "Memcached has no authentication by default."],
  [27017, "MongoDB is reachable from other machines."]
]);

function serviceForPort(port) {
  return SERVICE_NAMES.get(port) || null;
}

function riskNoteFor(port) {
  return SENSITIVE_PORTS.get(port) || null;
}

function normalizeAddress(raw) {
  const value = String(raw || "").trim();

  if (!value) return "";

  if (value.startsWith("[")) {
    const end = value.indexOf("]");
    return end === -1 ? value : value.slice(1, end);
  }

  return value;
}

function scopeForAddress(address) {
  const value = String(address || "").toLowerCase();

  if (!value) return "unknown";
  if (value === "localhost" || value === "localhost.localdomain") return "loopback";
  if (value === "::1" || value.startsWith("127.")) return "loopback";
  if (value === "*" || value === "0.0.0.0" || value === "::" || value === "[::]") {
    return "network";
  }

  return "network";
}

function splitHostPort(raw) {
  const value = String(raw || "").trim().replace(/\(LISTEN\)$/i, "");

  if (!value) return { address: "", port: 0 };

  if (value.startsWith("[")) {
    const end = value.indexOf("]");
    if (end === -1) return { address: normalizeAddress(value), port: 0 };

    const rest = value.slice(end + 1);
    const port = Number(rest.replace(/^:/, ""));
    return { address: normalizeAddress(value), port: Number.isFinite(port) ? port : 0 };
  }

  const colon = value.lastIndexOf(":");
  if (colon === -1) return { address: value, port: 0 };

  const port = Number(value.slice(colon + 1));
  return { address: value.slice(0, colon), port: Number.isFinite(port) ? port : 0 };
}

function toService({ protocol, address, port, process, pid }) {
  const scopedAddress = normalizeAddress(address);
  const scope = scopeForAddress(scopedAddress);
  const risky = scope === "network" && SENSITIVE_PORTS.has(port);

  return {
    protocol: String(protocol || "").toUpperCase(),
    address: scopedAddress || "unknown",
    port,
    scope,
    wildcard: scope === "network" && ["*", "0.0.0.0", "::"].includes(scopedAddress),
    process: process || null,
    pid: Number.isFinite(pid) ? pid : null,
    service: serviceForPort(port),
    risky,
    riskNote: risky ? riskNoteFor(port) : null
  };
}

function dedupe(services) {
  const seen = new Set();
  const list = [];

  for (const service of services) {
    if (service.port <= 0) continue;

    const key = `${service.protocol}:${service.address}:${service.port}:${service.pid || ""}`;
    if (seen.has(key)) continue;

    seen.add(key);
    list.push(service);
  }

  return list.sort((a, b) => {
    if (a.scope !== b.scope) return a.scope === "network" ? -1 : 1;
    if (a.risky !== b.risky) return a.risky ? -1 : 1;
    return a.port - b.port;
  });
}

// lsof -nP -iTCP -sTCP:LISTEN / lsof -nP -iUDP
// COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
function parseLsof(output) {
  const services = [];

  for (const line of String(output || "").split(/\r?\n/)) {
    const tokens = line.trim().split(/\s+/);
    if (tokens.length < 4 || tokens[0] === "COMMAND") continue;

    const protocolIndex = tokens.findIndex(token => token === "TCP" || token === "UDP");
    if (protocolIndex === -1 || !tokens[protocolIndex + 1]) continue;

    const protocol = tokens[protocolIndex];
    const name = tokens[protocolIndex + 1];

    if (protocol === "TCP" && !/\(LISTEN\)/.test(line)) continue;

    const { address, port } = splitHostPort(name);
    const pid = Number(tokens[1]);

    services.push(
      toService({
        protocol,
        address,
        port,
        process: tokens[0],
        pid: Number.isFinite(pid) ? pid : null
      })
    );
  }

  return dedupe(services);
}

// ss -lntu
// Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
function parseSs(output) {
  const services = [];

  for (const line of String(output || "").split(/\r?\n/)) {
    const tokens = line.trim().split(/\s+/);
    if (tokens.length < 5 || tokens[0] === "Netid") continue;
    if (!["tcp", "udp"].includes(tokens[0].toLowerCase())) continue;

    const local = tokens[4];
    const { address, port } = splitHostPort(local);
    const processMatch = line.match(/\(\("([^"]+)",pid=(\d+)/);

    services.push(
      toService({
        protocol: tokens[0].toUpperCase().slice(0, 3),
        address,
        port,
        process: processMatch ? processMatch[1] : null,
        pid: processMatch ? Number(processMatch[2]) : null
      })
    );
  }

  return dedupe(services);
}

// netstat -ano -p tcp / udp
//   TCP    0.0.0.0:135    0.0.0.0:0    LISTENING    1234
//   UDP    0.0.0.0:5353   *:*                       9012
function parseNetstat(output) {
  const services = [];

  for (const line of String(output || "").split(/\r?\n/)) {
    const tokens = line.trim().split(/\s+/);
    if (tokens.length < 4) continue;

    const protocol = tokens[0].toUpperCase();
    if (protocol !== "TCP" && protocol !== "UDP") continue;
    if (protocol === "TCP" && tokens[3] !== "LISTENING") continue;

    const { address, port } = splitHostPort(tokens[1]);
    const pidToken = protocol === "TCP" ? tokens[4] : tokens[tokens.length - 1];
    const pid = Number(pidToken);

    services.push(
      toService({
        protocol,
        address,
        port,
        process: null,
        pid: Number.isFinite(pid) ? pid : null
      })
    );
  }

  return dedupe(services);
}

// tasklist /FO CSV /NH  →  "node.exe","1234","Console","1","120,000 K"
function parseTasklist(output) {
  const names = new Map();

  for (const line of String(output || "").split(/\r?\n/)) {
    const match = line.match(/^"([^"]+)","(\d+)"/);
    if (!match) continue;
    names.set(Number(match[2]), match[1]);
  }

  return names;
}

async function run(command, args, timeout = COMMAND_TIMEOUT_MS) {
  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      timeout,
      maxBuffer: 4 * 1024 * 1024
    });
    return { ok: true, stdout: String(stdout || ""), stderr: String(stderr || "") };
  } catch (error) {
    return {
      ok: false,
      stdout: String(error.stdout || ""),
      stderr: String(error.stderr || ""),
      message: error.message
    };
  }
}

function summarize(services, extra = {}) {
  const network = services.filter(service => service.scope === "network");
  const loopback = services.filter(service => service.scope === "loopback");
  const risky = network.filter(service => service.risky);

  return {
    supported: true,
    readAt: new Date().toISOString(),
    platform: process.platform,
    elevated: typeof process.getuid === "function" && process.getuid() === 0,
    total: services.length,
    networkBound: network.length,
    loopbackOnly: loopback.length,
    riskyCount: risky.length,
    services: services.slice(0, MAX_SERVICES),
    findings: risky.slice(0, 20).map(service => ({
      id: `exposed-${service.protocol}-${service.port}`,
      title: `${service.service || "Service"} on port ${service.port}`,
      severity: "medium",
      detail: `${service.protocol} listener on ${service.address}${service.process ? ` (${service.process}${service.pid ? `, PID ${service.pid}` : ""})` : ""}.`,
      why: service.riskNote
    })),
    notes: [],
    error: null,
    ...extra
  };
}

// Read-only enumeration of listening sockets. Nothing is connected to, probed,
// or changed; only socket table entries and the owning process names are read.
async function collectNetworkExposure({ runner = run } = {}) {
  if (process.platform === "win32") {
    const [tcp, udp, tasks] = await Promise.all([
      runner("netstat", ["-ano", "-p", "tcp"]),
      runner("netstat", ["-ano", "-p", "udp"]),
      runner("tasklist", ["/FO", "CSV", "/NH"])
    ]);

    if (!tcp.ok && !udp.ok) {
      return {
        supported: false,
        readAt: new Date().toISOString(),
        platform: process.platform,
        total: 0,
        networkBound: 0,
        loopbackOnly: 0,
        riskyCount: 0,
        services: [],
        findings: [],
        notes: [],
        error: tcp.message || udp.message || "netstat did not report any sockets."
      };
    }

    const names = tasks.ok ? parseTasklist(tasks.stdout) : new Map();
    const services = dedupe([
      ...parseNetstat(tcp.stdout),
      ...parseNetstat(udp.stdout)
    ]).map(service =>
      service.pid && names.has(service.pid)
        ? { ...service, process: names.get(service.pid) }
        : service
    );

    const snapshot = summarize(services);
    snapshot.notes.push("Sockets owned by other Windows users can be hidden unless the server runs elevated.");
    return snapshot;
  }

  const [tcp, udp] = await Promise.all([
    runner("lsof", ["-nP", "-iTCP", "-sTCP:LISTEN"]),
    runner("lsof", ["-nP", "-iUDP"])
  ]);

  if (!tcp.ok && !udp.ok) {
    const ss = await runner("ss", ["-lntu"]);

    if (ss.ok && ss.stdout.trim()) {
      const snapshot = summarize(parseSs(ss.stdout));
      snapshot.notes.push("Read with `ss`; process names are shown only for processes this user can inspect.");
      return snapshot;
    }

    return {
      supported: false,
      readAt: new Date().toISOString(),
      platform: process.platform,
      total: 0,
      networkBound: 0,
      loopbackOnly: 0,
      riskyCount: 0,
      services: [],
      findings: [],
      notes: [],
      error:
        tcp.message ||
        udp.message ||
        "The socket table could not be read on this host (lsof and ss are unavailable)."
    };
  }

  const services = dedupe([...parseLsof(tcp.stdout), ...parseLsof(udp.stdout)]);
  const snapshot = summarize(services);

  if (!snapshot.elevated) {
    snapshot.notes.push(
      "Sockets owned by other users or system daemons can be hidden unless the server runs as root."
    );
  }

  return snapshot;
}

module.exports = {
  collectNetworkExposure,
  parseLsof,
  parseSs,
  parseNetstat,
  parseTasklist,
  scopeForAddress,
  serviceForPort,
  riskNoteFor
};
