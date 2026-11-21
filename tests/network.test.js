"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const network = require("../src/networkAudit");

const LSOF_TCP = `COMMAND     PID           USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
node       6177 meetprajapati   12u  IPv6 0xad2acbbb90277c      0t0  TCP *:3999 (LISTEN)
postgres   712 meetprajapati    5u  IPv6 0x1111111111111      0t0  TCP [::1]:5432 (LISTEN)
node       7000 meetprajapati   23u  IPv4 0x2222222222222      0t0  TCP 192.168.1.20:445 (LISTEN)
`;

const LSOF_UDP = `COMMAND     PID           USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
mDNSRespo   101  _mdnsresponder    7u  IPv4 0x3333333333333      0t0  UDP *:5353
`;

test("parses lsof listeners and classifies loopback separately", () => {
  const services = network.parseLsof(LSOF_TCP);

  assert.equal(services.length, 3);
  assert.ok(services.some(item => item.port === 3999 && item.scope === "network" && item.process === "node"));
  assert.ok(services.some(item => item.port === 5432 && item.scope === "loopback"));
  assert.ok(services.some(item => item.port === 445 && item.scope === "network" && item.risky));
});

test("parses udp listeners and ignores the header", () => {
  const services = network.parseLsof(LSOF_UDP);

  assert.equal(services.length, 1);
  assert.equal(services[0].protocol, "UDP");
  assert.equal(services[0].port, 5353);
  assert.equal(services[0].scope, "network");
});

test("classifies addresses without inventing scope", () => {
  assert.equal(network.scopeForAddress("127.0.0.1"), "loopback");
  assert.equal(network.scopeForAddress("::1"), "loopback");
  assert.equal(network.scopeForAddress("0.0.0.0"), "network");
  assert.equal(network.scopeForAddress("::"), "network");
  assert.equal(network.scopeForAddress("192.168.1.20"), "network");
  assert.equal(network.scopeForAddress(""), "unknown");
});

test("names common services and flags only sensitive network-bound ports", () => {
  assert.equal(network.serviceForPort(5432), "PostgreSQL");
  assert.equal(network.serviceForPort(59999), null);
  assert.match(network.riskNoteFor(6379), /no authentication/i);
  assert.equal(network.riskNoteFor(8080), null);

  const services = network.parseLsof(LSOF_TCP);
  const loopbackDb = services.find(item => item.port === 5432);

  assert.equal(loopbackDb.risky, false, "a loopback-only database must not be flagged as exposed");
});

test("parses netstat listening lines and ignores established connections", () => {
  const output = `
  Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1234
  TCP    127.0.0.1:5939         0.0.0.0:0              LISTENING       5678
  TCP    192.168.1.20:50000     93.184.216.34:443      ESTABLISHED     9012
  UDP    0.0.0.0:5353           *:*                                    3456
  `;

  const services = network.parseNetstat(output);

  assert.equal(services.length, 3);
  assert.ok(services.some(item => item.port === 135 && item.scope === "network" && item.pid === 1234));
  assert.ok(services.some(item => item.port === 5939 && item.scope === "loopback"));
  assert.ok(!services.some(item => item.port === 50000), "established connections are not listeners");
  assert.ok(services.some(item => item.protocol === "UDP" && item.port === 5353));
});

test("maps Windows pids to process names", () => {
  const names = network.parseTasklist(`"node.exe","1234","Console","1","120,000 K"\n"svchost.exe","5678","Services","0","12,000 K"\n`);

  assert.equal(names.get(1234), "node.exe");
  assert.equal(names.get(5678), "svchost.exe");
});

test("parses ss listeners when lsof is unavailable", () => {
  const output = `Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   LISTEN 0      511          127.0.0.1:6379      0.0.0.0:*     users:(("redis-server",pid=777,fd=6))
udp   UNCONN 0      0              0.0.0.0:5353        0.0.0.0:*
`;

  const services = network.parseSs(output);

  assert.equal(services.length, 2);
  assert.ok(services.some(item => item.port === 6379 && item.process === "redis-server"));
  assert.ok(services.some(item => item.port === 5353 && item.scope === "network"));
});

test("reports the socket table honestly when the host cannot be read", async () => {
  const snapshot = await network.collectNetworkExposure({
    runner: async () => ({ ok: false, stdout: "", stderr: "", message: "not installed" })
  });

  assert.equal(snapshot.supported, false);
  assert.match(snapshot.error, /not installed/);
  assert.deepEqual(snapshot.services, []);
});

test("summarizes a real parse into counted findings", async () => {
  const runner = async (command, args) => {
    if (command === "lsof" && args.includes("-iTCP")) return { ok: true, stdout: LSOF_TCP, stderr: "" };
    if (command === "lsof" && args.includes("-iUDP")) return { ok: true, stdout: LSOF_UDP, stderr: "" };
    return { ok: false, stdout: "", stderr: "", message: "unexpected" };
  };

  const snapshot = await network.collectNetworkExposure({ runner });

  assert.equal(snapshot.supported, true);
  assert.equal(snapshot.total, 4);
  assert.equal(snapshot.networkBound, 3);
  assert.equal(snapshot.loopbackOnly, 1);
  assert.equal(snapshot.riskyCount, 1);
  assert.equal(snapshot.findings[0].title, "SMB on port 445");
  assert.equal(snapshot.services[0].scope, "network");
});
