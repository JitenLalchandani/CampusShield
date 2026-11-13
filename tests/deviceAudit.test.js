"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const {
  parseBitLocker,
  parseFirewallProfiles,
  parseDefenderStatus,
  parseHotFix,
  parseWindowsCaption,
  scoreFindings
} = require("../src/deviceAudit");

test("reads BitLocker protection from PowerShell JSON", () => {
  assert.deepEqual(
    parseBitLocker('{"VolumeStatus":"FullyDecrypted","ProtectionStatus":0}'),
    { known: true, on: false }
  );
  assert.deepEqual(
    parseBitLocker('{"VolumeStatus":"FullyEncrypted","ProtectionStatus":1}'),
    { known: true, on: true }
  );
  assert.equal(parseBitLocker("").known, false);
  assert.equal(parseBitLocker("not json").known, false);
});

test("requires every Windows firewall profile to be enabled", () => {
  const all = parseFirewallProfiles(
    '[{"Name":"Domain","Enabled":true},{"Name":"Private","Enabled":true},{"Name":"Public","Enabled":true}]'
  );
  assert.deepEqual(all, { known: true, on: true, names: 3, total: 3 });

  const partial = parseFirewallProfiles(
    '[{"Name":"Domain","Enabled":true},{"Name":"Public","Enabled":false}]'
  );
  assert.equal(partial.on, false);
  assert.equal(partial.names, 1);
  assert.equal(partial.total, 2);

  const single = parseFirewallProfiles('{"Name":"Public","Enabled":true}');
  assert.equal(single.total, 1);
  assert.equal(single.on, true);
  assert.equal(parseFirewallProfiles("garbage").known, false);
});

test("interprets Defender real-time state and signature age", () => {
  assert.deepEqual(
    parseDefenderStatus('{"RealTimeProtectionEnabled":true,"AntivirusEnabled":true,"AntivirusSignatureAge":1}'),
    { known: true, realtime: true, enabled: true, signatureAge: 1 }
  );

  const off = parseDefenderStatus('{"RealTimeProtectionEnabled":false,"AntivirusSignatureAge":9}');
  assert.equal(off.realtime, false);
  assert.equal(off.signatureAge, 9);
  assert.equal(parseDefenderStatus("{").known, false);
});

test("parses the most recent installed Windows update", () => {
  const state = parseHotFix('{"HotFixID":"KB5041585","InstalledOn":"2026-11-01"}');
  assert.equal(state.known, true);
  assert.equal(state.id, "KB5041585");
  assert.equal(state.installedOn.toISOString(), "2026-11-01T00:00:00.000Z");

  assert.equal(parseHotFix('{"HotFixID":"KB1"}').installedOn, null);
  assert.equal(parseHotFix("").known, false);
});

test("cleans the Windows product caption", () => {
  assert.equal(
    parseWindowsCaption('{"Caption":"Microsoft Windows 11 Pro","Version":"10.0.22631"}'),
    "Windows 11 Pro"
  );
  assert.equal(parseWindowsCaption('{"Caption":"Microsoft Windows 10 Enterprise Insider Preview"}'), "Windows 10 Enterprise");
  assert.equal(parseWindowsCaption("{}"), "");
});

test("unverified Windows checks never change the score", () => {
  const summary = scoreFindings([
    { status: "pass", severity: "info" },
    { status: "unknown", severity: "high" },
    { status: "fail", severity: "medium" }
  ]);

  assert.equal(summary.score, 90);
  assert.equal(summary.unverified, 1);
  assert.equal(summary.attention, 1);
});
