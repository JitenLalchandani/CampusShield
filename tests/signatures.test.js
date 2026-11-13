"use strict";

const assert = require("node:assert/strict");
const http = require("node:http");
const test = require("node:test");

const { loadSignatures, refreshSignaturesFromUrl } = require("../src/scanner/signatures");

const NEW_HASH = "b".repeat(64);

function serve(body, status = 200) {
  return new Promise(resolve => {
    const server = http.createServer((_req, res) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(body);
    });

    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ server, url: `http://127.0.0.1:${port}/feed.json` });
    });
  });
}

test("merges a remote feed into the built-in signature set", async () => {
  const signatures = loadSignatures();
  const before = signatures.count;
  const { server, url } = await serve(
    JSON.stringify({
      version: "campus-2026.11",
      entries: [{ sha256: NEW_HASH, name: "Campus test hash", severity: "high" }]
    })
  );

  try {
    const result = await refreshSignaturesFromUrl(signatures, url);

    assert.equal(result.added, 1);
    assert.equal(signatures.count, before + 1);
    assert.ok(signatures.byHash.has(NEW_HASH));
    assert.match(signatures.version, /campus-2026\.11$/);

    const again = await refreshSignaturesFromUrl(signatures, url);
    assert.equal(again.added, 0);
    assert.equal(signatures.count, before + 1);
  } finally {
    server.close();
  }
});

test("rejects a feed without an entries array", async () => {
  const signatures = loadSignatures();
  const { server, url } = await serve('{"version":"bad","entries":"nope"}');

  try {
    await assert.rejects(() => refreshSignaturesFromUrl(signatures, url), /entries array/);
  } finally {
    server.close();
  }
});

test("rejects non-local plain HTTP feeds", async () => {
  const signatures = loadSignatures();

  await assert.rejects(
    () => refreshSignaturesFromUrl(signatures, "http://example.com/feed.json"),
    /HTTPS/
  );
});

test("surfaces a non-200 feed response", async () => {
  const signatures = loadSignatures();
  const { server, url } = await serve("{}", 503);

  try {
    await assert.rejects(() => refreshSignaturesFromUrl(signatures, url), /HTTP 503/);
  } finally {
    server.close();
  }
});
