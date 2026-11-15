"use strict";

const assert = require("node:assert/strict");
const http = require("node:http");
const test = require("node:test");

const {
  DISCLAIMER,
  chatCompletionsUrl,
  complete,
  normalizeBaseUrl,
  normalizeConfig
} = require("../src/ai");

const canFetch = typeof fetch === "function";

function serve(handler) {
  return new Promise(resolve => {
    const server = http.createServer(handler);

    server.listen(0, "127.0.0.1", () => {
      resolve({ server, origin: `http://127.0.0.1:${server.address().port}` });
    });
  });
}

test("requires HTTPS except for localhost endpoints", () => {
  assert.equal(normalizeBaseUrl("https://api.example.com/v1/"), "https://api.example.com/v1");
  assert.equal(normalizeBaseUrl("http://localhost:11434/v1"), "http://localhost:11434/v1");
  assert.equal(normalizeBaseUrl("http://127.0.0.1:8080/v1"), "http://127.0.0.1:8080/v1");

  assert.throws(() => normalizeBaseUrl("http://api.example.com/v1"), /HTTPS/);
  assert.throws(() => normalizeBaseUrl("ftp://api.example.com"), /HTTPS/);
  assert.throws(() => normalizeBaseUrl(""), /Enter an AI endpoint/);
  assert.throws(() => normalizeBaseUrl("not a url"), /valid URL/);
});

test("appends the chat completions path once", () => {
  assert.equal(
    chatCompletionsUrl("https://api.example.com/v1"),
    "https://api.example.com/v1/chat/completions"
  );
  assert.equal(
    chatCompletionsUrl("https://api.example.com/v1/chat/completions"),
    "https://api.example.com/v1/chat/completions"
  );
});

test("requires a model name", () => {
  assert.throws(() => normalizeConfig({ baseUrl: "https://api.example.com/v1" }), /model/);

  const config = normalizeConfig({
    baseUrl: "https://api.example.com/v1",
    model: "  gpt-test  ",
    apiKey: "  secret  "
  });

  assert.equal(config.model, "gpt-test");
  assert.equal(config.apiKey, "secret");
});

test("sends an OpenAI-compatible request and returns the reply", { skip: !canFetch }, async () => {
  let captured = null;
  const { server, origin } = await serve((req, res) => {
    let body = "";
    req.on("data", chunk => (body += chunk));
    req.on("end", () => {
      captured = { url: req.url, headers: req.headers, body: JSON.parse(body) };
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        model: "test-model",
        choices: [{ message: { content: "This file looks like a test marker." } }]
      }));
    });
  });

  try {
    const config = normalizeConfig({ baseUrl: `${origin}/v1`, model: "test-model", apiKey: "k-123" });
    const result = await complete(config, [{ role: "user", content: "hello" }]);

    assert.equal(result.reply, "This file looks like a test marker.");
    assert.equal(result.model, "test-model");
    assert.equal(captured.url, "/v1/chat/completions");
    assert.equal(captured.body.model, "test-model");
    assert.equal(captured.headers.authorization, "Bearer k-123");
    assert.equal(captured.body.messages[0].content, "hello");
  } finally {
    server.close();
  }
});

test("maps provider errors to a readable message", { skip: !canFetch }, async () => {
  const { server, origin } = await serve((_req, res) => {
    res.writeHead(401, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: { message: "bad key" } }));
  });

  try {
    const config = normalizeConfig({ baseUrl: `${origin}/v1`, model: "test-model", apiKey: "wrong" });

    await assert.rejects(
      () => complete(config, [{ role: "user", content: "hello" }]),
      error => error.statusCode === 502 && /rejected the API key/.test(error.message)
    );
  } finally {
    server.close();
  }
});

test("states that AI never decides a detection", () => {
  assert.match(DISCLAIMER, /decides detections locally/i);
  assert.match(DISCLAIMER, /cannot change results/i);
});
