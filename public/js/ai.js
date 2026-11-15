import { api, getAiConfig } from "./api.js";

function requireConfig() {
  const config = getAiConfig();

  if (!config.baseUrl || !config.model) {
    throw new Error("Connect an AI endpoint in Settings first.");
  }

  return config;
}

export async function testAiConnection(config = getAiConfig()) {
  return api("/api/ai/test", { method: "POST", body: config });
}

export async function explainThreat(scanId, threatId) {
  return api("/api/ai/explain", {
    method: "POST",
    body: { ...requireConfig(), scanId, threatId }
  });
}

export async function summarizeProtection() {
  return api("/api/ai/summary", {
    method: "POST",
    body: requireConfig()
  });
}
