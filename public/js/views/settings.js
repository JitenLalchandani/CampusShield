import {
  api,
  getAiConfig,
  getApiBase,
  getApiToken,
  getSettings,
  isDesktopShell,
  isNativeShell,
  isStandalone,
  saveSettings,
  setAiConfig,
  setApiBase,
  setApiToken
} from "../api.js";
import { testAiConnection } from "../ai.js";
import { dateTime, esc, icon, toast } from "../ui.js";

export const meta = {
  eyebrow: "Configure",
  title: "Settings",
  subtitle: "Connection, preferences, and local data controls."
};

let deferredPrompt = null;

window.addEventListener("beforeinstallprompt", event => {
  event.preventDefault();
  deferredPrompt = event;
});

export async function render(root) {
  const health = await api("/api/health").catch(() => null);
  const summary = await api("/api/summary").catch(() => null);
  const scanner = await api("/api/scanner").catch(() => null);
  const settings = getSettings();
  const ai = getAiConfig();
  const base = getApiBase();
  const token = getApiToken();
  const native = isNativeShell();
  const desktop = isDesktopShell();
  const installed = isStandalone();
  const prefs = scanner?.preferences || {
    realtime: false,
    notify: true,
    exclusions: [],
    schedule: { enabled: false, scope: "quick", frequency: "daily", weekday: 1, time: "09:00" }
  };
  const schedule = prefs.schedule || {};

  root.innerHTML = `
    <div class="settings-grid">
      <div class="stack">
        <section class="card">
          <div class="card-head">
            <div>
              <h2>API connection</h2>
              <p>Where the app reads events from</p>
            </div>
            <span class="chip">${health ? "Reachable" : "Unreachable"}</span>
          </div>

          <label class="field">
            <span>API base URL</span>
            <input class="input" id="apiBaseInput" type="url" inputmode="url"
              placeholder="Same origin (default)"
              value="${esc(base)}" autocomplete="off" spellcheck="false">
          </label>

          <label class="field" style="margin-top:12px">
            <span>API access token</span>
            <input class="input" id="apiTokenInput" type="password" autocomplete="off" spellcheck="false"
              placeholder="${health?.authRequired ? "Required by this server" : "Not required by this server"}"
              value="${esc(token)}">
          </label>

          <div class="form-row" style="margin-top:10px">
            <button class="btn primary" id="saveApi" type="button">Save &amp; test</button>
            <button class="btn subtle" id="resetApi" type="button">Use same origin</button>
          </div>

          <p class="helper" id="apiTestResult"></p>
          <p class="helper">
            Leave the URL blank when the web app is served by the same Express
            server. Native shells and remote deployments need the full URL.
            On a phone sharing this Mac's Wi-Fi, use
            <span class="mono">http://&lt;mac-ip&gt;:3000</span>.
            A token is only needed when the server sets
            <span class="mono">CAMPUSSHIELD_API_TOKEN</span> or
            <span class="mono">CAMPUSSHIELD_VIEW_TOKEN</span>.
          </p>
          ${health?.authRequired && !token
            ? `<p class="warning-note">This server requires a token. Other pages stay empty until you save one here.</p>`
            : ""}
          ${native
            ? `<p class="warning-note">Native shell detected. Use an HTTPS API in production — mobile operating systems block cleartext traffic by default.</p>`
            : ""}
        </section>

        <section class="card">
          <div class="card-head">
            <div>
              <h2>Protection</h2>
              <p>Real-time watch, scheduled scans, and exclusions</p>
            </div>
            <span class="chip">${scanner?.watch?.enabled ? "Real-time on" : "Real-time off"}</span>
          </div>

          ${scanner ? "" : `<p class="warning-note">Protection settings need a reachable API. Check the connection above.</p>`}

          <label class="switch">
            <input type="checkbox" id="prefRealtime" ${prefs.realtime ? "checked" : ""}
              ${scanner?.watchSupported ? "" : "disabled"}>
            <span>Real-time folder watch${scanner?.watchSupported ? "" : " (macOS and Windows only)"}</span>
          </label>

          <label class="switch" style="margin-top:10px">
            <input type="checkbox" id="prefNotify" ${prefs.notify ? "checked" : ""}>
            <span>Desktop notification for each new threat</span>
          </label>

          <p class="helper" style="margin:10px 0 0">Protection settings live on the server, so every device that connects to this workspace sees the same schedule and exclusions.</p>

          <div class="divider"></div>

          <label class="switch">
            <input type="checkbox" id="scheduleEnabled" ${schedule.enabled ? "checked" : ""} ${scanner ? "" : "disabled"}>
            <span>Scheduled scan</span>
          </label>

          <div class="form-row" style="margin-top:12px">
            <label class="field" style="max-width:170px">
              <span>Scope</span>
              <select class="select" id="scheduleScope" ${scanner ? "" : "disabled"}>
                <option value="quick" ${schedule.scope === "quick" ? "selected" : ""}>Quick scan</option>
                <option value="full" ${schedule.scope === "full" ? "selected" : ""}>Full scan</option>
              </select>
            </label>
            <label class="field" style="max-width:150px">
              <span>Frequency</span>
              <select class="select" id="scheduleFrequency" ${scanner ? "" : "disabled"}>
                <option value="daily" ${schedule.frequency === "daily" ? "selected" : ""}>Daily</option>
                <option value="weekly" ${schedule.frequency === "weekly" ? "selected" : ""}>Weekly</option>
              </select>
            </label>
            <label class="field" style="max-width:130px">
              <span>Time</span>
              <input class="input" id="scheduleTime" type="time" value="${esc(schedule.time || "09:00")}" ${scanner ? "" : "disabled"}>
            </label>
            <label class="field" id="weekdayField" style="max-width:150px" ${schedule.frequency === "weekly" ? "" : "hidden"}>
              <span>Day</span>
              <select class="select" id="scheduleWeekday" ${scanner ? "" : "disabled"}>
                ${["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"].map((day, index) => `
                  <option value="${index}" ${Number(schedule.weekday) === index ? "selected" : ""}>${day}</option>
                `).join("")}
              </select>
            </label>
          </div>

          <p class="helper" id="scheduleNext">
            ${scanner?.scheduleNextRunAt && schedule.enabled
              ? `Next run: ${esc(dateTime(scanner.scheduleNextRunAt))}.`
              : "No automatic scan is scheduled."}
            Scheduled scans start only while CampusShield is running.
          </p>

          <div class="divider"></div>

          <label class="field">
            <span>Excluded folders and files</span>
            <textarea class="input" id="exclusionsInput" rows="3" spellcheck="false"
              style="min-height:84px;resize:vertical"
              placeholder="/Users/you/Projects/vendor">${esc((prefs.exclusions || []).join("\n"))}</textarea>
          </label>
          <p class="helper">One absolute path per line. Quick and full scans and the real-time watch skip these paths. A manual folder scan still checks them.</p>

          <div class="form-row">
            <button class="btn primary" id="saveProtection" type="button" ${scanner ? "" : "disabled"}>Save protection</button>
            <button class="btn subtle" id="updateSignatures" type="button" ${scanner?.remoteFeed?.url ? "" : "disabled"}
              title="${scanner?.remoteFeed?.url ? "Download new hashes from the configured feed" : "Set CAMPUSSHIELD_SIGNATURES_URL and restart to enable feed updates"}">
              Update signatures
            </button>
          </div>
          <p class="helper" id="protectionResult"></p>
          <p class="helper">
            Signatures ${esc(scanner?.signatureVersion || "unknown")} · ${Number(scanner?.signatureCount || 0)} hash${Number(scanner?.signatureCount || 0) === 1 ? "" : "es"}.
            ${scanner?.remoteFeed?.url
              ? `Feed ${esc(scanner.remoteFeed.url)}: ${esc(scanner.remoteFeed.state || "off")}${scanner.remoteFeed.checkedAt ? ` · checked ${esc(dateTime(scanner.remoteFeed.checkedAt))}` : ""}.`
              : "No remote feed configured; only built-in hashes are loaded."}
          </p>
        </section>

        <section class="card">
          <div class="card-head">
            <div>
              <h2>Preferences</h2>
              <p>Stored in this browser or app shell</p>
            </div>
          </div>

          <label class="switch">
            <input type="checkbox" id="autoRefresh" ${settings.autoRefresh ? "checked" : ""}>
            <span>Auto-refresh the protection view</span>
          </label>

          <div class="field" style="margin-top:14px;max-width:260px">
            <span>Refresh interval</span>
            <select class="select" id="refreshSeconds" ${settings.autoRefresh ? "" : "disabled"}>
              ${[15, 30, 60, 120].map(seconds => `
                <option value="${seconds}" ${settings.refreshSeconds === seconds ? "selected" : ""}>Every ${seconds} seconds</option>
              `).join("")}
            </select>
          </div>
        </section>

        <section class="card">
          <div class="card-head">
            <div>
              <h2>Install</h2>
              <p>Add CampusShield to this device</p>
            </div>
          </div>
          <p class="helper" style="margin-top:0">
            ${desktop
              ? "This is the CampusShield desktop app. It runs a local server and stores its workspace in the app's data folder."
              : installed
                ? "Running as an installed app. Launch it from your home screen, app folder, or Dock."
                : native
                  ? "You are inside the native shell. Use the iOS or Android project to build a store-ready binary."
                  : "Install CampusShield as a standalone app. On iOS use Share → Add to Home Screen."}
          </p>
          ${installed || desktop ? "" : `<button class="btn ghost" id="installBtn" type="button">Install app</button>`}
        </section>
      </div>

      <div class="stack">
        <section class="card">
          <div class="card-head">
            <div>
              <h2>Workspace</h2>
              <p>What the server reports right now</p>
            </div>
          </div>
          <dl class="kv">
            <dt>API status</dt><dd>${health ? "Online" : "Unreachable"}</dd>
            <dt>Storage</dt><dd>${esc(health?.storage || "—")}</dd>
            <dt>Data source</dt><dd>${esc(summary?.dataSource || health?.dataSource || "—")}</dd>
            <dt>Platform</dt><dd>${esc(health?.platform || "unknown")}</dd>
            <dt>Version</dt><dd>${esc(health?.version || "—")}</dd>
            <dt>Events</dt><dd>${esc(summary?.eventsTotal ?? "—")}</dd>
            <dt>Devices</dt><dd>${esc(summary?.devicesReporting ?? "—")}</dd>
            <dt>Audit entries</dt><dd>${esc(summary?.auditTotal ?? "—")}</dd>
          </dl>
        </section>

        <section class="card">
          <div class="card-head">
            <div>
              <h2>AI assistant</h2>
              <p>Optional, bring your own key</p>
            </div>
            <span class="chip">${ai.baseUrl && ai.model ? "Configured" : "Not configured"}</span>
          </div>

          <label class="field">
            <span>API base URL</span>
            <input class="input" id="aiBaseInput" type="url" inputmode="url" autocomplete="off"
              spellcheck="false" placeholder="https://api.openai.com/v1" value="${esc(ai.baseUrl)}">
          </label>

          <label class="field" style="margin-top:12px">
            <span>Model</span>
            <input class="input" id="aiModelInput" type="text" autocomplete="off" spellcheck="false"
              placeholder="gpt-4o-mini" value="${esc(ai.model)}">
          </label>

          <label class="field" style="margin-top:12px">
            <span>API key</span>
            <input class="input" id="aiKeyInput" type="password" autocomplete="off" spellcheck="false"
              placeholder="Stored only in this browser" value="${esc(ai.apiKey)}">
          </label>

          <div class="form-row" style="margin-top:10px">
            <button class="btn primary" id="saveAi" type="button">Save</button>
            <button class="btn subtle" id="testAi" type="button">Test connection</button>
            <button class="btn ghost" id="clearAi" type="button">Remove</button>
          </div>

          <p class="helper" id="aiResult"></p>
          <p class="helper">
            Works with any OpenAI-compatible <span class="mono">/chat/completions</span> endpoint,
            including a local Ollama at <span class="mono">http://localhost:11434/v1</span>.
            Remote endpoints must use HTTPS. The key stays in this browser and is sent with each
            request through the local server; it is never stored on the server.
            Detection stays local — the assistant only explains results and cannot change them.
          </p>
        </section>

        <section class="card">
          <div class="card-head">
            <div>
              <h2>Data controls</h2>
              <p>Export or remove everything held for this workspace</p>
            </div>
          </div>
          <div class="form-row">
            <button class="btn ghost" id="exportData" type="button">
              ${icon("download")} Export JSON
            </button>
            <button class="btn danger" id="clearData" type="button">
              ${icon("trash")} Clear all data
            </button>
          </div>
          <p class="warning-note">
            Clearing deletes events, decisions, linked devices, scan history,
            quarantined files, and audit history from the configured store. In
            MongoDB Atlas this affects the connected database.
          </p>
        </section>

        <section class="card">
          <div class="card-head">
            <div>
              <h2>About this build</h2>
              <p>CampusShield 1.0</p>
            </div>
          </div>
          <ul class="checklist">
            <li>${icon("info")}<span>Telemetry is limited to approved or locally scanned events; nothing is fabricated.</span></li>
            <li>${icon("info")}<span>Detection is rule-based and illustrative, not a validated engine.</span></li>
            <li>${icon("info")}<span>API access is open by default. Set CAMPUSSHIELD_API_TOKEN for full access and CAMPUSSHIELD_VIEW_TOKEN for a read-only token.</span></li>
            <li>${icon("info")}<span>Containment records a decision only; it does not change any real system.</span></li>
            <li>${icon("info")}<span>Device checks are read-only and run on macOS and Windows hosts. The file scanner uses a small local signature set plus heuristics and cannot block execution; see Protection for what it found.</span></li>
            <li>${icon("info")}<span>Protection settings (real-time watch, scheduled scans, exclusions) are stored on this server. Scheduled scans run only while the app is open.</span></li>
            <li>${icon("info")}<span>The AI assistant is optional and uses your own provider key. Only the finding you ask about is sent; the assistant explains results and never changes them.</span></li>
          </ul>
        </section>
      </div>
    </div>
  `;

  bind(root, { settings });
}

function bind(root, { settings }) {
  const baseInput = root.querySelector("#apiBaseInput");
  const tokenInput = root.querySelector("#apiTokenInput");
  const result = root.querySelector("#apiTestResult");

  root.querySelector("#saveApi")?.addEventListener("click", async () => {
    setApiBase(baseInput.value);
    setApiToken(tokenInput.value);
    window.dispatchEvent(new Event("campusshield:api-changed"));
    toast("Connection settings saved.", { type: "success" });
    await testConnection(result);
  });

  root.querySelector("#resetApi")?.addEventListener("click", async () => {
    setApiBase("");
    baseInput.value = "";
    window.dispatchEvent(new Event("campusshield:api-changed"));
    toast("Using the same origin as this page.", { type: "success" });
    await testConnection(result);
  });

  const autoRefresh = root.querySelector("#autoRefresh");
  const interval = root.querySelector("#refreshSeconds");

  autoRefresh?.addEventListener("change", () => {
    saveSettings({ autoRefresh: autoRefresh.checked });
    interval.disabled = !autoRefresh.checked;
    toast("Preferences saved.", { type: "success" });
  });

  interval?.addEventListener("change", () => {
    saveSettings({ refreshSeconds: Number(interval.value) || settings.refreshSeconds });
    toast("Preferences saved.", { type: "success" });
  });

  const weekdayField = root.querySelector("#weekdayField");

  root.querySelector("#scheduleFrequency")?.addEventListener("change", event => {
    if (weekdayField) weekdayField.hidden = event.currentTarget.value !== "weekly";
  });

  root.querySelector("#prefNotify")?.addEventListener("change", async event => {
    if (!event.currentTarget.checked) return;

    if (!("Notification" in window)) {
      toast("This build cannot show desktop notifications.", { type: "info", timeout: 5000 });
      return;
    }

    if (Notification.permission === "default") await Notification.requestPermission();

    if (Notification.permission !== "granted") {
      toast("The operating system is blocking notifications for CampusShield.", {
        type: "error",
        timeout: 6000
      });
    }
  });

  root.querySelector("#saveProtection")?.addEventListener("click", async event => {
    const button = event.currentTarget;
    const result = root.querySelector("#protectionResult");
    const exclusions = String(root.querySelector("#exclusionsInput")?.value || "")
      .split("\n")
      .map(line => line.trim())
      .filter(Boolean);

    const body = {
      realtime: Boolean(root.querySelector("#prefRealtime")?.checked),
      notify: Boolean(root.querySelector("#prefNotify")?.checked),
      exclusions,
      schedule: {
        enabled: Boolean(root.querySelector("#scheduleEnabled")?.checked),
        scope: root.querySelector("#scheduleScope")?.value || "quick",
        frequency: root.querySelector("#scheduleFrequency")?.value || "daily",
        weekday: Number(root.querySelector("#scheduleWeekday")?.value ?? 1),
        time: root.querySelector("#scheduleTime")?.value || "09:00"
      }
    };

    button.disabled = true;
    if (result) {
      result.textContent = "Saving…";
      result.style.color = "var(--faint)";
    }

    try {
      await api("/api/scanner/settings", { method: "PATCH", body });
      toast("Protection settings saved.", { type: "success" });
      await render(root);
    } catch (error) {
      if (result) {
        result.textContent = error.message;
        result.style.color = "var(--red)";
      }
      toast(error.message, { type: "error", timeout: 6000 });
      button.disabled = false;
    }
  });

  root.querySelector("#updateSignatures")?.addEventListener("click", async event => {
    const button = event.currentTarget;
    const result = root.querySelector("#protectionResult");

    button.disabled = true;
    if (result) {
      result.textContent = "Downloading signatures…";
      result.style.color = "var(--faint)";
    }

    try {
      const updated = await api("/api/scanner/signatures/update", { method: "POST" });
      toast(
        `Signature update: ${updated.updated} new hash${updated.updated === 1 ? "" : "es"} · ${updated.signatureCount} loaded.`,
        { type: "success" }
      );
      await render(root);
    } catch (error) {
      if (result) {
        result.textContent = error.message;
        result.style.color = "var(--red)";
      }
      toast(error.message, { type: "error", timeout: 6000 });
      button.disabled = false;
    }
  });

  const aiResult = root.querySelector("#aiResult");
  const aiFields = () => ({
    baseUrl: root.querySelector("#aiBaseInput")?.value || "",
    model: root.querySelector("#aiModelInput")?.value || "",
    apiKey: root.querySelector("#aiKeyInput")?.value || ""
  });

  root.querySelector("#saveAi")?.addEventListener("click", () => {
    setAiConfig(aiFields());
    toast("AI settings saved in this browser.", { type: "success" });
    if (aiResult) {
      aiResult.textContent = "Saved. Use Test connection to check the provider.";
      aiResult.style.color = "var(--faint)";
    }
  });

  root.querySelector("#testAi")?.addEventListener("click", async event => {
    const button = event.currentTarget;
    const config = setAiConfig(aiFields());

    if (!config.baseUrl || !config.model) {
      toast("Enter the endpoint URL and model first.", { type: "error" });
      return;
    }

    button.disabled = true;
    if (aiResult) {
      aiResult.textContent = "Contacting the provider…";
      aiResult.style.color = "var(--faint)";
    }

    try {
      const outcome = await testAiConnection(config);
      if (aiResult) {
        aiResult.textContent = `Connected · ${outcome.model} replied: ${outcome.reply}`;
        aiResult.style.color = "var(--green)";
      }
      toast("AI connection verified.", { type: "success" });
    } catch (error) {
      if (aiResult) {
        aiResult.textContent = error.message;
        aiResult.style.color = "var(--red)";
      }
      toast(error.message, { type: "error", timeout: 7000 });
    } finally {
      button.disabled = false;
    }
  });

  root.querySelector("#clearAi")?.addEventListener("click", async () => {
    setAiConfig({ baseUrl: "", model: "", apiKey: "" });
    toast("AI settings removed from this browser.", { type: "success" });
    await render(root);
  });

  root.querySelector("#installBtn")?.addEventListener("click", async () => {
    if (!deferredPrompt) {
      toast("Use your browser's Install or Add to Home Screen option.", { type: "info", timeout: 5500 });
      return;
    }

    deferredPrompt.prompt();
    await deferredPrompt.userChoice;
    deferredPrompt = null;
  });

  root.querySelector("#exportData")?.addEventListener("click", async event => {
    const button = event.currentTarget;
    button.disabled = true;

    try {
      const payload = await buildExport();
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `campusshield-export-${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 2000);
      toast("Export downloaded.", { type: "success" });
    } catch (error) {
      toast(error.message, { type: "error" });
    } finally {
      button.disabled = false;
    }
  });

  root.querySelector("#clearData")?.addEventListener("click", async event => {
    const confirmed = window.confirm(
      "Delete all events, decisions, linked devices, and audit history? This cannot be undone."
    );

    if (!confirmed) return;

    const button = event.currentTarget;
    button.disabled = true;

    try {
      const data = await api("/api/events", { method: "DELETE" });
      toast(
        `Cleared ${data.deletedEvents} events, ${data.deletedActions} decisions, and ${data.deletedDevices} devices.`,
        { type: "success" }
      );
      window.dispatchEvent(new Event("campusshield:data-changed"));
    } catch (error) {
      toast(error.message, { type: "error" });
      button.disabled = false;
    }
  });
}

async function testConnection(result) {
  if (!result) return false;

  result.textContent = "Testing connection…";
  result.style.color = "var(--faint)";

  try {
    const [health] = await Promise.all([api("/api/health"), api("/api/summary")]);
    const tokenNote = health.authRequired ? " · token accepted" : "";
    result.textContent = `Connected · ${health.storage} · ${health.platform} · v${health.version}${tokenNote}`;
    result.style.color = "var(--green)";
    toast("API connection verified.", { type: "success" });
    return true;
  } catch (error) {
    result.textContent = error.message;
    result.style.color = "var(--red)";
    toast("Connection failed. Check the URL and that the server is running.", { type: "error" });
    return false;
  }
}

async function buildExport() {
  const payload = {
    exportedAt: new Date().toISOString(),
    app: "CampusShield",
    events: [],
    activity: [],
    devices: []
  };

  await collectPages(
    offset => api(`/api/events?limit=200&offset=${offset}`),
    data => data.events,
    payload.events
  );

  await collectPages(
    offset => api(`/api/activity?limit=200&offset=${offset}`),
    data => data.activity,
    payload.activity
  );

  const protection = await api("/api/protection").catch(() => null);
  payload.devices = Array.isArray(protection?.devices) ? protection.devices : [];

  return payload;
}

async function collectPages(fetchPage, select, target) {
  let offset = 0;
  let total = 1;
  let guard = 0;

  while (offset < total && guard < 20) {
    const data = await fetchPage(offset);
    const rows = select(data) || [];

    target.push(...rows);
    total = Number(data.total) || 0;
    offset += rows.length;
    guard += 1;

    if (!rows.length) break;
  }
}
