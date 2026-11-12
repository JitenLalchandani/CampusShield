import {
  api,
  getApiBase,
  getSettings,
  isDesktopShell,
  isNativeShell,
  isStandalone,
  saveSettings,
  setApiBase
} from "../api.js";
import { esc, icon, toast } from "../ui.js";

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
  const settings = getSettings();
  const base = getApiBase();
  const native = isNativeShell();
  const desktop = isDesktopShell();
  const installed = isStandalone();

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

          <div class="form-row" style="margin-top:10px">
            <button class="btn primary" id="saveApi" type="button">Save &amp; test</button>
            <button class="btn subtle" id="resetApi" type="button">Use same origin</button>
          </div>

          <p class="helper" id="apiTestResult"></p>
          <p class="helper">
            Leave this blank when the web app is served by the same Express
            server. Native shells and remote deployments need the full URL.
            On a phone sharing this Mac's Wi-Fi, use
            <span class="mono">http://&lt;mac-ip&gt;:3000</span>.
          </p>
          ${native
            ? `<p class="warning-note">Native shell detected. Use an HTTPS API in production — mobile operating systems block cleartext traffic by default.</p>`
            : ""}
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
            Clearing deletes events, decisions, linked devices, and audit
            history from the configured store. In MongoDB Atlas this affects the
            connected database.
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
            <li>${icon("info")}<span>There is no authentication or role-based access in this build.</span></li>
            <li>${icon("info")}<span>Containment records a decision only; it does not change any real system.</span></li>
            <li>${icon("info")}<span>Device checks are read-only. CampusShield does not scan for malware or block traffic.</span></li>
          </ul>
        </section>
      </div>
    </div>
  `;

  bind(root, { settings });
}

function bind(root, { settings }) {
  const baseInput = root.querySelector("#apiBaseInput");
  const result = root.querySelector("#apiTestResult");

  root.querySelector("#saveApi")?.addEventListener("click", async () => {
    setApiBase(baseInput.value);
    window.dispatchEvent(new Event("campusshield:api-changed"));
    toast("API URL saved.", { type: "success" });
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
    const health = await api("/api/health");
    result.textContent = `Connected · ${health.storage} · ${health.platform} · v${health.version}`;
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
