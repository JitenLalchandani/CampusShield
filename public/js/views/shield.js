import { api } from "../api.js";
import { dateTime, esc, icon, num, relativeTime, toast } from "../ui.js";

// Ransomware shield UI: the settings card in Protection, the alert drawer, and the app-wide banner.
// Everything shown comes from /api/shield. Nothing is guessed: a missing suspect says so, and
// actions that could not be done say what failed.

const STATUS_LABEL = { open: "Open", contained: "Contained", dismissed: "Dismissed" };

const RECOVERY = {
  darwin: "networksetup -setnetworkserviceenabled \"Wi-Fi\" on",
  win32: "Enable-NetAdapter -Name \"Wi-Fi\" -Confirm:$false   (run PowerShell as Administrator)",
  linux: "nmcli networking on"
};

function shortPath(value) {
  return String(value || "").replace(/^\/(Users|home)\/[^/]+/, "~").replace(/^[A-Za-z]:\\Users\\[^\\]+/, "~");
}

function severityClass(severity) {
  return severity === "critical" || severity === "high" ? "high" : "medium";
}

function evidenceLine(evidence = {}) {
  const parts = [`${num(evidence.filesTouched)} files changed in ${num(evidence.windowSec)}s`];

  if (evidence.extChanged) parts.push(`${num(evidence.extChanged)} with an extension new to this folder`);
  if (evidence.highEntropy) parts.push(`${num(evidence.highEntropy)} text files that now look encrypted`);

  return parts.join(" · ");
}

// ---- Protection card ------------------------------------------------------------------------------

export function renderShieldCard(status, alerts) {
  if (!status) {
    return `
      <section class="card protect-section shield-card" id="shieldCard">
        <div class="card-head"><div><h2>Ransomware shield</h2><p>Not available</p></div><span class="chip">Unavailable</span></div>
        <p class="helper">The shield state could not be loaded. Sign in again or check the server.</p>
      </section>`;
  }

  const open = alerts.filter(alert => alert.status === "open");
  const recent = alerts.filter(alert => alert.status !== "open").slice(0, 3);
  const state = !status.supported ? "Unsupported" : !status.enabled ? "Off" : status.running ? "Watching" : "Not running";
  const tone = !status.supported ? "idle" : status.running ? "ok" : status.enabled ? "warn" : "idle";

  const folders = status.folders
    .map(folder => {
      const failed = status.failedFolders.find(item => item.folder === folder);
      const live = status.watching.includes(folder);

      return `<li class="shield-folder" data-state="${failed ? "failed" : live ? "live" : "idle"}">
        <span class="shield-dot" aria-hidden="true"></span>
        <code>${esc(shortPath(folder))}</code>
        <span class="helper">${failed ? esc(failed.message) : live ? "Watching" : status.enabled ? "Not watched" : "Not watching"}</span>
      </li>`;
    })
    .join("");

  const alertRows = [...open, ...recent]
    .map(
      alert => `<li>
        <button class="shield-alert-row" type="button" data-shield-alert="${esc(alert.id)}">
          <span class="sev ${severityClass(alert.severity)}">${esc(alert.severity)}</span>
          <span class="shield-alert-main">
            <strong>${esc(shortPath(alert.folder))}</strong>
            <span class="helper">${esc(evidenceLine(alert.evidence))}</span>
          </span>
          <span class="chip" data-status="${esc(alert.status)}">${esc(STATUS_LABEL[alert.status] || alert.status)}</span>
          <span class="helper">${esc(relativeTime(alert.updatedAt || alert.startedAt))}</span>
        </button>
      </li>`
    )
    .join("");

  const t = status.thresholds;

  return `
    <section class="card protect-section shield-card" id="shieldCard">
      <div class="card-head">
        <div>
          <h2>Ransomware shield</h2>
          <p>Flags mass file encryption in the folders you choose</p>
        </div>
        <span class="chip" data-tone="${tone}">${state}</span>
      </div>

      ${status.error ? `<div class="scan-warning">${icon("alert")} <span>${esc(status.error)}</span></div>` : ""}
      ${status.notes.map(note => `<p class="helper">${esc(note)}</p>`).join("")}

      <label class="switch-row">
        <span><strong>Watch my folders</strong><span class="helper">Off by default. Nothing is watched until you turn this on.</span></span>
        <span class="switch"><input type="checkbox" id="shieldEnabled" ${status.enabled ? "checked" : ""} ${status.supported ? "" : "disabled"} aria-label="Turn the ransomware shield on"></span>
      </label>

      <ul class="shield-folders">${folders || `<li class="helper">No folders chosen.</li>`}</ul>

      <details class="shield-details">
        <summary>Rules and limits</summary>
        <p class="helper">An alert needs at least <strong>${num(t.minFiles)}</strong> files changed within <strong>${num(t.windowSec)} seconds</strong> in one folder, with at least <strong>${num(t.minSignalPct)}%</strong> showing a sign of encryption: a new file extension, or a text file whose contents now look random.</p>
        <ul class="checklist">${status.limits.map(line => `<li>${icon("info")}<span>${esc(line)}</span></li>`).join("")}</ul>
        <label class="switch-row">
          <span><strong>Allow Contain from another device</strong><span class="helper">Stopping a program can be approved remotely. Turning the network off always needs approval on this computer.</span></span>
          <span class="switch"><input type="checkbox" id="shieldRemote" ${status.allowRemoteContain ? "checked" : ""} aria-label="Allow remote Contain"></span>
        </label>
      </details>

      ${
        alertRows
          ? `<h3 class="shield-sub">Alerts</h3><ul class="shield-alerts">${alertRows}</ul>`
          : `<p class="helper shield-none">${status.enabled ? "No alerts. The shield has not seen mass encryption." : "No alerts recorded."}</p>`
      }
    </section>`;
}

export function bindShieldCard(root, refresh) {
  root.querySelector("#shieldEnabled")?.addEventListener("change", async event => {
    const box = event.currentTarget;
    box.disabled = true;

    try {
      await api("/api/shield/settings", { method: "PATCH", body: { enabled: box.checked } });
      toast(box.checked ? "Ransomware shield is on." : "Ransomware shield is off.", { type: "success" });
    } catch (error) {
      toast(error.message, { type: "error" });
    }

    refresh();
  });

  root.querySelector("#shieldRemote")?.addEventListener("change", async event => {
    try {
      await api("/api/shield/settings", { method: "PATCH", body: { allowRemoteContain: event.currentTarget.checked } });
    } catch (error) {
      toast(error.message, { type: "error" });
    }

    refresh();
  });

  root.querySelectorAll("[data-shield-alert]").forEach(button => {
    button.addEventListener("click", () => openShieldAlert(button.dataset.shieldAlert, refresh));
  });
}

// ---- Alert drawer ---------------------------------------------------------------------------------

let drawerCleanup = null;

export function closeShieldAlert() {
  drawerCleanup?.();
  drawerCleanup = null;
}

function actionResultLine(result) {
  const tone = result.ok ? "ok" : result.pending ? "idle" : "warn";
  const label = result.type === "stop-suspect" ? "Stop program" : "Turn off network";

  return `<li data-tone="${tone}"><strong>${label}:</strong> ${esc(result.message || (result.ok ? "Done." : "Not done."))}</li>`;
}

function drawerBody(alert, token, results = []) {
  const suspect = alert.suspect;
  const open = alert.status === "open";
  const canAct = alert.status !== "dismissed" && Boolean(token);
  const interfaces = (alert.actions || []).filter(action => action.type === "isolate-network").flatMap(action => action.interfaces || []);
  const recovery = RECOVERY[navigator.platform?.toLowerCase().includes("win") ? "win32" : navigator.platform?.toLowerCase().includes("mac") ? "darwin" : "linux"];

  return `
    <section class="drawer-section">
      <h3>What was seen</h3>
      <p>${esc(evidenceLine(alert.evidence))} in <code>${esc(shortPath(alert.folder))}</code>.</p>
      <p class="helper">Started ${esc(dateTime(alert.startedAt))}. Confidence: ${esc(alert.confidence)}. ${alert.confidence === "high" ? "Most changed files carry an extension never seen in this folder." : "Based on file contents only, with no new extensions."}</p>
      ${alert.evidence?.newExtensions?.length ? `<p class="helper">New extensions: ${alert.evidence.newExtensions.map(item => `<code>${esc(item.ext)}</code> × ${num(item.count)}`).join(", ")}</p>` : ""}
      ${alert.evidence?.samples?.length ? `<details class="shield-details"><summary>Example files (${num(alert.evidence.samples.length)})</summary><ul class="shield-samples">${alert.evidence.samples.map(file => `<li><code>${esc(file)}</code></li>`).join("")}</ul></details>` : ""}
    </section>

    <section class="drawer-section">
      <h3>Suspect program</h3>
      ${
        suspect
          ? `<p><strong>${esc(suspect.name)}</strong> (PID ${num(suspect.pid)}) held ${num(suspect.filesHeld)} files open in this folder, ${num(suspect.sharePct)}% of all open files there.</p>
             <p class="helper">This is a best guess from ${esc(suspect.method || "open-file sampling")}. It could be the wrong program. Confidence: ${esc(suspect.confidence)}.</p>`
          : `<p>No suspect identified.</p><p class="helper">${esc(alert.suspectNote || "Looking for the program that holds these files open…")}</p>`
      }
    </section>

    ${
      alert.pendingApproval?.includes("isolate-network")
        ? `<div class="scan-warning">${icon("alert")} <span><strong>Waiting for approval on the protected computer.</strong> Turning the network off needs an administrator prompt there.</span></div>`
        : ""
    }

    ${
      alert.isolationActive
        ? `<section class="drawer-section shield-isolated">
             <h3>Network is off</h3>
             <ul class="shield-results">${interfaces.map(item => `<li data-tone="${item.ok && !item.restoredAt ? "warn" : "ok"}"><strong>${esc(item.name)}:</strong> ${item.restoredAt ? "Connected again" : item.ok ? "Turned off" : esc(item.message || "Not changed")}</li>`).join("")}</ul>
             <p class="helper">${alert.restoreAt ? `Restores automatically ${alert.restoreDue ? "now" : esc(relativeTime(alert.restoreAt))} (${esc(dateTime(alert.restoreAt))}).` : "Automatic restore is off. Restore the network yourself."}</p>
             <div class="drawer-actions">
               <button class="btn primary" type="button" data-shield-undo>Restore network</button>
               ${alert.restoreAt ? `<button class="btn ghost" type="button" data-shield-keep>Keep isolated</button>` : ""}
             </div>
             <details class="shield-details"><summary>If the button does not work</summary><p class="helper">Run this yourself:</p><pre class="shield-code">${esc(recovery)}</pre></details>
           </section>`
        : ""
    }

    ${results.length ? `<ul class="shield-results">${results.map(actionResultLine).join("")}</ul>` : ""}

    ${
      canAct && alert.status !== "dismissed"
        ? `<section class="drawer-section" id="shieldActs">
             <h3>${open ? "Contain" : "Contain again"}</h3>
             <label class="check-row"><input type="checkbox" data-shield-act="stop-suspect" ${suspect ? "checked" : "disabled"}> <span>Stop the suspect program${suspect ? "" : " (none found)"}</span></label>
             <label class="check-row"><input type="checkbox" data-shield-act="isolate-network" checked> <span>Turn off network connections</span></label>
             <p class="helper">Turning the network off stops a program from sending files away, and also stops you. Connections you turn off come back automatically after the restore time, or when you press Restore.</p>
             <div class="drawer-actions">
               <button class="btn danger" type="button" data-shield-contain>Contain</button>
             </div>
           </section>`
        : ""
    }

    ${
      open
        ? `<section class="drawer-section">
             <h3>Not ransomware?</h3>
             <label class="field"><span>Ignore this folder for</span>
               <select class="select" id="shieldIgnore"><option value="0">Do not ignore</option><option value="1">1 hour</option><option value="24">24 hours</option><option value="168">7 days</option></select>
             </label>
             <div class="drawer-actions"><button class="btn ghost" type="button" data-shield-dismiss>Dismiss as false alarm</button></div>
           </section>`
        : ""
    }
  `;
}

export async function openShieldAlert(id, onChange = () => {}) {
  closeShieldAlert();

  const root = document.getElementById("drawerRoot");
  if (!root) return;

  const backdrop = document.createElement("div");
  backdrop.className = "drawer-backdrop";
  backdrop.innerHTML = `
    <aside class="drawer" role="dialog" aria-modal="true" aria-label="Ransomware alert" tabindex="-1">
      <div class="drawer-head">
        <div><p class="eyebrow" style="margin:0">Ransomware shield</p><h2>Loading alert…</h2></div>
        <button class="icon-btn" type="button" data-close aria-label="Close details">${icon("x")}</button>
      </div>
      <div class="drawer-body"><div class="drawer-loading"><div class="skeleton"></div><div class="skeleton"></div></div></div>
    </aside>`;

  root.appendChild(backdrop);
  document.body.style.overflow = "hidden";

  const onKey = event => {
    if (event.key === "Escape") closeShieldAlert();
  };

  document.addEventListener("keydown", onKey);

  drawerCleanup = () => {
    document.removeEventListener("keydown", onKey);
    backdrop.remove();
    document.body.style.overflow = "";
    onChange();
  };

  backdrop.addEventListener("click", event => {
    if (event.target === backdrop || event.target.closest("[data-close]")) closeShieldAlert();
  });

  const drawer = backdrop.querySelector(".drawer");
  const body = backdrop.querySelector(".drawer-body");
  const title = backdrop.querySelector("h2");
  let token = null;

  async function load(results = []) {
    try {
      const data = await api(`/api/shield/alerts/${encodeURIComponent(id)}`);
      token = data.confirmToken || null;
      const alert = data.alert;

      title.textContent = `${shortPath(alert.folder)} · ${STATUS_LABEL[alert.status] || alert.status}`;
      body.innerHTML = drawerBody(alert, token, results);
      drawer.focus();
    } catch (error) {
      body.innerHTML = `<p class="helper">${esc(error.message)}</p>`;
    }
  }

  async function run(button, task) {
    button.disabled = true;

    try {
      await task();
    } catch (error) {
      toast(error.message, { type: "error" });
      await load();
    } finally {
      button.disabled = false;
    }
  }

  body.addEventListener("click", event => {
    const button = event.target.closest("button");
    if (!button) return;

    if (button.matches("[data-shield-contain]")) {
      const actions = [...body.querySelectorAll("[data-shield-act]:checked")].map(box => box.dataset.shieldAct);
      if (!actions.length) return toast("Choose at least one action.", { type: "error" });

      if (!window.confirm(`Contain now?\n\n${actions.includes("stop-suspect") ? "• Stop the suspect program\n" : ""}${actions.includes("isolate-network") ? "• Turn off network connections\n" : ""}`)) return;

      run(button, async () => {
        const data = await api(`/api/shield/alerts/${encodeURIComponent(id)}/contain`, {
          method: "POST",
          body: { actions, confirm: true, confirmToken: token }
        });

        await load(data.results || []);
      });
    }

    if (button.matches("[data-shield-undo]")) {
      run(button, async () => {
        const data = await api(`/api/shield/alerts/${encodeURIComponent(id)}/undo`, { method: "POST", body: {} });
        await load([{ type: "isolate-network", ok: data.result.ok, message: data.result.message }]);
      });
    }

    if (button.matches("[data-shield-keep]")) {
      run(button, async () => {
        await api(`/api/shield/alerts/${encodeURIComponent(id)}/keep-isolated`, { method: "POST", body: {} });
        toast("Automatic restore cancelled. The network stays off until you restore it.");
        await load();
      });
    }

    if (button.matches("[data-shield-dismiss]")) {
      run(button, async () => {
        await api(`/api/shield/alerts/${encodeURIComponent(id)}/dismiss`, {
          method: "POST",
          body: { ignoreHours: Number(body.querySelector("#shieldIgnore")?.value) || 0 }
        });
        toast("Alert dismissed.");
        closeShieldAlert();
      });
    }
  });

  await load();
}

// ---- Global banner --------------------------------------------------------------------------------

export async function refreshShieldBanner() {
  let host = document.getElementById("shieldBanner");

  if (!host) {
    const anchor = document.getElementById("bannerRoot");
    if (!anchor) return;
    host = document.createElement("div");
    host.id = "shieldBanner";
    anchor.after(host);
  }

  let alerts = [];

  try {
    alerts = (await api("/api/shield/alerts?status=open")).alerts || [];
  } catch {
    host.innerHTML = "";
    return;
  }

  if (!alerts.length) {
    host.innerHTML = "";
    return;
  }

  const first = alerts[0];

  host.innerHTML = `
    <div class="shield-banner" role="alert">
      ${icon("alert")}
      <span><strong>Possible ransomware activity</strong> in ${esc(shortPath(first.folder))}: ${esc(evidenceLine(first.evidence))}.${alerts.length > 1 ? ` ${num(alerts.length - 1)} more open.` : ""}</span>
      <button class="btn danger small" type="button" data-open-shield="${esc(first.id)}">Review</button>
    </div>`;

  host.querySelector("[data-open-shield]").addEventListener("click", event => {
    openShieldAlert(event.currentTarget.dataset.openShield, refreshShieldBanner);
  });
}
