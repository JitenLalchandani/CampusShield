import { api } from "../api.js";
import { dateTime, esc, icon, num, relativeTime, toast } from "../ui.js";

function bytes(value) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = Number(value) || 0;
  let index = 0;

  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }

  return `${size >= 10 || index === 0 ? Math.round(size) : size.toFixed(1)} ${units[index]}`;
}

const STATUS_LABEL = {
  scanning: "Scanning",
  clean: "Clean",
  open: "Needs attention",
  incomplete: "Incomplete",
  removed: "Removed",
  dismissed: "Dismissed"
};

const STATUS_TONE = { scanning: "warn", clean: "ok", open: "bad", incomplete: "warn", removed: "idle", dismissed: "idle" };

function scanLine(event) {
  if (event.status === "scanning") return event.note || "Scanning…";
  if (!event.scan) return event.note || "Only the top of the drive was checked.";

  const scan = event.scan;
  const parts = [`${num(scan.filesScanned)} files read`];

  if (scan.skipped) parts.push(`${num(scan.skipped)} skipped`);
  if (scan.errorCount) parts.push(`${num(scan.errorCount)} unreadable`);
  if (scan.truncated) parts.push(`stopped early: ${scan.stopReason || "limit reached"}`);
  if (scan.status !== "complete") parts.push(`scan ${scan.status}, results are partial`);

  return parts.join(" · ");
}

export function renderUsbCard(status, events) {
  if (!status) {
    return `
      <section class="card protect-section shield-card" id="usbCard">
        <div class="card-head"><div><h2>USB auto-scan</h2><p>Not available</p></div><span class="chip">Unavailable</span></div>
        <p class="helper">The USB state could not be loaded. Sign in again or check the server.</p>
      </section>`;
  }

  const state = !status.supported ? "Unsupported" : !status.enabled ? "Off" : status.running ? "Watching" : "Not running";
  const tone = !status.supported ? "idle" : status.running ? "ok" : status.enabled ? "warn" : "idle";

  const drives = status.drives
    .map(
      drive => `<li class="shield-folder" data-state="live">
        <span class="shield-dot" aria-hidden="true"></span>
        <span class="usb-drive"><strong>${esc(drive.label)}</strong> <code>${esc(drive.mountPoint)}</code>
          <span class="helper">${[drive.fsType, drive.sizeBytes ? bytes(drive.sizeBytes) : null, drive.ignored ? "auto-scan skipped" : null].filter(Boolean).map(esc).join(" · ")}</span></span>
        <span class="usb-actions">
          <button class="btn ghost small" type="button" data-usb-scan="${esc(drive.id)}">Scan now</button>
          <button class="btn ghost small" type="button" data-usb-ignore="${esc(drive.id)}" data-ignored="${drive.ignored}">${drive.ignored ? "Auto-scan this drive" : "Skip auto-scan"}</button>
        </span>
      </li>`
    )
    .join("");

  const rows = events
    .slice(0, 6)
    .map(
      event => `<li><button class="shield-alert-row" type="button" data-usb-event="${esc(event.id)}">
        <span class="chip" data-tone="${STATUS_TONE[event.status] || "idle"}">${esc(STATUS_LABEL[event.status] || event.status)}</span>
        <span class="shield-alert-main"><strong>${esc(event.label)}</strong><span class="helper">${esc(scanLine(event))}</span></span>
        <span class="helper">${esc(relativeTime(event.updatedAt || event.startedAt))}</span>
      </button></li>`
    )
    .join("");

  return `
    <section class="card protect-section shield-card" id="usbCard">
      <div class="card-head">
        <div><h2>USB auto-scan</h2><p>Checks removable drives when you plug them in</p></div>
        <span class="chip" data-tone="${tone}">${state}</span>
      </div>

      ${status.error ? `<div class="scan-warning">${icon("alert")} <span>${esc(status.error)}</span></div>` : ""}
      ${status.notes.map(note => `<p class="helper">${esc(note)}</p>`).join("")}

      <label class="switch-row">
        <span><strong>Scan drives I plug in</strong><span class="helper">Off by default. Drives already connected are listed but only scanned when you ask.</span></span>
        <span class="switch"><input type="checkbox" id="usbEnabled" ${status.enabled ? "checked" : ""} ${status.supported ? "" : "disabled"} aria-label="Turn on USB auto-scan"></span>
      </label>

      <label class="switch-row">
        <span><strong>Run a full file scan on new drives</strong><span class="helper">When off, only the top of the drive is checked for autorun tricks.</span></span>
        <span class="switch"><input type="checkbox" id="usbAuto" ${status.autoScan ? "checked" : ""} ${status.enabled ? "" : "disabled"} aria-label="Scan new drives automatically"></span>
      </label>

      ${status.enabled ? `<ul class="shield-folders">${drives || `<li class="helper">No removable drive is connected.</li>`}</ul>` : ""}

      <details class="shield-details">
        <summary>Rules and limits</summary>
        <ul class="checklist">${status.limits.map(line => `<li>${icon("info")}<span>${esc(line)}</span></li>`).join("")}</ul>
      </details>

      ${rows ? `<h3 class="shield-sub">Recent drives</h3><ul class="shield-alerts">${rows}</ul>` : `<p class="helper shield-none">${status.enabled ? "No drives have been scanned yet." : "No drive records."}</p>`}
    </section>`;
}

export function bindUsbCard(root, refresh) {
  const patch = async (body, done) => {
    try {
      await api("/api/usb/settings", { method: "PATCH", body });
      if (done) toast(done, { type: "success" });
    } catch (error) {
      toast(error.message, { type: "error" });
    }

    refresh();
  };

  root.querySelector("#usbEnabled")?.addEventListener("change", event => {
    event.currentTarget.disabled = true;
    patch({ enabled: event.currentTarget.checked }, event.currentTarget.checked ? "USB auto-scan is on." : "USB auto-scan is off.");
  });

  root.querySelector("#usbAuto")?.addEventListener("change", event => patch({ autoScan: event.currentTarget.checked }));

  root.querySelectorAll("[data-usb-scan]").forEach(button => {
    button.addEventListener("click", async () => {
      button.disabled = true;

      try {
        const data = await api(`/api/usb/drives/${encodeURIComponent(button.dataset.usbScan)}/scan`, { method: "POST", body: {} });
        toast("Scanning the drive…");
        openUsbEvent(data.event.id, refresh);
      } catch (error) {
        toast(error.message, { type: "error" });
        button.disabled = false;
      }
    });
  });

  root.querySelectorAll("[data-usb-ignore]").forEach(button => {
    button.addEventListener("click", async () => {
      try {
        await api(`/api/usb/drives/${encodeURIComponent(button.dataset.usbIgnore)}/ignore`, {
          method: "POST",
          body: { ignore: button.dataset.ignored !== "true" }
        });
      } catch (error) {
        toast(error.message, { type: "error" });
      }

      refresh();
    });
  });

  root.querySelectorAll("[data-usb-event]").forEach(button => {
    button.addEventListener("click", () => openUsbEvent(button.dataset.usbEvent, refresh));
  });
}

// ---- Event drawer ---------------------------------------------------------------------------------

let drawerCleanup = null;

export function closeUsbEvent() {
  drawerCleanup?.();
  drawerCleanup = null;
}

function drawerBody(event, token) {
  const detected = (event.threats || []).filter(threat => threat.status === "detected");
  const actionable = (event.findings || []).length;

  return `
    <section class="drawer-section">
      <h3>What was checked</h3>
      <p><strong>${esc(event.label)}</strong> <code>${esc(event.mountPoint)}</code> · ${esc(STATUS_LABEL[event.status] || event.status)}</p>
      <p class="helper">${esc(dateTime(event.startedAt))} · ${event.trigger === "manual" ? "scanned on request" : "scanned when plugged in"}.</p>
      <p class="helper">File scan: ${esc(scanLine(event))}.</p>
      <p class="helper">Top of the drive: ${event.inspect?.ok ? `${num(event.inspect.entriesChecked)} items checked${event.inspect.truncated ? ", the rest were not" : ""}` : esc(event.inspect?.reason || "not checked")}.</p>
      ${event.note && event.status !== "scanning" ? `<div class="scan-warning">${icon("alert")} <span>${esc(event.note)}</span></div>` : ""}
    </section>

    <section class="drawer-section">
      <h3>Autorun signs</h3>
      ${
        actionable
          ? `<ul class="shield-results">${event.findings.map(item => `<li data-tone="${item.severity === "low" ? "idle" : "warn"}"><strong>${esc(item.severity)}:</strong> ${esc(item.detail)}<br><code>${esc(item.path)}</code></li>`).join("")}</ul>
             <p class="helper">CampusShield never opens or changes these. Delete them yourself if you recognise them as unwanted.</p>`
          : `<p class="helper">None found at the top of the drive.</p>`
      }
    </section>

    <section class="drawer-section">
      <h3>Files the scanner flagged</h3>
      ${
        (event.threats || []).length
          ? `<ul class="shield-results">${event.threats.map(item => `<li data-tone="${item.status === "detected" ? "warn" : "ok"}"><strong>${esc(item.name)}</strong> (${esc(item.severity)}) · ${esc(item.status)}<br><code>${esc(item.filePath)}</code></li>`).join("")}</ul>`
          : `<p class="helper">${event.scan ? "None." : "No file scan ran."}</p>`
      }
      ${
        detected.length && token
          ? `<p class="helper">Quarantine moves each file off the drive into CampusShield's quarantine, where you can restore it.</p>
             <div class="drawer-actions"><button class="btn danger" type="button" data-usb-quarantine>Quarantine ${num(detected.length)} file${detected.length === 1 ? "" : "s"}</button></div>`
          : ""
      }
    </section>

    ${
      ["open", "incomplete", "clean"].includes(event.status)
        ? `<div class="drawer-actions"><button class="btn ghost" type="button" data-usb-dismiss>Dismiss</button></div>`
        : ""
    }`;
}

export async function openUsbEvent(id, onChange = () => {}) {
  closeUsbEvent();

  const root = document.getElementById("drawerRoot");
  if (!root) return;

  const backdrop = document.createElement("div");
  backdrop.className = "drawer-backdrop";
  backdrop.innerHTML = `
    <aside class="drawer" role="dialog" aria-modal="true" aria-label="USB drive details" tabindex="-1">
      <div class="drawer-head">
        <div><p class="eyebrow" style="margin:0">USB auto-scan</p><h2>Loading…</h2></div>
        <button class="icon-btn" type="button" data-close aria-label="Close details">${icon("x")}</button>
      </div>
      <div class="drawer-body"><div class="drawer-loading"><div class="skeleton"></div><div class="skeleton"></div></div></div>
    </aside>`;

  root.appendChild(backdrop);
  document.body.style.overflow = "hidden";

  const onKey = event => {
    if (event.key === "Escape") closeUsbEvent();
  };

  document.addEventListener("keydown", onKey);

  let timer = null;

  drawerCleanup = () => {
    clearTimeout(timer);
    document.removeEventListener("keydown", onKey);
    backdrop.remove();
    document.body.style.overflow = "";
    onChange();
  };

  backdrop.addEventListener("click", event => {
    if (event.target === backdrop || event.target.closest("[data-close]")) closeUsbEvent();
  });

  const body = backdrop.querySelector(".drawer-body");
  const title = backdrop.querySelector("h2");
  let token = null;

  async function load() {
    try {
      const data = await api(`/api/usb/events/${encodeURIComponent(id)}`);
      token = data.confirmToken || null;
      title.textContent = data.event.label;
      body.innerHTML = drawerBody(data.event, token);

      // A scan in progress is real work; show it finishing instead of a made-up progress bar.
      if (data.event.status === "scanning" && document.body.contains(backdrop)) timer = setTimeout(load, 1500);
    } catch (error) {
      body.innerHTML = `<p class="helper">${esc(error.message)}</p>`;
    }
  }

  body.addEventListener("click", async event => {
    const button = event.target.closest("button");
    if (!button) return;

    try {
      if (button.matches("[data-usb-quarantine]")) {
        if (!window.confirm("Move the flagged files off this drive into quarantine?")) return;
        button.disabled = true;

        const data = await api(`/api/usb/events/${encodeURIComponent(id)}/quarantine-all`, {
          method: "POST",
          body: { confirm: true, confirmToken: token }
        });

        const failed = data.results.filter(item => !item.ok);
        toast(failed.length ? `${failed.length} file${failed.length === 1 ? "" : "s"} could not be moved: ${failed[0].message}` : "Files moved to quarantine.", { type: failed.length ? "error" : "success" });
        await load();
      }

      if (button.matches("[data-usb-dismiss]")) {
        await api(`/api/usb/events/${encodeURIComponent(id)}/dismiss`, { method: "POST", body: {} });
        closeUsbEvent();
      }
    } catch (error) {
      toast(error.message, { type: "error" });
      await load();
    }
  });

  await load();
}

// ---- Global banner --------------------------------------------------------------------------------

export async function refreshUsbBanner() {
  let host = document.getElementById("usbBanner");

  if (!host) {
    const anchor = document.getElementById("shieldBanner") || document.getElementById("bannerRoot");
    if (!anchor) return;
    host = document.createElement("div");
    host.id = "usbBanner";
    anchor.after(host);
  }

  let events = [];

  try {
    events = (await api("/api/usb/events?status=open")).events || [];
  } catch {
    host.innerHTML = "";
    return;
  }

  if (!events.length) {
    host.innerHTML = "";
    return;
  }

  const first = events[0];

  host.innerHTML = `
    <div class="shield-banner" role="alert" data-kind="usb">
      ${icon("alert")}
      <span><strong>USB drive needs attention:</strong> ${esc(first.label)}${events.length > 1 ? ` and ${num(events.length - 1)} more` : ""}.</span>
      <button class="btn danger small" type="button" data-open-usb="${esc(first.id)}">Review</button>
    </div>`;

  host.querySelector("[data-open-usb]").addEventListener("click", event => {
    openUsbEvent(event.currentTarget.dataset.openUsb, refreshUsbBanner);
  });
}
