import { api, getApiBase, getSettings, isDesktopShell, isNativeShell } from "./api.js";
import { closeEvent, openEvent } from "./drawer.js";
import { icon, toast } from "./ui.js";
import * as protection from "./views/protection.js";
import * as threats from "./views/threats.js";
import * as activity from "./views/activity.js";
import * as coverage from "./views/coverage.js";
import * as settings from "./views/settings.js";

const routes = { protection, threats, activity, coverage, settings };

let health = null;
let currentName = null;
let lastRenderAt = 0;
let scanning = false;

function routeName() {
  const raw = (location.hash.replace(/^#\/?/, "") || "protection").split("?")[0];
  const name = raw === "dashboard" ? "protection" : raw;
  return Object.hasOwn(routes, name) ? name : "protection";
}

function setActiveNav(name) {
  document.querySelectorAll("[data-route]").forEach(element => {
    element.classList.toggle("active", element.dataset.route === name);
  });
}

async function renderRoute({ silent = false } = {}) {
  if (location.hash.startsWith("#/dashboard")) {
    history.replaceState(null, "", "#/protection");
  }

  const name = routeName();
  const view = routes[name];
  const viewEl = document.getElementById("view");

  if (!viewEl) return;

  const switched = currentName !== name;
  currentName = name;

  if (switched) closeEvent();

  document.getElementById("pageEyebrow").textContent = view.meta.eyebrow;
  document.getElementById("pageTitle").textContent = view.meta.title;
  document.getElementById("pageSubtitle").textContent = view.meta.subtitle;
  document.title = `${view.meta.title} · CampusShield`;
  setActiveNav(name);

  if (switched && !silent) window.scrollTo({ top: 0 });

  lastRenderAt = Date.now();

  try {
    await view.render(viewEl);
  } catch (error) {
    viewEl.innerHTML = `
      <section class="card" style="margin-top:12px">
        <div class="empty">
          ${icon("alert")}
          <strong>Could not load this view</strong>
          <p>${error.message}</p>
          <button class="btn ghost small" id="retryView" type="button">Try again</button>
        </div>
      </section>
    `;
    viewEl.querySelector("#retryView")?.addEventListener("click", () => renderRoute());
  }
}

async function refreshHealth() {
  const pill = document.getElementById("connPill");
  const pillText = document.getElementById("connText");
  const pillDot = pill?.querySelector(".dot");
  const storageName = document.getElementById("storageName");
  const storageText = document.getElementById("storageText");
  const storageDot = document.getElementById("storageDot");
  const scanBtn = document.getElementById("deviceCheckBtn");
  const badge = document.getElementById("threatCount");

  try {
    const [nextHealth, summary] = await Promise.all([
      api("/api/health"),
      api("/api/summary")
    ]);

    health = nextHealth;

    pill?.classList.add("online");
    if (pillDot) pillDot.className = "dot on";
    if (pillText) pillText.textContent = "API online";
    if (pill) pill.title = `${getApiBase() || window.location.origin} · ${nextHealth.storage}`;

    if (storageDot) storageDot.className = "dot on";
    if (storageName) storageName.textContent = nextHealth.storage;
    if (storageText) {
      storageText.textContent = nextHealth.deviceAuditAvailable
        ? "Device checks ready"
        : "Device checks unavailable";
    }

    if (scanBtn) {
      scanBtn.disabled = scanning || !nextHealth.deviceAuditAvailable;
      scanBtn.title = nextHealth.deviceAuditAvailable
        ? "Run read-only checks on this computer"
        : "Device checks are implemented for macOS and Windows hosts";
    }

    if (badge) {
      const count = Number(summary.highPriority) || 0;
      badge.hidden = count === 0;
      badge.textContent = count > 99 ? "99+" : String(count);
    }
  } catch (error) {
    health = null;
    const locked = error?.status === 401;

    pill?.classList.remove("online");
    if (pillDot) pillDot.className = "dot off";
    if (pillText) pillText.textContent = locked ? "Token required" : "API offline";
    if (pill) {
      pill.title = locked
        ? "Add the API access token in Settings"
        : `Cannot reach ${getApiBase() || window.location.origin}`;
    }

    if (storageDot) storageDot.className = "dot off";
    if (storageName) storageName.textContent = locked ? "API locked" : "API offline";
    if (storageText) {
      storageText.textContent = locked ? "Enter a token in Settings" : getApiBase() || "Same origin";
    }

    if (scanBtn) scanBtn.disabled = true;
    if (badge) badge.hidden = true;
  }
}

function setTopbarBusy(label, text) {
  const button = document.getElementById("deviceCheckBtn");
  const labelEl = button?.querySelector(".btn-label");

  if (button) button.disabled = true;
  if (labelEl) labelEl.textContent = text;

  return () => {
    if (labelEl) labelEl.textContent = label;
    if (button) button.disabled = Boolean(health && !health.deviceAuditAvailable);
  };
}

async function runDeviceCheck() {
  if (scanning) return;

  scanning = true;

  const reset = setTopbarBusy("Check device", "Checking…");

  try {
    const result = await api("/api/protection/scan", { method: "POST" });

    toast(
      `Device check complete · ${result.device.score}/100 (${result.device.grade}) · ` +
      `${result.device.summary.attention} to fix, ${result.device.summary.unverified} unverified.`,
      { type: result.device.summary.attention ? "info" : "success", timeout: 6500 }
    );

    await refreshHealth();

    if (currentName === "protection" || currentName === "coverage") {
      await renderRoute({ silent: true });
    }
  } catch (error) {
    toast(error.message, { type: "error", timeout: 6000 });
  } finally {
    scanning = false;
    reset();
  }
}

async function runLogScan() {
  try {
    const result = await api("/api/scan", { method: "POST" });

    toast(
      `${result.indicatorsMatched} indicators · ${result.newEventsSaved} new events · ` +
      `${result.duplicatesSkipped} duplicates skipped. Indicators need review.`,
      { type: "success", timeout: 6500 }
    );

    await refreshHealth();

    if (currentName === "threats" || currentName === "coverage") {
      await renderRoute({ silent: true });
    }
  } catch (error) {
    toast(error.message, { type: "error", timeout: 6000 });
  }
}

function renderBanner() {
  const root = document.getElementById("bannerRoot");

  if (!root) return;

  if (isNativeShell() && !getApiBase()) {
    root.innerHTML = `
      <div class="banner">
        <span>This native shell needs a CampusShield server URL before it can load data.</span>
        <a href="#/settings">Open settings</a>
      </div>
    `;
  } else {
    root.innerHTML = "";
  }
}

function startAutoRefresh() {
  window.setInterval(() => {
    const preferences = getSettings();

    if (!preferences.autoRefresh) return;
    if (document.visibilityState !== "visible") return;
    if (currentName !== "protection") return;
    if (document.getElementById("drawerRoot")?.children.length) return;

    const interval = Math.max(10, Number(preferences.refreshSeconds) || 30) * 1000;

    if (Date.now() - lastRenderAt < interval - 1500) return;

    renderRoute({ silent: true });
  }, 10000);
}

function registerServiceWorker() {
  if (!("serviceWorker" in navigator)) return;
  if (!location.protocol.startsWith("http")) return;
  if (isNativeShell() || isDesktopShell()) return;

  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/sw.js").catch(() => {
      /* offline support is optional */
    });
  });
}

function init() {
  if (!location.hash) {
    history.replaceState(null, "", "#/protection");
  } else if (location.hash.startsWith("#/dashboard")) {
    history.replaceState(null, "", "#/protection");
  }

  document.getElementById("refreshBtn")?.addEventListener("click", async event => {
    const button = event.currentTarget;
    button.classList.add("spinning");
    await Promise.all([refreshHealth(), renderRoute({ silent: true })]);
    window.setTimeout(() => button.classList.remove("spinning"), 400);
  });

  document.getElementById("deviceCheckBtn")?.addEventListener("click", runDeviceCheck);

  document.addEventListener("click", event => {
    const trigger = event.target.closest("[data-event-id]");

    if (trigger) {
      event.preventDefault();
      openEvent(trigger.dataset.eventId, () => renderRoute({ silent: true }));
      return;
    }

    if (event.target.closest('[data-action="scan"]')) {
      runLogScan();
    }

    if (currentName !== "protection" && event.target.closest('[data-action="device-check"]')) {
      runDeviceCheck();
    }
  });

  window.addEventListener("hashchange", () => renderRoute());
  window.addEventListener("resize", renderBanner);

  window.addEventListener("campusshield:api-changed", async () => {
    renderBanner();
    await refreshHealth();
  });

  window.addEventListener("campusshield:data-changed", async () => {
    await refreshHealth();
    await renderRoute({ silent: true });
  });

  renderBanner();
  registerServiceWorker();

  refreshHealth();
  renderRoute({ silent: true });
  startAutoRefresh();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
