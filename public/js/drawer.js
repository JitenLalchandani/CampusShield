import { api } from "./api.js";
import {
  dateTime,
  esc,
  icon,
  iconForKind,
  relativeTime,
  sevClass,
  statusClass,
  toast
} from "./ui.js";

let active = null;

export async function openEvent(id, onChange = () => {}) {
  closeEvent();

  const root = document.getElementById("drawerRoot");

  if (!root) return;

  const backdrop = document.createElement("div");
  backdrop.className = "drawer-backdrop";
  backdrop.innerHTML = `
    <aside class="drawer" role="dialog" aria-modal="true" aria-label="Event details" tabindex="-1">
      <div class="drawer-head">
        <div>
          <p class="eyebrow" style="margin:0">Event detail</p>
          <h2>Loading event…</h2>
        </div>
        <button class="icon-btn" type="button" data-close aria-label="Close details">${icon("x")}</button>
      </div>
      <div class="drawer-body">
        <div class="drawer-loading">
          <div class="skeleton"></div>
          <div class="skeleton"></div>
          <div class="skeleton"></div>
        </div>
      </div>
    </aside>
  `;

  root.appendChild(backdrop);
  document.body.style.overflow = "hidden";

  const onKey = event => {
    if (event.key === "Escape") closeEvent();
  };

  document.addEventListener("keydown", onKey);
  active = { id, backdrop, onKey, onChange };

  backdrop.addEventListener("click", async event => {
    if (event.target === backdrop) {
      closeEvent();
      return;
    }

    if (event.target.closest("[data-close]")) {
      closeEvent();
      return;
    }

    const button = event.target.closest("button[data-alert-action]");

    if (!button) return;

    button.disabled = true;

    try {
      const result = await api(`/api/alerts/${encodeURIComponent(id)}/action`, {
        method: "POST",
        body: { action: button.dataset.alertAction }
      });

      toast(result.note || "Action recorded.", { type: "success" });
      onChange();
      await load(id);
    } catch (error) {
      toast(error.message, { type: "error" });
      button.disabled = false;
    }
  });

  const panel = backdrop.querySelector(".drawer");
  panel?.focus();

  await load(id);
}

export function closeEvent() {
  if (!active) return;

  document.removeEventListener("keydown", active.onKey);
  active.backdrop.remove();
  document.body.style.overflow = "";
  active = null;
}

async function load(id) {
  try {
    const data = await api(`/api/events/${encodeURIComponent(id)}`);
    renderDetail(data);
  } catch (error) {
    renderError(error);
  }
}

function renderDetail(data) {
  if (!active) return;

  const event = data.event || {};
  const history = Array.isArray(data.history) ? data.history : [];
  const drawer = active.backdrop.querySelector(".drawer");

  if (!drawer) return;

  const actions = [];

  if (event.status !== "Under review") {
    actions.push(["Investigate", "Investigate", "btn ghost small"]);
  }
  if (event.status !== "Contained (demo)") {
    actions.push(["Contain", "Record containment", "btn ghost small"]);
  }
  if (event.status !== "Open") {
    actions.push(["Reopen", "Reopen", "btn subtle small"]);
  }

  drawer.innerHTML = `
    <div class="drawer-head">
      <div>
        <div class="event-top" style="margin-bottom:6px">
          <span class="sev ${sevClass(event.severity)}">${esc(event.severity)}</span>
          <span class="status ${statusClass(event.status)}">${esc(event.status)}</span>
        </div>
        <h2>${esc(event.type)}</h2>
        <p class="tiny mono" style="margin-top:5px">${esc(event.id)}</p>
      </div>
      <button class="icon-btn" type="button" data-close aria-label="Close details">${icon("x")}</button>
    </div>

    <div class="drawer-body">
      <section class="drawer-section">
        <h3>Detail</h3>
        <p class="detail-copy">${esc(event.detail || "No detail supplied.")}</p>
      </section>

      <section class="drawer-section">
        <h3>Rule matched</h3>
        <p class="detail-copy">${esc(event.rule || "No rule matched.")}</p>
      </section>

      <section class="drawer-section">
        <h3>Recommended next step</h3>
        <p class="detail-copy reco">${esc(event.recommendation || "Continue monitoring.")}</p>
      </section>

      <dl class="meta-grid">
        <div><dt>Campus group</dt><dd>${esc(event.group || "—")}</dd></div>
        <div><dt>Source</dt><dd>${esc(event.source || "—")}</dd></div>
        <div><dt>Signal count</dt><dd>${esc(event.count ?? "—")}</dd></div>
        <div><dt>Received</dt><dd>${esc(relativeTime(event.time))} · ${esc(dateTime(event.time))}</dd></div>
      </dl>

      <section class="drawer-section">
        <h3>History</h3>
        ${renderHistory(history)}
      </section>

      <p class="warning-note">
        Containment is a status label in this build. No device, account, or
        network setting is changed.
      </p>
    </div>

    <div class="drawer-actions">
      ${actions.map(([action, label, className]) => `
        <button class="${className}" type="button" data-alert-action="${esc(action)}">${esc(label)}</button>
      `).join("")}
    </div>
  `;
}

function renderHistory(history) {
  if (!history.length) {
    return `<p class="helper">No audit history for this event yet.</p>`;
  }

  return `
    <div class="timeline">
      ${history.map(entry => {
        const meta = iconForKind(entry.kind);
        return `
          <div class="tl-item">
            <span class="tl-icon ${meta.className}">${icon(meta.icon)}</span>
            <div class="tl-body">
              <div class="tl-message">${esc(entry.message)}</div>
              <div class="tl-meta">
                <span>${esc(dateTime(entry.time))}</span>
                ${entry.status ? `<span class="status ${statusClass(entry.status)}">${esc(entry.status)}</span>` : ""}
              </div>
            </div>
          </div>
        `;
      }).join("")}
    </div>
  `;
}

function renderError(error) {
  if (!active) return;

  const drawer = active.backdrop.querySelector(".drawer");

  if (!drawer) return;

  drawer.innerHTML = `
    <div class="drawer-head">
      <div>
        <p class="eyebrow" style="margin:0">Event detail</p>
        <h2>Could not load this event</h2>
      </div>
      <button class="icon-btn" type="button" data-close aria-label="Close details">${icon("x")}</button>
    </div>
    <div class="drawer-body">
      <div class="empty">
        ${icon("alert")}
        <strong>${esc(error.message)}</strong>
        <p>The event may have been cleared, or the API is unreachable.</p>
      </div>
    </div>
  `;
}
