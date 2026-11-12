import { api } from "../api.js";
import {
  dateTime,
  dayKey,
  dayLabel,
  emptyState,
  esc,
  icon,
  iconForKind,
  num,
  statusClass,
  toast
} from "../ui.js";

export const meta = {
  eyebrow: "Audit",
  title: "Activity",
  subtitle: "Every check, scan, detection, ingestion, and analyst decision."
};

const PAGE_SIZE = 50;
const KINDS = [
  { value: "all", label: "All" },
  { value: "action", label: "Decisions" },
  { value: "detection", label: "Detections" },
  { value: "ingest", label: "Ingested" },
  { value: "scan", label: "Scans" },
  { value: "device", label: "Devices" },
  { value: "admin", label: "Admin" }
];

let kind = "all";
let items = [];
let total = 0;
let loading = false;
let rootRef = null;

export async function render(root) {
  rootRef = root;
  items = [];
  kind = "all";

  root.innerHTML = `
    <div class="filter-chips">
      ${KINDS.map(item => `
        <button class="filter-chip ${item.value === kind ? "active" : ""}" type="button" data-kind="${esc(item.value)}">
          ${esc(item.label)}
        </button>
      `).join("")}
    </div>

    <section class="card">
      <div class="card-head">
        <div>
          <h2>Audit trail</h2>
          <p id="activitySummary">Loading history…</p>
        </div>
        <span class="chip">${icon("clock")} Local retention</span>
      </div>
      <div id="activityList">
        <div class="loading-state">
          <span class="spinner" aria-hidden="true"></span>
          <p>Loading activity…</p>
        </div>
      </div>
      <div id="activityFoot"></div>
    </section>
  `;

  root.querySelectorAll("[data-kind]").forEach(button => {
    button.addEventListener("click", () => {
      kind = button.dataset.kind;
      root.querySelectorAll("[data-kind]").forEach(other => {
        other.classList.toggle("active", other.dataset.kind === kind);
      });
      load(true);
    });
  });

  await load(true);
}

async function load(reset) {
  if (loading || !rootRef) return;

  loading = true;

  if (reset) items = [];

  try {
    const params = new URLSearchParams({
      limit: String(PAGE_SIZE),
      offset: String(items.length)
    });

    if (kind !== "all") params.set("kind", kind);

    const data = await api(`/api/activity?${params.toString()}`);
    const entries = Array.isArray(data.activity) ? data.activity : [];

    items = reset ? entries : items.concat(entries);
    total = data.total;

    paint();
  } catch (error) {
    toast(error.message, { type: "error" });

    const list = rootRef.querySelector("#activityList");

    if (list) {
      list.innerHTML = `
        <div class="empty">
          ${icon("alert")}
          <strong>Could not load activity</strong>
          <p>${esc(error.message)}</p>
        </div>
      `;
    }
  } finally {
    loading = false;
  }
}

function paint() {
  if (!rootRef) return;

  const list = rootRef.querySelector("#activityList");
  const summary = rootRef.querySelector("#activitySummary");
  const foot = rootRef.querySelector("#activityFoot");

  if (!list || !summary || !foot) return;

  const label = KINDS.find(item => item.value === kind)?.label || "All";

  summary.textContent = kind === "all"
    ? `${num(total)} recorded ${total === 1 ? "entry" : "entries"}`
    : `${num(total)} ${label.toLowerCase()} ${total === 1 ? "entry" : "entries"}`;

  if (!items.length) {
    list.innerHTML = kind === "all"
      ? emptyState({
          iconName: "activity",
          title: "No activity recorded",
          body: "Run a scan, ingest an approved event, or record a decision and it will appear here."
        })
      : emptyState({
          iconName: "activity",
          title: `No ${label.toLowerCase()} entries`,
          body: "Nothing has been recorded for this category yet."
        });

    foot.innerHTML = "";
    return;
  }

  let lastDay = null;
  const rows = [];

  for (const entry of items) {
    const key = dayKey(entry.time);

    if (key !== lastDay) {
      rows.push(`<div class="tl-day">${esc(dayLabel(key))}</div>`);
      lastDay = key;
    }

    rows.push(timelineRow(entry));
  }

  list.innerHTML = `<div class="timeline">${rows.join("")}</div>`;

  const more = items.length < total;

  foot.innerHTML = `
    <div class="list-foot">
      <span>Showing ${num(items.length)} of ${num(total)}</span>
      ${more ? '<button class="btn subtle small" id="loadMoreActivity" type="button">Load more</button>' : ""}
    </div>
  `;

  foot.querySelector("#loadMoreActivity")?.addEventListener("click", () => load(false));
}

function timelineRow(entry) {
  const meta = iconForKind(entry.kind);

  return `
    <div class="tl-item">
      <span class="tl-icon ${meta.className}">${icon(meta.icon)}</span>
      <div class="tl-body">
        <div class="tl-message">${esc(entry.message)}</div>
        <div class="tl-meta">
          <span>${esc(dateTime(entry.time))}</span>
          ${entry.status ? `<span class="status ${statusClass(entry.status)}">${esc(entry.status)}</span>` : ""}
          ${entry.severity ? `<span class="sev ${entry.severity === "HIGH" ? "high" : entry.severity === "MEDIUM" ? "medium" : "low"}">${esc(entry.severity)}</span>` : ""}
          ${entry.eventId ? `<a class="link" href="#/threats" data-event-id="${esc(entry.eventId)}">Open event</a>` : ""}
        </div>
      </div>
    </div>
  `;
}
