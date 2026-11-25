import { api } from "../api.js";
import {
  debounce,
  emptyState,
  esc,
  icon,
  num,
  relativeTime,
  sevClass,
  statusClass,
  toast
} from "../ui.js";

export const meta = {
  eyebrow: "Triage",
  title: "Threat queue",
  subtitle: "Filter, inspect, and record a decision for each alert."
};

const PAGE_SIZE = 25;
const filters = {
  q: "",
  severity: "all",
  status: "all",
  type: "all",
  sort: "newest"
};

let items = [];
let total = 0;
let allTotal = 0;
let loading = false;
let rootRef = null;

export async function render(root) {
  rootRef = root;
  items = [];

  root.innerHTML = `
    <div class="toolbar">
      <label class="field field-search">
        <span>Search</span>
        <span class="search">
          ${icon("search")}
          <input class="input" id="searchInput" type="search" placeholder="Type, group, source, rule, ID…" value="${esc(filters.q)}" autocomplete="off">
        </span>
      </label>
      <label class="field">
        <span>Severity</span>
        <select class="select" id="severityFilter">
          ${option("all", "All severities", filters.severity)}
          ${option("HIGH", "High", filters.severity)}
          ${option("MEDIUM", "Medium", filters.severity)}
          ${option("LOW", "Low", filters.severity)}
        </select>
      </label>
      <label class="field">
        <span>Status</span>
        <select class="select" id="statusFilter">
          ${option("all", "All statuses", filters.status)}
          ${option("Open", "Open", filters.status)}
          ${option("Under review", "Under review", filters.status)}
        </select>
      </label>
      <label class="field">
        <span>Type</span>
        <select class="select" id="typeFilter">
          <option value="all">All types</option>
        </select>
      </label>
      <label class="field">
        <span>Order</span>
        <select class="select" id="sortFilter">
          ${option("newest", "Newest first", filters.sort)}
          ${option("oldest", "Oldest first", filters.sort)}
          ${option("severity", "Severity first", filters.sort)}
        </select>
      </label>
    </div>

    <section class="card">
      <div class="card-head">
        <div>
          <h2>Events</h2>
          <p id="threatSummary">Loading the queue…</p>
        </div>
        <button class="btn subtle small" id="resetFilters" type="button">Reset filters</button>
      </div>
      <div id="threatList">
        <div class="loading-state">
          <span class="spinner" aria-hidden="true"></span>
          <p>Loading events…</p>
        </div>
      </div>
      <div id="threatFoot"></div>
    </section>
  `;

  bind(root);
  await load(true);
}

function bind(root) {
  const search = root.querySelector("#searchInput");

  search?.addEventListener("input", debounce(() => {
    filters.q = search.value.trim();
    load(true);
  }, 300));

  for (const [id, key] of [
    ["#severityFilter", "severity"],
    ["#statusFilter", "status"],
    ["#typeFilter", "type"],
    ["#sortFilter", "sort"]
  ]) {
    root.querySelector(id)?.addEventListener("change", event => {
      filters[key] = event.target.value;
      load(true);
    });
  }

  root.querySelector("#resetFilters")?.addEventListener("click", resetFilters);
}

async function load(reset) {
  if (loading || !rootRef) return;

  loading = true;

  if (reset) items = [];

  try {
    const params = new URLSearchParams({
      limit: String(PAGE_SIZE),
      offset: String(items.length),
      sort: filters.sort
    });

    if (filters.q) params.set("q", filters.q);
    if (filters.severity !== "all") params.set("severity", filters.severity);
    if (filters.status !== "all") params.set("status", filters.status);
    if (filters.type !== "all") params.set("type", filters.type);

    const data = await api(`/api/events?${params.toString()}`);

    const events = Array.isArray(data.events) ? data.events : [];
    items = reset ? events : items.concat(events);
    total = data.total;
    allTotal = data.allTotal;

    updateTypeOptions(data.facets?.types || []);
    paint();
  } catch (error) {
    toast(error.message, { type: "error" });
    const list = rootRef.querySelector("#threatList");

    if (list) {
      list.innerHTML = `
        <div class="empty">
          ${icon("alert")}
          <strong>Could not load events</strong>
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

  const list = rootRef.querySelector("#threatList");
  const summary = rootRef.querySelector("#threatSummary");
  const foot = rootRef.querySelector("#threatFoot");

  if (!list || !summary || !foot) return;

  const filtered = Boolean(filters.q) || filters.severity !== "all" ||
    filters.status !== "all" || filters.type !== "all";

  summary.textContent = filtered
    ? `${num(total)} of ${num(allTotal)} events match these filters`
    : `${num(total)} event${total === 1 ? "" : "s"} in the queue`;

  if (!items.length) {
    list.innerHTML = filtered
      ? emptyState({
          iconName: "search",
          title: "No matching events",
          body: "Nothing matches this combination of filters. Try widening the search or resetting the filters.",
          actionLabel: "Clear filters",
          actionAttrs: "data-clear-filters"
        })
      : emptyState({
          iconName: "shield",
          title: "No events received",
          body: "The queue is empty. Run a local scan on this Mac, or send approved events to POST /api/events.",
          actionLabel: "Run local scan",
          actionAttrs: 'data-action="scan"'
        });

    list.querySelector("[data-clear-filters]")?.addEventListener("click", resetFilters);
    foot.innerHTML = "";
    return;
  }

  list.innerHTML = `
    <div class="event-list">
      ${items.map(eventRow).join("")}
    </div>
  `;

  const more = items.length < total;

  foot.innerHTML = `
    <div class="list-foot">
      <span>Showing ${num(items.length)} of ${num(total)}</span>
      ${more ? '<button class="btn subtle small" id="loadMoreBtn" type="button">Load more</button>' : ""}
    </div>
  `;

  foot.querySelector("#loadMoreBtn")?.addEventListener("click", () => load(false));
}

function updateTypeOptions(types) {
  const select = rootRef?.querySelector("#typeFilter");

  if (!select) return;

  if (filters.type !== "all" && !types.includes(filters.type)) {
    filters.type = "all";
  }

  select.innerHTML = `
    <option value="all">All types</option>
    ${types.map(type => option(type, type, filters.type)).join("")}
  `;
}

function resetFilters() {
  filters.q = "";
  filters.severity = "all";
  filters.status = "all";
  filters.type = "all";
  filters.sort = "newest";

  if (rootRef) {
    const search = rootRef.querySelector("#searchInput");
    const severity = rootRef.querySelector("#severityFilter");
    const status = rootRef.querySelector("#statusFilter");
    const type = rootRef.querySelector("#typeFilter");
    const sort = rootRef.querySelector("#sortFilter");

    if (search) search.value = "";
    if (severity) severity.value = "all";
    if (status) status.value = "all";
    if (type) type.value = "all";
    if (sort) sort.value = "newest";
  }

  load(true);
}

function option(value, label, current) {
  return `<option value="${esc(value)}" ${value === current ? "selected" : ""}>${esc(label)}</option>`;
}

function eventRow(event) {
  return `
    <button class="event-row" type="button" data-event-id="${esc(event.id)}">
      <span class="sev ${sevClass(event.severity)}">${esc(event.severity)}</span>
      <span class="event-main">
        <span class="event-top">
          <span class="event-title">${esc(event.type)}</span>
          <span class="status ${statusClass(event.status)}">${esc(event.status)}</span>
        </span>
        <span class="event-rule">${esc(event.rule)}</span>
        <span class="event-meta">
          <span>${esc(event.group)}</span>
          <span class="sep">·</span>
          <span>${esc(event.source)}</span>
          <span class="sep">·</span>
          <span>${esc(relativeTime(event.time))}</span>
          <span class="sep">·</span>
          <span class="mono">${esc(event.id)}</span>
        </span>
      </span>
      <span class="chev">${icon("chevron")}</span>
    </button>
  `;
}
