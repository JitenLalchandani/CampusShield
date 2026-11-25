const ICONS = {
  alert: '<path d="M12 3 21 20H3L12 3Z"/><path d="M12 10v4.5"/><circle cx="12" cy="17.4" r=".9" fill="currentColor" stroke="none"/>',
  shield: '<path d="M12 2.8 19 5.6v5.1c0 4.6-3 8.1-7 10.5-4-2.4-7-5.9-7-10.5V5.6L12 2.8Z"/><path d="M9.2 11.8 11.3 14l3.5-4.2"/>',
  clock: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 1.8"/>',
  check: '<path d="m4.5 12.5 4.5 4.5 10-10"/>',
  layers: '<path d="m12 3 9 5-9 5-9-5 9-5Z"/><path d="m3 13 9 5 9-5"/>',
  activity: '<path d="M3 12h3.6l2.4-6 4 12 2.6-6H21"/>',
  scan: '<circle cx="12" cy="12" r="2.2"/><path d="M12 3v3.2M12 17.8V21M3 12h3.2M17.8 12H21"/><path d="M6.2 17.8a8.2 8.2 0 0 1 0-11.6M17.8 6.2a8.2 8.2 0 0 1 0 11.6"/>',
  search: '<circle cx="11" cy="11" r="6.5"/><path d="m16 16 4.5 4.5"/>',
  download: '<path d="M12 4v11"/><path d="m7.5 10.5 4.5 4.5 4.5-4.5"/><path d="M5 20h14"/>',
  trash: '<path d="M4 7h16"/><path d="M9 7V4.8h6V7"/><path d="M6.5 7 7.5 20h9L17.5 7"/><path d="M10 11v5M14 11v5"/>',
  x: '<path d="M6 6 18 18M18 6 6 18"/>',
  chevron: '<path d="m9 5 7 7-7 7"/>',
  info: '<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5"/><circle cx="12" cy="7.9" r=".9" fill="currentColor" stroke="none"/>',
  admin: '<path d="M4 20h16"/><path d="M6 20V9.5L12 4l6 5.5V20"/><path d="M10 20v-5h4v5"/>',
  ingest: '<path d="M12 3v11"/><path d="m8 10 4 4 4-4"/><path d="M4 17v2.5h16V17"/>',
  detection: '<path d="M12 3 21 20H3L12 3Z"/>',
  database: '<ellipse cx="12" cy="6" rx="7.5" ry="3"/><path d="M4.5 6v12c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3V6"/><path d="M4.5 12c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3"/>',
  server: '<rect x="3.5" y="4" width="17" height="6.5" rx="2"/><rect x="3.5" y="13.5" width="17" height="6.5" rx="2"/><path d="M7 7.2h.01M7 16.8h.01"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="m11 12 8-8"/><path d="m16 4 3 3M14 6l3 3"/>',
  computer: '<rect x="3" y="4.5" width="18" height="12" rx="2"/><path d="M8 20.5h8"/><path d="M12 16.5v4"/>',
  phone: '<rect x="7" y="2.5" width="10" height="19" rx="2.6"/><path d="M10.5 18.6h3"/>',
  tablet: '<rect x="4.5" y="2.5" width="15" height="19" rx="2.6"/><path d="M10.5 18.6h3"/>',
  browser: '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17"/><path d="M12 3.5c2.4 2.3 3.7 5.3 3.7 8.5s-1.3 6.2-3.7 8.5c-2.4-2.3-3.7-5.3-3.7-8.5S9.6 5.8 12 3.5Z"/>',
  link: '<path d="M10 13.8a3.6 3.6 0 0 0 5.1 0l3-3a3.6 3.6 0 0 0-5.1-5.1l-1 1"/><path d="M14 10.2a3.6 3.6 0 0 0-5.1 0l-3 3a3.6 3.6 0 0 0 5.1 5.1l1-1"/>',
  lock: '<rect x="4.5" y="10.5" width="15" height="10" rx="2.4"/><path d="M8 10.5V8a4 4 0 0 1 8 0v2.5"/>',
  plus: '<path d="M12 5v14M5 12h14"/>'
};

const KIND_META = {
  action: { icon: "check", className: "action" },
  detection: { icon: "scan", className: "" },
  ingest: { icon: "ingest", className: "" },
  scan: { icon: "scan", className: "scan" },
  device: { icon: "shield", className: "device" },
  admin: { icon: "admin", className: "admin" }
};

export function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, character => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[character]));
}

export function icon(name, className = "") {
  const inner = ICONS[name] || ICONS.info;
  return `<svg class="${className}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${inner}</svg>`;
}

export function iconForKind(kind) {
  return KIND_META[kind] || KIND_META.ingest;
}

export function num(value) {
  return new Intl.NumberFormat().format(Number(value) || 0);
}

function byteSize(value) {
  const bytes = Number(value) || 0;
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = bytes / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(size >= 10 ? 0 : 1)} ${units[unit]}`;
}

function spanLabel(ms) {
  const seconds = Math.round((Number(ms) || 0) / 1000);
  if (seconds < 1) return "under 1s";
  if (seconds < 60) return `${seconds}s`;
  return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

// Proof of work for a finished scan, built only from the stored record. A field that was not
// recorded is left out rather than guessed.
export function scanProof(scan) {
  if (!scan) return "";

  const parts = [`${num(scan.filesScanned)} files read`];
  if (Number(scan.bytesScanned) > 0) parts.push(`${byteSize(scan.bytesScanned)} hashed`);
  if (Number(scan.durationMs) > 0) parts.push(`took ${spanLabel(scan.durationMs)}`);
  if (scan.engineVersion) parts.push(`engine ${scan.engineVersion}`);
  if (Number(scan.skipped) > 0) parts.push(`${num(scan.skipped)} skipped`);
  if (scan.truncated) parts.push(`stopped early (${scan.stopReason || "limit reached"})`);
  return parts.join(" · ");
}

export function relativeTime(value) {
  const timestamp = Date.parse(value);

  if (!Number.isFinite(timestamp)) return "Unknown time";

  const diff = Date.now() - timestamp;

  if (diff < 45000) return "just now";

  const minutes = Math.round(diff / 60000);

  if (minutes < 60) return `${minutes}m ago`;

  const hours = Math.round(minutes / 60);

  if (hours < 24) return `${hours}h ago`;

  const days = Math.round(hours / 24);

  if (days < 7) return `${days}d ago`;

  return new Date(timestamp).toLocaleDateString(undefined, {
    day: "numeric",
    month: "short"
  });
}

export function dateTime(value) {
  const timestamp = Date.parse(value);

  if (!Number.isFinite(timestamp)) return "Unknown time";

  return new Date(timestamp).toLocaleString(undefined, {
    day: "numeric",
    month: "short",
    hour: "2-digit",
    minute: "2-digit"
  });
}

export function dayKey(value) {
  const date = new Date(value);

  if (Number.isNaN(date.getTime())) return "unknown";

  return [
    date.getFullYear(),
    String(date.getMonth() + 1).padStart(2, "0"),
    String(date.getDate()).padStart(2, "0")
  ].join("-");
}

export function dayLabel(key) {
  if (key === "unknown") return "Unknown date";

  const date = new Date(`${key}T12:00:00`);

  if (Number.isNaN(date.getTime())) return key;

  const today = dayKey(new Date());
  const yesterday = dayKey(new Date(Date.now() - 86400000));

  if (key === today) return "Today";
  if (key === yesterday) return "Yesterday";

  return date.toLocaleDateString(undefined, {
    weekday: "short",
    day: "numeric",
    month: "short"
  });
}

export function sevClass(severity) {
  const key = String(severity || "").toUpperCase();
  if (key === "HIGH") return "high";
  if (key === "MEDIUM") return "medium";
  return "low";
}

export function statusClass(status) {
  if (status === "Under review") return "review";
  return "open";
}

export function debounce(fn, wait = 280) {
  let timer = null;

  return (...args) => {
    window.clearTimeout(timer);
    timer = window.setTimeout(() => fn(...args), wait);
  };
}

export function emptyState({
  iconName = "info",
  title,
  body = "",
  actionLabel = "",
  actionAttrs = ""
}) {
  return `
    <div class="empty">
      ${icon(iconName)}
      <strong>${esc(title)}</strong>
      ${body ? `<p>${esc(body)}</p>` : ""}
      ${actionLabel ? `<button class="btn ghost small" type="button" ${actionAttrs}>${esc(actionLabel)}</button>` : ""}
    </div>`;
}

export function toast(message, { type = "info", timeout = 4200 } = {}) {
  const root = document.getElementById("toastRoot");

  if (!root) return;

  const iconName = type === "success" ? "check" : type === "error" ? "alert" : "info";
  const element = document.createElement("div");
  element.className = `toast ${type}`;
  element.innerHTML = `
    ${icon(iconName)}
    <div class="toast-body">${esc(message)}</div>
    <button class="toast-close" type="button" aria-label="Dismiss">${icon("x")}</button>
  `;

  root.appendChild(element);

  while (root.children.length > 4) {
    root.firstElementChild?.remove();
  }

  let removed = false;
  const remove = () => {
    if (removed) return;
    removed = true;
    element.classList.add("leaving");
    window.setTimeout(() => element.remove(), 180);
  };

  element.querySelector(".toast-close")?.addEventListener("click", remove);
  window.setTimeout(remove, timeout);
}
