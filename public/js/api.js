const BASE_KEY = "campusshield.apiBase";
const TOKEN_KEY = "campusshield.apiToken";
const SETTINGS_KEY = "campusshield.settings";

const DEFAULT_SETTINGS = {
  autoRefresh: true,
  refreshSeconds: 30
};

export class ApiError extends Error {
  constructor(message, status = 0) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export function getApiBase() {
  try {
    return (localStorage.getItem(BASE_KEY) || "").trim();
  } catch {
    return "";
  }
}

export function setApiBase(value) {
  const clean = String(value || "").trim().replace(/\/+$/, "");

  try {
    if (clean) localStorage.setItem(BASE_KEY, clean);
    else localStorage.removeItem(BASE_KEY);
  } catch {
    /* storage may be unavailable; the in-memory default still works */
  }

  return clean;
}

export function getApiToken() {
  try {
    return (localStorage.getItem(TOKEN_KEY) || "").trim();
  } catch {
    return "";
  }
}

export function setApiToken(value) {
  const clean = String(value || "").trim();

  try {
    if (clean) localStorage.setItem(TOKEN_KEY, clean);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage may be unavailable */
  }

  return clean;
}

export function apiUrl(path) {
  const base = getApiBase();
  return base ? `${base}${path}` : path;
}

export async function api(path, options = {}) {
  const token = getApiToken();
  const init = {
    method: options.method || "GET",
    headers: {
      Accept: "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.headers || {})
    }
  };

  if (options.body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(options.body);
  }

  let response;

  try {
    response = await fetch(apiUrl(path), init);
  } catch {
    const target = getApiBase() || window.location.origin;
    throw new ApiError(
      `Cannot reach the CampusShield API at ${target}. Check the server and the API URL in Settings.`,
      0
    );
  }

  const raw = await response.text();
  let payload = null;

  if (raw) {
    try {
      payload = JSON.parse(raw);
    } catch {
      payload = null;
    }
  }

  if (response.status === 401) {
    throw new ApiError(
      "This server requires an API token. Add it in Settings → API access token.",
      401
    );
  }

  if (response.status === 403) {
    throw new ApiError(
      payload?.error || "This token is read-only, so this change was blocked.",
      403
    );
  }

  if (!response.ok) {
    throw new ApiError(
      payload?.error || payload?.message || `Request failed with status ${response.status}`,
      response.status
    );
  }

  return payload;
}

export function getSettings() {
  try {
    const parsed = JSON.parse(localStorage.getItem(SETTINGS_KEY) || "{}");
    return { ...DEFAULT_SETTINGS, ...parsed };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

export function saveSettings(patch) {
  const next = { ...getSettings(), ...patch };

  try {
    localStorage.setItem(SETTINGS_KEY, JSON.stringify(next));
  } catch {
    /* ignore storage failures */
  }

  return next;
}

export function isNativeShell() {
  return Boolean(window.Capacitor?.isNativePlatform?.());
}

export function isDesktopShell() {
  return Boolean(window.campusshieldDesktop?.isDesktop);
}

export function isStandalone() {
  return Boolean(
    window.matchMedia?.("(display-mode: standalone)")?.matches ||
    window.navigator.standalone ||
    isNativeShell()
  );
}
