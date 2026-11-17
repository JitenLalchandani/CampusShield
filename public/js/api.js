const BASE_KEY = "campusshield.apiBase";
const TOKEN_KEY = "campusshield.apiToken";
const SESSION_KEY = "campusshield.session";
const SETTINGS_KEY = "campusshield.settings";
const AI_KEY = "campusshield.ai";

const DEFAULT_SETTINGS = {
  autoRefresh: true,
  refreshSeconds: 30
};

export class ApiError extends Error {
  constructor(message, status = 0, code = "") {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
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

export function getSessionToken() {
  try {
    return (localStorage.getItem(SESSION_KEY) || "").trim();
  } catch {
    return "";
  }
}

export function setSessionToken(value) {
  const clean = String(value || "").trim();

  try {
    if (clean) localStorage.setItem(SESSION_KEY, clean);
    else localStorage.removeItem(SESSION_KEY);
  } catch {
    /* storage may be unavailable */
  }

  return clean;
}

export function clearSessionToken() {
  return setSessionToken("");
}

export async function api(path, options = {}) {
  const token = getApiToken();
  const session = getSessionToken();
  const init = {
    method: options.method || "GET",
    headers: {
      Accept: "application/json",
      ...(session ? { Authorization: `Bearer ${session}` } : {}),
      ...(token ? { "X-Api-Token": token } : {}),
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
    if (payload?.code === "auth_required") {
      window.dispatchEvent(new CustomEvent("campusshield:auth-required"));
      throw new ApiError("Sign in to use CampusShield.", 401, "auth_required");
    }

    throw new ApiError(
      "This server requires an API token. Add it in Settings → API access token.",
      401,
      payload?.code || ""
    );
  }

  if (response.status === 403) {
    throw new ApiError(
      payload?.error || "This token is read-only, so this change was blocked.",
      403,
      payload?.code || ""
    );
  }

  if (!response.ok) {
    throw new ApiError(
      payload?.error || payload?.message || `Request failed with status ${response.status}`,
      response.status,
      payload?.code || ""
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

export function getAiConfig() {
  try {
    const parsed = JSON.parse(localStorage.getItem(AI_KEY) || "{}");
    return {
      baseUrl: String(parsed.baseUrl || "").trim(),
      model: String(parsed.model || "").trim(),
      apiKey: String(parsed.apiKey || "").trim()
    };
  } catch {
    return { baseUrl: "", model: "", apiKey: "" };
  }
}

export function setAiConfig(value) {
  const next = {
    baseUrl: String(value?.baseUrl || "").trim(),
    model: String(value?.model || "").trim(),
    apiKey: String(value?.apiKey || "").trim()
  };

  try {
    localStorage.setItem(AI_KEY, JSON.stringify(next));
  } catch {
    /* ignore storage failures */
  }

  return next;
}

export function isAiConfigured() {
  const config = getAiConfig();
  return Boolean(config.baseUrl && config.model);
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
