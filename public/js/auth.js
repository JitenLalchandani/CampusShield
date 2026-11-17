import {
  api,
  clearSessionToken,
  getApiBase,
  setApiBase,
  setSessionToken
} from "./api.js";
import { esc, icon } from "./ui.js";

export async function fetchAuthStatus() {
  return api("/api/auth/status");
}

export async function createAccount({ name, email, password }) {
  const result = await api("/api/auth/signup", {
    method: "POST",
    body: { name, email, password }
  });

  setSessionToken(result.token);
  return result;
}

export async function signIn({ email, password }) {
  const result = await api("/api/auth/login", {
    method: "POST",
    body: { email, password }
  });

  setSessionToken(result.token);
  return result;
}

export async function signOut() {
  try {
    await api("/api/auth/logout", { method: "POST" });
  } catch {
    /* the local session is cleared even if the server call fails */
  }

  clearSessionToken();
}

export function renderAuthGate(root, { status = null, error = "", onSignedIn }) {
  const signup = Boolean(status?.signupOpen);
  const base = getApiBase();
  const title = signup ? "Create the owner account" : "Sign in to CampusShield";
  const subtitle = signup
    ? "This server has no account yet. The first account becomes the owner and can manage the rest."
    : "Use the account for this CampusShield server.";

  root.innerHTML = `
    <div class="auth-screen">
      <section class="auth-pitch">
        <div class="auth-brand">
          <span class="brand-mark" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 2.8 19 5.6v5.1c0 4.6-3 8.1-7 10.5-4-2.4-7-5.9-7-10.5V5.6L12 2.8Z"/>
              <path d="M9.2 11.8 11.3 14l3.5-4.2"/>
            </svg>
          </span>
          <span>
            <strong>CampusShield</strong>
            <small>Security tests that report real results</small>
          </span>
        </div>

        <h1>Sign in, see what needs attention, and run a real security test.</h1>
        <p>
          CampusShield checks the device it runs on, scans files with signatures and heuristics,
          quarantines what it flags, and explains the results. Scores and detections come from
          those checks, never from a demo dataset.
        </p>

        <ul class="auth-points">
          <li>${icon("shield")}<span>Read-only posture checks: disk encryption, firewall, screen lock, updates, and startup items.</span></li>
          <li>${icon("scan")}<span>Signature and heuristic file scans with quarantine, so a detection can be contained.</span></li>
          <li>${icon("info")}<span>Grounded recommendations. An AI endpoint can explain them, but never decides them.</span></li>
        </ul>
      </section>

      <section class="auth-panel">
        <form class="card auth-card" id="authForm" autocomplete="on">
          <p class="eyebrow">${signup ? "First run" : "Private server"}</p>
          <h2>${esc(title)}</h2>
          <p class="helper">${esc(subtitle)}</p>

          ${error ? `<p class="warning-note" id="authError">${esc(error)}</p>` : ""}

          ${signup ? `
            <label class="field">
              <span>Your name</span>
              <input class="input" id="authName" name="name" type="text" autocomplete="name"
                maxlength="80" placeholder="Meera Patel" required>
            </label>` : ""}

          <label class="field" style="margin-top:12px">
            <span>Email</span>
            <input class="input" id="authEmail" name="email" type="email" autocomplete="username"
              placeholder="you@campus.edu" required>
          </label>

          <label class="field" style="margin-top:12px">
            <span>Password</span>
            <input class="input" id="authPassword" name="password" type="password"
              autocomplete="${signup ? "new-password" : "current-password"}"
              minlength="10" placeholder="At least 10 characters" required>
          </label>

          <details class="auth-server" ${base ? "open" : ""}>
            <summary>Server address</summary>
            <label class="field" style="margin-top:10px">
              <span>API base URL</span>
              <input class="input" id="authBase" type="url" inputmode="url" spellcheck="false"
                placeholder="Same origin (default)" value="${esc(base)}">
            </label>
            <p class="helper">
              Leave blank when this page is served by the CampusShield server.
              Native shells need the full URL, for example
              <span class="mono">http://127.0.0.1:3999</span>.
            </p>
          </details>

          <button class="btn primary wide" id="authSubmit" type="submit">
            ${signup ? "Create account" : "Sign in"}
          </button>

          <p class="tiny" id="authFoot">
            ${signup
              ? "Passwords are hashed with scrypt on the server. The session token stays in this browser."
              : "Sessions last 30 days. Sign out from Settings when you are done."}
          </p>

          ${status === null
            ? `<p class="helper" style="margin-top:10px">Account status could not be read, so this form may be out of date.</p>`
            : ""}
        </form>
      </section>
    </div>
  `;

  const form = root.querySelector("#authForm");
  const submit = root.querySelector("#authSubmit");
  const errorEl = root.querySelector("#authError");

  const showError = message => {
    if (errorEl) {
      errorEl.textContent = message;
      return;
    }

    const note = document.createElement("p");
    note.className = "warning-note";
    note.id = "authError";
    note.textContent = message;
    form.querySelector("#authPassword")?.closest(".field")?.after(note);
  };

  form.addEventListener("submit", async event => {
    event.preventDefault();

    const email = form.querySelector("#authEmail").value.trim();
    const password = form.querySelector("#authPassword").value;
    const name = form.querySelector("#authName")?.value.trim() || "";
    const baseValue = form.querySelector("#authBase")?.value ?? "";
    const passwordField = form.querySelector("#authPassword");

    if (signup && !name) {
      showError("Enter the name the owner account should use.");
      return;
    }

    if (!email) {
      showError("Enter the email for this account.");
      return;
    }

    if (password.length < 10) {
      showError("Use at least 10 characters. Long passphrases are easier to remember.");
      passwordField?.focus();
      return;
    }

    if (String(getApiBase()) !== String(baseValue || "").trim().replace(/\/+$/, "")) {
      setApiBase(baseValue);
    }

    submit.disabled = true;
    submit.textContent = signup ? "Creating…" : "Signing in…";

    try {
      const result = signup
        ? await createAccount({ name, email, password })
        : await signIn({ email, password });
      onSignedIn(result);
    } catch (failure) {
      submit.disabled = false;
      submit.textContent = signup ? "Create account" : "Sign in";

      if (failure.status === 409 && signup) {
        showError("This server already has an account. Reload to sign in instead.");
        form.querySelector("#authFoot").textContent = "Reload the page to switch to sign-in.";
        return;
      }

      showError(failure.message || "Could not reach the CampusShield API.");
    }
  });
}
