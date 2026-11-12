import { api } from "../api.js";
import {
  canHashPasswords,
  checkBreachedPassword,
  inspectUrl
} from "../tools.js";
import {
  dateTime,
  emptyState,
  esc,
  icon,
  num,
  relativeTime,
  toast
} from "../ui.js";

export const meta = {
  eyebrow: "Protection",
  title: "Device safety",
  subtitle: "One score across every device you add, with read-only checks and plain-language findings."
};

const RING_RADIUS = 52;
const RING_LENGTH = 2 * Math.PI * RING_RADIUS;

const KIND_ICONS = {
  computer: "computer",
  phone: "phone",
  tablet: "tablet",
  browser: "browser"
};

const CHECK_STATE = {
  pass: { tone: "ok", label: "Passed" },
  info: { tone: "info", label: "For review" },
  warn: { tone: "warn", label: "Needs action" },
  fail: { tone: "warn", label: "Needs action" },
  unknown: { tone: "idle", label: "Unverified" }
};

const CHECK_ORDER = { fail: 0, warn: 0, unknown: 1, pass: 2, info: 3 };

let checking = false;

export async function render(root) {
  root.innerHTML = `
    <div class="loading-state">
      <span class="spinner" aria-hidden="true"></span>
      <p>Loading the cross-device score…</p>
    </div>
  `;

  const [protection, summary] = await Promise.all([
    api("/api/protection"),
    api("/api/summary")
  ]);

  const devices = Array.isArray(protection.devices) ? protection.devices : [];
  const score = protection.summary?.average;
  const host = devices.find(device => device.role === "host") || null;
  const checked = Array.isArray(host?.checks) ? host.checks : [];
  const attention = checked.filter(check => check.status === "fail" || check.status === "warn");
  const tone = scoreTone(score);

  root.innerHTML = `
    <section class="card score-hero" data-tone="${tone}">
      <div class="score-ring" role="img" aria-label="${score == null ? "Safety score not checked" : `Safety score ${score} out of 100, ${esc(protection.summary.grade)}`}">
        <svg viewBox="0 0 120 120" aria-hidden="true">
          <circle class="ring-track" cx="60" cy="60" r="${RING_RADIUS}"></circle>
          <circle class="ring-value" cx="60" cy="60" r="${RING_RADIUS}"
            style="stroke-dasharray:${ringLength(score)} ${RING_LENGTH.toFixed(1)}"></circle>
        </svg>
        <div class="ring-text">
          <strong>${score == null ? "—" : num(score)}</strong>
          <span>${score == null ? "not checked" : "/ 100"}</span>
        </div>
      </div>

      <div class="score-copy">
        <p class="eyebrow">Cross-device safety score</p>
        <h2>${esc(protection.summary?.grade || "Not checked")}</h2>
        <p class="score-sub">
          ${protection.summary?.checked
            ? `Average of ${num(protection.summary.checked)} checked device${protection.summary.checked === 1 ? "" : "s"} of ${num(protection.summary.total)} linked.${protection.summary.weakest ? ` Weakest: ${esc(protection.summary.weakest.name)} at ${num(protection.summary.weakest.score)}.` : ""}`
            : "No device has been checked yet. Run a check on this computer to start the score."}
        </p>
        <div class="form-row">
          <button class="btn primary" id="checkDevice" type="button"
            ${protection.auditAvailable ? "" : "disabled"}
            title="${protection.auditAvailable ? "Run read-only checks on this Mac" : "Device checks are currently implemented for macOS hosts"}">
            ${icon("scan")} Check this computer
          </button>
          <button class="btn ghost" id="linkDevice" type="button">${icon("plus")} Link a device</button>
        </div>
        <p class="helper">
          ${protection.auditAvailable
            ? `Read-only checks run on the server host (${esc(protection.platformLabel)}). No setting is changed and no malware scan is performed.`
            : `Checks are implemented for macOS hosts. This host reports ${esc(protection.platformLabel)}, so link devices from the app instead.`}
          Rules ${esc(protection.rulesVersion)}.
        </p>
      </div>
    </section>

    <form class="card link-form" id="linkForm" hidden>
      <div class="card-head">
        <div>
          <h2>Link a device</h2>
          <p>Add a phone, tablet, or second computer to the shared score</p>
        </div>
        <button class="icon-btn" type="button" data-close-link aria-label="Close">${icon("x")}</button>
      </div>
      <div class="link-fields">
        <label class="field">
          <span>Device name</span>
          <input class="input" name="name" maxlength="60" placeholder="e.g. Aarav's iPad" required>
        </label>
        <label class="field">
          <span>Type</span>
          <select class="select" name="kind">
            <option value="phone">Phone</option>
            <option value="tablet">Tablet</option>
            <option value="computer">Computer</option>
            <option value="browser">Browser</option>
          </select>
        </label>
        <label class="field">
          <span>Platform</span>
          <select class="select" name="platform">
            <option value="ios">iOS / iPadOS</option>
            <option value="android">Android</option>
            <option value="darwin">macOS</option>
            <option value="win32">Windows</option>
            <option value="linux">Linux</option>
            <option value="web">Web browser</option>
          </select>
        </label>
      </div>
      <div class="form-row">
        <button class="btn primary" type="submit">Add device</button>
        <p class="helper" style="margin:0">
          A linked device starts as “Not checked” and only affects the average
          after it runs its own check.
        </p>
      </div>
    </form>

    <section class="card protect-section">
      <div class="card-head">
        <div>
          <h2>Devices</h2>
          <p>Every device included in the shared score</p>
        </div>
        <span class="chip">${num(protection.summary?.total || 0)} linked</span>
      </div>
      ${devices.length
        ? `<div class="device-list">${devices.map(deviceRow).join("")}</div>`
        : `<div data-empty-device>${emptyState({
            iconName: "computer",
            title: "No devices yet",
            body: "Check this computer or link a phone, tablet, or second computer.",
            actionLabel: "Check this computer",
            actionAttrs: 'data-action="device-check"'
          })}</div>`}
    </section>

    <section class="card protect-section">
      <div class="card-head">
        <div>
          <h2>Findings on this computer</h2>
          <p>${host?.checkedAt ? `Checked ${esc(dateTime(host.checkedAt))}` : "Read-only posture checks"}</p>
        </div>
        ${attention.length
          ? `<span class="chip warn-chip">${num(attention.length)} to fix</span>`
          : `<span class="chip">${checked.length ? "No action found" : "Not checked"}</span>`}
      </div>
      ${checked.length
        ? `<ul class="check-list">${checked.slice().sort((a, b) => (CHECK_ORDER[a.status] ?? 4) - (CHECK_ORDER[b.status] ?? 4)).map(checkRow).join("")}</ul>`
        : emptyState({
            iconName: "shield",
            title: protection.auditAvailable ? "This computer has not been checked" : "Checks are macOS-only today",
            body: protection.auditAvailable
              ? "Run a device check to collect FileVault, firewall, Gatekeeper, update, and login-item status."
              : "The iOS and Android builds report a narrower set of signals. See Coverage for what is available on each platform.",
            actionLabel: protection.auditAvailable ? "Run a check" : "",
            actionAttrs: 'data-action="device-check"'
          })}
    </section>

    <section class="panel-grid two">
      <article class="card">
        <div class="card-head">
          <div>
            <h2>Link inspector</h2>
            <p>Pattern checks before you tap a link</p>
          </div>
          <span class="chip">${icon("link")} No live blocklist</span>
        </div>
        <form class="tool-form" id="linkToolForm">
          <label class="field">
            <span>Link to inspect</span>
            <input class="input" id="linkToolInput" type="text" inputmode="url" autocomplete="off"
              spellcheck="false" placeholder="https://example.com/sign-in">
          </label>
          <button class="btn subtle" type="submit">Inspect link</button>
        </form>
        <div id="linkToolResult" class="tool-result"></div>
        <p class="helper">
          Checks run in this browser: scheme, encoded characters, shortened
          domains, brand lookalikes, and risky domain endings. The link is never
          opened.
        </p>
      </article>

      <article class="card">
        <div class="card-head">
          <div>
            <h2>Breached password check</h2>
            <p>Has this password appeared in a public breach?</p>
          </div>
          <span class="chip">${icon("lock")} k-anonymity</span>
        </div>
        <form class="tool-form" id="passwordToolForm">
          <label class="field">
            <span>Password</span>
            <input class="input" id="passwordToolInput" type="password" autocomplete="off"
              spellcheck="false" placeholder="Never stored or sent">
          </label>
          <button class="btn subtle" type="submit">Check password</button>
        </form>
        <div id="passwordToolResult" class="tool-result"></div>
        <p class="helper">
          ${canHashPasswords()
            ? "The password is hashed in this browser. Only the first five characters of the hash go to the Pwned Passwords API — the password and full hash stay on this device."
            : "This page needs HTTPS (or localhost) before the browser will allow local hashing. The password check is unavailable here."}
        </p>
      </article>
    </section>

    <section class="panel-grid two">
      <article class="card">
        <div class="card-head">
          <div>
            <h2>Campus threat signals</h2>
            <p>Telemetry received by this workspace</p>
          </div>
          <a class="link" href="#/threats">Open queue</a>
        </div>
        <div class="signal-row">
          <div class="signal"><strong>${num(summary.eventsTotal)}</strong><span>events received</span></div>
          <div class="signal"><strong>${num(summary.highPriority)}</strong><span>open high priority</span></div>
          <div class="signal"><strong>${num(summary.auditTotal)}</strong><span>audit entries</span></div>
        </div>
        <p class="helper">
          ${summary.eventsTotal
            ? "Events come from the macOS log scanner or an approved source. They are indicators for review, not proof of an attack."
            : "Nothing has been received yet. Run the macOS log scan from Coverage, or connect an approved source."}
        </p>
      </article>

      <article class="card">
        <div class="card-head">
          <div>
            <h2>How the score works</h2>
            <p>Explainable by design</p>
          </div>
          <span class="chip">${esc(protection.rulesVersion)}</span>
        </div>
        <ul class="checklist">
          <li>${icon("check")}<span>Every check starts at 100. A critical finding costs 30 points, high 18, medium 10, low 4. Info and unverified checks cost nothing.</span></li>
          <li>${icon("check")}<span>95+ is Protected, 80+ Good, 60+ Needs attention, below 60 At risk.</span></li>
          <li>${icon("check")}<span>The shared score is the average of checked devices. Linked devices count only after their own check runs.</span></li>
          <li>${icon("info")}<span>This build reports posture and privacy risks. It does not scan for malware, block traffic, or replace a system antivirus.</span></li>
        </ul>
      </article>
    </section>
  `;

  bind(root);
}

function bind(root) {
  root.querySelectorAll("#checkDevice, [data-action='device-check']").forEach(button => {
    button.addEventListener("click", () => runDeviceCheck(root));
  });

  const linkForm = root.querySelector("#linkForm");
  const linkToggle = root.querySelector("#linkDevice");

  linkToggle?.addEventListener("click", () => {
    linkForm.hidden = false;
    linkForm.querySelector("input[name='name']")?.focus();
  });

  root.querySelector("[data-close-link]")?.addEventListener("click", () => {
    linkForm.hidden = true;
  });

  linkForm?.addEventListener("submit", async event => {
    event.preventDefault();

    const data = new FormData(linkForm);
    const name = String(data.get("name") || "").trim();

    if (!name) {
      toast("Give the device a name.", { type: "error" });
      return;
    }

    const submit = linkForm.querySelector("button[type='submit']");
    submit.disabled = true;
    submit.textContent = "Adding…";

    try {
      const result = await api("/api/devices", {
        method: "POST",
        body: {
          name,
          kind: data.get("kind"),
          platform: data.get("platform"),
          source: "web"
        }
      });

      toast(`Linked ${result.device.name}. Run a check on it to add its score.`, { type: "success" });
      await render(root);
    } catch (error) {
      toast(error.message, { type: "error" });
      submit.disabled = false;
      submit.textContent = "Add device";
    }
  });

  root.querySelectorAll("[data-remove-device]").forEach(button => {
    button.addEventListener("click", async () => {
      const id = button.dataset.removeDevice;
      const confirmed = window.confirm("Remove this device from the shared score?");

      if (!confirmed) return;

      button.disabled = true;

      try {
        await api(`/api/devices/${encodeURIComponent(id)}`, { method: "DELETE" });
        toast("Device removed from the shared score.", { type: "success" });
        await render(root);
      } catch (error) {
        toast(error.message, { type: "error" });
        button.disabled = false;
      }
    });
  });

  root.querySelector("#linkToolForm")?.addEventListener("submit", event => {
    event.preventDefault();
    const input = root.querySelector("#linkToolInput");
    const result = root.querySelector("#linkToolResult");

    try {
      result.innerHTML = linkResult(inspectUrl(input.value));
    } catch (error) {
      result.innerHTML = `<p class="tool-error">${esc(error.message)}</p>`;
    }
  });

  root.querySelector("#passwordToolForm")?.addEventListener("submit", async event => {
    event.preventDefault();

    const input = root.querySelector("#passwordToolInput");
    const result = root.querySelector("#passwordToolResult");
    const button = event.currentTarget.querySelector("button[type='submit']");

    if (!canHashPasswords()) {
      result.innerHTML = `<p class="tool-error">${esc("This page needs HTTPS or localhost to hash the password locally.")}</p>`;
      return;
    }

    button.disabled = true;
    button.textContent = "Checking…";
    result.innerHTML = `<p class="helper">Hashing locally and asking Pwned Passwords for the range…</p>`;

    try {
      const outcome = await checkBreachedPassword(input.value);

      result.innerHTML = outcome.breached
        ? `<div class="tool-verdict warn">${icon("alert")} Seen in a breach</div>
           <p class="tool-copy">This password appears in public breach data <strong>${num(outcome.times)}</strong> time${outcome.times === 1 ? "" : "s"}. Stop using it anywhere and change every account that shares it.</p>`
        : `<div class="tool-verdict ok">${icon("check")} Not in the breach list</div>
           <p class="tool-copy">No match in the Pwned Passwords dataset. That is not proof of strength — use a unique password per account and turn on two-factor authentication.</p>`;
    } catch (error) {
      result.innerHTML = `<p class="tool-error">${esc(error.message)}</p>`;
    } finally {
      button.disabled = false;
      button.textContent = "Check password";
    }
  });
}

async function runDeviceCheck(root) {
  if (checking) return;

  checking = true;

  const buttons = [...root.querySelectorAll("#checkDevice, [data-action='device-check']")];
  buttons.forEach(button => {
    button.disabled = true;
    button.classList.add("spinning");
  });

  try {
    const result = await api("/api/protection/scan", { method: "POST" });
    toast(
      `Check complete · ${result.device.score}/100 (${result.device.grade}) · ` +
      `${result.device.summary.attention} to fix, ${result.device.summary.unverified} unverified.`,
      { type: result.device.summary.attention ? "info" : "success", timeout: 6500 }
    );
    await render(root);
  } catch (error) {
    toast(error.message, { type: "error", timeout: 6000 });
    buttons.forEach(button => {
      button.disabled = false;
      button.classList.remove("spinning");
    });
  } finally {
    checking = false;
  }
}

function ringLength(score) {
  if (!Number.isFinite(score)) return 0;
  return Math.max(0, Math.min(100, score)) / 100 * RING_LENGTH;
}

function scoreTone(score) {
  if (!Number.isFinite(score)) return "idle";
  if (score >= 95) return "good";
  if (score >= 80) return "ok";
  if (score >= 60) return "warn";
  return "risk";
}

function deviceRow(device) {
  const tone = scoreTone(device.score);
  const checks = Array.isArray(device.checks) ? device.checks : [];
  const attention = checks.filter(check => check.status === "fail" || check.status === "warn").length;

  return `
    <article class="device-card" data-tone="${tone}">
      <div class="device-top">
        <span class="device-icon">${icon(KIND_ICONS[device.kind] || "computer")}</span>
        <div class="device-id">
          <strong>${esc(device.name)}</strong>
          <span class="device-sub">
            ${esc(device.platformLabel || device.platform)}
            ${device.model ? ` · ${esc(device.model)}` : ""}
            · ${device.role === "host" ? "This computer" : "Linked device"}
          </span>
        </div>
        <span class="device-score" data-tone="${tone}">
          ${device.score == null ? "—" : num(device.score)}
          <small>${device.score == null ? "not checked" : "/100"}</small>
        </span>
      </div>
      <div class="device-meta">
        <span class="state-pill ${tone === "good" || tone === "ok" ? "on" : tone === "warn" || tone === "risk" ? "warn" : ""}">${esc(device.grade)}</span>
        <span class="device-when">
          ${device.checkedAt ? `Checked ${esc(relativeTime(device.checkedAt))}` : "Waiting for its first check"}
          ${checks.length ? ` · ${checks.length - attention} passed · ${attention} to fix` : ""}
        </span>
        ${device.role === "host"
          ? ""
          : `<button class="link danger-link" type="button" data-remove-device="${esc(device.id)}">Remove</button>`}
      </div>
    </article>
  `;
}

function checkRow(check) {
  const state = CHECK_STATE[check.status] || CHECK_STATE.info;
  const isActionable = check.status === "fail" || check.status === "warn";

  return `
    <li class="check-item" data-tone="${state.tone}">
      <span class="check-dot" aria-hidden="true"></span>
      <div class="check-body">
        <div class="check-title">
          <span>${esc(check.title)}</span>
          <span class="check-state">${esc(state.label)}${isActionable && check.severity ? ` · ${esc(String(check.severity).toUpperCase())}` : ""}</span>
        </div>
        <p class="check-detail">${esc(check.detail)}</p>
        ${isActionable && check.recommendation ? `<p class="check-reco">${esc(check.recommendation)}</p>` : ""}
      </div>
    </li>
  `;
}

function linkResult(result) {
  const details = result.findings.map(item => `
    <li class="tool-finding" data-tone="${item.tone}">
      <strong>${esc(item.title)}</strong>
      <span>${esc(item.detail)}</span>
    </li>
  `).join("");

  return `
    <div class="tool-verdict ${result.verdict.tone}">
      ${icon(result.verdict.tone === "ok" ? "check" : "alert")}
      ${esc(result.verdict.label)}
    </div>
    <p class="tool-copy"><span class="mono">${esc(result.host)}</span></p>
    ${details ? `<ul class="tool-findings">${details}</ul>` : ""}
    <p class="helper">${esc(result.note)}</p>
  `;
}
