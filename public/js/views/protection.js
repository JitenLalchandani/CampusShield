import { api, isAiConfigured } from "../api.js";
import { explainThreat, summarizeProtection } from "../ai.js";
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
  scanProof,
  toast
} from "../ui.js";
import { bindShieldCard, renderShieldCard } from "./shield.js";
import { bindUsbCard, renderUsbCard } from "./usb.js";

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
let pollTimer = null;
let aiExplain = null;
let aiSummary = null;
let lastThreatKeys = null;

export async function render(root) {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }

  root.innerHTML = `
    <div class="loading-state">
      <span class="spinner" aria-hidden="true"></span>
      <p>Loading the cross-device score…</p>
    </div>
  `;

  const [protection, summary, shieldStatus, shieldAlerts, usbStatus, usbEvents] = await Promise.all([
    api("/api/protection"),
    api("/api/summary"),
    api("/api/shield").catch(() => null),
    api("/api/shield/alerts?limit=10").then(data => data.alerts || []).catch(() => []),
    api("/api/usb").catch(() => null),
    api("/api/usb/events?limit=10").then(data => data.events || []).catch(() => [])
  ]);

  const devices = Array.isArray(protection.devices) ? protection.devices : [];
  const score = protection.summary?.average;
  const host = devices.find(device => device.role === "host") || null;
  const checked = Array.isArray(host?.checks) ? host.checks : [];
  const attention = checked.filter(check => check.status === "fail" || check.status === "warn");
  const tone = scoreTone(score);

  const scanner = protection.scanner || {};
  const scans = Array.isArray(protection.scans) ? protection.scans : [];
  const quarantine = Array.isArray(protection.quarantine) ? protection.quarantine : [];
  const openByPath = new Map();

  for (const scan of scans) {
    for (const threat of scan.threats || []) {
      if (threat.status === "detected" && !openByPath.has(threat.filePath)) {
        openByPath.set(threat.filePath, { ...threat, scanId: scan.id });
      }
    }
  }

  const openThreats = [...openByPath.values()];
  const lastScan = scans.find(scan => scan.scope !== "realtime") || null;
  const lastScanOpen = lastScan
    ? (lastScan.threats || []).filter(threat => threat.status === "detected").length
    : 0;
  const activeScan = scanner.active || null;
  const coverage = scanCoverage(lastScan);
  const coverageWarning = coverage.blocked.length
    ? `<div class="scan-warning">${icon("alert")} <span><strong>${num(coverage.blocked.length)} folder${coverage.blocked.length === 1 ? "" : "s"} could not be read.</strong> macOS blocked access to ${esc(coverage.blocked.join(", "))}. Only ${num(lastScan.filesScanned)} file${lastScan.filesScanned === 1 ? "" : "s"} were checked. Grant CampusShield Full Disk Access in System Settings → Privacy &amp; Security, then scan again.</span></div>`
    : "";

  const aiReady = isAiConfigured();
  const schedule = scanner.preferences?.schedule || null;
  const scheduleLine = schedule?.enabled
    ? `Scheduled ${schedule.scope === "full" ? "full" : "quick"} scan ${
        schedule.frequency === "weekly"
          ? `every ${["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"][schedule.weekday] || "Monday"}`
          : "daily"
      } at ${esc(schedule.time)}${scanner.scheduleNextRunAt ? ` · next ${esc(dateTime(scanner.scheduleNextRunAt))}` : ""}.`
    : "";

  notifyNewThreats(openThreats, scanner.preferences);

  const explainPanel = aiExplain
    ? `<div class="ai-output" data-tone="${aiExplain.error ? "warn" : "ok"}">
         <div class="ai-output-head">
           <strong>${icon("shield")} AI explanation${aiExplain.name ? ` · ${esc(aiExplain.name)}` : ""}</strong>
           <button class="icon-btn" type="button" data-close-explain aria-label="Close">${icon("x")}</button>
         </div>
         <p class="ai-text">${esc(aiExplain.text)}</p>
         ${aiExplain.disclaimer ? `<p class="helper">${esc(aiExplain.disclaimer)}</p>` : ""}
       </div>`
    : "";

  const aiSummaryCard = `
    <section class="card protect-section">
      <div class="card-head">
        <div>
          <h2>AI assistant</h2>
          <p>Plain-language summary of the findings above</p>
        </div>
        <span class="chip">${aiReady ? "Your provider" : "Not configured"}</span>
      </div>
      ${aiReady
        ? `<div class="form-row">
             <button class="btn subtle" id="aiSummaryBtn" type="button">Summarize findings</button>
             ${aiSummary ? `<button class="link" type="button" data-clear-summary>Clear</button>` : ""}
           </div>
           ${aiSummary
             ? `<div class="ai-output" data-tone="${aiSummary.error ? "warn" : "ok"}">
                  <p class="ai-text">${esc(aiSummary.text)}</p>
                  <p class="helper">${esc(aiSummary.disclaimer || "AI guidance is advisory; detection stays local.")}</p>
                </div>`
             : ""}`
        : `<p class="helper" style="margin-top:0">
             Connect an OpenAI-compatible endpoint in <a class="link" href="#/settings">Settings → AI assistant</a>
             to explain findings in plain language. The assistant is optional and never decides a detection.
           </p>`}
    </section>
  `;

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
            title="${protection.auditAvailable ? "Run read-only checks on this computer" : "Device checks are implemented for macOS and Windows hosts"}">
            ${icon("scan")} Check this computer
          </button>
          <button class="btn ghost" id="linkDevice" type="button">${icon("plus")} Link a device</button>
        </div>
        <p class="helper">
          ${protection.auditAvailable
            ? `Read-only checks run on the server host (${esc(protection.platformLabel)}). No setting is changed. File scanning is a separate, read-only pass you start below.`
            : `Checks are implemented for macOS and Windows hosts. This host reports ${esc(protection.platformLabel)}, so link devices from the app instead.`}
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

    ${renderShieldCard(shieldStatus, shieldAlerts)}

    ${renderUsbCard(usbStatus, usbEvents)}

    <section class="card protect-section scan-section" id="scanSection">
      <div class="card-head">
        <div>
          <h2>Malware scan</h2>
          <p>${lastScan
            ? `Last ${esc(lastScan.scope)} scan ${esc(relativeTime(lastScan.finishedAt || lastScan.startedAt))} · ${esc(scanProof(lastScan))} · ${num(lastScanOpen)} open threat${lastScanOpen === 1 ? "" : "s"}`
            : "Signature and heuristic checks on files on this computer"}${scheduleLine ? ` ${scheduleLine}` : ""}</p>
        </div>
        <span class="chip">${icon("scan")} ${num(scanner.signatureCount || 0)} signature${scanner.signatureCount === 1 ? "" : "s"}</span>
      </div>

      <div class="form-row">
        <button class="btn primary" type="button" data-scan="quick" ${activeScan ? "disabled" : ""}>${icon("scan")} Quick scan</button>
        <button class="btn ghost" type="button" data-scan="full" ${activeScan ? "disabled" : ""}>Full scan</button>
        <button class="btn ghost" type="button" id="cancelScan" data-scan-id="${activeScan ? esc(activeScan.id) : ""}" ${activeScan ? "" : "hidden"}>Cancel scan</button>
      </div>

      <div class="custom-scan">
        <input class="input" id="customScanPath" type="text" spellcheck="false" autocomplete="off"
          placeholder="Scan a specific folder or file…" ${activeScan ? "disabled" : ""}>
        <button class="btn ghost" type="button" id="customScanBtn" ${activeScan ? "disabled" : ""}>Scan path</button>
      </div>

      <div class="scan-progress" id="scanProgress" ${activeScan ? "" : "hidden"}>
        <div class="scan-bar"><span id="scanBarFill"></span></div>
        <p class="helper" id="scanProgressText">Preparing the scan…</p>
      </div>

      ${explainPanel}

      ${openThreats.length
        ? `<div class="threat-head">
             <strong>${num(openThreats.length)} threat${openThreats.length === 1 ? "" : "s"} need a decision</strong>
             <span>Quarantine moves the file into the app vault. Nothing is deleted until you say so.</span>
           </div>
           <div class="threat-list">${openThreats.slice(0, 25).map(threatRow).join("")}</div>
           ${openThreats.length > 25 ? `<p class="helper">Showing 25 of ${num(openThreats.length)}. Quarantine or delete these to see the rest.</p>` : ""}
           ${coverageWarning}`
        : lastScan
          ? `<div class="scan-clear">${icon("check")} <span>No open threats. ${lastScan.truncated ? `The last scan stopped early (${esc(lastScan.stopReason || "limit reached")}) — run a full scan when you have time.` : coverage.blocked.length ? "Nothing was found in the files it could read — this is not a clean result." : "The last scan found nothing that needs action."}</span></div>
             ${coverageWarning}`
          : emptyState({
              iconName: "shield",
              title: "No scan has run yet",
              body: "A quick scan checks Downloads, Desktop, Documents, and launch agents. A full scan adds your whole home folder and system app folders.",
              actionLabel: "Run a quick scan",
              actionAttrs: 'data-action="scan-quick"'
            })}

      <div class="watch-row">
        <div class="watch-copy">
          <strong>Real-time folder watch</strong>
          <span>${scanner.watch?.enabled
            ? `Watching ${num(scanner.watch.roots?.length || 0)} folders since ${esc(relativeTime(scanner.watch.startedAt))} · ${num(scanner.watch.alerts || 0)} alerts`
            : "Flags new files as they land in your quick-scan folders"}</span>
        </div>
        <button class="btn subtle" type="button" id="watchToggle" ${scanner.watchSupported ? "" : "disabled"}>
          ${scanner.watch?.enabled ? "Stop watching" : "Start watching"}
        </button>
      </div>
      <p class="helper">
        ${scanner.watchSupported
          ? "The watch works in your user session: it sees files as they appear and scans them, but the operating system does not let a user-space app block execution. Kernel-level blocking needs an Apple Endpoint Security entitlement or a signed Windows driver, which this build does not ship."
          : "Folder watching is not available on this platform build."}
        Signatures: ${esc(scanner.signatureVersion || "unknown")}. ${esc(scanner.signatureNote || "")}
        ${scanner.signatureWarnings?.length ? ` ${esc(scanner.signatureWarnings.join(" "))}` : ""}
        ${scanner.remoteFeed?.state === "loaded"
          ? ` Remote feed: ${num(scanner.remoteFeed.added)} new hash${scanner.remoteFeed.added === 1 ? "" : "es"} from ${esc(scanner.remoteFeed.url)}.`
          : scanner.remoteFeed?.state === "error"
            ? ` Remote feed failed: ${esc(scanner.remoteFeed.message || "unknown error")}.`
            : scanner.remoteFeed?.state === "pending"
              ? " Remote feed: loading…"
              : ""}
      </p>
    </section>

    ${aiSummaryCard}

    ${quarantine.length
      ? `<section class="card protect-section">
          <div class="card-head">
            <div>
              <h2>Quarantine</h2>
              <p>Files held in the app vault. They are not on your normal folders.</p>
            </div>
            <span class="chip">${num(quarantine.length)} held</span>
          </div>
          <div class="quarantine-list">
            ${quarantine.map(quarantineRow).join("")}
          </div>
        </section>`
      : ""}

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
            title: protection.auditAvailable ? "This computer has not been checked" : "No posture checks on this platform",
            body: protection.auditAvailable
              ? "Run a device check to collect disk encryption, firewall, antivirus, update, and login-item status."
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
          <li>${icon("check")}<span>Open malware findings cost the same amounts, capped at 45 points per device. Quarantining or deleting a file removes its penalty.</span></li>
          <li>${icon("check")}<span>95+ is Protected, 80+ Good, 60+ Needs attention, below 60 At risk.</span></li>
          <li>${icon("check")}<span>The shared score is the average of checked devices. Linked devices count only after their own check runs.</span></li>
          <li>${icon("info")}<span>Scanning compares files against the loaded signature set and local heuristics. It does not block traffic, inspect running memory, or replace a system antivirus.</span></li>
        </ul>
      </article>
    </section>
  `;

  bind(root);
  bindShieldCard(root, () => render(root));
  bindUsbCard(root, () => render(root));

  if (activeScan) pollScan(root, activeScan.id);
}

function bind(root) {
  root.querySelectorAll("#checkDevice, [data-action='device-check']").forEach(button => {
    button.addEventListener("click", () => runDeviceCheck(root));
  });

  root.querySelectorAll("[data-scan]").forEach(button => {
    button.addEventListener("click", () => startScan(root, button.dataset.scan));
  });

  root.querySelectorAll("[data-action='scan-quick']").forEach(button => {
    button.addEventListener("click", () => startScan(root, "quick"));
  });

  root.querySelector("#customScanBtn")?.addEventListener("click", () => {
    startScan(root, "custom", root.querySelector("#customScanPath")?.value || "");
  });

  root.querySelector("#customScanPath")?.addEventListener("keydown", event => {
    if (event.key !== "Enter") return;
    event.preventDefault();
    startScan(root, "custom", event.currentTarget.value || "");
  });

  root.querySelectorAll("[data-explain]").forEach(button => {
    button.addEventListener("click", async () => {
      if (!isAiConfigured()) {
        toast("Connect an AI endpoint in Settings → AI assistant first.", { type: "info", timeout: 6000 });
        return;
      }

      const [scanId, threatId] = String(button.dataset.explain).split(":");
      const name = button.closest(".threat-item")?.querySelector(".threat-title strong")?.textContent || "";
      const label = button.textContent;

      button.disabled = true;
      button.textContent = "Explaining…";

      try {
        const data = await explainThreat(scanId, threatId);
        aiExplain = {
          key: `${scanId}:${threatId}`,
          name,
          text: data.reply,
          disclaimer: data.disclaimer
        };
        await render(root);
      } catch (error) {
        toast(error.message, { type: "error", timeout: 7000 });
        button.disabled = false;
        button.textContent = label;
      }
    });
  });

  root.querySelector("[data-close-explain]")?.addEventListener("click", async () => {
    aiExplain = null;
    await render(root);
  });

  root.querySelector("#aiSummaryBtn")?.addEventListener("click", async event => {
    const button = event.currentTarget;

    button.disabled = true;
    button.textContent = "Summarizing…";

    try {
      const data = await summarizeProtection();
      aiSummary = { text: data.reply, disclaimer: data.disclaimer };
      await render(root);
    } catch (error) {
      toast(error.message, { type: "error", timeout: 7000 });
      button.disabled = false;
      button.textContent = "Summarize findings";
    }
  });

  root.querySelector("[data-clear-summary]")?.addEventListener("click", async () => {
    aiSummary = null;
    await render(root);
  });

  root.querySelector("#cancelScan")?.addEventListener("click", async event => {
    const button = event.currentTarget;
    const scanId = button.dataset.scanId;

    if (!scanId) return;

    button.disabled = true;

    try {
      await api(`/api/scans/${encodeURIComponent(scanId)}/cancel`, { method: "POST" });
      toast("Scan cancelled.", { type: "info" });
    } catch (error) {
      toast(error.message, { type: "error" });
      button.disabled = false;
    }
  });

  root.querySelectorAll("[data-quarantine]").forEach(button => {
    button.addEventListener("click", async () => {
      const [scanId, threatId] = String(button.dataset.quarantine).split(":");
      button.disabled = true;

      try {
        await api(
          `/api/threats/${encodeURIComponent(scanId)}/${encodeURIComponent(threatId)}/quarantine`,
          { method: "POST" }
        );
        toast("File moved to quarantine.", { type: "success" });
        await render(root);
      } catch (error) {
        toast(error.message, { type: "error" });
        button.disabled = false;
      }
    });
  });

  root.querySelectorAll("[data-delete-threat]").forEach(button => {
    button.addEventListener("click", async () => {
      if (!window.confirm("Delete this file permanently? This cannot be undone.")) return;

      const [scanId, threatId] = String(button.dataset.deleteThreat).split(":");
      button.disabled = true;

      try {
        await api(
          `/api/threats/${encodeURIComponent(scanId)}/${encodeURIComponent(threatId)}`,
          { method: "DELETE" }
        );
        toast("File deleted.", { type: "success" });
        await render(root);
      } catch (error) {
        toast(error.message, { type: "error" });
        button.disabled = false;
      }
    });
  });

  root.querySelectorAll("[data-restore-q]").forEach(button => {
    button.addEventListener("click", async () => {
      button.disabled = true;

      try {
        await api(`/api/quarantine/${encodeURIComponent(button.dataset.restoreQ)}/restore`, { method: "POST" });
        toast("File restored to its original folder.", { type: "success" });
        await render(root);
      } catch (error) {
        toast(error.message, { type: "error" });
        button.disabled = false;
      }
    });
  });

  root.querySelectorAll("[data-delete-q]").forEach(button => {
    button.addEventListener("click", async () => {
      if (!window.confirm("Delete this quarantined file permanently?")) return;

      button.disabled = true;

      try {
        await api(`/api/quarantine/${encodeURIComponent(button.dataset.deleteQ)}`, { method: "DELETE" });
        toast("Quarantined file deleted.", { type: "success" });
        await render(root);
      } catch (error) {
        toast(error.message, { type: "error" });
        button.disabled = false;
      }
    });
  });

  root.querySelector("#watchToggle")?.addEventListener("click", async event => {
    const button = event.currentTarget;
    const enabled = !/stop/i.test(button.textContent);

    button.disabled = true;

    try {
      await api("/api/scanner/watch", { method: "POST", body: { enabled } });
      toast(
        enabled ? "Real-time watch started for your quick-scan folders." : "Real-time watch stopped.",
        { type: "success" }
      );
      await render(root);
    } catch (error) {
      toast(error.message, { type: "error" });
      button.disabled = false;
    }
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

async function startScan(root, scope, target = null) {
  const customPath = String(target || "").trim();

  if (scope === "custom" && !customPath) {
    toast("Enter a folder or full file path to scan.", { type: "error" });
    return;
  }

  const buttons = [...root.querySelectorAll("[data-scan]")];
  const customButton = root.querySelector("#customScanBtn");
  const customInput = root.querySelector("#customScanPath");

  if (buttons.some(button => button.disabled) || customButton?.disabled) return;

  buttons.forEach(button => {
    button.disabled = true;
  });

  if (customButton) customButton.disabled = true;
  if (customInput) customInput.disabled = true;

  const progress = root.querySelector("#scanProgress");
  const progressText = root.querySelector("#scanProgressText");

  if (progress) progress.hidden = false;
  if (progressText) progressText.textContent = "Collecting folders and starting the scan…";

  try {
    const result = await api("/api/scans", {
      method: "POST",
      body: scope === "custom" ? { scope: "custom", path: customPath } : { scope: scope === "full" ? "full" : "quick" }
    });

    toast(
      `${scanLabel(scope)} scan started. It runs in the background — you can keep using the app.`,
      { type: "info" }
    );

    const cancel = root.querySelector("#cancelScan");

    if (cancel && result.scan?.id) {
      cancel.hidden = false;
      cancel.disabled = false;
      cancel.dataset.scanId = result.scan.id;
    }

    pollScan(root, result.scan?.id);
  } catch (error) {
    toast(error.message, { type: "error" });
    buttons.forEach(button => {
      button.disabled = false;
    });
    if (customButton) customButton.disabled = false;
    if (customInput) customInput.disabled = false;
    if (progress) progress.hidden = true;
  }
}

function pollScan(root, scanId) {
  if (!scanId) return;

  if (pollTimer) clearInterval(pollTimer);

  const tick = async () => {
    if (!root.isConnected) {
      clearInterval(pollTimer);
      pollTimer = null;
      return;
    }

    try {
      const { scan } = await api(`/api/scans/${encodeURIComponent(scanId)}`);

      if (scan.status === "running") {
        const count = Number(scan.filesScanned || 0);
        const found = Number(scan.threatCount || 0);
        const text = root.querySelector("#scanProgressText");

        if (text) {
          text.textContent =
            `Scanning… ${num(count)} files checked` +
            `${found ? ` · ${num(found)} threat${found === 1 ? "" : "s"}` : ""}` +
            `${scan.currentDirectory ? ` · ${scan.currentDirectory}` : ""}`;
        }
        // The total file count is unknown until the walk ends, so there is no honest percentage.
        // The bar only signals activity; the numbers above are the measurement.
        return;
      }

      clearInterval(pollTimer);
      pollTimer = null;

      const threats = Number(scan.threats?.length || 0);
      const cancelled = scan.status === "cancelled";
      const failed = scan.status === "failed";

      toast(
        failed
          ? `Scan failed: ${scan.error || "unknown error"}`
          : `${scanLabel(scan.scope)} scan ${cancelled ? "cancelled" : "finished"}: ` +
            `${num(scan.filesScanned)} files, ${num(threats)} threat${threats === 1 ? "" : "s"}.`,
        { type: failed ? "error" : threats ? "info" : "success", timeout: 6000 }
      );

      if (root.isConnected) await render(root);
    } catch (error) {
      clearInterval(pollTimer);
      pollTimer = null;
      toast(error.message, { type: "error" });
    }
  };

  pollTimer = setInterval(tick, 900);
  tick();
}

function scanCoverage(scan) {
  if (!scan) return { blocked: [], skipped: 0 };

  const blocked = [];

  for (const error of scan.errors || []) {
    if (!/EPERM|EACCES|operation not permitted/i.test(String(error?.message || ""))) continue;
    if (error?.path && !blocked.includes(error.path)) blocked.push(error.path);
  }

  return { blocked, skipped: Number(scan.skipped) || 0 };
}

function scanLabel(scope) {
  if (scope === "full") return "Full";
  if (scope === "custom") return "Path";
  return "Quick";
}

function notifyNewThreats(threats, preferences) {
  const keys = new Set(threats.map(threat => `${threat.scanId}:${threat.id}`));

  if (
    lastThreatKeys &&
    preferences?.notify &&
    typeof Notification !== "undefined" &&
    Notification.permission === "granted"
  ) {
    for (const threat of threats) {
      const key = `${threat.scanId}:${threat.id}`;
      if (lastThreatKeys.has(key)) continue;

      try {
        new Notification("CampusShield flagged a file", {
          body: `${threat.name} · ${String(threat.severity || "low").toUpperCase()} · ${threat.filePath}`,
          tag: `campusshield-${key}`
        });
      } catch {
        /* notifications can be unavailable in some shells */
      }
    }
  }

  lastThreatKeys = keys;
}

function severityTone(severity) {
  if (severity === "critical" || severity === "high") return "high";
  if (severity === "medium") return "medium";
  return "low";
}

function threatRow(threat) {
  const reasons = Array.isArray(threat.reasons) ? threat.reasons : [];
  const primary = reasons[0];
  const key = `${threat.scanId}:${threat.id}`;

  return `
    <article class="threat-item">
      <div class="threat-main">
        <div class="threat-title">
          <strong>${esc(threat.name)}</strong>
          <span class="sev ${severityTone(threat.severity)}">${esc(String(threat.severity || "low").toUpperCase())}</span>
        </div>
        <span class="threat-path">${esc(threat.filePath)}</span>
        <span class="threat-reason">
          ${esc(primary?.title || "Suspicious file")}
          ${reasons.length > 1 ? ` · ${num(reasons.length - 1)} more signal${reasons.length - 1 === 1 ? "" : "s"}` : ""}
        </span>
      </div>
      <div class="threat-actions">
        <button class="link" type="button" data-explain="${esc(key)}">Explain</button>
        <button class="btn subtle" type="button" data-quarantine="${esc(key)}">Quarantine</button>
        <button class="link danger-link" type="button" data-delete-threat="${esc(key)}">Delete</button>
      </div>
    </article>
  `;
}

function quarantineRow(entry) {
  return `
    <article class="threat-item">
      <div class="threat-main">
        <div class="threat-title">
          <strong>${esc(entry.name)}</strong>
          <span class="sev ${severityTone(entry.severity)}">${esc(String(entry.severity || "low").toUpperCase())}</span>
        </div>
        <span class="threat-path">${esc(entry.originalPath)}</span>
        <span class="threat-reason">Held ${esc(relativeTime(entry.quarantinedAt))} · ${esc(entry.sha256?.slice(0, 16) || "no hash")}…</span>
      </div>
      <div class="threat-actions">
        <button class="btn subtle" type="button" data-restore-q="${esc(entry.id)}">Restore</button>
        <button class="link danger-link" type="button" data-delete-q="${esc(entry.id)}">Delete</button>
      </div>
    </article>
  `;
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
