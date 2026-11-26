import { api, getAiConfig, isAiConfigured } from "../api.js";
import { esc, icon, iconForKind, num, relativeTime, scanProof, sevClass, toast } from "../ui.js";

export const meta = {
  eyebrow: "Security overview",
  title: "Your device, checked for real",
  subtitle: "One test runs a read-only device check, a full file scan, and a socket read. Every value comes from this computer — nothing is demo data."
};

const chatHistory = [];

let running = false;
let pollingTimer = null;
let loadedOnce = false;

export async function render(root) {
  clearTimeout(pollingTimer);
  pollingTimer = null;
  running = false;
  delete root.dataset.activeScan;

  root.innerHTML = `
    <section class="hero-card">
      <div class="hero-main">
        <span class="hero-badge" id="heroBadge">THIS DEVICE</span>
        <h2 class="hero-title">Your device.<br><span>Real checks, no guesses.</span></h2>
        <p class="hero-sub">
          One test reads this computer's settings, scans every readable file, and reads the listening
          socket table. Nothing on this page is simulated.
        </p>
        <div class="hero-actions">
          <button class="btn primary lg" id="runTestBtn" type="button">
            ${icon("scan")}<span>Run full scan</span>
          </button>
          <button class="btn subtle" id="quickScanBtn" type="button">Quick scan</button>
          <button class="btn ghost small" id="refreshSuggestionsBtn" type="button">Refresh</button>
          <span class="chip" id="testChip">${loadedOnce ? "Ready" : "Loading"}</span>
        </div>
        <p class="hero-note">
          A full scan reads files under your home folder plus the app folders, then the socket table.
          It can take several minutes; the file count updates live. Ports are reported, never probed or scored.
        </p>
      </div>

      <aside class="hero-side" aria-label="Live posture">
        <div class="hero-ring" id="heroRing" style="--score:0%;--ring:rgba(255,255,255,0.14)">
          <div>
            <strong id="heroScore">—</strong>
            <small>Safety score</small>
          </div>
        </div>
        <ul class="hero-facts">
          <li><span>Signatures</span><strong id="heroSignatures">—</strong></li>
          <li><span>Last scan</span><strong id="heroLastScan">—</strong></li>
          <li><span>Ports reachable</span><strong id="heroPorts">—</strong></li>
        </ul>
      </aside>
    </section>

    <div class="test-run" id="testRun" hidden></div>

    <div class="stat-grid" id="assistantFacts">
      <div class="stat-card"><span class="stat-label">Safety score</span><strong class="stat-value">—</strong><small>Reading stored checks…</small></div>
    </div>

    <section class="card coverage-card">
      <div class="card-head">
        <div>
          <h2>Protection coverage</h2>
          <p>Each tile is filled from a real reading on this computer.</p>
        </div>
        <span class="chip" id="coverageChip">Loading</span>
      </div>
      <div class="coverage-grid" id="coverageGrid">
        <div class="coverage-tile"><span class="cov-title">Reading…</span></div>
      </div>
      <p class="tiny" id="coverageFoot">
        No coverage value is simulated. A tile reads "Not read" until the matching check has actually run.
      </p>
    </section>

    <div class="dash-grid">
      <div class="stack">
        <section class="card" id="aiCard">
          <div class="card-head">
            <div>
              <h2>AI suggestions</h2>
              <p>Optional explanation layer</p>
            </div>
          </div>
          <p class="helper">Checking whether an AI endpoint is configured…</p>
        </section>

        <section class="card">
          <div class="card-head">
            <div>
              <h2>Prioritized next steps</h2>
              <p id="recCaption">Derived from stored checks, scans, and quarantine records.</p>
            </div>
            <span class="chip" id="recCount">—</span>
          </div>
          <div id="recList" class="loading-state" style="padding:18px 0">
            <span class="spinner" aria-hidden="true"></span>
            <p>Reading the verified state…</p>
          </div>
        </section>
      </div>

      <section class="card feed-card">
        <div class="card-head">
          <div>
            <h2>Event feed</h2>
            <p>Checks, scans, and account actions as they are recorded.</p>
          </div>
          <span class="chip" id="feedChip">—</span>
        </div>

        <div class="readiness">
          <div class="readiness-head">
            <span>Safety score</span>
            <strong id="readinessValue">—</strong>
          </div>
          <div class="readiness-track"><span id="readinessBar" style="width:0%" data-tone="neutral"></span></div>
          <small id="readinessNote">Run a device check to create a real score.</small>
        </div>

        <div class="feed-list" id="feedList">
          <p class="helper">Reading the audit log…</p>
        </div>

        <a class="feed-link" href="#/activity">Open the full activity log</a>
      </section>
    </div>

    <section class="card" id="networkCard" style="margin-top:13px">
      <div class="card-head">
        <div>
          <h2>Network exposure</h2>
          <p>Listening sockets read from this computer</p>
        </div>
        <span class="chip" id="networkChip">—</span>
      </div>
      <div id="networkBody">
        <p class="helper">No port audit has run yet. Run a full scan to read the socket table.</p>
      </div>
    </section>

    <section class="card chat-card">
      <div class="card-head">
        <div>
          <h2>Ask CampusShield</h2>
          <p>Answers use the same stored facts as the dashboard.</p>
        </div>
      </div>

      <div class="chat-log" id="chatLog"></div>

      <div class="chat-chips">
        <button class="filter-chip" type="button" data-chat-prompt="Run a full scan">Run a full scan</button>
        <button class="filter-chip" type="button" data-chat-prompt="What is my status?">What is my status?</button>
        <button class="filter-chip" type="button" data-chat-prompt="Any threats?">Any threats?</button>
      </div>

      <form class="chat-form" id="chatForm">
        <input class="input" id="chatInput" type="text" maxlength="2000" autocomplete="off"
          placeholder="Ask about your device, scans, or detections" aria-label="Ask the assistant">
        <button class="btn primary" id="chatSend" type="submit">Send</button>
      </form>

      <p class="tiny">
        AI guidance is advisory. CampusShield decides detections locally; the assistant cannot change
        results, quarantine files, or edit settings.
      </p>
    </section>

    <section class="card steps-card">
      <div class="card-head">
        <div>
          <h2>How CampusShield works</h2>
          <p>Four steps, each backed by what actually ran on this machine.</p>
        </div>
      </div>
      <ol class="steps-grid">
        <li class="step">
          <span class="step-no">1</span>
          ${icon("scan")}
          <strong>Run the test</strong>
          <p>A read-only device check, a file scan, and a socket read start together.</p>
        </li>
        <li class="step">
          <span class="step-no">2</span>
          ${icon("layers")}
          <strong>See what was found</strong>
          <p>Settings, file detections, and reachable listeners are listed with their evidence.</p>
        </li>
        <li class="step">
          <span class="step-no">3</span>
          ${icon("shield")}
          <strong>Fix or contain</strong>
          <p>Quarantine flagged files, change a setting yourself, or close a port you did not mean to share.</p>
        </li>
        <li class="step">
          <span class="step-no">4</span>
          ${icon("activity")}
          <strong>Keep the record</strong>
          <p>Every check, scan, and decision is logged so the next run has a baseline.</p>
        </li>
      </ol>
    </section>
  `;

  paintChat(root);
  wire(root);

  root.querySelector("#runTestBtn")?.addEventListener("click", () => runSecurityTest(root, "full"));
  root.querySelector("#quickScanBtn")?.addEventListener("click", () => runSecurityTest(root, "quick"));
  root.querySelector("#refreshSuggestionsBtn")?.addEventListener("click", async event => {
    const button = event.currentTarget;
    button.disabled = true;
    await load(root, { quiet: true });
    button.disabled = false;
  });

  await load(root, { quiet: false });

  const activeScan = root.dataset.activeScan;

  if (activeScan) {
    showRunPanel(root);
    root.querySelector("#testRun").innerHTML = `
      <div class="run-head">
        <h3>Test results</h3>
        <span class="chip" id="runStatus">Scanning</span>
      </div>
      <div id="scanBlock"></div>
      <div id="runSummary"></div>`;
    running = true;
    pollScan(root, activeScan);
  }
}

function aiBody() {
  return { ai: isAiConfigured() ? getAiConfig() : null };
}

async function load(root, { quiet }) {
  try {
    const data = await api("/api/assistant/suggest", { method: "POST", body: aiBody() });

    loadedOnce = true;
    paintHero(root, data.snapshot);
    paintFacts(root, data.snapshot);
    paintCoverage(root, data.snapshot);
    paintReadiness(root, data.snapshot);
    paintNetwork(root, data.snapshot.network);
    paintAi(root, data);
    paintRecs(root, data);
    await refreshFeed(root);

    const chip = root.querySelector("#testChip");

    if (chip && !running) {
      chip.textContent = data.snapshot.scanner.activeScan ? "Scanning" : "Ready";
    }

    if (data.snapshot.scanner.activeScan) {
      root.dataset.activeScan = data.snapshot.scanner.activeScan.id;
    } else {
      delete root.dataset.activeScan;
    }

    return data;
  } catch (error) {
    root.querySelector("#recList").innerHTML = `
      <div class="empty">
        ${icon("alert")}
        <strong>Could not read the verified state</strong>
        <p>${esc(error.message)}</p>
        <button class="btn ghost small" id="retryAssistant" type="button">Try again</button>
      </div>`;

    root.querySelector("#retryAssistant")?.addEventListener("click", () => load(root, { quiet: false }));

    if (quiet) toast(error.message, { type: "error", timeout: 6000 });
    return null;
  }
}

function scoreTone(score) {
  if (!Number.isFinite(score)) return "";
  if (score >= 85) return "ok";
  if (score >= 70) return "warn";
  return "risk";
}

function paintHero(root, snapshot) {
  const host = snapshot.host;
  const network = snapshot.network;
  const lastScan = snapshot.lastScan;
  const score = host && Number.isFinite(host.score) ? Math.round(host.score) : null;
  const badge = root.querySelector("#heroBadge");
  const platform = (host && host.platform) || snapshot.platform || "this host";

  if (badge) {
    badge.textContent = `THIS DEVICE · ${platform}`;
    if (host?.name) badge.title = host.name;
  }

  const scoreEl = root.querySelector("#heroScore");
  const ring = root.querySelector("#heroRing");

  if (scoreEl) scoreEl.textContent = score === null ? "—" : String(score);
  if (ring) {
    const color = score === null
      ? "rgba(255,255,255,0.14)"
      : score >= 85
        ? "var(--green)"
        : score >= 70
          ? "var(--amber)"
          : "var(--red)";
    ring.style.setProperty("--score", `${score === null ? 0 : Math.max(0, Math.min(100, score))}%`);
    ring.style.setProperty("--ring", color);
    ring.title = score === null
      ? "No device check has run yet"
      : `${host?.grade || "Checked"} · ${relativeTime(host?.checkedAt)}`;
  }

  const signatures = root.querySelector("#heroSignatures");
  if (signatures) signatures.textContent = num(snapshot.scanner.signatureCount);

  const lastScanEl = root.querySelector("#heroLastScan");
  if (lastScanEl) {
    lastScanEl.textContent = lastScan
      ? relativeTime(lastScan.finishedAt || lastScan.startedAt)
      : "Never";
  }

  const ports = root.querySelector("#heroPorts");
  if (ports) {
    ports.textContent = network
      ? network.supported
        ? num(network.networkBound)
        : "Unread"
      : "Not read";
  }
}

function paintFacts(root, snapshot) {
  const facts = root.querySelector("#assistantFacts");

  if (!facts) return;

  const host = snapshot.host;
  const lastScan = snapshot.lastScan;
  const score = host && Number.isFinite(host.score) ? Math.round(host.score) : null;
  const scoreDisplay = score === null ? "Not checked" : String(score);
  const scoreNote = host
    ? `${host.name || "This host"}${host.grade ? ` · ${host.grade}` : ""}${host.checkedAt ? ` · ${relativeTime(host.checkedAt)}` : ""}`
    : "Run a device check to create a score.";
  const scanValue = lastScan ? num(lastScan.filesScanned) : "0";
  const scanNote = lastScan
    ? `${esc(lastScan.scope)} scan ${relativeTime(lastScan.finishedAt || lastScan.startedAt)}${lastScan.threatCount ? ` · ${num(lastScan.threatCount)} flagged` : ""}`
    : "No file scan is recorded yet.";
  const openThreats = snapshot.openThreats.length;
  const network = snapshot.network;
  const networkValue = network
    ? network.supported
      ? num(network.networkBound)
      : "Unread"
    : "Not read";
  const networkNote = network
    ? network.supported
      ? `${num(network.total)} listeners · ${num(network.loopbackOnly)} loopback only${network.riskyCount ? ` · ${num(network.riskyCount)} sensitive` : ""}`
      : network.error || "The socket table could not be read."
    : "Run a full scan to read the socket table.";

  facts.innerHTML = `
    <div class="stat-card" data-tone="${scoreTone(score)}">
      <span class="stat-icon">${icon("shield")}</span>
      <span class="stat-label">Safety score</span>
      <strong class="stat-value">${esc(scoreDisplay)}${score === null ? "" : `<span class="stat-unit">/100</span>`}</strong>
      <small>${esc(scoreNote)}</small>
    </div>
    <div class="stat-card">
      <span class="stat-icon">${icon("scan")}</span>
      <span class="stat-label">Files scanned</span>
      <strong class="stat-value">${esc(scanValue)}</strong>
      <small>${scanNote}</small>
    </div>
    <div class="stat-card" data-tone="${openThreats ? "risk" : "ok"}">
      <span class="stat-icon">${icon("alert")}</span>
      <span class="stat-label">Open detections</span>
      <strong class="stat-value">${num(openThreats)}</strong>
      <small>${openThreats ? "Waiting for a decision" : "Nothing flagged right now"}</small>
    </div>
    <div class="stat-card" data-tone="${network?.supported && network.riskyCount ? "risk" : network?.supported ? "ok" : ""}">
      <span class="stat-icon">${icon("browser")}</span>
      <span class="stat-label">Network reachable</span>
      <strong class="stat-value">${esc(networkValue)}</strong>
      <small>${esc(networkNote)}</small>
    </div>
  `;
}

function paintCoverage(root, snapshot) {
  const grid = root.querySelector("#coverageGrid");
  const chip = root.querySelector("#coverageChip");

  if (!grid) return;

  const host = snapshot.host;
  const lastScan = snapshot.lastScan;
  const network = snapshot.network;
  const scanner = snapshot.scanner;
  const score = host && Number.isFinite(host.score) ? Math.round(host.score) : null;

  const tiles = [
    {
      iconName: "shield",
      title: "Device settings",
      value: score === null ? "Not checked" : `${score}/100`,
      chip: host?.grade || (score === null ? "Unchecked" : "Checked"),
      tone: scoreTone(score),
      note: score === null
        ? "No read-only posture check has run yet."
        : `Read ${relativeTime(host.checkedAt)}; settings were not changed.`
    },
    {
      iconName: "scan",
      title: "File scanning",
      value: lastScan ? `${num(lastScan.filesScanned)} files` : "Not run",
      chip: lastScan ? lastScan.scope : "Never",
      tone: lastScan ? "" : "warn",
      note: lastScan
        ? `${num(lastScan.threatCount)} detection${lastScan.threatCount === 1 ? "" : "s"} · last finished ${relativeTime(lastScan.finishedAt || lastScan.startedAt)}`
        : "No file scan is recorded yet."
    },
    {
      iconName: "browser",
      title: "Network exposure",
      value: network
        ? network.supported
          ? `${num(network.networkBound)} reachable`
          : "Unread"
        : "Not read",
      chip: network?.supported
        ? network.riskyCount
          ? `${num(network.riskyCount)} sensitive`
          : "No sensitive port"
        : "Unread",
      tone: network?.supported && network.riskyCount ? "risk" : network?.supported ? "ok" : "",
      note: network
        ? network.supported
          ? `${num(network.total)} listeners read ${relativeTime(network.readAt)}; nothing was contacted.`
          : network.error || "The socket table could not be read."
        : "Run a full scan to read the socket table."
    },
    {
      iconName: "lock",
      title: "Real-time watch",
      value: scanner.realtime ? "On" : scanner.watchSupported ? "Off" : "Unsupported",
      chip: scanner.realtime ? "Watching" : "Manual",
      tone: scanner.realtime ? "ok" : "",
      note: scanner.realtime
        ? "Downloads, Desktop, and Documents are watched as files appear."
        : scanner.watchSupported
          ? "Folder watching is available but turned off."
          : "This platform does not support the folder watcher."
    }
  ];

  grid.innerHTML = tiles.map(tile => `
    <div class="coverage-tile">
      <div class="cov-top">
        <span class="cov-icon">${icon(tile.iconName)}</span>
        <span class="cov-chip" data-tone="${tile.tone}">${esc(tile.chip)}</span>
      </div>
      <span class="cov-title">${esc(tile.title)}</span>
      <strong class="cov-value">${esc(tile.value)}</strong>
      <small class="cov-note">${esc(tile.note)}</small>
    </div>`).join("");

  if (chip) {
    const read = [host && Number.isFinite(host.score), Boolean(lastScan), Boolean(network?.supported), true]
      .filter(Boolean).length;
    chip.textContent = `${read}/4 read`;
  }

  const foot = root.querySelector("#coverageFoot");
  if (foot) {
    foot.textContent = scanner.signatureCount
      ? `${num(scanner.signatureCount)} local signatures loaded${scanner.signatureVersion ? ` · ${scanner.signatureVersion}` : ""}. Watch mode and schedule reflect saved preferences, not a claim that they are running.`
      : "No signature set is loaded, so file scanning falls back to built-in heuristics.";
  }
}

function paintReadiness(root, snapshot) {
  const value = root.querySelector("#readinessValue");
  const bar = root.querySelector("#readinessBar");
  const note = root.querySelector("#readinessNote");
  const host = snapshot.host;
  const score = host && Number.isFinite(host.score) ? Math.round(host.score) : null;

  if (value) value.textContent = score === null ? "Not checked" : `${score}/100`;
  if (bar) {
    bar.style.width = `${score === null ? 0 : Math.max(0, Math.min(100, score))}%`;
    bar.dataset.tone = scoreTone(score) || "neutral";
  }
  if (note) {
    note.textContent = score === null
      ? "Run a device check to create a real score."
      : `From the last read-only check${host.grade ? ` (${host.grade})` : ""} ${relativeTime(host.checkedAt)}.`;
  }
}

async function refreshFeed(root) {
  const list = root.querySelector("#feedList");
  const chip = root.querySelector("#feedChip");

  if (!list) return;

  try {
    const data = await api("/api/activity?limit=6");
    const entries = (data.activity || []).filter(entry => entry && entry.message);

    if (chip) chip.textContent = data.total ? `${num(data.total)} logged` : "Empty";

    if (!entries.length) {
      list.innerHTML = `
        <div class="empty compact">
          ${icon("activity")}
          <strong>No activity recorded yet</strong>
          <p>Run a full scan or a device check; each action is written to the audit log.</p>
        </div>`;
      return;
    }

    list.innerHTML = entries.map(feedItem).join("");
  } catch (error) {
    if (chip) chip.textContent = "Unavailable";
    list.innerHTML = `
      <div class="empty compact">
        ${icon("alert")}
        <strong>Activity could not be read</strong>
        <p>${esc(error.message)}</p>
      </div>`;
  }
}

function feedItem(entry) {
  const kind = iconForKind(entry.kind);
  const severity = entry.severity
    ? `<span class="feed-sev ${sevClass(entry.severity)}">${esc(entry.severity)}</span>`
    : "";

  return `
    <div class="feed-item">
      <span class="feed-icon ${esc(kind.className)}">${icon(kind.icon)}</span>
      <div class="feed-body">
        <strong>${esc(entry.message)}</strong>
        <small>${esc(relativeTime(entry.time))}${entry.kind ? ` · ${esc(entry.kind)}` : ""}</small>
      </div>
      ${severity}
    </div>`;
}

function paintNetwork(root, network) {
  const body = root.querySelector("#networkBody");
  const chip = root.querySelector("#networkChip");

  if (!body) return;

  if (!network) {
    if (chip) chip.textContent = "Not read";
    body.innerHTML = `<p class="helper">No port audit has run yet. Run a full scan to read the socket table.</p>`;
    return;
  }

  if (chip) {
    chip.textContent = network.supported
      ? `${num(network.networkBound)} reachable`
      : "Unavailable";
  }

  body.innerHTML = networkBody(network);
}

function networkBody(network) {
  if (!network.supported) {
    return `
      <div class="empty compact">
        ${icon("alert")}
        <strong>Could not read the socket table</strong>
        <p>${esc(network.error || "The listening sockets could not be read on this host.")}</p>
      </div>
      <p class="tiny">Nothing was guessed to fill the gap.</p>`;
  }

  const services = (network.services || []).filter(service => service.scope === "network");
  const rows = services.length
    ? services
        .map(
          service => `
        <tr${service.risky ? ' class="exposure-risky"' : ""}>
          <td class="exposure-port">${esc(service.protocol)} ${esc(String(service.port))}</td>
          <td>${esc(service.service || "—")}</td>
          <td>${esc(service.process || "unknown")}</td>
          <td>${service.risky ? esc(service.riskNote || "Sensitive port") : "Reported, not flagged"}</td>
        </tr>`
        )
        .join("")
    : `<tr><td colspan="4" class="exposure-none">No listener accepted connections from the network.</td></tr>`;

  const notes = (network.notes || []).map(note => `<li>${esc(note)}</li>`).join("");
  const findings = (network.findings || []).length
    ? `<div class="exposure-findings">
        ${network.findings
          .map(
            finding => `
          <div class="tool-finding" data-tone="warn">
            <strong>${esc(finding.title)} · ${esc(finding.severity)}</strong>
            <p>${esc(finding.why || finding.detail)}</p>
          </div>`
          )
          .join("")}
      </div>`
    : "";

  return `
    <div class="exposure-counts">
      <span><strong>${num(network.total)}</strong> listeners</span>
      <span><strong>${num(network.networkBound)}</strong> reachable from the network</span>
      <span><strong>${num(network.loopbackOnly)}</strong> loopback only</span>
      <span><strong>${num(network.riskyCount)}</strong> sensitive</span>
    </div>
    ${findings}
    <div class="exposure-table-wrap">
      <table class="exposure-table">
        <thead>
          <tr><th>Port</th><th>Service</th><th>Process</th><th>Exposure</th></tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    ${notes ? `<ul class="exposure-notes">${notes}</ul>` : ""}
    <p class="tiny">
      Read at ${esc(relativeTime(network.readAt))} from the socket table${network.elevated ? " as root" : ""}.
      No port was contacted, opened, or scored — a reachable listener is a fact, not a detection.
    </p>
  `;
}

function paintAi(root, data) {
  const card = root.querySelector("#aiCard");
  const ai = data.ai || {};

  if (!ai.available) {
    card.innerHTML = `
      <div class="card-head">
        <div>
          <h2>AI suggestions</h2>
          <p>Optional explanation layer, never a detector</p>
        </div>
        <span class="chip">Not configured</span>
      </div>
      <p class="helper">
        Connect an OpenAI-compatible endpoint in Settings to get written explanations of the same facts
        shown here. Until then, the prioritized steps below are generated from real checks without AI.
      </p>
      <p class="helper">
        The prioritized steps, every score, and every detection are already produced from real checks
        and scans. The AI only adds explanation and cannot change a detection.
      </p>
      <div class="form-row" style="margin-top:10px">
        <a class="btn subtle small" href="#/settings">Add an AI endpoint</a>
      </div>
    `;
    return;
  }

  card.innerHTML = `
    <div class="card-head">
      <div>
        <h2>AI suggestions${ai.model ? ` · ${esc(ai.model)}` : ""}</h2>
        <p>Explains the verified snapshot; does not decide detections</p>
      </div>
      <span class="chip">Configured</span>
    </div>
    ${ai.reply
      ? `<p class="ai-reply">${esc(ai.reply)}</p>`
      : `<p class="warning-note">The endpoint did not answer: ${esc(ai.error || "no reply")}</p>`}
    <p class="tiny">${esc(ai.disclaimer || "")}</p>
  `;
}

function paintRecs(root, data) {
  const list = root.querySelector("#recList");
  const count = root.querySelector("#recCount");
  const caption = root.querySelector("#recCaption");
  const recommendations = data.recommendations || [];

  count.textContent = recommendations.length ? `${recommendations.length}` : "0";
  caption.textContent = data.snapshot.openThreats.length
    ? `${data.snapshot.openThreats.length} open detection${data.snapshot.openThreats.length === 1 ? "" : "s"} in stored scans · generated ${relativeTime(data.generatedAt)}`
    : `No open detections in stored scans · generated ${relativeTime(data.generatedAt)}`;

  if (!recommendations.length) {
    list.innerHTML = `
      <div class="empty compact">
        ${icon("check")}
        <strong>Nothing needs attention from stored data</strong>
        <p>Run a security test to check this device again. This list never adds items to look busy.</p>
      </div>`;
    return;
  }

  list.innerHTML = recommendations.map(recommendationCard).join("");
}

function recommendationCard(recommendation) {
  const action = recommendation.action || {};
  const attrs = [
    `data-rec-kind="${esc(action.kind || "")}"`,
    action.scanId ? `data-scan-id="${esc(action.scanId)}"` : "",
    action.threatId ? `data-threat-id="${esc(action.threatId)}"` : ""
  ]
    .filter(Boolean)
    .join(" ");

  return `
    <article class="rec-row">
      <span class="sev ${sevClass(recommendation.severity)}">${esc(recommendation.severity)}</span>
      <div class="rec-body">
        <strong>${esc(recommendation.title)}</strong>
        <p>${esc(recommendation.detail)}</p>
      </div>
      ${action.kind ? `<button class="btn subtle small" type="button" data-rec-action ${attrs}>${esc(actionLabel(action.kind))}</button>` : ""}
    </article>
  `;
}

function actionLabel(kind) {
  if (kind === "quarantine-threat") return "Quarantine";
  if (kind === "run-check") return "Run check";
  if (kind === "run-scan") return "Run scan";
  if (kind === "enable-watch") return "Turn on";
  if (kind === "schedule-scan" || kind === "open-settings") return "Open settings";
  if (kind === "open-protection") return "Review";
  if (kind === "open-exposure") return "View ports";
  return "Open";
}

function wire(root) {
  if (!root.dataset.assistantWired) {
    root.dataset.assistantWired = "1";

    root.addEventListener("click", async event => {
      const button = event.target.closest("[data-rec-action]");

      if (button) {
        await handleAction(root, button.dataset);
        return;
      }

      const chip = event.target.closest("[data-chat-prompt]");

      if (chip) {
        const input = root.querySelector("#chatInput");
        if (input) input.value = chip.dataset.chatPrompt;
        root.querySelector("#chatForm")?.requestSubmit();
      }
    });
  }

  root.querySelector("#chatForm")?.addEventListener("submit", async event => {
    event.preventDefault();
    const input = root.querySelector("#chatInput");
    const message = String(input?.value || "").trim();

    if (!message) return;

    input.value = "";
    await sendChat(root, message);
  });
}

async function handleAction(root, dataset) {
  const kind = dataset.recKind;

  if (kind === "run-scan") {
    await runSecurityTest(root);
    return;
  }

  if (kind === "run-check") {
    try {
      const result = await api("/api/protection/scan", { method: "POST" });

      toast(
        `Device check complete · ${result.device.score}/100 (${result.device.grade}) · ` +
          `${result.summary.attention} to fix, ${result.summary.unverified} unverified.`,
        { type: result.summary.attention ? "info" : "success", timeout: 6500 }
      );
    } catch (error) {
      toast(error.message, { type: "error", timeout: 6000 });
    }

    await refreshAfterChange(root);
    return;
  }

  if (kind === "quarantine-threat") {
    try {
      await api(
        `/api/threats/${encodeURIComponent(dataset.scanId)}/${encodeURIComponent(dataset.threatId)}/quarantine`,
        { method: "POST" }
      );
      toast("File moved to quarantine. You can restore it from Protection.", { type: "success" });
    } catch (error) {
      toast(error.message, { type: "error", timeout: 6000 });
    }

    await refreshAfterChange(root);
    return;
  }

  if (kind === "enable-watch") {
    try {
      const result = await api("/api/scanner/watch", { method: "POST", body: { enabled: true } });
      toast(
        result.watch?.enabled
          ? "Real-time folder watching is on for Downloads, Desktop, and Documents."
          : "This platform does not support the folder watcher.",
        { type: result.watch?.enabled ? "success" : "info", timeout: 6000 }
      );
    } catch (error) {
      toast(error.message, { type: "error", timeout: 6000 });
    }

    await refreshAfterChange(root);
    return;
  }

  if (kind === "open-protection") {
    location.hash = "#/protection";
    return;
  }

  if (kind === "open-exposure") {
    const card = root.querySelector("#networkCard");
    card?.scrollIntoView({ behavior: "smooth", block: "center" });
    card?.classList.add("flash");
    setTimeout(() => card?.classList.remove("flash"), 1400);
    return;
  }

  location.hash = "#/settings";
}

async function refreshAfterChange(root) {
  window.dispatchEvent(new CustomEvent("campusshield:health-refresh"));
  await load(root, { quiet: true });
}

async function runSecurityTest(root, scope = "full") {
  if (running) return;

  running = true;

  const button = root.querySelector("#runTestBtn");
  const quickButton = root.querySelector("#quickScanBtn");
  const chip = root.querySelector("#testChip");
  const label = scope === "quick" ? "quick" : "full";

  if (button) button.disabled = true;
  if (quickButton) quickButton.disabled = true;
  if (chip) chip.textContent = "Checking…";

  showRunPanel(root);
  root.querySelector("#testRun").innerHTML = `
    <div class="run-head">
      <h3>Scan results</h3>
      <span class="chip">Checking</span>
    </div>
    <div class="loading-state" style="padding:14px 0">
      <span class="spinner" aria-hidden="true"></span>
      <p>Running the device check, starting the ${label} file scan, and reading the socket table…</p>
    </div>`;

  try {
    const result = await api("/api/assistant/security-test", { method: "POST", body: { scope } });

    renderRun(root, result);
    paintNetwork(root, result.network);

    if (result.scan?.id) {
      pollScan(root, result.scan.id);
    } else {
      await finishRun(root, null, result.scanError);
    }

    window.dispatchEvent(new CustomEvent("campusshield:health-refresh"));
    await load(root, { quiet: true });
  } catch (error) {
    root.querySelector("#testRun").innerHTML = `
      <div class="run-head">
        <h3>Scan results</h3>
        <span class="chip">Failed</span>
      </div>
      <p class="warning-note">The security test could not start: ${esc(error.message)}</p>`;
    running = false;
    if (button) button.disabled = false;
    if (quickButton) quickButton.disabled = false;
    if (chip) chip.textContent = "Failed";
    toast(error.message, { type: "error", timeout: 6000 });
  }
}

function showRunPanel(root) {
  const panel = root.querySelector("#testRun");

  if (panel) panel.hidden = false;
}

function renderRun(root, result) {
  const panel = root.querySelector("#testRun");
  const check = result.check || {};
  const device = result.device || null;
  const scan = result.scan;
  const network = result.network;

  const checkBlock = check.supported && device
    ? `<div class="run-check">
        <span class="run-check-score">${num(device.score)}<small>/100</small></span>
        <div>
          <strong>${esc(device.grade || "Checked")} · ${esc(device.name || "This host")}</strong>
          <p>Read-only: ${num(device.summary?.passed)} passed, ${num(device.summary?.attention)} need attention, ${num(device.summary?.unverified)} unverified. Settings were not changed.</p>
        </div>
      </div>`
    : `<p class="warning-note">${esc(check.message || "The device check is not available on this host.")}</p>`;

  panel.innerHTML = `
    <div class="run-head">
      <h3>Scan results</h3>
      <span class="chip" id="runStatus">${scan ? "Scanning" : "Scan unavailable"}</span>
    </div>
    ${checkBlock}
    <div id="scanBlock">
      ${scan ? scanBlock(scan) : ""}
    </div>
    ${network ? `<div class="run-network" id="runNetwork">${networkBody(network)}</div>` : ""}
    <div id="runSummary"></div>
  `;
}

function scanBlock(scan) {
  const runningScan = scan.status === "running";
  const detections = Number(scan.threatCount) || 0;

  return `
    <div class="run-scan">
      <div class="run-scan-head">
        <strong>${esc(scan.scope || "quick")} file scan</strong>
        <span>${esc(scan.status)}${runningScan ? " · " + num(scan.filesScanned) + " files read" : " · " + num(scan.filesScanned) + " files"}</span>
      </div>
      ${runningScan ? `<div class="scan-progress" aria-hidden="true"></div>` : ""}
      <p>${runningScan
        ? "Reading files against local signatures and heuristics. The count updates as the scan runs."
        : `${esc(scanProof(scan))} · ${scan.status !== "complete"
          ? `scan ${esc(scan.status)}, so these results are partial.`
          : detections
            ? `${num(detections)} detection${detections === 1 ? "" : "s"}. Detections are listed below and in the threat queue.`
            : scan.truncated
              ? "nothing suspicious in the files read before it stopped."
              : "nothing suspicious found."}`}</p>
      ${!runningScan && Array.isArray(scan.errors) && scan.errors.length
        ? `<p class="tiny">${num(scan.errors.length)} location(s) could not be read (folder permission), so their files were skipped. Grant the app access and scan again to include them.</p>`
        : ""}
    </div>
  `;
}

function pollScan(root, scanId) {
  clearTimeout(pollingTimer);

  const startedAt = Date.now();
  const tick = async () => {
    const block = root.querySelector("#scanBlock");

    if (!block) {
      running = false;
      clearTimeout(pollingTimer);
      return;
    }

    try {
      const { scan } = await api(`/api/scans/${encodeURIComponent(scanId)}`);

      block.innerHTML = scanBlock(scan);

      if (scan.status === "running") {
        const chip = root.querySelector("#runStatus");
        if (chip) chip.textContent = `Scanning · ${num(scan.filesScanned)} files`;

        if (Date.now() - startedAt > 10 * 60 * 1000) {
          await finishRun(root, scan);
          return;
        }

        pollingTimer = setTimeout(tick, 1200);
        return;
      }

      await finishRun(root, scan);
    } catch (error) {
      if (error.status === 404) {
        await finishRun(root, null, "The scan record disappeared.");
        return;
      }

      pollingTimer = setTimeout(tick, 3000);
    }
  };

  tick();
}

async function finishRun(root, scan, scanError = "") {
  clearTimeout(pollingTimer);
  pollingTimer = null;
  running = false;

  const button = root.querySelector("#runTestBtn");

  if (button) button.disabled = false;
  const quickButton = root.querySelector("#quickScanBtn");
  if (quickButton) quickButton.disabled = false;

  const failed = scan?.status === "failed" || scan?.status === "cancelled";
  const detections = Number(scan?.threatCount) || 0;

  if (scanError) {
    root.querySelector("#scanBlock")?.insertAdjacentHTML(
      "afterbegin",
      `<p class="warning-note">${esc(scanError)}</p>`
    );
  }

  if (scan?.error) {
    root.querySelector("#scanBlock")?.insertAdjacentHTML(
      "afterbegin",
      `<p class="warning-note">The scan stopped: ${esc(scan.error)}</p>`
    );
  }

  window.dispatchEvent(new CustomEvent("campusshield:health-refresh"));
  await load(root, { quiet: true });

  const chip = root.querySelector("#testChip");
  const status = root.querySelector("#runStatus");

  if (chip) chip.textContent = failed ? "Needs attention" : detections ? "Detections found" : "Complete";
  if (status) status.textContent = scan ? scan.status : "Scan unavailable";

  if (!root.querySelector("#runSummary")) return;

  root.querySelector("#runSummary").innerHTML = `
    <div class="loading-state" style="padding:10px 0">
      <span class="spinner" aria-hidden="true"></span>
      <p>Summarizing the recorded results…</p>
    </div>`;

  try {
    const summary = await api("/api/assistant/run-summary", { method: "POST", body: aiBody() });

    root.querySelector("#runSummary").innerHTML = `
      <p class="run-summary">${esc(summary.summary)}</p>
      ${summary.ai?.error ? `<p class="tiny">AI summary unavailable: ${esc(summary.ai.error)}</p>` : ""}
    `;
  } catch {
    root.querySelector("#runSummary").innerHTML = "";
  }
}

function paintChat(root) {
  const log = root.querySelector("#chatLog");

  if (!log) return;

  if (!chatHistory.length) {
    log.innerHTML = `
      <div class="chat-empty">
        <p>Ask for a full scan, the current status, or open detections. Without an AI endpoint,
           CampusShield answers these three from stored facts.</p>
      </div>`;
    return;
  }

  log.innerHTML = chatHistory
    .map(
      message => `
        <div class="chat-bubble ${message.role}">
          ${message.pending ? `<span class="spinner small" aria-hidden="true"></span>` : ""}
          <p>${esc(message.content)}</p>
        </div>`
    )
    .join("");

  log.scrollTop = log.scrollHeight;
}

async function sendChat(root, message) {
  const send = root.querySelector("#chatSend");

  chatHistory.push({ role: "user", content: message });
  const pending = { role: "assistant", content: "Checking stored checks and scans…", pending: true };
  chatHistory.push(pending);
  paintChat(root);

  if (send) send.disabled = true;

  try {
    const reply = await api("/api/assistant/chat", {
      method: "POST",
      body: {
        message,
        ...aiBody(),
        history: chatHistory
          .filter(item => !item.pending)
          .slice(-6)
          .map(item => ({ role: item.role, content: item.content }))
      }
    });

    pending.pending = false;
    pending.content = reply.reply || "No answer was recorded.";

    if (reply.run?.scan?.id) {
      showRunPanel(root);
      renderRun(root, reply.run);
      pollScan(root, reply.run.scan.id);
    }

    paintChat(root);
    await load(root, { quiet: true });
  } catch (error) {
    pending.pending = false;
    pending.content = error.message;
    paintChat(root);
  } finally {
    if (send) send.disabled = false;
  }
}
