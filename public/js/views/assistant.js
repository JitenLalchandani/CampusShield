import { api, getAiConfig, isAiConfigured } from "../api.js";
import { esc, icon, num, relativeTime, sevClass, toast } from "../ui.js";

export const meta = {
  eyebrow: "Protection assistant",
  title: "How to stay protected",
  subtitle: "Guidance from real checks, scans, and listening ports. The AI explains the facts; it never decides detections."
};

const chatHistory = [];

let running = false;
let pollingTimer = null;
let loadedOnce = false;

export async function render(root) {
  clearTimeout(pollingTimer);
  pollingTimer = null;
  running = false;

  root.innerHTML = `
    <section class="card">
      <div class="card-head">
        <div>
          <h2>How to stay protected</h2>
          <p>One test runs a read-only device check, a full file scan of this computer, and a read of every listening port. Nothing is estimated.</p>
        </div>
        <span class="chip" id="testChip">${loadedOnce ? "Ready" : "Loading"}</span>
      </div>

      <div class="assistant-facts" id="assistantFacts">
        <div class="fact-tile"><span class="fact-label">Device score</span><strong>—</strong><small>Reading stored checks…</small></div>
      </div>

      <div class="form-row" style="margin-top:14px">
        <button class="btn primary" id="runTestBtn" type="button">
          ${icon("scan")}<span>Run full scan</span>
        </button>
        <button class="btn subtle" id="quickScanBtn" type="button">Quick scan</button>
        <button class="btn subtle" id="refreshSuggestionsBtn" type="button">Refresh suggestions</button>
      </div>
      <p class="tiny" style="margin-top:8px">
        A full scan reads files under your home folder plus the app folders, then reads the socket table.
        It can take several minutes; the file count updates live. Ports are reported, never probed or scored.
      </p>

      <div class="test-run" id="testRun" hidden></div>
    </section>

    <div class="assistant-grid">
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

        <section class="card" id="networkCard">
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

        <section class="card">
          <div class="card-head">
            <div>
              <h2>Recommended next steps</h2>
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
    </div>
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

  const activeScan = root.querySelector("#assistantFacts")?.dataset.activeScan;

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
    paintFacts(root, data.snapshot);
    paintNetwork(root, data.snapshot.network);
    paintAi(root, data);
    paintRecs(root, data);

    const chip = root.querySelector("#testChip");

    if (chip && !running) {
      chip.textContent = data.snapshot.scanner.activeScan ? "Scanning" : "Ready";
    }

    if (data.snapshot.scanner.activeScan) {
      const facts = root.querySelector("#assistantFacts");
      facts && facts.setAttribute("data-active-scan", data.snapshot.scanner.activeScan.id);
    } else {
      root.querySelector("#assistantFacts")?.removeAttribute("data-active-scan");
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

function paintFacts(root, snapshot) {
  const facts = root.querySelector("#assistantFacts");

  if (!facts) return;

  const host = snapshot.host;
  const lastScan = snapshot.lastScan;
  const score = host && Number.isFinite(host.score) ? `${Math.round(host.score)}/100` : "Not checked";
  const scoreNote = host
    ? `${host.name || "This host"}${host.grade ? ` · ${host.grade}` : ""}${host.checkedAt ? ` · ${relativeTime(host.checkedAt)}` : ""}`
    : "Run a device check to create a score.";
  const scanValue = lastScan ? `${num(lastScan.filesScanned)} files` : "Never";
  const scanNote = lastScan
    ? `${esc(lastScan.scope)} scan · ${relativeTime(lastScan.finishedAt || lastScan.startedAt)} · ${num(lastScan.threatCount)} detection${lastScan.threatCount === 1 ? "" : "s"}`
    : "No file scan is recorded yet.";
  const openThreats = snapshot.openThreats.length;
  const quarantine = snapshot.quarantine.count;
  const network = snapshot.network;
  const networkValue = network
    ? network.supported
      ? `${num(network.networkBound)}`
      : "Unread"
    : "Not read";
  const networkNote = network
    ? network.supported
      ? `${num(network.total)} listeners · ${num(network.loopbackOnly)} loopback-only · ${relativeTime(network.readAt)}`
      : network.error || "The socket table could not be read."
    : "Run a full scan to read the socket table.";

  facts.innerHTML = `
    <div class="fact-tile">
      <span class="fact-label">Device score</span>
      <strong>${esc(score)}</strong>
      <small>${esc(scoreNote)}</small>
    </div>
    <div class="fact-tile">
      <span class="fact-label">Last scan</span>
      <strong>${esc(scanValue)}</strong>
      <small>${scanNote}</small>
    </div>
    <div class="fact-tile" data-tone="${network?.riskyCount ? "risk" : ""}">
      <span class="fact-label">Network reachable</span>
      <strong>${esc(networkValue)}</strong>
      <small>${esc(networkNote)}</small>
    </div>
    <div class="fact-tile" data-tone="${openThreats ? "risk" : "ok"}">
      <span class="fact-label">Open detections</span>
      <strong>${num(openThreats)}</strong>
      <small>${openThreats ? "Waiting for a decision" : "Nothing flagged right now"}</small>
    </div>
    <div class="fact-tile">
      <span class="fact-label">Quarantine</span>
      <strong>${num(quarantine)}</strong>
      <small>${quarantine ? "Contained files remain recoverable" : "Nothing is contained"}</small>
    </div>
  `;
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
          <h2>AI suggestions need an endpoint</h2>
          <p>Connect an OpenAI-compatible endpoint to get explanations</p>
        </div>
        <span class="chip">Not configured</span>
      </div>
      <p class="helper">
        ${esc(data.aiSetup || "Add an endpoint in Settings to get AI explanations.")}
      </p>
      <p class="helper">
        The recommendation list and every number on this page already come from real checks and scans.
        The AI only adds explanation and cannot change a detection.
      </p>
      <div class="form-row" style="margin-top:10px">
        <a class="btn subtle small" href="#/settings">Open AI settings</a>
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
        : `${num(scan.filesScanned)} files read · ${num(detections)} detection${detections === 1 ? "" : "s"} · ${num(scan.skipped || 0)} skipped${detections ? ". Detections are listed below and in the threat queue." : "."}`}</p>
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
