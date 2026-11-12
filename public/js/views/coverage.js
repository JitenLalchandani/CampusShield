import { api } from "../api.js";
import { esc, icon } from "../ui.js";

export const meta = {
  eyebrow: "Coverage",
  title: "What is actually connected",
  subtitle: "An honest map of telemetry sources and response controls."
};

export async function render(root) {
  root.innerHTML = `
    <div class="loading-state">
      <span class="spinner" aria-hidden="true"></span>
      <p>Checking connected sources…</p>
    </div>
  `;

  const [health, summary] = await Promise.all([
    api("/api/health"),
    api("/api/summary")
  ]);

  const scanner = Boolean(health.scannerAvailable);
  const deviceChecks = Boolean(health.deviceAuditAvailable);
  const devicesLinked = Number(summary.devicesReporting) || 0;

  const sources = [
    {
      iconName: "scan",
      name: "macOS Unified Log",
      state: scanner ? "Available" : "Unavailable",
      stateClass: scanner ? "on" : "",
      description: scanner
        ? "Scans authentication phrases from the host running the server over the last 15 minutes. Phrase matches are indicators, not proof of an attack."
        : "This host is not macOS, so the local unified-log scanner cannot run here.",
      action: scanner ? "Run local scan" : ""
    },
    {
      iconName: "shield",
      name: "Device posture checks",
      state: deviceChecks ? "Available" : "Unavailable",
      stateClass: deviceChecks ? "on" : "",
      description: deviceChecks
        ? "Read-only checks on the server host: FileVault, firewall, Gatekeeper, SIP, screen lock, guest account, updates, Downloads, and login items. Scores feed the cross-device total."
        : "Posture checks currently run on macOS hosts only. Mobile and Windows checks need native plugins before they can report a score.",
      action: deviceChecks ? "Run device check" : "",
      actionAttr: 'data-action="device-check"' 
    },
    {
      iconName: "key",
      name: "Identity provider",
      state: "Not connected",
      description: "Failed sign-ins, MFA failures, and risky sign-in signals per student, faculty, and staff account."
    },
    {
      iconName: "server",
      name: "DNS / secure web gateway",
      state: "Not connected",
      description: "Threat-intelligence domain reputation and outbound volume baselines for campus networks."
    },
    {
      iconName: "shield",
      name: "Endpoint management",
      state: "Not connected",
      description: "Patch state, installed software, and per-device posture for managed laptops and lab machines."
    },
    {
      iconName: "layers",
      name: "SIEM (Wazuh)",
      state: "Not connected",
      description: "Correlated detections, long-term log retention, and the alert pipeline feeding this queue."
    },
    {
      iconName: "database",
      name: "Campus inventory",
      state: "Not connected",
      description: "Accurate counts of students, faculty, labs, and guests so totals can be compared against real coverage."
    }
  ];

  root.innerHTML = `
    <section class="card">
      <div class="card-head">
        <div>
          <h2>Collection status</h2>
          <p>Nothing is fabricated to make the app look complete</p>
        </div>
        <span class="chip">${esc(health.storage)}</span>
      </div>
      <dl class="kv">
        <dt>API</dt><dd>Online · v${esc(health.version)}</dd>
        <dt>Storage</dt><dd>${esc(health.storage)}</dd>
        <dt>Server host</dt><dd>${esc(health.platform)}${scanner ? " · log scanner available" : ""}${deviceChecks ? " · device checks available" : ""}</dd>
        <dt>Data source</dt><dd>${esc(summary.dataSource)}</dd>
        <dt>Events held</dt><dd>${esc(summary.eventsTotal)} · audit entries: ${esc(summary.auditTotal)}</dd>
        <dt>Devices</dt><dd>${esc(devicesLinked)} linked · score ${esc(summary.protection?.average ?? "not checked")}</dd>
      </dl>
      <p class="helper">
        The macOS log scanner and read-only device posture checks are the only
        collectors implemented today. The cards below are the integrations a
        production deployment would need before the coverage numbers are
        meaningful.
      </p>
    </section>

    <section class="coverage-grid">
      ${sources.map(sourceCard).join("")}
    </section>

    <section class="panel-grid two">
      <article class="card">
        <div class="card-head">
          <div>
            <h2>Before a production rollout</h2>
            <p>Ordered by what changes the risk picture fastest</p>
          </div>
        </div>
        <ul class="checklist">
          <li>${icon("check")}<span>Add authentication and role-based access before exposing the API beyond localhost.</span></li>
          <li>${icon("check")}<span>Connect one approved identity source and validate detection precision against real authentication logs.</span></li>
          <li>${icon("check")}<span>Move events, decisions, and audit history into a database with retention and access controls.</span></li>
          <li>${icon("check")}<span>Tune rules per campus group and review false positives with the security team.</span></li>
          <li>${icon("check")}<span>Keep a human approval step in front of any action that affects a real account or device.</span></li>
        </ul>
      </article>

      <article class="card">
        <div class="card-head">
          <div>
            <h2>Deliberate limits</h2>
            <p>What this build will not pretend to do</p>
          </div>
        </div>
        <ul class="checklist">
          <li>${icon("info")}<span>No campus devices, identity provider, SIEM, or inventory source is monitored.</span></li>
          <li>${icon("info")}<span>No events are generated to populate an empty queue.</span></li>
          <li>${icon("info")}<span>Containment only records a status label; no traffic is blocked and no account is disabled.</span></li>
          <li>${icon("info")}<span>The detector is an illustrative rule set, not a validated detection engine.</span></li>
          <li>${icon("info")}<span>Device checks only run on the macOS server host. iOS, Android, and Windows checks need native plugins before they can score.</span></li>
        </ul>
        <p class="warning-note">
          Treat every finding as a lead that needs context from the systems that
          actually saw the activity.
        </p>
      </article>
    </section>
  `;
}

function sourceCard(source) {
  return `
    <article class="card source-card">
      <div class="source-top">
        <span class="source-icon">${icon(source.iconName)}</span>
        <span class="state-pill ${source.stateClass || ""}">${esc(source.state)}</span>
      </div>
      <h3>${esc(source.name)}</h3>
      <p>${esc(source.description)}</p>
      ${source.action ? `<button class="btn subtle small" type="button" ${source.actionAttr || 'data-action="scan"'}>${esc(source.action)}</button>` : ""}
    </article>
  `;
}
