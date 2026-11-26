import { api } from "../api.js";
import { dateTime, esc, icon, num, relativeTime, toast } from "../ui.js";

const VERDICT = {
  block: { label: "Blocked", tone: "bad", lead: "This link matches a block rule." },
  warn: { label: "Warning", tone: "warn", lead: "This link has signs of phishing." },
  allowed: { label: "Allowed by you", tone: "ok", lead: "This domain is on your allow list, so it was not judged." },
  "no-signs": { label: "No warning signs", tone: "ok", lead: "None of the checks found a problem. That is not a promise the site is safe." }
};

const LIST_LABEL = { blocklist: "your block list", allowlist: "your allow list", feed: "your feed" };

function resultHtml(result) {
  const verdict = VERDICT[result.verdict] || VERDICT["no-signs"];

  return `
    <div class="web-result" data-tone="${verdict.tone}" role="status">
      <div class="web-result-head">
        <span class="chip" data-tone="${verdict.tone}">${esc(verdict.label)}</span>
        <strong>${esc(result.host || "Runs code")}</strong>
        <span class="helper">score ${num(result.score)} of 100 · warns from ${num(result.warnScore)}</span>
      </div>
      <p>${esc(verdict.lead)}${result.list ? ` Matched ${esc(LIST_LABEL[result.list.kind])}: <code>${esc(result.list.entry)}</code>.` : ""}</p>
      ${result.schemeAdded ? `<p class="helper">No https:// was given, so it was added for the check.</p>` : ""}
      ${
        result.signals.length
          ? `<ul class="shield-results">${result.signals.map(item => `<li data-tone="${item.points >= 30 ? "warn" : "idle"}"><strong>+${num(item.points)}</strong> ${esc(item.detail)}</li>`).join("")}</ul>`
          : `<p class="helper">No signs were found in the text of the link.</p>`
      }
      <details class="shield-details"><summary>What was not checked</summary>
        <ul class="checklist">${result.notChecked.map(line => `<li>${icon("info")}<span>${esc(line)}</span></li>`).join("")}<li>${icon("info")}<span>${esc(result.approximate)}</span></li></ul>
      </details>
      <p class="helper">${result.logged ? "Logged by website name only." : result.listsInUse ? "Not logged." : "Web protection is off, so your lists were not used and nothing was logged."}</p>
    </div>`;
}

export function renderWebCard(status, events) {
  if (!status) {
    return `
      <section class="card protect-section shield-card" id="webCard">
        <div class="card-head"><div><h2>Web &amp; phishing links</h2><p>Not available</p></div><span class="chip">Unavailable</span></div>
        <p class="helper">The web protection state could not be loaded. Sign in again or check the server.</p>
      </section>`;
  }

  const rows = events
    .slice(0, 6)
    .map(
      event => `<li class="web-event">
        <span class="chip" data-tone="${event.verdict === "block" ? "bad" : "warn"}">${event.verdict === "block" ? "Blocked" : "Warning"}</span>
        <span class="shield-alert-main"><strong>${esc(event.host)}</strong>
          <span class="helper">${esc(event.signals[0]?.detail || (event.list ? `Matched ${LIST_LABEL[event.list.kind]}` : ""))}${event.count > 1 ? ` · seen ${num(event.count)} times` : ""}</span></span>
        <span class="helper" title="${esc(dateTime(event.lastSeen))}">${esc(relativeTime(event.lastSeen))}</span>
        ${event.status === "open" ? `<button class="btn ghost small" type="button" data-web-dismiss="${esc(event.id)}">Dismiss</button>` : `<span class="helper">Dismissed</span>`}
      </li>`
    )
    .join("");

  const feed = status.feed;

  return `
    <section class="card protect-section shield-card" id="webCard">
      <div class="card-head">
        <div><h2>Web &amp; phishing links</h2><p>Check a link before you open it</p></div>
        <span class="chip" data-tone="${status.enabled ? "ok" : "idle"}">${status.enabled ? "On" : "Off"}</span>
      </div>

      <form class="web-form" id="webForm" novalidate>
        <label class="field"><span>Paste a link</span>
          <input class="input" id="webUrl" type="text" inputmode="url" autocomplete="off" spellcheck="false" maxlength="2048" placeholder="https://example.com/login" aria-describedby="webHint">
        </label>
        <button class="btn primary" type="submit" id="webCheck">Check link</button>
      </form>
      <p class="helper" id="webHint">The page is never opened and redirects are not followed.</p>
      <div id="webResult" aria-live="polite"></div>

      <label class="switch-row">
        <span><strong>Use my lists and log warnings</strong><span class="helper">Off by default. Warned and blocked links are saved by website name only.</span></span>
        <span class="switch"><input type="checkbox" id="webEnabled" ${status.enabled ? "checked" : ""} aria-label="Turn on web protection"></span>
      </label>

      <details class="shield-details" ${status.blocklist.length || status.allowlist.length || status.feedUrl ? "open" : ""}>
        <summary>Block list, allow list and feed</summary>
        <label class="field"><span>Always block (one domain per line)</span>
          <textarea class="input web-list" id="webBlock" rows="4" spellcheck="false">${esc(status.blocklist.join("\n"))}</textarea></label>
        <label class="field"><span>Always allow (one domain per line)</span>
          <textarea class="input web-list" id="webAllow" rows="3" spellcheck="false">${esc(status.allowlist.join("\n"))}</textarea></label>
        <label class="field"><span>Warn from score</span>
          <input class="input" id="webWarn" type="number" min="${status.warnBounds.min}" max="${status.warnBounds.max}" step="1" value="${num(status.warnScore)}"></label>
        <label class="field"><span>Known-bad domain feed (https address, optional)</span>
          <input class="input" id="webFeedUrl" type="url" maxlength="300" value="${esc(status.feedUrl)}" placeholder="https://example.org/blocklist.txt"></label>
        <label class="check-row"><input type="checkbox" id="webFeedOn" ${status.feedEnabled ? "checked" : ""}> <span>Use this feed (CampusShield downloads it from that address when you turn it on or refresh)</span></label>
        ${
          status.feedEnabled
            ? `<p class="helper">${feed.error ? `Feed problem: ${esc(feed.error)}` : `${num(feed.count)} domains from ${esc(feed.host || "the feed")}${feed.fetchedAt ? `, fetched ${esc(relativeTime(feed.fetchedAt))}` : ""}.`}${feed.error && feed.count ? ` Still using the last ${num(feed.count)} domains.` : ""}</p>`
            : ""
        }
        <div class="drawer-actions">
          <button class="btn primary" type="button" id="webSave">Save lists</button>
          ${status.feedEnabled ? `<button class="btn ghost" type="button" id="webRefresh">Refresh feed</button>` : ""}
        </div>
      </details>

      <details class="shield-details"><summary>Rules and limits</summary>
        <ul class="checklist">${status.limits.map(line => `<li>${icon("info")}<span>${esc(line)}</span></li>`).join("")}</ul></details>

      ${rows ? `<h3 class="shield-sub">Recent warnings</h3><ul class="shield-alerts">${rows}</ul>` : `<p class="helper shield-none">${status.enabled ? "No warned or blocked links yet." : "Nothing is logged while this is off."}</p>`}
    </section>`;
}

export function bindWebCard(root, refresh) {
  const form = root.querySelector("#webForm");
  const out = root.querySelector("#webResult");

  form?.addEventListener("submit", async event => {
    event.preventDefault();
    const input = root.querySelector("#webUrl");
    const button = root.querySelector("#webCheck");

    if (!input.value.trim()) {
      out.innerHTML = `<p class="helper">Paste a link to check.</p>`;
      return input.focus();
    }

    button.disabled = true;
    out.innerHTML = `<p class="helper">Checking…</p>`;

    try {
      const result = await api("/api/web/check", { method: "POST", body: { url: input.value } });
      out.innerHTML = resultHtml(result);
      if (result.logged) refreshEvents(root, refresh);
    } catch (error) {
      out.innerHTML = `<div class="scan-warning">${icon("alert")} <span>${esc(error.message)}</span></div>`;
    } finally {
      button.disabled = false;
    }
  });

  const patch = async (body, message) => {
    try {
      await api("/api/web/settings", { method: "PATCH", body });
      if (message) toast(message, { type: "success" });
    } catch (error) {
      toast(error.message, { type: "error" });
    }

    refresh();
  };

  root.querySelector("#webEnabled")?.addEventListener("change", event => {
    event.currentTarget.disabled = true;
    patch({ enabled: event.currentTarget.checked }, event.currentTarget.checked ? "Web protection is on." : "Web protection is off.");
  });

  root.querySelector("#webSave")?.addEventListener("click", () => {
    const lines = id => root.querySelector(id).value.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
    const feedUrl = root.querySelector("#webFeedUrl").value.trim();

    patch(
      {
        blocklist: lines("#webBlock"),
        allowlist: lines("#webAllow"),
        warnScore: Number(root.querySelector("#webWarn").value),
        feedUrl,
        feedEnabled: root.querySelector("#webFeedOn").checked && Boolean(feedUrl)
      },
      "Saved."
    );
  });

  root.querySelector("#webRefresh")?.addEventListener("click", async event => {
    event.currentTarget.disabled = true;

    try {
      await api("/api/web/feed/refresh", { method: "POST", body: {} });
    } catch (error) {
      toast(error.message, { type: "error" });
    }

    refresh();
  });

  bindDismiss(root, refresh);
}

function bindDismiss(root, refresh) {
  root.querySelectorAll("[data-web-dismiss]").forEach(button => {
    button.addEventListener("click", async () => {
      button.disabled = true;

      try {
        await api(`/api/web/events/${encodeURIComponent(button.dataset.webDismiss)}/dismiss`, { method: "POST", body: {} });
      } catch (error) {
        toast(error.message, { type: "error" });
      }

      refresh();
    });
  });
}

// After a logged check, refresh only the list so the result stays on screen.
async function refreshEvents(root, refresh) {
  try {
    const { events } = await api("/api/web/events?limit=10");
    const status = await api("/api/web");
    const holder = document.createElement("div");
    holder.innerHTML = renderWebCard(status, events);

    const next = holder.querySelector(".shield-sub")?.nextElementSibling;
    const current = root.querySelector("#webCard .shield-alerts");

    if (next && current) {
      current.replaceWith(next);
      bindDismiss(root, refresh);
    }
  } catch {
    // The list refreshes on the next full render.
  }
}
