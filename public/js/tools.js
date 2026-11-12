const SHORTENERS = new Set([
  "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "buff.ly", "is.gd",
  "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly", "t.ly", "lnkd.in"
]);

const RISKY_TLDS = new Set([
  "zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "country",
  "stream", "download", "review", "win", "loan", "work", "kim", "men", "date",
  "racing", "party", "cam", "rest", "sbs", "cyou"
]);

const BRANDS = [
  { token: "paypal", domains: ["paypal.com", "paypal.me", "paypalobjects.com"] },
  { token: "apple", domains: ["apple.com", "icloud.com", "apple-cloudkit.com"] },
  { token: "google", domains: ["google.com", "google.co.in", "gmail.com", "youtube.com", "googleusercontent.com"] },
  { token: "microsoft", domains: ["microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com", "microsoft365.com"] },
  { token: "amazon", domains: ["amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com", "amazontrust.com"] },
  { token: "netflix", domains: ["netflix.com"] },
  { token: "instagram", domains: ["instagram.com"] },
  { token: "facebook", domains: ["facebook.com", "fb.com"] },
  { token: "whatsapp", domains: ["whatsapp.com", "wa.me"] },
  { token: "linkedin", domains: ["linkedin.com"] },
  { token: "flipkart", domains: ["flipkart.com"] },
  { token: "paytm", domains: ["paytm.com"] },
  { token: "phonepe", domains: ["phonepe.com"] },
  { token: "icici", domains: ["icicibank.com"] },
  { token: "hdfc", domains: ["hdfcbank.com"] },
  { token: "sbi", domains: ["sbi.co.in", "onlinesbi.sbi"] }
];

const MULTI_SUFFIXES = new Set([
  "co.in", "co.uk", "com.au", "co.jp", "com.br", "co.za", "org.uk",
  "ac.in", "gov.in", "net.in", "com.sg"
]);

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

function labelsOf(hostname) {
  return hostname.replace(/\.$/, "").split(".").filter(Boolean);
}

function registrableDomain(hostname) {
  const labels = labelsOf(hostname);

  if (labels.length <= 2) return labels.join(".");

  const lastTwo = labels.slice(-2).join(".");

  if (MULTI_SUFFIXES.has(lastTwo)) return labels.slice(-3).join(".");

  return lastTwo;
}

function isIpAddress(hostname) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.includes(":");
}

function editDistance(a, b) {
  const rows = Array.from({ length: a.length + 1 }, (_, index) => [index]);

  for (let column = 1; column <= b.length; column += 1) rows[0][column] = column;

  for (let row = 1; row <= a.length; row += 1) {
    for (let column = 1; column <= b.length; column += 1) {
      const cost = a[row - 1] === b[column - 1] ? 0 : 1;
      rows[row][column] = Math.min(
        rows[row - 1][column] + 1,
        rows[row][column - 1] + 1,
        rows[row - 1][column - 1] + cost
      );
    }
  }

  return rows[a.length][b.length];
}

function finding(tone, title, detail) {
  return { tone, title, detail };
}

// Heuristics only. Nothing is fetched and no external reputation list is used,
// so a clean result means "no obvious signals", not "verified safe".
export function inspectUrl(raw) {
  const input = String(raw || "").trim();

  if (!input) throw new Error("Paste a link to inspect.");

  const candidate = /^[a-z][a-z0-9+.-]*:/i.test(input) ? input : `https://${input}`;

  let url;

  try {
    url = new URL(candidate);
  } catch {
    throw new Error("That does not look like a valid web address.");
  }

  const hostname = url.hostname.toLowerCase();
  const findings = [];
  const isLocal = LOCAL_HOSTS.has(hostname);

  if (!["http:", "https:"].includes(url.protocol)) {
    findings.push(finding(
      "risk",
      `${url.protocol} link`,
      "This is not a normal web link. Do not open it unless you trust the sender completely."
    ));
    return {
      href: url.href,
      host: hostname,
      verdict: { tone: "risk", label: "High risk" },
      findings,
      note: "Non-web links can run code or embed data. CampusShield did not open it."
    };
  }

  if (url.protocol === "http:" && !isLocal) {
    findings.push(finding(
      "risk",
      "Not encrypted",
      "The page would load over plain HTTP, so anything typed into it can be read in transit."
    ));
  }

  if (url.username || url.password) {
    findings.push(finding(
      "risk",
      "Sign-in details inside the link",
      "The address contains a username or password before the host name. This is a common way to disguise the real destination."
    ));
  }

  if (isIpAddress(hostname) && !isLocal) {
    findings.push(finding(
      "warn",
      "Raw IP address instead of a name",
      "Legitimate services almost always use a domain name. A bare address is unusual in a message."
    ));
  }

  if (hostname.startsWith("xn--") || hostname.includes(".xn--")) {
    findings.push(finding(
      "warn",
      "Encoded international characters",
      "The domain uses punycode, which can make lookalike characters hard to spot."
    ));
  }

  if (url.port && !["80", "443"].includes(url.port)) {
    findings.push(finding(
      "warn",
      `Unusual port ${url.port}`,
      "Most websites use the default port. A custom port often points at a temporary or self-hosted page."
    ));
  }

  if (labelsOf(hostname).length > 4) {
    findings.push(finding(
      "warn",
      "Deeply nested address",
      "Many subdomains can push the real domain out of view on a phone."
    ));
  }

  const domain = registrableDomain(hostname);

  if (SHORTENERS.has(domain)) {
    findings.push(finding(
      "warn",
      "Shortened link",
      "Link shorteners hide the final destination. Expand it before signing in or paying."
    ));
  }

  const tld = labelsOf(hostname).slice(-1)[0] || "";

  if (RISKY_TLDS.has(tld)) {
    findings.push(finding(
      "warn",
      `".${tld}" domain ending`,
      "This top-level domain is cheap to register and is frequently used in scam campaigns."
    ));
  }

  const domainLabel = labelsOf(domain)[0] || "";
  const domainTokens = domainLabel.split(/[-_]/).filter(Boolean);

  for (const brand of BRANDS) {
    if (brand.domains.includes(domain)) continue;

    if (hostname.includes(brand.token) || domainTokens.includes(brand.token)) {
      findings.push(finding(
        "warn",
        `Uses the ${brand.token} name on another domain`,
        `The real domain is ${domain}, which is not controlled by ${brand.token}. Brand names on unrelated domains are a classic impersonation pattern.`
      ));
      break;
    }

    const lookalike = domainTokens.find(
      token => token.length >= 4 && editDistance(token, brand.token) === 1
    );

    if (lookalike) {
      findings.push(finding(
        "risk",
        `Lookalike of ${brand.token}`,
        `${lookalike} is one character away from ${brand.token}. Check each letter before entering anything.`
      ));
      break;
    }
  }

  const risks = findings.filter(item => item.tone === "risk").length;
  const warnings = findings.filter(item => item.tone === "warn").length;

  const verdict = risks
    ? { tone: "risk", label: "High risk" }
    : warnings
      ? { tone: "warn", label: "Treat with care" }
      : { tone: "ok", label: "No obvious signals" };

  return {
    href: url.href,
    host: domain || hostname,
    verdict,
    findings,
    note:
      "Pattern checks only. CampusShield did not open the link and does not query a live blocklist."
  };
}

export function canHashPasswords() {
  return Boolean(globalThis.crypto?.subtle);
}

// k-anonymity: only the first five characters of the SHA-1 hash leave the
// browser, so the password and its full hash are never sent to the API.
export async function checkBreachedPassword(password) {
  const value = String(password || "");

  if (!value) throw new Error("Enter the password you want to check.");

  if (!canHashPasswords()) {
    throw new Error(
      "Password checks need HTTPS or localhost because browsers hide the hashing API on plain HTTP."
    );
  }

  const digest = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(value));
  const hash = [...new Uint8Array(digest)]
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  let response;

  try {
    response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { "Add-Padding": "true" }
    });
  } catch {
    throw new Error("Could not reach the Pwned Passwords service. Check the connection and try again.");
  }

  if (!response.ok) {
    throw new Error(`Pwned Passwords returned status ${response.status}. Try again later.`);
  }

  const body = await response.text();

  for (const line of body.split("\n")) {
    const [candidate, count] = line.trim().split(":");

    if (candidate === suffix) {
      const times = Number(count) || 0;

      // Padded rows always report 0 and must be ignored.
      if (times === 0) break;

      return { breached: true, times, prefix };
    }
  }

  return { breached: false, times: 0, prefix };
}
