"use strict";

// Explainable phishing signs for one parsed link. Each sign has a fixed number of points and a plain
// sentence. The score is their sum, capped at 100. There is no hidden model and no reputation
// lookup here: this only reads the text of the link.

const { MAX_URL } = require("./url");

// A short list of well-known sites people are impersonated as. A lookalike is judged against these
// only; a site not on this list can still be flagged by the other signs.
const BRANDS = Object.freeze([
  { name: "Google", label: "google", domains: ["google.com", "google.co.in", "youtube.com", "gstatic.com", "gmail.com"] },
  { name: "Microsoft", label: "microsoft", domains: ["microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com", "windows.com"] },
  { name: "Apple", label: "apple", domains: ["apple.com", "icloud.com"] },
  { name: "PayPal", label: "paypal", domains: ["paypal.com", "paypal.me"] },
  { name: "Amazon", label: "amazon", domains: ["amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com"] },
  { name: "Facebook", label: "facebook", domains: ["facebook.com", "fb.com", "messenger.com"] },
  { name: "Instagram", label: "instagram", domains: ["instagram.com"] },
  { name: "WhatsApp", label: "whatsapp", domains: ["whatsapp.com", "whatsapp.net"] },
  { name: "Netflix", label: "netflix", domains: ["netflix.com"] },
  { name: "LinkedIn", label: "linkedin", domains: ["linkedin.com"] },
  { name: "GitHub", label: "github", domains: ["github.com", "githubusercontent.com", "github.io"] },
  { name: "Dropbox", label: "dropbox", domains: ["dropbox.com"] },
  { name: "Twitter / X", label: "twitter", domains: ["twitter.com", "x.com", "t.co"] },
  { name: "Zoom", label: "zoom", domains: ["zoom.us", "zoom.com"] },
  { name: "SBI", label: "onlinesbi", domains: ["onlinesbi.sbi", "onlinesbi.com", "sbi.co.in"] },
  { name: "HDFC Bank", label: "hdfcbank", domains: ["hdfcbank.com"] },
  { name: "ICICI Bank", label: "icicibank", domains: ["icicibank.com"] },
  { name: "Paytm", label: "paytm", domains: ["paytm.com"] },
  { name: "Flipkart", label: "flipkart", domains: ["flipkart.com"] },
  { name: "IRCTC", label: "irctc", domains: ["irctc.co.in"] }
]);

const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "tiny.cc", "shorturl.at"]);
const SENSITIVE_WORDS = ["login", "signin", "sign-in", "verify", "verification", "account", "secure", "update", "password", "wallet", "banking", "confirm", "suspended"];
const CONFUSING_TLDS = new Set(["zip", "mov"]);

const POINTS = Object.freeze({
  runsCode: 100,
  ipHost: 40,
  userinfo: 40,
  mixedScript: 40,
  lookalike: 45,
  brandInName: 35,
  nonLatin: 15,
  shortener: 15,
  manySubdomains: 10,
  longHost: 10,
  manyHyphens: 10,
  noTls: 10,
  confusingTld: 10,
  sensitiveWords: 10,
  longUrl: 5
});

function editDistance(a, b) {
  if (Math.abs(a.length - b.length) > 1) return 2;
  const row = Array.from({ length: b.length + 1 }, (_, i) => i);

  for (let i = 1; i <= a.length; i += 1) {
    let previous = row[0];
    row[0] = i;

    for (let j = 1; j <= b.length; j += 1) {
      const held = row[j];
      row[j] = Math.min(row[j] + 1, row[j - 1] + 1, previous + (a[i - 1] === b[j - 1] ? 0 : 1));
      previous = held;
    }
  }

  return row[b.length];
}

// Undoes the common letter swaps: paypa1 -> paypal, rn -> m, 0 -> o.
function deconfuse(label) {
  return label.replace(/rn/g, "m").replace(/vv/g, "w").replace(/0/g, "o").replace(/[1|]/g, "l").replace(/3/g, "e").replace(/5/g, "s");
}

function scriptsIn(text) {
  const scripts = new Set();
  if (/\p{Script=Latin}/u.test(text)) scripts.add("Latin");
  if (/\p{Script=Cyrillic}/u.test(text)) scripts.add("Cyrillic");
  if (/\p{Script=Greek}/u.test(text)) scripts.add("Greek");
  if (/\p{Script=Arabic}|\p{Script=Hebrew}|\p{Script=Han}|\p{Script=Hiragana}|\p{Script=Katakana}|\p{Script=Hangul}|\p{Script=Devanagari}/u.test(text)) scripts.add("Other");
  return scripts;
}

function ownsDomain(brand, registrable, host) {
  return brand.domains.some(domain => registrable === domain || host === domain || host.endsWith(`.${domain}`));
}

function analyze(parsed) {
  const signals = [];
  const add = (id, points, detail) => signals.push({ id, points, detail });

  if (parsed.runsCode) {
    add("runs-code", POINTS.runsCode, `A ${parsed.scheme.replace(":", "")}: link runs code or embeds a page. It is not a website address.`);
    return { score: 100, signals };
  }

  const { host, unicodeHost, registrable, url } = parsed;
  const labels = host.split(".");
  const registrableLabels = registrable.split(".");
  const subdomainLabels = parsed.isIp ? [] : labels.slice(0, labels.length - registrableLabels.length);

  if (parsed.isIp) add("ip-host", POINTS.ipHost, "The link uses a numeric address instead of a website name.");
  if (url.username || url.password) add("userinfo", POINTS.userinfo, `Text before an "@" in the link ("${url.username.slice(0, 40)}") can make it look like a different site. The real site is ${host}.`);
  if (url.protocol === "http:") add("no-tls", POINTS.noTls, "The link does not use HTTPS, so anything typed on it is sent unprotected.");

  if (!parsed.isIp) {
    const scripts = scriptsIn(unicodeHost);

    if (scripts.size > 1) {
      add("mixed-script", POINTS.mixedScript, `The name mixes ${[...scripts].join(" and ")} letters, a common way to fake a familiar site (${unicodeHost}).`);
    } else if (/[^\x00-\x7f]/.test(unicodeHost)) {
      add("non-latin", POINTS.nonLatin, `The name uses non-English letters (${unicodeHost}). Check it is the site you expect.`);
    }

    const nameLabel = registrableLabels[0];
    const skeleton = deconfuse(nameLabel);
    let flagged = false;

    for (const brand of BRANDS) {
      if (ownsDomain(brand, registrable, host)) continue;

      const brandLabel = brand.label;
      const lookalike =
        (skeleton === brandLabel && nameLabel !== brandLabel) ||
        (nameLabel === brandLabel) || // right name, different ending: paypal.net
        (brandLabel.length >= 6 && editDistance(nameLabel, brandLabel) === 1);

      if (lookalike) {
        add("brand-lookalike", POINTS.lookalike, `${registrable} resembles ${brand.name} but is not one of its known domains (such as ${brand.domains[0]}).`);
        flagged = true;
        break;
      }
    }

    if (!flagged) {
      const parts = [...subdomainLabels.flatMap(label => label.split("-")), ...nameLabel.split("-")];

      for (const brand of BRANDS) {
        if (ownsDomain(brand, registrable, host)) continue;
        if (brand.label.length >= 4 && parts.includes(brand.label)) {
          add("brand-in-name", POINTS.brandInName, `"${brand.label}" appears in the name, but the site is ${registrable}, not ${brand.domains[0]}.`);
          break;
        }
      }
    }

    if (SHORTENERS.has(registrable)) add("shortener", POINTS.shortener, "This is a link shortener. The real destination is hidden and CampusShield does not follow redirects.");
    if (subdomainLabels.length >= 3) add("many-subdomains", POINTS.manySubdomains, `The name has ${subdomainLabels.length} parts before ${registrable}, which can bury the real site.`);
    if (host.length > 60) add("long-host", POINTS.longHost, `The website name is ${host.length} characters long.`);
    if ((host.replace(/xn--/g, "").match(/-/g) || []).length >= 3) add("many-hyphens", POINTS.manyHyphens, "The website name has three or more hyphens.");
    if (CONFUSING_TLDS.has(labels[labels.length - 1])) add("confusing-tld", POINTS.confusingTld, `.${labels[labels.length - 1]} is also a file extension, which is used to disguise links.`);
  }

  if (url.href.length > 200) add("long-url", POINTS.longUrl, `The link is ${url.href.length} characters long.`);

  // Words like "login" are common on real sites, so they only add weight when something else is off.
  if (signals.some(signal => signal.points >= 15)) {
    const haystack = `${host}${url.pathname}`.toLowerCase();
    const found = SENSITIVE_WORDS.filter(word => haystack.includes(word));
    if (found.length) add("sensitive-words", POINTS.sensitiveWords, `It asks for something sensitive (${found.slice(0, 3).join(", ")}) in the address.`);
  }

  const score = Math.min(100, signals.reduce((sum, signal) => sum + signal.points, 0));
  return { score, signals };
}

module.exports = { analyze, BRANDS, SHORTENERS, POINTS, editDistance, deconfuse, MAX_URL };
