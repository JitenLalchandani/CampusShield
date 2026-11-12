"use strict";

const path = require("node:path");

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
const SEVERITY_WEIGHT = { critical: 30, high: 18, medium: 10, low: 4 };

const EXECUTABLE_EXTENSIONS = new Set([
  ".app", ".bat", ".cmd", ".com", ".command", ".dmg", ".exe", ".jar", ".jse",
  ".msi", ".pkg", ".ps1", ".scr", ".sh", ".vbs", ".wsf", ".hta"
]);

const DOCUMENT_EXTENSIONS = new Set([
  ".csv", ".doc", ".docx", ".gif", ".jpg", ".jpeg", ".mp3", ".mp4", ".pdf",
  ".png", ".ppt", ".pptx", ".rtf", ".svg", ".txt", ".xls", ".xlsx", ".zip"
]);

const SCRIPT_EXTENSIONS = new Set([
  ".bash", ".command", ".js", ".mjs", ".php", ".pl", ".ps1", ".py", ".rb",
  ".sh", ".zsh"
]);

const SCRIPT_PATTERNS = [
  {
    id: "download-execute",
    title: "Downloads and runs code",
    severity: "high",
    pattern: /\b(curl|wget)\b[^\n]{0,300}\|\s*(sudo\s+)?(sh|bash|zsh|dash|python[0-9.]*|perl|ruby)\b/i,
    detail: "A script downloads content and pipes it directly into an interpreter.",
    recommendation: "Open the script in a text editor and verify the source before running it."
  },
  {
    id: "powershell-encoded",
    title: "Encoded PowerShell command",
    severity: "high",
    pattern: /\bpowershell(\.exe)?\b[^\n]{0,200}\s-(enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}/i,
    detail: "An encoded PowerShell command is present, a common way to hide malicious code.",
    recommendation: "Decode the command or delete the file unless you created it."
  },
  {
    id: "obfuscated-execution",
    title: "Obfuscated code execution",
    severity: "medium",
    pattern: /(base64\s+(-d|--decode)[^\n|]{0,120}\|\s*(sh|bash)|eval\s*\(\s*(atob|Buffer\.from)\s*\(|FromBase64String\s*\([^)]{0,200}\)\s*\)?\s*\|\s*IEX|Invoke-Expression[^\n]{0,120}FromBase64String)/i,
    detail: "The file decodes hidden content and executes it.",
    recommendation: "Treat the file as untrusted and inspect what it decodes before running it."
  },
  {
    id: "reverse-shell",
    title: "Reverse shell pattern",
    severity: "high",
    pattern: /(\/dev\/tcp\/|nc\s+(-[a-z]*e|--exec)\s|ncat\s+(-[a-z]*e|--exec)\s|bash\s+-i\s+>&\s*\/dev\/tcp)/i,
    detail: "The file contains a pattern used to open a remote command shell.",
    recommendation: "Do not run it. Quarantine the file and review how it arrived."
  },
  {
    id: "disable-security",
    title: "Tampers with security settings",
    severity: "medium",
    pattern: /(spctl\s+--master-disable|csrutil\s+disable|Set-MpPreference\s+-Disable|netsh\s+advfirewall\s+set\s+.*\s+state\s+off)/i,
    detail: "The script tries to disable a platform security control.",
    recommendation: "Do not run it. Review the file and who delivered it."
  }
];

const MAGIC_CHECKS = [
  { kind: "macho", test: head => isMachO(head) },
  { kind: "pe", test: head => head.length >= 2 && head[0] === 0x4d && head[1] === 0x5a },
  { kind: "elf", test: head => head.subarray(0, 4).toString("latin1") === "\x7fELF" },
  { kind: "script", test: head => head.subarray(0, 2).toString("latin1") === "#!" },
  { kind: "zip", test: head => head.subarray(0, 2).toString("latin1") === "PK" },
  { kind: "pdf", test: head => head.subarray(0, 4).toString("latin1") === "%PDF" }
];

function isMachO(head) {
  if (head.length < 4) return false;

  const magic = head.readUInt32BE(0);
  return [
    0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe,
    0xcafebabe, 0xbebafeca
  ].includes(magic);
}

function extensionOf(name) {
  return path.extname(String(name || "")).toLowerCase();
}

function parseBaseName(name) {
  return String(name || "").split(/[\\/]/).pop() || "unknown";
}

function detectMagic(head) {
  for (const check of MAGIC_CHECKS) {
    if (check.test(head)) return check.kind;
  }
  return "unknown";
}

function isTextLike(head) {
  if (!head.length) return false;
  if (head.includes(0)) return false;

  let printable = 0;

  for (const byte of head) {
    if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte < 127) || byte >= 160) {
      printable += 1;
    }
  }

  return printable / head.length > 0.85;
}

function doubleExtension(name) {
  return /\.(csv|docx?|gif|jpe?g|mp[34]|pdf|png|pptx?|rar|rtf|svg|txt|xlsx?|zip|7z)\.(app|bat|cmd|com|command|dmg|exe|hta|jar|jse|msi|pkg|ps1|scr|sh|vbs|wsf)$/i
    .test(name);
}

function finding(id, title, severity, detail, recommendation) {
  return { id, title, severity, detail, recommendation };
}

function analyzeFile({ filePath, name, head, signature, isScriptContent }) {
  const findings = [];
  const base = parseBaseName(name);
  const ext = extensionOf(base);
  const magic = detectMagic(head);

  if (signature) {
    findings.push(finding(
      "signature-match",
      `Signature match: ${signature.name}`,
      signature.severity,
      signature.note || "The file hash matches a known signature in the local database.",
      "Quarantine the file and review where it came from. Do not open or run it."
    ));
  }

  if (doubleExtension(base)) {
    findings.push(finding(
      "double-extension",
      "Disguised file type",
      "high",
      `The name ends in a document extension but the real extension is ${ext || "unknown"}.`,
      "Rename or remove the file unless you expected an executable with this name."
    ));
  }

  if (base.startsWith(".") && EXECUTABLE_EXTENSIONS.has(ext) && base !== ".DS_Store") {
    findings.push(finding(
      "hidden-executable",
      "Hidden executable",
      "medium",
      "The file is hidden and has an executable extension.",
      "Reveal hidden files and confirm you created this file."
    ));
  }

  if (DOCUMENT_EXTENSIONS.has(ext) && ["macho", "pe", "elf", "script"].includes(magic)) {
    findings.push(finding(
      "type-mismatch",
      "File contents do not match the extension",
      "high",
      `The file is named ${ext} but its header is ${magic === "script" ? "a script" : `an ${magic} executable`}.`,
      "Do not open it. Delete or quarantine the file and check how it arrived."
    ));
  }

  if (isScriptContent && SCRIPT_EXTENSIONS.has(ext) && isTextLike(head)) {
    const text = head.toString("utf8");

    for (const rule of SCRIPT_PATTERNS) {
      if (rule.pattern.test(text)) {
        findings.push(finding(
          rule.id,
          rule.title,
          rule.severity,
          rule.detail,
          rule.recommendation
        ));
      }
    }
  }

  if (!findings.length) return null;

  const severity = findings.reduce(
    (worst, item) => SEVERITY_RANK[item.severity] > SEVERITY_RANK[worst] ? item.severity : worst,
    "low"
  );

  return {
    filePath,
    name: base,
    extension: ext || null,
    magic,
    severity,
    reasons: findings
  };
}

function severityWeight(severity) {
  return SEVERITY_WEIGHT[severity] || 0;
}

module.exports = {
  analyzeFile,
  detectMagic,
  severityWeight,
  isTextLike,
  parseBaseName,
  EXECUTABLE_EXTENSIONS,
  SCRIPT_EXTENSIONS,
  SEVERITY_RANK
};
