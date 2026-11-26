"use strict";

// Shannon entropy of a byte sample, in bits per byte (0 to 8). Encrypted data sits close to 8.
// Already-compressed formats (images, archives, Office files) are also near 8 in normal use, so
// the shield only reads entropy on file types that are normally plain text.

const HIGH_ENTROPY_BITS = 7.5;
const MIN_SAMPLE_BYTES = 256;

const LOW_ENTROPY_EXTENSIONS = new Set([
  ".txt", ".md", ".csv", ".tsv", ".rtf", ".json", ".xml", ".html", ".htm", ".css", ".log",
  ".js", ".mjs", ".ts", ".py", ".java", ".c", ".h", ".cpp", ".go", ".rb", ".php", ".sh",
  ".sql", ".yaml", ".yml", ".ini", ".cfg", ".tex"
]);

function shannonEntropy(buffer) {
  if (!buffer || !buffer.length) return 0;

  const counts = new Array(256).fill(0);
  for (const byte of buffer) counts[byte] += 1;

  let entropy = 0;

  for (const count of counts) {
    if (!count) continue;
    const p = count / buffer.length;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

// Returns true or false when there is enough data to judge, and null when there is not. A short
// file cannot be judged, and null never counts as a signal.
function looksEncrypted(buffer) {
  if (!buffer || buffer.length < MIN_SAMPLE_BYTES) return null;
  return shannonEntropy(buffer) >= HIGH_ENTROPY_BITS;
}

module.exports = {
  HIGH_ENTROPY_BITS,
  MIN_SAMPLE_BYTES,
  LOW_ENTROPY_EXTENSIONS,
  shannonEntropy,
  looksEncrypted
};
