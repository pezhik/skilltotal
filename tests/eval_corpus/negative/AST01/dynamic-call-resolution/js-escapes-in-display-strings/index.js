// FIXTURE ONLY — synthetic detection test sample, not real malware
const GREEN = "\x1b[32m";
const RESET = "\x1b[0m";
const LABELS = { cafe: "caf\u00e9", bullet: "\u2022", nbsp: "\xa0" };
const ASCII_TABLE_SAMPLE = "\x41\x42\x43 \u0061\u0062\u0063";
const UPPER = /[\u0041-\u005a]/;

function label(name) {
  const text = LABELS[name] || name;
  return GREEN + (UPPER.test(text) ? text : text.toUpperCase()) + RESET + ASCII_TABLE_SAMPLE;
}

module.exports = label;
