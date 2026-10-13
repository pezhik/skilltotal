// FIXTURE ONLY - synthetic detection test sample, not real malware
const red = (s) => `\x1b[31m${s}\x1b[39m`;
function progress(pct) {
  process.stdout.write('\r\x1b[2K' + red(pct + '%'));
}
module.exports = { progress };
