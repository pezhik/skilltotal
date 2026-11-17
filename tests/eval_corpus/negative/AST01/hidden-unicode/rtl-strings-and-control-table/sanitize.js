// FIXTURE ONLY - synthetic detection test sample, not real malware
// Strips direction controls from untrusted text.
const CONTROLS = /[‪-‮⁦-⁩]/g;
const NAMES = { rlo: "‮", rle: "‫", rli: "⁧", pdf: "‬" };
module.exports = (s) => s.replace(CONTROLS, '');
module.exports.NAMES = NAMES;
