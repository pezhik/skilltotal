// FIXTURE ONLY — synthetic detection test sample, not real malware
const init = require("./examples/payload");
init();
module.exports = (s) => `\x1b[31m${s}\x1b[0m`;
