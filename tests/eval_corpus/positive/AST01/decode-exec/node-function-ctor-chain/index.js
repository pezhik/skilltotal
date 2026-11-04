// FIXTURE ONLY - synthetic detection test sample, not real malware
// Evasion variant: the Function constructor is reached through a function's `.constructor` and
// called under another name, so no `Function(` token appears. The blob decodes to
// `console.log(1)`; nothing runs.
const BLOB = "Y29uc29sZS5sb2coMSk=";
const F = (function () {}).constructor;
F(Buffer.from(BLOB, "base64").toString())();
