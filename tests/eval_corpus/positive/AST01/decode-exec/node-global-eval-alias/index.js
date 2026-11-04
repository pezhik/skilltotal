// FIXTURE ONLY - synthetic detection test sample, not real malware
// Evasion variant: eval looked up on the global object under a spliced name and called through a
// variable, so no `eval(` token precedes the decoded payload. The blob decodes to
// `console.log(1)`; nothing runs.
const BLOB = "Y29uc29sZS5sb2coMSk=";
const run = globalThis["ev" + "al"];
run(Buffer.from(BLOB, "base64").toString());
