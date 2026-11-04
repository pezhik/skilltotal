// FIXTURE ONLY - synthetic detection test sample, not real malware
// Evasion variant: the decoded payload is compiled into a vm.Script and run, with no eval( or
// Function( token. The blob decodes to `console.log(1)`; nothing runs.
const vm = require("vm");
const BLOB = "Y29uc29sZS5sb2coMSk=";
new vm.Script(Buffer.from(BLOB, "base64").toString()).runInThisContext();
