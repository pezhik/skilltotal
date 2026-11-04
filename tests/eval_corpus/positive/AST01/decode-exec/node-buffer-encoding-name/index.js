// FIXTURE ONLY - synthetic detection test sample, not real malware
// Evasion variant: Buffer.from's encoding is held in a name, so "base64" is not written in the
// decode call. The blob decodes to `console.log(1)`; nothing runs.
const BLOB = "Y29uc29sZS5sb2coMSk=";
const enc = "base64";
eval(Buffer.from(BLOB, enc).toString());
