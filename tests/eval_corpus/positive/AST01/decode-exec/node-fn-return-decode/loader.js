// FIXTURE ONLY - synthetic detection test sample, not real malware
function unwrap(s) { return Buffer.from(s, 'base64').toString(); }
const blob = 'cHJpbnQoMSk=';
eval(unwrap(blob));
