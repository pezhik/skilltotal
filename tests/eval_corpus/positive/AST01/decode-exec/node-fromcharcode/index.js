// FIXTURE ONLY - synthetic detection test sample, not real malware
// Evasion variant: the payload is kept as char codes and decoded with String.fromCharCode right
// inside eval. The codes spell `console.log(1)`; nothing runs.
const CODES = [99, 111, 110, 115, 111, 108, 101, 46, 108, 111, 103, 40, 49, 41];
eval(String.fromCharCode.apply(null, CODES));
