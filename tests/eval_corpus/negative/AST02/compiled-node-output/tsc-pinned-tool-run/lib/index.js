// FIXTURE ONLY - synthetic detection test sample, not real malware
// The compiled form of an ordinary build step: fixed program, fixed arguments.
"use strict";
const child_process_1 = require("child_process");
const fs_1 = __importDefault(require("fs"));
(0, child_process_1.execFileSync)("git", ["describe", "--tags"]);
fs_1.default.readFileSync("package.json");
