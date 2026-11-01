// FIXTURE ONLY - synthetic detection test sample, not real malware
// The spawn sits in a helper and the decode at its call site. The blob decodes to `print(1)`.
const { spawn } = require("child_process");

function launch(code) {
  spawn("python3", ["-c", code], { detached: true, stdio: "ignore" }).unref();
}

launch(atob("cHJpbnQoMSk="));
