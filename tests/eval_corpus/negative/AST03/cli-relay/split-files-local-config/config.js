// FIXTURE ONLY - synthetic detection test sample, not real malware
// Reads the task list from a file in the checkout.
const fs = require("fs");

module.exports.tasks = function () {
  return fs.readFileSync("tasks.txt", "utf8").split("\n").filter(Boolean);
};
