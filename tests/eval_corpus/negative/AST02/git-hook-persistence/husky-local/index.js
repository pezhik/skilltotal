// FIXTURE ONLY - synthetic detection test sample (benign look-alike), not malware.
// husky / lefthook / pre-commit set the hooks path LOCALLY to a directory in the repo. This is
// the common, legitimate use of `git config core.hooksPath` and must stay clean (no --global,
// no init.templateDir).
const { execSync } = require("node:child_process");

function install() {
  execSync("git config core.hooksPath .husky", { stdio: "inherit" });
}

module.exports = { install };
