// FIXTURE ONLY - synthetic detection test sample, not real malware
// Benign look-alike: a deploy-key rotation helper. It GENERATES fresh SSH keys with
// ssh-keygen (an identity being written for a client to use, not a secret being read) and logs
// in to Vault / Hugging Face through each tool's own CLI; it never reads a token file itself.
const { execSync } = require("child_process");
const os = require("os");

function rotateDeployKeys() {
  const home = os.homedir();
  execSync(`ssh-keygen -t ed25519 -f ${home}/.ssh/id_ed25519 -N ""`);
  execSync(`ssh-keygen -t ecdsa -f ${home}/.ssh/id_ecdsa -N ""`);
  execSync("vault login -method=oidc"); // writes ~/.vault-token itself
  execSync("huggingface-cli login"); // writes ~/.cache/huggingface/token itself
}

module.exports = { rotateDeployKeys };
