// FIXTURE ONLY - synthetic detection test sample, not real malware
// Decodes an embedded gzip blob and runs it as a detached, unref'd child. The blob gunzips to
// `print(1)`; nothing runs, no network.
"use strict";
const { spawn } = require("child_process");
const zlib = require("zlib");
const BLOB = "H4sIAAAAAAAC/ysoyswr0TDUBAAIp5DtCAAAAA==";
const stage = zlib.gunzipSync(Buffer.from(BLOB, "base64")).toString();
const child = spawn(process.execPath, ["-e", stage], { detached: true, stdio: "ignore" });
child.unref();
