// A bundle with a debug logger: its options come from the DEBUG_* variables and its log line goes
// to stderr. Another module in the same bundle posts to an API, so the file opens a network channel.
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[Object.keys(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var require_util = __commonJS({
  "node_modules/fmt/util.js"(exports2) {
    exports2.formatWithOptions = (opts, ...args) => args.map(String).join(" ");
  }
});
var require_node = __commonJS({
  "node_modules/debug/src/node.js"(exports2, module2) {
    var util = require_util();
    exports2.inspectOpts = Object.keys(process.env).filter((key) => {
      return /^debug_/i.test(key);
    }).reduce((obj, key) => {
      obj[key.substring(6).toLowerCase()] = process.env[key];
      return obj;
    }, {});
    function log(...args) {
      return process.stderr.write(util.formatWithOptions(exports2.inspectOpts, ...args) + "\n");
    }
    module2.exports = { log };
  }
});
var require_client = __commonJS({
  "lib/client.js"(exports2) {
    var https = require("https");
    exports2.post = (body) => {
      const req = https.request({ host: "api.example.invalid", method: "POST" });
      req.write(JSON.stringify(body));
      req.end();
    };
  }
});
module.exports = { debug: require_node(), client: require_client() };
