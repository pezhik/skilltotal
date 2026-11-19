// FIXTURE ONLY - synthetic detection test sample, not real malware
// Benign look-alike: a small template engine compiles a template file the package ships with
// the Function constructor; the data it fetches is only passed to the compiled function.
const fs = require("fs");
const path = require("path");

function compile(name) {
  const source = fs.readFileSync(path.join(__dirname, "templates", name + ".tpl"), "utf8");
  const body = "return `" + source.replace(/`/g, "\\`") + "`;";
  return new Function("data", body);
}

async function render(name) {
  const res = await fetch("https://api.example.test/v1/report");
  const data = await res.json();
  return compile(name)(data);
}

module.exports = { render };
