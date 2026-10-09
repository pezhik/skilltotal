"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { candidates, choose, isAvailable, helpText } = require("../lib/runner");
const pkg = require("../package.json");

test("uvx and pipx run the release that matches the npm version", () => {
  const [uvx, pipx] = candidates("1.2.3", "linux");
  assert.deepEqual([uvx.cmd, ...uvx.args], ["uvx", "--from", "skilltotal==1.2.3", "skilltotal"]);
  assert.deepEqual(
    [pipx.cmd, ...pipx.args],
    ["pipx", "run", "--spec", "skilltotal==1.2.3", "skilltotal"],
  );
});

test("an installed Python is the fallback, and only one that already has the engine", () => {
  const linux = candidates("1.0.0", "linux").slice(2);
  assert.deepEqual(linux.map((c) => c.cmd), ["python3", "python"]);
  for (const c of linux) {
    assert.deepEqual(c.args, ["-m", "skilltotal"]);
    assert.deepEqual(c.probe, ["-c", "import skilltotal"]);
  }
  const win = candidates("1.0.0", "win32").slice(2);
  assert.deepEqual(win.map((c) => c.cmd), ["py", "python", "python3"]);
  assert.deepEqual(win[0].args, ["-3", "-m", "skilltotal"]);
});

test("nothing in the plan installs anything", () => {
  for (const c of candidates("1.0.0", "linux")) {
    assert.ok(!c.args.includes("install") && !c.probe.includes("install"), c.name);
  }
});

test("choose takes the first available way, best first", () => {
  const only = (name) => (c) => c.name === name;
  assert.equal(choose("1.0.0", () => true, "linux").name, "uvx");
  assert.equal(choose("1.0.0", only("pipx"), "linux").name, "pipx");
  assert.equal(choose("1.0.0", only("python"), "linux").name, "python");
  assert.equal(choose("1.0.0", () => false, "linux"), null);
});

test("a command that does not exist is not available", () => {
  assert.equal(isAvailable({ cmd: "skilltotal-no-such-binary", probe: ["--version"] }), false);
});

test("the help names the pinned pip spec", () => {
  assert.match(helpText("9.9.9"), /pip install skilltotal==9\.9\.9/);
});

test("the package ships no install scripts and no dependencies", () => {
  const scripts = pkg.scripts || {};
  for (const hook of ["preinstall", "install", "postinstall", "prepare"]) {
    assert.equal(scripts[hook], undefined, hook);
  }
  assert.equal(pkg.dependencies, undefined);
});

// End to end through the real bin: runs only where some runner exists (CI installs the engine).
const bin = path.join(__dirname, "..", "bin", "skilltotal.js");
const runner = choose(pkg.version, isAvailable);

test("the bin runs the engine and passes the exit code through", { skip: !runner }, () => {
  const ok = spawnSync(process.execPath, [bin, "--version"], { encoding: "utf8" });
  assert.equal(ok.status, 0, ok.stderr);
  assert.match(ok.stdout, /^skilltotal \d+\.\d+\.\d+/);
  const bad = spawnSync(process.execPath, [bin, "no-such-command"], { encoding: "utf8" });
  assert.notEqual(bad.status, 0);
});
