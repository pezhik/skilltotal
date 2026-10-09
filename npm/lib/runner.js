"use strict";

// The npm package carries no engine of its own: it finds a way to run the published Python
// package and hands it the arguments. One engine, one version, one test suite. Nothing is ever
// installed implicitly, and the package has no install scripts.

const { spawnSync } = require("node:child_process");

const PACKAGE = "skilltotal";

/**
 * Ways to run the engine, best first. uvx and pipx run the release that matches this npm
 * version in an isolated environment; an installed Python runs whatever skilltotal it has.
 */
function candidates(version, platform = process.platform) {
  const spec = `${PACKAGE}==${version}`;
  const pythons =
    platform === "win32"
      ? [["py", ["-3"]], ["python", []], ["python3", []]]
      : [["python3", []], ["python", []]];
  return [
    { name: "uvx", cmd: "uvx", args: ["--from", spec, PACKAGE], probe: ["--version"] },
    { name: "pipx", cmd: "pipx", args: ["run", "--spec", spec, PACKAGE], probe: ["--version"] },
    ...pythons.map(([cmd, pre]) => ({
      name: cmd,
      cmd,
      args: [...pre, "-m", PACKAGE],
      // Only a Python that already has the engine counts: never pip-install on the user's behalf.
      probe: [...pre, "-c", `import ${PACKAGE}`],
    })),
  ];
}

/** The first candidate `available` accepts, or null. */
function choose(version, available, platform = process.platform) {
  for (const c of candidates(version, platform)) {
    if (available(c)) return c;
  }
  return null;
}

/** True when the candidate's probe command runs and exits 0. */
function isAvailable(candidate) {
  const r = spawnSync(candidate.cmd, candidate.probe, {
    stdio: "ignore",
    windowsHide: true,
    timeout: 20000,
  });
  return !r.error && r.status === 0;
}

function helpText(version) {
  return [
    "skilltotal: no way to run the engine was found.",
    "The scanner is a Python package (Python 3.10+). Install one of these, then run the same command again:",
    "  uv    https://docs.astral.sh/uv/   (recommended: npx skilltotal then runs it in isolation)",
    "  pipx  https://pipx.pypa.io",
    `  pip   python -m pip install skilltotal==${version}`,
    "",
  ].join("\n");
}

module.exports = { PACKAGE, candidates, choose, isAvailable, helpText };
