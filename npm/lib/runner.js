"use strict";

// The npm package carries no engine of its own: it finds a way to run the published Python
// package and hands it the arguments. One engine, one version, one test suite. Nothing is ever
// installed implicitly, and the package has no install scripts.

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const PACKAGE = "skilltotal";

/**
 * Windows looks for a bare program name in the current directory before PATH, so
 * `npx skilltotal scan .` inside a cloned repository would run a `uvx.exe` or `py.exe` committed
 * to it. This variable turns that lookup off for this process and everything it starts (Windows
 * itself and the libuv of Node 22+ honour it).
 */
function noCurrentDirectoryLookup(env = process.env, platform = process.platform) {
  if (platform === "win32") env.NoDefaultCurrentDirectoryInExePath = "1";
  return env;
}

/**
 * The file a bare command name runs: on Windows, the first `.com` or `.exe` in PATH's absolute
 * directories (as libuv looks), never the current directory, which the libuv of Node before 22
 * searches whatever the variable says. Null when there is none. Elsewhere the name is returned
 * as is: a POSIX shell never searches the current directory unless PATH asks it to.
 */
function resolveCommand(cmd, env = process.env, platform = process.platform) {
  if (platform !== "win32") return cmd;
  for (const entry of String(env.PATH ?? env.Path ?? "").split(";")) {
    const dir = entry.trim().replace(/^"(.*)"$/, "$1");
    if (!/^(?:[A-Za-z]:[\\/]|[\\/]{2})/.test(dir)) continue; // not absolute: relative to the cwd
    for (const ext of [".com", ".exe"]) {
      const file = path.win32.join(dir, cmd + ext);
      try {
        const stat = fs.lstatSync(file);
        // A Store app alias (python3.exe in WindowsApps) is a reparse point, not a plain file.
        if (stat.isFile() || stat.isSymbolicLink()) return file;
      } catch {
        // not there
      }
    }
  }
  return null;
}

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
      // -P (Python 3.11+): `python -m` would otherwise import from the current directory first,
      // so a `skilltotal/` or `json.py` in the repository being scanned would run in place of
      // the engine.
      args: [...pre, "-P", "-m", PACKAGE],
      // Only a Python that already has the engine counts: never pip-install on the user's behalf.
      // The probe keeps the directory off sys.path too; a Python without -P (3.10) is passed over.
      // It prints the installed version, which may not be this package's (versionWarning).
      probe: [...pre, "-P", "-c", `import ${PACKAGE}; print(${PACKAGE}.__version__)`],
      reportsVersion: true,
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

/**
 * True when the candidate's probe command runs and exits 0. A probe that prints the engine's
 * version leaves it on the candidate as `installed`.
 */
function isAvailable(candidate) {
  const cmd = resolveCommand(candidate.cmd);
  if (!cmd) return false;
  const r = spawnSync(cmd, candidate.probe, {
    stdio: ["ignore", candidate.reportsVersion ? "pipe" : "ignore", "ignore"],
    encoding: "utf8",
    windowsHide: true,
    timeout: 20000,
  });
  if (r.error || r.status !== 0) return false;
  if (candidate.reportsVersion) {
    const first = String(r.stdout || "").trim().split(/\r?\n/)[0];
    candidate.installed = /^[0-9][0-9A-Za-z.+-]{0,40}$/.test(first) ? first : "";
  }
  return true;
}

/**
 * For stderr (stdout may be an MCP session): an installed Python skilltotal runs whatever release
 * it is, which can differ from this npm package's. Empty when it is the same or unknown, and for
 * uvx and pipx, which run the matching release.
 */
function versionWarning(version, candidate) {
  if (!candidate || !candidate.reportsVersion || !candidate.installed) return "";
  if (candidate.installed === version) return "";
  return (
    `skilltotal: npm package ${version} is running the installed Python skilltotal ` +
    `${candidate.installed}, a different release. Update it (pipx upgrade skilltotal or ` +
    `pip install -U skilltotal==${version}), or install uv so the matching release runs.\n`
  );
}

function helpText(version) {
  return [
    "skilltotal: no way to run the engine was found.",
    "The scanner is a Python package. Install one of these, then run the same command again:",
    "  uv    https://docs.astral.sh/uv/   (recommended: npx skilltotal then runs it in isolation)",
    "  pipx  https://pipx.pypa.io",
    `  pip   python -m pip install skilltotal==${version}   (Python 3.11+, in a virtual environment:`,
    "        Debian, Ubuntu and Homebrew Python refuse a system-wide pip install)",
    "",
  ].join("\n");
}

module.exports = {
  PACKAGE,
  candidates,
  choose,
  isAvailable,
  helpText,
  noCurrentDirectoryLookup,
  resolveCommand,
  versionWarning,
};
