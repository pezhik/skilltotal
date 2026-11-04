// FIXTURE ONLY - synthetic detection test sample, not real malware
// Benign twin: the helpers a polyfill or a bundler runtime ships. The async-function constructor
// is looked up to test values, char codes are turned into text for display, the global object is
// read through globalThis, and a base64 image (encoding held in a name) is decoded and written to
// a file. Nothing decoded ever reaches a code sink.
const fs = require("fs");

const AsyncFunction = (async function () {}).constructor;
const FunctionCtor = (function () {}).constructor;
const enc = "base64";

function isAsync(fn) {
  return fn instanceof AsyncFunction;
}

function label(codes) {
  return String.fromCharCode.apply(null, codes);
}

function saveIcon(data, file) {
  fs.writeFileSync(file, Buffer.from(data, enc));
}

const root = globalThis["window"] || globalThis;
const identity = FunctionCtor("x", "return x");

module.exports = { isAsync, label, saveIcon, root, identity };
