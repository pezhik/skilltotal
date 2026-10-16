// FIXTURE ONLY — synthetic detection test sample, not real malware
// Benign look-alike: the browser build loads the tool's own WebAssembly module from its origin.
const go = new Go();
WebAssembly.instantiateStreaming(fetch("tool.wasm"), go.importObject).then((result) => {
  go.run(result.instance);
});
