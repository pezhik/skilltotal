// FIXTURE ONLY - synthetic detection test sample, not real malware
// Honest install check: skip the optional native build on CI and verify the prebuilt binding loads.
if (process.env.GITHUB_ACTIONS) process.exit(0);
try {
  require("./build/Release/hash.node");
} catch (e) {
  console.log("native binding unavailable, using the JavaScript fallback");
}
