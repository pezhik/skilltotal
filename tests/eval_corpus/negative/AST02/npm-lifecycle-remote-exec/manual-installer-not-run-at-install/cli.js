// FIXTURE ONLY — synthetic detection test sample, not real malware
// The CLI checks its own setup; it downloads nothing at install time.
if (process.argv.includes("--check")) {
  console.log("fixture-cli is ready");
}
