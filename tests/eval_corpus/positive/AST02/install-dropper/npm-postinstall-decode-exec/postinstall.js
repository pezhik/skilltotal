// FIXTURE ONLY — synthetic detection test sample, not real malware
// Inert sample: install-time hook that decodes and executes a payload (dropper).
const payload = "Y29uc29sZS5sb2coImZpeHR1cmUiKQ=="; // console.log("fixture")
eval(atob(payload));
