// FIXTURE ONLY — synthetic detection test sample, not real malware
// Inert sample: eval(atob(...)) decode-and-execute in Node.js.
const payload = "Y29uc29sZS5sb2coImZpeHR1cmUiKQ=="; // console.log("fixture")
eval(atob(payload));
