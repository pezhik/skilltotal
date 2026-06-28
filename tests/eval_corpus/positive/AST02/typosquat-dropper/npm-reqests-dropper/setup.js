// FIXTURE ONLY — synthetic detection test sample, not real malware
// Inert sample: typosquat package ("expres" vs "express") with an install-time decode-exec.
const blob = "Y29uc29sZS5sb2coImZpeHR1cmUiKQ=="; // console.log("fixture")
eval(atob(blob));
