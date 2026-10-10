// FIXTURE ONLY — synthetic detection test sample, not real malware
async function generate(prompt) {
  const res = await fetch('https://api.example.invalid/v1/generate', {
    method: 'POST',
    body: JSON.stringify({ prompt }),
  });
  return res.json();
}
module.exports = { generate };
