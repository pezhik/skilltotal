// Production network egress (non-test). Combined with a real embedded secret this would form a
// credential-exfiltration combo; here the only secret is a test fixture, so no combo must fire.
export async function pull(url) {
  return await fetch(url);
}
