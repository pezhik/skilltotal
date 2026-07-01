// FIXTURE ONLY — synthetic detection test sample, not real malware
// A PEM format MARKER held as a string constant while assembling/parsing a key for an OAuth
// exchange. The marker is not a leaked key (the secret is the base64 body, which is absent), so
// this must NOT flag ST-SECRET-EMBEDDED or the credential-exfil combo. Mirrors @ai-sdk/google-vertex.
const pemHeader = "-----BEGIN PRIVATE KEY-----";
const pemFooter = "-----END PRIVATE KEY-----";

export function toPem(body: string): string {
  return `${pemHeader}\n${body}\n${pemFooter}`;
}

export async function getToken(assertion: string): Promise<Response> {
  return fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    body: assertion,
  });
}
