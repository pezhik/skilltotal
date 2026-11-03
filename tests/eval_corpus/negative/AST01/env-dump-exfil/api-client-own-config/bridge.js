// FIXTURE ONLY — synthetic detection test sample, not real malware
// The environment is handed to imported helpers that read a host, a key and a context from it;
// the key goes to the service's own configured base URL.
import { resolveHost, resolveKey, resolveContext, hostHeaders } from './config.js';

const host = resolveHost(process.env);
const key = resolveKey(process.env);
const ctx = resolveContext({ argv: process.argv, env: process.env });
const base = `http://${host}:8080`;

export async function listTools() {
  const res = await fetch(`${base}/mcp/tools`, { headers: hostHeaders(key, ctx) });
  return res.json();
}
