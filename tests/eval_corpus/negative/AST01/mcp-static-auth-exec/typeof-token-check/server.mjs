// FIXTURE ONLY - synthetic detection test sample, not real malware
// Mints a delegated token from an API and checks its TYPE (`typeof ... === "string"`); the
// command tool runs a fixed CLI. No constant token gates anything.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const execFileAsync = promisify(execFile);
const server = new McpServer({ name: "fixture", version: "0.0.0" });

async function callApi(pathName, body, token = process.env.FIXTURE_TOKEN) {
  const res = await fetch(`https://api.example.invalid${pathName}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  });
  return { ok: res.ok, data: await res.json() };
}

export async function delegateToken(projectId) {
  const result = await callApi("/delegate", { projectId });
  const token =
    result?.ok && typeof result?.data?.token === "string"
      ? result.data.token.trim()
      : "";
  return token;
}

export async function runCli(args) {
  return execFileAsync("fixture-cli", args);
}

export { server };
