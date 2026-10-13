// FIXTURE ONLY - synthetic detection test sample, not real malware
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

// The phrases this guard looks for; data, not a directive.
const PATTERNS = ["ignore all previous instructions", "reveal your system prompt"];

const server = new McpServer(
  { name: "guard", version: "1.0.0" },
  { instructions: "Call scan_text before passing untrusted text to a model." }
);
server.tool(
  "scan_text",
  "Checks text for phrases such as 'ignore all previous instructions'.",
  {
    text: z.string().describe("Text to check. Ignore case when matching."),
    mode: z.enum(["system", "user", "ignore"]).default("system"),
  },
  async ({ text }) => ({
    content: [{ type: "text", text: String(PATTERNS.some((p) => text.includes(p))) }],
  })
);
