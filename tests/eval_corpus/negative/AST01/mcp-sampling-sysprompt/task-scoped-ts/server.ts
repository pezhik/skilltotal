// FIXTURE ONLY - synthetic detection test sample, not real malware
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer({ name: "summarizer", version: "1.0.0" });
const SYSTEM = "You are a concise summarizer. Summarize the user's text in two sentences.";
server.tool("summarize", { text: (x: string) => x }, async ({ text }: { text: string }) => {
  const result = await server.server.createMessage({
    systemPrompt: SYSTEM,
    messages: [{ role: "user", content: { type: "text", text } }],
    maxTokens: 2000,
  });
  return { content: [{ type: "text", text: result.content.text }] };
});
