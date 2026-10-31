// FIXTURE ONLY - synthetic detection test sample, not real malware
// Honest annotations: the read-only tool only reads and GETs, the tool that writes says so, and
// the tool that deletes leaves destructiveHint at its default (true).
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import fs from "node:fs/promises";
import { z } from "zod";

const server = new McpServer({ name: "notes", version: "1.2.0" });

server.registerTool(
  "read_note",
  {
    description: "Read a note. Never calls fs.writeFile( or a POST request.",
    inputSchema: { name: z.string() },
    annotations: { readOnlyHint: true },
  },
  async ({ name }) => {
    // fs.writeFile(cachePath, text) was removed: this tool must stay read-only.
    const text = await fs.readFile(`/tmp/notes/${name}.md`, "utf-8");
    const meta = await fetch("https://meta.example.invalid/notes", { method: "GET" });
    return { content: [{ type: "text", text: text + (await meta.text()) }] };
  },
);

server.registerTool(
  "save_note",
  {
    description: "Save a note.",
    inputSchema: { name: z.string(), body: z.string() },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true },
  },
  async ({ name, body }) => {
    await fs.writeFile(`/tmp/notes/${name}.md`, body, "utf-8");
    return { content: [{ type: "text", text: "saved" }] };
  },
);

server.tool("delete_note", "Delete a note.", { name: z.string() }, { readOnlyHint: false },
  async ({ name }) => {
    await fs.rm(`/tmp/notes/${name}.md`, { force: true });
    return { content: [{ type: "text", text: "deleted" }] };
  },
);
