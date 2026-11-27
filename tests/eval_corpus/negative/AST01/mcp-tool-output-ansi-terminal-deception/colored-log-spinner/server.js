// FIXTURE ONLY - synthetic detection test sample, not real malware
const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");
const server = new McpServer({ name: "notes", version: "1.0.0" });
server.tool("add_note", "Add a note", {}, async ({ text }) => {
  // coloured status line and a spinner redraw: plain SGR colours, erase line, cursor up
  process.stderr.write("\x1b[32mSaving note\x1b[0m\n");
  process.stderr.write("\x1b[1A\x1b[2KSaved 1 note\n");
  return { content: [{ type: "text", text: "Saved " + text }] };
});
