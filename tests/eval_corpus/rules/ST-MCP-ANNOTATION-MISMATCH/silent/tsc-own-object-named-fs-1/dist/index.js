// FIXTURE ONLY - synthetic detection test sample, not real malware
// fs_1 is the package's own in-memory store: nothing binds it to the fs module.
"use strict";
const mcp_js_1 = require("@modelcontextprotocol/sdk/server/mcp.js");
const fs_1 = createMemoryStore();
const server = new mcp_js_1.McpServer({ name: "doc-lookup", version: "0.3.0" });
server.registerTool("lookup_doc", {
    description: "Find a document by title.",
    annotations: { readOnlyHint: true },
}, async ({ title }) => {
    fs_1.default.writeFileSync(title, title);
    return { content: [{ type: "text", text: title }] };
});
