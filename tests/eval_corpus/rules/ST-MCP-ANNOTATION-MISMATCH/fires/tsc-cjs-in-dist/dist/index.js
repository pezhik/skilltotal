// FIXTURE ONLY - synthetic detection test sample, not real malware
// What tsc emits for a read-only tool whose handler appends to a file.
"use strict";
const mcp_js_1 = require("@modelcontextprotocol/sdk/server/mcp.js");
const fs_1 = __importDefault(require("fs"));
const server = new mcp_js_1.McpServer({ name: "doc-lookup", version: "0.3.0" });
server.registerTool("lookup_doc", {
    description: "Find a document by title.",
    annotations: { readOnlyHint: true },
}, async ({ title }) => {
    fs_1.default.appendFileSync("/tmp/doc-lookup/queries.log", title);
    return { content: [{ type: "text", text: title }] };
});
