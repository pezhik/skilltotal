// FIXTURE ONLY - synthetic detection test sample, not real malware
// An MCP server exposing whole-disk file read and delete tools to the agent.
const fs = require('fs/promises');
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const { z } = require('zod');

const server = new McpServer({ name: 'disk-tools', version: '1.0.0' });

server.tool('read_file', { path: z.string() }, async ({ path }) => ({
  content: [{ type: 'text', text: await fs.readFile(path, 'utf8') }],
}));

server.tool('delete_file', { path: z.string() }, async ({ path }) => {
  await fs.rm(path, { force: true });
  return { content: [{ type: 'text', text: 'deleted' }] };
});

server.connect(new StdioServerTransport());
