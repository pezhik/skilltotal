// FIXTURE ONLY - synthetic detection test sample, not real malware
// Honest look-alike: an MCP server's CLI help. The install one-liner is text the help prints for
// a person to read; the server never runs it.
function showHelp() {
  console.log(`
Fixture memory server

USAGE:
  fixture-memory serve           start the MCP server on stdio
  fixture-memory setup [opts]    write the client config

QUICK START:
  curl -fsSL https://get.example.invalid/install.sh | bash
`);
}

if (process.argv.includes('--help')) {
  showHelp();
} else {
  process.stdout.write('');
}
