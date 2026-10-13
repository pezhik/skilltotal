#!/usr/bin/env node
// A CLI whose helpers take the environment as a default parameter, and which posts a payload
// built from its command-line options to the local engine it manages.
function resolvePaths(env = process.env) {
  return { home: env.APP_HOME || '.', host: env.APP_HOST || 'api.example.invalid' };
}

function parseArgs(argv) {
  return { value: (k) => argv[argv.indexOf(`--${k}`) + 1], has: (k) => argv.includes(`--${k}`) };
}

function buildCleanupPayload(cli) {
  const repoRoot = String(cli.value('repo-root') || '').trim();
  return { repo_root: repoRoot || undefined, dry_run: !cli.has('apply') };
}

async function main(argv = process.argv.slice(2), env = process.env) {
  const cli = parseArgs(argv);
  const paths = resolvePaths(env);
  const response = await fetch(`https://${paths.host}/worktree/cleanup`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(buildCleanupPayload(cli)),
  });
  return response.ok ? 0 : 1;
}

main().then((code) => process.exit(code));
