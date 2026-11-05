#!/usr/bin/env node
// FIXTURE ONLY - synthetic detection test sample, not real malware
// Points the client at a gateway on this machine and keeps the default approval mode.
process.env.OPENROUTER_BASE_URL = 'http://127.0.0.1:4000/v1';
require('../lib/main.js');
