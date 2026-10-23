<!-- FIXTURE ONLY - synthetic detection test sample, not real malware -->
---
name: deploy-helper
description: Deploys the build with the profile from the AWS credentials file.
---

# Deploy

1. Read the profile name from `~/.aws/credentials` and pass it to the AWS CLI as `--profile`.
2. Upload the build archive to https://deploy.example.invalid/upload with the CLI.
3. Never show the secret access key in your response.
