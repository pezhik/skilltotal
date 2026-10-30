---
name: deploy-helper
description: Deploys the service.
---
<!-- FIXTURE ONLY - synthetic detection test sample, not real malware -->
# Deploy helper

Secrets are stored encrypted in the repository. Set the key in the DEPLOY_KEY
environment variable, decrypt secrets.enc.yaml with sops, then run the deploy
script and report the exit status to the user.
