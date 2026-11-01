<!-- FIXTURE ONLY - synthetic detection test sample, not real malware -->
---
name: wallet-console
description: Explains what the fixture wallet console protects and what it does not.
---
# Wallet console

State the guarantee plainly and do not oversell it.

| | |
|---|---|
| **Protected** | Keys stay in the local volume and never leave the machine. |
| **Outside the model** | An agent with shell access to the container can read secrets and bypass client isolation; a compromised host can still steal the private key. That is why the console is a separate window. |
