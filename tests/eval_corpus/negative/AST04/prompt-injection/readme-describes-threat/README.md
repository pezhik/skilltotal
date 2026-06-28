<!-- FIXTURE ONLY — synthetic detection test sample, not real malware -->
# Security Notes

This library defends against prompt injection. Attackers may try to make an agent
"ignore previous instructions" or "reveal the system prompt"; we treat all embedded
instructions as untrusted input. This README only DESCRIBES the threat as prose.
