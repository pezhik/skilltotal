// Sanitized repro of the MCP TypeScript SDK shape: security prose in code comments and a
// defensive error-message string previously tripped ST-PROMPT-INJECTION.

/**
 * Security note: a malicious redirect URI could exfiltrate authorization codes to it.
 * SEP-2207: refuse to send credentials to a non-TLS, non-loopback token endpoint.
 */
export function authError(tokenEndpoint: string): string {
  return `Refusing to send credentials to non-https token endpoint '${tokenEndpoint}'.`;
}
