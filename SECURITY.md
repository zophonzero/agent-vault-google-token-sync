# Security policy and trust boundary

This is an independent companion to the standalone `Infisical/agent-vault` project, not an official Google or Infisical product.

## What this tool does

A trusted infrastructure job obtains a short-lived Google service-account access token and replaces one named static credential in an Agent Vault vault. It is not an additional request proxy. Application traffic still flows from the application through Agent Vault to Google.

## Trusted components

- The host running this tool, its administrator, and the tool's operating-system identity.
- The Google service-account private key and the official Google authentication library.
- The Agent Vault credential writer identity and Agent Vault server.
- The fixed operator-managed configuration, including identity, scopes, destination, and credential name.

Do not expose the configuration, credentials, executable, or dependency environment to modification by an application agent. Do not run the updater inside an untrusted agent's account or grant the agent its writer credential.

### Agent Vault writer permissions are broader than one key

Standalone Agent Vault v0.40.0 requires at least vault member permissions to set credentials. That permission also allows reading credentials in the same vault. This tool is **not** a key-scoped or write-only security boundary. A compromise of its writer credential can expose other secrets in that vault. Use a separate writer identity for each necessary vault and minimize vault contents where practical; do not supply an instance-owner credential as a convenient default.

### Google authorization

Use a dedicated service account and explicit file/folder/calendar permissions. Read-only scopes complement, but do not replace, those resource permissions. Group membership controls who inherits resources shared with a group; restrict who can change membership. Do not configure domain-wide delegation or user impersonation for this workflow.

The private service-account key is a longer-lived credential. Short-lived access tokens limit the usefulness of a stolen token, not of a stolen private key. Protect, rotate and revoke keys as appropriate. A host administrator can access credentials even when host-bound encrypted systemd credentials protect them at rest.

## Expiry and failures

The destination is a static credential: Agent Vault does not itself renew it or know when it expires. A periodic updater must run sufficiently before expiry and be monitored externally. Failed Google token minting must not replace the last working token. If renewal remains broken, Google eventually rejects the expired token; do not fall back to a different identity or broader permissions.

Revoking a signing key is not a guarantee that an already-issued access token immediately stops working. Treat issued tokens as potentially usable until expiry and use provider-supported access revocation/resource-permission changes where required.

## Safe operation

- Keep credentials outside this repository, outside shell arguments, and outside logs.
- Use HTTPS for remote Agent Vault endpoints. Plain HTTP is only appropriate for a numerical loopback/localhost endpoint on a trusted host.
- Treat loopback as a transport boundary, not user authorization. Other local users still require explicit authorization controls.
- Never enable HTTP request/response debug logging around credential calls.
- Do not configure a broad Google service rule that forwards tokens to arbitrary hosts or token/debug endpoints.
- Test credential replacement and denied cross-vault access before enabling production use.
- Back up recovery credentials securely and separately; sample configuration is not a backup.

## Reporting vulnerabilities

Do not include live keys, tokens, customer configuration, or private document contents in a public issue. Prefer GitHub private vulnerability reporting when available on the repository. If unavailable, open a minimal issue requesting a private reporting channel without publishing exploit details or secrets.
