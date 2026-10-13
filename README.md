# Agent Vault Google Token Sync

A small, independent Linux companion for [standalone Infisical Agent Vault](https://github.com/Infisical/agent-vault): mint a short-lived Google service-account access token with the official `google-auth` SDK and publish it as a static Agent Vault credential.

**Your application keeps using Agent Vault.** This program is a scheduled credential updater, not another document proxy.

```text
Application ──► Agent Vault proxy ──► Google API
                       ▲
                       │ replace static credential
Scheduled updater ─────┘
       │
       └──► Google token endpoint (signed service-account assertion)
```

## Why this exists

Standalone Agent Vault v0.40.0 can inject static credentials and refresh OAuth credentials, but does not natively mint Google service-account tokens. This tool bridges that gap without changing Agent Vault or putting a service-account private key inside an application agent's environment.

One invocation uses one fixed service-account identity, scope list, vault and credential key. For multiple identities, run separately configured systemd timer instances. No database, web server, local token cache or additional proxy is needed.

## Status and limits

- Initial version: **0.1.0**. Linux, Python 3.11 or later.
- Unit/transport tests use generated ephemeral RSA keys and synthetic Google responses; no live credentials are required.
- Real-binary Agent Vault v0.40.0 backport testing has verified two complete updater publications using actual SDK-signed assertions (synthetic Google responses), hot replacement on a persistent HTTP proxy connection, encrypted credential storage, failure preservation and cross-vault denial. A separate lifecycle probe verified restart persistence.
- Offline systemd 259 testing exercised encrypted runtime credentials, DynamicUser, the service sandbox, successful key validation and wrong-identity rejection with generated test keys and networking disabled.
- **Real Google authentication, HTTPS CONNECT forwarding, and access to your shared documents must be verified in your deployment.** Tests using synthetic Google responses do not prove these work for your account.
- Only the read-only Drive, Docs, Sheets and Calendar scopes listed below are accepted. No Gmail, user impersonation, domain-wide delegation, arbitrary token endpoint, or write scope support.
- Not an official Google or Infisical product. Not compatible by assumption with other products also named “Agent Vault.”

## Security boundary — read this first

The updater is trusted infrastructure. Keep its config, code, private key and writer credential outside application-agent accounts and writable workspaces.

**Agent Vault v0.40.0 requires a vault member credential to publish tokens. Members can also read other credentials and write other keys in that vault. This is not a write-only or key-scoped credential.** Never give this credential to an application agent; do not use an instance-owner credential as a shortcut. See [SECURITY.md](SECURITY.md).

Use a built-in, static-only vault dedicated to this integration where possible. The upstream metadata API enumerates the vault even when a key is specified and can process dynamic leases. Existing OAuth/dynamic target keys are rejected. There is no compare-and-set operation: prevent concurrent key-type changes and run only one writer per target.

The Google private key stays on the trusted updater host. A signed assertion is sent to Google; the private key itself is not. Returned access tokens are published into Agent Vault's encrypted credential store. The program never intentionally prints credentials or provider error bodies; stdout/stderr use constant status/error categories.

## Install

Install from a reviewed checkout or pinned release on your trusted host:

```sh
python3 -m venv /opt/agent-vault-google-token-sync/venv
/opt/agent-vault-google-token-sync/venv/bin/pip install -r requirements.lock
/opt/agent-vault-google-token-sync/venv/bin/pip install --no-deps .
/opt/agent-vault-google-token-sync/venv/bin/agent-vault-google-token-sync --help
```

`requirements.lock` pins runtime versions; it is not a hash-verified cross-platform lock. For stricter supply-chain requirements, build and checksum a private wheelhouse before deployment. Keep the installation root-owned and read-only to the service user. Do not install into an agent's virtual environment.

## Configure

1. Create a dedicated Google service account. Do **not** grant broad Cloud project roles or enable domain-wide delegation.
2. Enable the Google APIs you need. Explicitly share the intended documents, folders or calendars with this service account (or a tightly managed group containing it).
3. Import its JSON key securely on the updater host, outside this repository. Never paste the key into chat, shell arguments, Git or logs.
4. Create a separate Agent Vault writer identity with member permissions only in the intended vault. Application identities must retain proxy-only permissions.
5. Copy [examples/config.json](examples/config.json), replace the example identity/vault, and select only needed scopes. This version uses systemd credential names; see the deployment guide below.

For direct execution, replace `service_account_credential` and `writer_token_credential` with `service_account_file` and `writer_token_file`, using absolute file paths. The writer file contains only the bearer token (one trailing newline is accepted). Never put the token itself in the JSON config.

Config and credential files must be regular, single-link files, owned by root or the executing user, mode **0600 or 0400**. Newer systemd's root-owned 0440 runtime credentials are also accepted inside the designated root-owned 0550 credential directory on a read-only filesystem, with matching root/service group ownership (systemd may grant access through a named-user ACL). Kernel access checks still apply; ordinary group-readable files remain rejected. Symlinks in any path component and ambiguous double-leading-slash paths are rejected. Protect parent directories against writes by untrusted users. Config validation also checks that the key's service-account email matches the configured identity and uses Google's fixed token endpoint.

```sh
agent-vault-google-token-sync --config /protected/config.json --check-config
agent-vault-google-token-sync --config /protected/config.json --once
```

`--check-config` checks configuration, protected file access and key parsing without network access; it does not verify Google authentication or Agent Vault authorization. `--once` is the default. Success prints `config-ok` or `sync-ok` and returns zero. Failures return nonzero without reflecting external error text.

### Allowed scopes

- `https://www.googleapis.com/auth/drive.readonly`
- `https://www.googleapis.com/auth/documents.readonly`
- `https://www.googleapis.com/auth/spreadsheets.readonly`
- `https://www.googleapis.com/auth/calendar.readonly`
- `https://www.googleapis.com/auth/calendar.events.readonly`

Scopes constrain API operations; they do not grant resource access. Resource sharing remains necessary.

### Agent Vault endpoint and proxy

The updater talks to the **management API**, not the forward-proxy port. It uses `GET /v1/credentials?reveal=false` for metadata and `POST /v1/credentials` for publication, always naming the vault explicitly. It reads metadata back after publication without revealing credential values.

HTTPS is required except when `allow_loopback_http: true` explicitly permits a numerical loopback address or `localhost`. TLS verification stays enabled; redirects and environment-provided proxies/netrc/CA overrides are not used.

Configure Agent Vault services separately to inject `Authorization: Bearer` from `GOOGLE_ACCESS_TOKEN` into only the Google API hosts/paths you need. Keep unmatched-host behavior denied and do not include token/debug endpoints. Proxy policy is not a replacement for Google's read-only scopes and resource permissions. This tool does not create proxy services, change agent permissions or distribute proxy credentials.

## Schedule and operate

Use [the systemd guide](docs/systemd.md) and the example service/timer. The service runs under a dynamic Unix identity with runtime credentials, a read-only filesystem and a 90-second whole-process timeout. The timer runs at startup and every five minutes, minting a fresh token every time. This intentionally trades a small number of additional token requests for no persistent secret cache or expiry state machine.

HTTP requests have bounded connect/read timeouts and response-size limits, but only the supervisor timeout bounds the whole process. There is no in-process retry loop: the next timer invocation retries the entire operation. Run exactly one job per target key.

If minting fails, no new credential is published and the old token remains until Google expires/revokes it. After an ambiguous publication/readback failure, the next run safely publishes another token. Agent Vault's static credential does **not** automatically know its Google expiry. Monitor timer failures externally before the token expires.

An optional `status_file` stores only `last_success` and `expires_at`, atomically with mode 0600. It must be an absolute, protected, writable path and not a config/credential path. Failures preserve the previous success status. A status-write failure can occur after successful token publication; monitor exit status as well as freshness. The example stateless service omits this file.

### Deployment acceptance checklist

- Offline config/key validation succeeds under the actual systemd identity.
- A real run produces `sync-ok`; only the intended vault/key is updated.
- A normal proxy-only application can read an explicitly shared test resource.
- A different identity cannot access that resource via the first identity's vault.
- A second scheduled run replaces the token without restarting Agent Vault.
- Logs contain only safe status categories, not assertions, keys or bearer tokens.
- Stop/start, timer enablement, monitoring and key/writer rotation are verified.

## Tests and development

```sh
python -m pip install -r requirements.lock
python -m pip install --no-deps -e .
python -m unittest discover -s tests -v
```

Tests cover identity and scope validation, protected files, official SDK assertion signing, redirects, reflected error bodies, response-size limits, timeout/failure preservation, publication/readback, next-run retries and sanitized output. All key material in tests is generated at runtime; no real credentials belong in fixtures.

## License

[MIT](LICENSE), copyright 2026 Aaron Steinke.
