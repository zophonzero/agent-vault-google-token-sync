# Linux systemd deployment

This example is for a trusted administrator on the **updater host**, preferably the Agent Vault host. It does not install inside an application-agent account or expose a new listening port. Commands below assume root administration and systemd with `LoadCredentialEncrypted` support. Verify your systemd distribution before deploying.

The template uses a dynamic, unprivileged Unix identity. systemd reads the root-only configuration and encrypted secrets and exposes private, read-only copies to that service for the duration of each run. A separate instance represents each fixed service-account/vault mapping.

## 1. Install a reviewed version

Follow the repository installation instructions. The executable must exist at:

```text
/opt/agent-vault-google-token-sync/venv/bin/agent-vault-google-token-sync
```

Keep the entire environment root-owned and non-writable to unprivileged users. Install from a pinned commit/release, not a moving branch. Retain the previous installation for rollback.

## 2. Prepare the instance and protected import

For the sample instance named `reader`:

```sh
install -d -o root -g root -m 0700 /etc/agent-vault-google-token-sync/reader
install -m 0600 examples/config.json /etc/agent-vault-google-token-sync/reader/config.json
```

Edit only this protected copy: set the expected service-account email, exact target vault, selected read-only scopes and Agent Vault management API URL. Do not replace the credential names with secret values. All configuration and credential paths must be real paths without symlinks.

Transfer the service-account JSON key and a **separate vault-scoped writer bearer token** directly to root-only staging files using an authenticated encrypted channel (for example SFTP over a private network). Never upload them into this repository, a chat, a public file share or an application-agent workspace. The destination directory must already be mode 0700; ensure files are 0600. Do not use inline shell assignments or command arguments containing secrets.

On the updater host, encrypt each staged file into a host-bound systemd credential:

```sh
systemd-creds encrypt --with-key=host --name=google-key /protected/staging/google-key.json /etc/agent-vault-google-token-sync/reader/google-key.cred
systemd-creds encrypt --with-key=host --name=av-writer /protected/staging/av-writer.token /etc/agent-vault-google-token-sync/reader/av-writer.cred
chmod 0600 /etc/agent-vault-google-token-sync/reader/*.cred
```

Keep a separate secure recovery copy under the human administrator's control. Host-bound encryption is not protection against root or a full host compromise and cannot be restored on another host without the appropriate recovery material. Remove plaintext staging copies after validation and confirmed recovery storage. Unlinking a file does not guarantee physical erasure on SSDs, snapshots or copy-on-write storage.

The private Google key is long-lived. Rotate it deliberately and revoke old keys only after verifying the replacement. Already-issued access tokens may remain usable until expiry.

## 3. Install units — do not enable yet

```sh
install -m 0644 examples/agent-vault-google-token-sync@.service /etc/systemd/system/
install -m 0644 examples/agent-vault-google-token-sync@.timer /etc/systemd/system/
systemd-analyze verify /etc/systemd/system/agent-vault-google-token-sync@.service /etc/systemd/system/agent-vault-google-token-sync@.timer
systemctl daemon-reload
```

The timer uses monotonic startup/interval scheduling, not an expiry-aware daemon. A boot triggers a new token, then the job runs every five minutes with up to fifteen seconds of jitter. The whole job is killed after ninety seconds if it hangs; per-request timeouts alone are not a whole-job deadline.

The management API must be ready before the first successful invocation. If it is not, that run fails and the next timer invocation retries. Optionally add a host-specific `After=`/`Requires=` drop-in for your Agent Vault unit; the generic template deliberately does not assume its unit name.

## 4. Validate and activate deliberately

Before publishing anything, run offline key/config validation using the same dynamic-user and credential-loading mechanism:

```sh
systemd-run --wait --pipe --collect --unit=google-token-sync-check-reader \
  -p DynamicUser=yes -p ProtectHome=yes -p ProtectSystem=strict \
  -p PrivateNetwork=yes -p LimitCORE=0 \
  -p LoadCredential=config:/etc/agent-vault-google-token-sync/reader/config.json \
  -p LoadCredentialEncrypted=google-key:/etc/agent-vault-google-token-sync/reader/google-key.cred \
  -p LoadCredentialEncrypted=av-writer:/etc/agent-vault-google-token-sync/reader/av-writer.cred \
  /opt/agent-vault-google-token-sync/venv/bin/agent-vault-google-token-sync \
  --config '${CREDENTIALS_DIRECTORY}/config' --check-config
```

Expected application output: `config-ok`. This proves file access, identity checks and private-key parsing, not provider authorization. The quoted environment reference is expanded by systemd in the service, not by your shell. `systemd-run` escapes percent specifiers in command arguments, so do not use `%d/config` here (the installed unit file can use it).

Then publish one token and inspect the real result:

```sh
systemctl start agent-vault-google-token-sync@reader.service
systemctl show agent-vault-google-token-sync@reader.service -p Result -p ExecMainStatus
journalctl -u agent-vault-google-token-sync@reader.service --no-pager -n 20
```

Require `Result=success`, `ExecMainStatus=0` and `sync-ok`. Next, verify an explicitly shared resource through the normal proxy-only application identity, and verify cross-vault access is denied. The updater does not provision Agent Vault proxy service rules.

Only after that acceptance test:

```sh
systemctl enable --now agent-vault-google-token-sync@reader.timer
systemctl list-timers agent-vault-google-token-sync@reader.timer
```

Wait for another scheduled execution and confirm the service succeeds again without restarting Agent Vault. A oneshot service becoming inactive after completion is normal; the timer must remain active.

## 5. Monitor and recover

Monitor service failures and recent success externally. A timer being active is not proof that token publication is succeeding. Add an `OnFailure=` integration appropriate to your existing monitoring, and alert if success stops for longer than your operational threshold (for example ten minutes for the five-minute schedule). Do not wait until token expiry to alert.

The template deliberately has no writable state directory. If you enable `status_file`, supply a protected persistent path writable by the service and account for its dynamic UID, or use a dedicated static Unix account and protected state directory. Do not weaken credential-file protections just to make status writing work. The status must contain only timestamps, never tokens.

When a run fails, check local ownership/modes, the fixed service-account identity, Google API enablement, intended vault membership, server reachability and resource sharing. Error categories intentionally omit provider details. Do not turn on HTTP wire debugging around live credentials.

If the timer remains broken, the last token eventually expires and Google rejects requests. There is no fallback to a different identity. For an urgent compromise, stop the timer and revoke/change the relevant credentials and resource permissions; merely stopping refresh does not immediately invalidate existing tokens.

Rollback: disable the affected timer, restore the previous pinned installation/configuration, validate offline, publish once, test normal proxy access, then re-enable the timer. Preserve Agent Vault data and backups. Do not remove the vault or delete its database as an updater rollback step.
