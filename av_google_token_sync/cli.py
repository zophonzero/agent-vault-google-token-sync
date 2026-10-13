"""Command-line interface: constant output only, never exception details."""
import argparse
import sys

from . import ALLOWED_SCOPES, SyncError, load_config, load_credentials, run_once

HELP = """\
One fixed service-account identity per protected JSON config. Mint a fresh token
on every run; there is no local token cache or daemon. Schedule --once at startup
and every few minutes using a systemd timer. Failures exit nonzero; the next timer
retries. Existing vault contents are unchanged when minting fails. Set service
TimeoutStartSec for a whole-process deadline in addition to HTTP timeouts.

Required JSON fields:
  service_account_email  expected *.iam.gserviceaccount.com identity
  scopes                 nonempty list from the read-only allowlist below
  vault                  explicit vault name (no default vault)
  credential_key         SCREAMING_SNAKE_CASE static credential key
  av_base_url            HTTPS origin; no userinfo/path/query/fragment
  service_account_file   absolute path to Google service-account JSON
  writer_token_file      absolute path to Agent Vault writer bearer token

Instead of either *_file, use service_account_credential or
writer_token_credential: a filename inside systemd CREDENTIALS_DIRECTORY.
Use LoadCredentialEncrypted to decrypt credentials only into the service runtime.
allow_loopback_http: true permits HTTP only to localhost or numerical loopback.
status_file: optional absolute path to atomically replaced 0600 JSON containing
only last_success and expires_at timestamps (never tokens). Failures leave the
last-success status unchanged. A status-write failure may follow a successful
publication; alert on exit status as well as freshness. No local status is read
to skip refresh. Tokens must have at least 600 seconds of useful lifetime before
publication; the accepted Google expires_in range is 600..7200 seconds.
Proxy, netrc and CA-bundle environment overrides are ignored. TLS is verified.
Files must be regular, single-link, root/current-user owned, mode 0600 or 0400.
Root-owned systemd 0440 credentials require root/service group, a root-owned 0550
credential directory and a read-only filesystem; kernel ACL checks still apply.
Symlinks are rejected in every path component. Protect directories from writes
by untrusted users. Config and credential files must not be agent-writable.
No delegated subject, arbitrary token endpoint, or arbitrary scopes are accepted.

SECURITY: The writer requires vault member access and can read the entire vault;
it is not key-scoped. Use a dedicated vault and keep this writer out of agents.
This tool requests metadata only (reveal=false), never credential values.
The upstream list API may return all key metadata despite a key filter; it may
also enumerate dynamic leases. Use a built-in, static-only dedicated vault.
Preflight refuses existing OAuth/dynamic keys. Agent Vault encrypts stored tokens.
There is no compare-and-set API: prevent concurrent credential-type changes and
run only one writer. Readback verifies static-key metadata, not token equality.
A failed write/readback can be ambiguous; a later run safely publishes again.
No Google API resource permissions are granted by this tool: share resources with
the configured service account separately. Alert on timer failures before expiry.

Allowed scopes:
""" + "\n".join("  " + scope for scope in sorted(ALLOWED_SCOPES))


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise SyncError("arguments-invalid")


def main(argv=None):
    parser = SafeParser(
        prog="agent-vault-google-token-sync",
        description="Publish a Google service-account access token to Agent Vault.",
        epilog=HELP, formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
    )
    parser.add_argument("--config", required=True, metavar="PATH", help="protected JSON config")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="mint and publish once (default)")
    mode.add_argument("--check-config", action="store_true", help="validate config and keys; no network")
    try:
        args = parser.parse_args(argv)
        config = load_config(args.config)
        if args.check_config:
            load_credentials(config)
            print("config-ok")
        else:
            run_once(config)
            print("sync-ok")
        return 0
    except SyncError as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 1
    except Exception:
        print("error: internal-error", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 1
