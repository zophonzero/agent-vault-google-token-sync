from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import unittest
from unittest.mock import patch
import subprocess
import sys

from test_sync import SyncFixture


class CLITests(SyncFixture, unittest.TestCase):
    def invoke(self, args):
        try:
            from av_google_token_sync.cli import main
        except ImportError:
            self.fail("CLI is not implemented")
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            result = main(args)
        return result, out.getvalue(), err.getvalue()

    def test_check_config_checks_keys_without_any_network(self):
        with patch("requests.Session.request", side_effect=AssertionError("network forbidden")):
            result, out, err = self.invoke(["--config", str(self.save()), "--check-config"])
        self.assertEqual(result, 0)
        self.assertEqual(out, "config-ok\n")
        self.assertEqual(err, "")
        self.key_path.write_text("SECRET-BAD-KEY")
        result, out, err = self.invoke(["--config", str(self.save()), "--check-config"])
        self.assertNotEqual(result, 0)
        self.assertEqual(out, "")
        self.assertEqual(err, "error: credentials-invalid\n")

    def test_default_once_success_and_explicit_once(self):
        for flag in [[], ["--once"]]:
            with self.subTest(flag=flag), patch(
                "google.oauth2.service_account.Credentials.refresh", self.refresh,
            ):
                result, out, err = self.invoke(["--config", str(self.save()), *flag])
                self.assertEqual((result, out, err), (0, "sync-ok\n", ""))

    def test_cli_never_prints_reflected_secrets_or_tracebacks(self):
        secret = "ADVERSARIAL-secret-token-key-body"
        cases = [RuntimeError(secret), ValueError(secret)]
        for exc in cases:
            with self.subTest(exc=type(exc)), patch(
                "google.oauth2.service_account.Credentials.refresh", side_effect=exc,
            ):
                result, out, err = self.invoke(["--config", str(self.save())])
                self.assertEqual((result, out, err), (1, "", "error: google-refresh-failed\n"))
        self.server.overrides[("GET", "/v1/credentials")] = (500, secret.encode(), {})
        result, out, err = self.invoke(["--config", str(self.save())])
        self.assertEqual((result, out, err), (1, "", "error: vault-request-failed\n"))
        self.assertNotIn(secret, out + err)

    def test_argument_errors_do_not_echo_values(self):
        for args in [[], ["--unknown", "SECRET"], ["--config", "SECRET", "--subject", "SECRET"]]:
            with self.subTest(args=args):
                result, out, err = self.invoke(args)
                self.assertEqual((result, out, err), (1, "", "error: arguments-invalid\n"))

    def test_module_help_describes_security_boundary(self):
        proc = subprocess.run([sys.executable, "-m", "av_google_token_sync", "--help"],
                              text=True, capture_output=True, timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for phrase in ["--config", "--once", "--check-config", "member", "entire vault",
                       "not key-scoped", "CREDENTIALS_DIRECTORY", "no network"]:
            self.assertIn(phrase, proc.stdout)
        self.assertEqual(proc.stderr, "")


if __name__ == "__main__":
    unittest.main()
