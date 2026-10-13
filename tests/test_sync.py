import json
import os
from pathlib import Path
import tempfile
import unittest


class ConfigFixture:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = {
            "service_account_email": "reader@example.iam.gserviceaccount.com",
            "scopes": ["https://www.googleapis.com/auth/drive.readonly"],
            "vault": "documents",
            "credential_key": "GOOGLE_ACCESS_TOKEN",
            "av_base_url": "https://vault.example.com",
            "service_account_file": str(self.root / "account.json"),
            "writer_token_file": str(self.root / "writer.token"),
        }

    def save(self, data=None):
        path = self.root / "config.json"
        path.write_text(json.dumps(self.config if data is None else data))
        path.chmod(0o600)
        return path

    def app(self):
        try:
            import av_google_token_sync as app
        except ImportError:
            self.fail("configuration loader is not implemented")
        self.assertTrue(hasattr(app, "load_config"), "configuration loader is not implemented")
        return app



class ConfigTests(ConfigFixture, unittest.TestCase):
    def test_load_explicit_identity_and_scopes(self):
        cfg = self.app().load_config(self.save())
        self.assertEqual(cfg.service_account_email, self.config["service_account_email"])
        self.assertEqual(cfg.scopes, tuple(self.config["scopes"]))
        self.assertEqual(cfg.av_base_url, self.config["av_base_url"])
        self.assertEqual(cfg.service_account_file, Path(self.config["service_account_file"]))

    def test_rejects_unsafe_config(self):
        app = self.app()
        self.assertTrue(hasattr(app, "SyncError"), "safe config errors are missing")
        bad = [
            {"scopes": []}, {"scopes": "drive.readonly"},
            {"scopes": ["https://www.googleapis.com/auth/drive"]},
            {"scopes": [1]}, {"scopes": self.config["scopes"] * 2},
            {"service_account_email": "not-an-email"},
            {"vault": ""}, {"credential_key": "bad-key"},
            {"subject": "person@example.com"}, {"surprise": True},
            {"av_base_url": "http://vault.example.com"},
            {"av_base_url": "http://127.0.0.1"},
            {"av_base_url": "https://user:secret@vault.example.com"},
            {"av_base_url": "https://vault.example.com?token=secret"},
            {"av_base_url": "https://vault.example.com#fragment"},
            {"av_base_url": "https://vault.example.com/prefix"},
            {"av_base_url": "https://vault.example.com\n"},
            {"av_base_url": "https://vault.example.com:bad"},
            {"av_base_url": "http://127.1", "allow_loopback_http": True},
            {"av_base_url": "http://localhost.evil.test", "allow_loopback_http": True},
            {"av_base_url": "http://192.0.2.1", "allow_loopback_http": True},
            {"allow_loopback_http": "true"},
            {"service_account_file": "relative.json"},
            {"writer_token_file": None},
        ]
        for fields in bad:
            with self.subTest(fields=fields):
                with self.assertRaises(app.SyncError) as ctx:
                    app.load_config(self.save(self.config | fields))
                self.assertEqual(str(ctx.exception), "config-invalid")
        for data in [[], None, 42, {}, self.config | {"vault": False}]:
            with self.subTest(data=data), self.assertRaises(app.SyncError):
                app.load_config(self.save(data if data is not None else []))

    def test_explicit_loopback_http(self):
        app = self.app()
        for url in ["http://127.0.0.1:1234", "http://localhost:1234", "http://[::1]:1234"]:
            with self.subTest(url=url):
                cfg = app.load_config(self.save(self.config | {
                    "av_base_url": url, "allow_loopback_http": True,
                }))
                self.assertEqual(cfg.av_base_url, url)

    def test_config_requires_protected_regular_file(self):
        app = self.app()
        path = self.save()
        for mode in [0o644, 0o640, 0o620, 0o604]:
            with self.subTest(mode=mode):
                path.chmod(mode)
                with self.assertRaises(app.SyncError):
                    app.load_config(path)
        path.chmod(0o600)
        link = self.root / "link.json"
        link.symlink_to(path)
        with self.assertRaises(app.SyncError):
            app.load_config(link)
        link.unlink()
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(app.SyncError):
            app.load_config(link / path.name)
        self.root.chmod(0o777)
        with self.assertRaises(app.SyncError):
            app.load_config(path)
        self.root.chmod(0o700)

    def test_rejects_duplicate_json_fields(self):
        app = self.app()
        path = self.save()
        path.write_text(json.dumps(self.config)[:-1] + ', "vault": "other"}')
        with self.assertRaises(app.SyncError):
            app.load_config(path)

    def test_systemd_credentials_directory(self):
        from unittest.mock import patch
        app = self.app()
        data = dict(self.config)
        del data["service_account_file"]
        del data["writer_token_file"]
        data.update(service_account_credential="google-key", writer_token_credential="av-writer")
        with patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": str(self.root)}):
            cfg = app.load_config(self.save(data))
            self.assertEqual(cfg.service_account_file, self.root / "google-key")
            self.assertEqual(cfg.writer_token_file, self.root / "av-writer")
            for name in ["../escape", "/absolute", "nested/file", "", ".", ".."]:
                with self.subTest(name=name), self.assertRaises(app.SyncError):
                    app.load_config(self.save(data | {"writer_token_credential": name}))
            with self.assertRaises(app.SyncError):
                app.load_config(self.save(data | {"writer_token_file": str(self.root / "extra")}))
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(app.SyncError):
            app.load_config(self.save(data))


class SyncFixture(ConfigFixture):
    def setUp(self):
        super().setUp()
        from support import LocalServer, synthetic_key
        self.server = LocalServer()
        self.addCleanup(self.server.close)
        self.config.update(av_base_url=self.server.url, allow_loopback_http=True)
        self.key = synthetic_key(self.config["service_account_email"])
        self.key_path = Path(self.config["service_account_file"])
        self.key_path.write_text(json.dumps(self.key))
        self.key_path.chmod(0o600)
        self.writer_path = Path(self.config["writer_token_file"])
        self.writer_path.write_text("synthetic-writer-token\n")
        self.writer_path.chmod(0o600)

    @staticmethod
    def refresh(credential, request):
        from datetime import datetime, timedelta, timezone
        credential.token = "synthetic-google-token"
        credential.expiry = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1)

    def run_once(self):
        app = self.app()
        self.assertTrue(hasattr(app, "run_once"), "one-shot synchronization is missing")
        return app.run_once(app.load_config(self.save()))



class SyncTests(SyncFixture, unittest.TestCase):
    def test_mints_and_publishes_with_metadata_readback(self):
        from unittest.mock import patch
        with patch("google.oauth2.service_account.Credentials.refresh", self.refresh):
            self.run_once()
        self.assertEqual(self.server.values, {"GOOGLE_ACCESS_TOKEN": "synthetic-google-token"})
        self.assertEqual([r[0] for r in self.server.requests], ["GET", "POST", "GET"])
        from urllib.parse import parse_qs, urlsplit
        for method, url, headers, body in self.server.requests:
            self.assertEqual(urlsplit(url).path, "/v1/credentials")
            self.assertEqual(headers["Authorization"], "Bearer synthetic-writer-token")
            if method == "GET":
                self.assertEqual(parse_qs(urlsplit(url).query), {
                    "vault": ["documents"], "key": ["GOOGLE_ACCESS_TOKEN"], "reveal": ["false"],
                })
            else:
                self.assertEqual(json.loads(body), {
                    "vault": "documents", "credentials": {"GOOGLE_ACCESS_TOKEN": "synthetic-google-token"},
                })

    def test_rejects_key_identity_endpoint_and_delegation_before_network(self):
        from unittest.mock import patch
        app = self.app()
        changes = [
            {"client_email": "other@example.iam.gserviceaccount.com"},
            {"type": "authorized_user"},
            {"token_uri": "https://evil.example/token"},
            {"token_uri": "https://oauth2.googleapis.com/token?x=1"},
            {"subject": "person@example.com"}, {"sub": "person@example.com"},
            {"universe_domain": "other.example"}, {"private_key": "REFLECTED-SECRET"},
        ]
        for change in changes:
            with self.subTest(change=list(change)), patch(
                "google.oauth2.service_account.Credentials.refresh", self.refresh,
            ):
                self.key_path.write_text(json.dumps(self.key | change))
                with self.assertRaises(app.SyncError) as ctx:
                    self.run_once()
                self.assertEqual(str(ctx.exception), "credentials-invalid")
                self.assertEqual(self.server.requests, [])

    def test_rejects_insecure_credential_files(self):
        from unittest.mock import patch
        app = self.app()
        for path in [self.key_path, self.writer_path]:
            with self.subTest(path=path.name), patch(
                "google.oauth2.service_account.Credentials.refresh", self.refresh,
            ):
                path.chmod(0o644)
                with self.assertRaises(app.SyncError) as ctx:
                    self.run_once()
                self.assertEqual(str(ctx.exception), "credentials-invalid")
                path.chmod(0o600)
        self.assertEqual(self.server.requests, [])

    def test_rejects_empty_or_header_injected_writer_token(self):
        from unittest.mock import patch
        app = self.app()
        for value in ["", "\n", "abc\nAuthorization: secret", "token space", "💥"]:
            with self.subTest(value=value), patch(
                "google.oauth2.service_account.Credentials.refresh", self.refresh,
            ):
                self.writer_path.write_text(value)
                with self.assertRaises(app.SyncError) as ctx:
                    self.run_once()
                self.assertEqual(str(ctx.exception), "credentials-invalid")
        self.assertEqual(self.server.requests, [])

    def test_refuses_nonstatic_or_ambiguous_metadata(self):
        from unittest.mock import patch
        app = self.app()
        for data in [
            {"keys": ["GOOGLE_ACCESS_TOKEN"], "credentials": [{"key": "GOOGLE_ACCESS_TOKEN", "type": "oauth"}]},
            {"keys": ["GOOGLE_ACCESS_TOKEN"], "credentials": [{"key": "GOOGLE_ACCESS_TOKEN", "type": "dynamic"}]},
            {"keys": ["GOOGLE_ACCESS_TOKEN"]},
            {"keys": ["GOOGLE_ACCESS_TOKEN"], "credentials": []},
            {"keys": [], "credentials": [{"key": "GOOGLE_ACCESS_TOKEN", "type": "static"}]},
            {"keys": ["GOOGLE_ACCESS_TOKEN"], "credentials": [{"key": "GOOGLE_ACCESS_TOKEN"}]},
            [], {"error": "REFLECTED-SECRET"},
        ]:
            with self.subTest(data=data), patch("google.oauth2.service_account.Credentials.refresh") as refresh:
                self.server.requests.clear()
                self.server.overrides[("GET", "/v1/credentials")] = (200, data, {})
                with self.assertRaises(app.SyncError):
                    self.run_once()
                refresh.assert_not_called()
                self.assertEqual([r[0] for r in self.server.requests], ["GET"])

    def test_av_reflected_errors_and_redirects_fail_without_retry(self):
        from unittest.mock import patch
        app = self.app()
        for method in ["GET", "POST"]:
            for status in [301, 302, 303, 307, 308, 400, 401, 403, 404, 429, 500, 503]:
                with self.subTest(method=method, status=status), patch(
                    "google.oauth2.service_account.Credentials.refresh", self.refresh,
                ):
                    self.server.requests.clear()
                    self.server.overrides.clear()
                    self.server.overrides[(method, "/v1/credentials")] = (
                        status, b"REFLECTED-SECRET", {"Location": self.server.url + "/stolen"},
                    )
                    with self.assertRaises(app.SyncError) as ctx:
                        self.run_once()
                    self.assertEqual(str(ctx.exception), "vault-request-failed")
                    self.assertEqual([r[0] for r in self.server.requests],
                                     ["GET"] if method == "GET" else ["GET", "POST"])

    def test_av_rejects_invalid_json_and_write_acknowledgement(self):
        from unittest.mock import patch
        app = self.app()
        for body in [b"REFLECTED-SECRET", {"set": []}, {"set": ["OTHER_KEY"]}, {}, []]:
            with self.subTest(body=body), patch(
                "google.oauth2.service_account.Credentials.refresh", self.refresh,
            ):
                self.server.overrides[("POST", "/v1/credentials")] = (200, body, {})
                with self.assertRaises(app.SyncError) as ctx:
                    self.run_once()
                self.assertEqual(str(ctx.exception), "vault-response-invalid")

    def test_rejects_missing_readback_after_success_ack(self):
        from unittest.mock import patch
        app = self.app()
        self.server.overrides[("POST", "/v1/credentials")] = (200, {"set": ["GOOGLE_ACCESS_TOKEN"]}, {})
        with patch("google.oauth2.service_account.Credentials.refresh", self.refresh):
            with self.assertRaises(app.SyncError) as ctx:
                self.run_once()
        self.assertEqual(str(ctx.exception), "vault-verification-failed")

    def test_sdk_expiry_validated_immediately_before_publish(self):
        from datetime import datetime, timedelta, timezone
        from unittest.mock import patch
        app = self.app()
        for expiry in [None, datetime.now(timezone.utc) - timedelta(seconds=1),
                       datetime.now(timezone.utc) + timedelta(seconds=599), "invalid"]:
            def refresh(credential, request):
                credential.token = "synthetic-google-token"
                credential.expiry = expiry
            with self.subTest(expiry=expiry), patch(
                "google.oauth2.service_account.Credentials.refresh", refresh,
            ), self.assertRaises(app.SyncError) as ctx:
                self.run_once()
            self.assertEqual(str(ctx.exception), "google-token-invalid")
        self.assertEqual(self.server.values, {})


if __name__ == "__main__":
    unittest.main()
