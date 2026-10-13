import json
import os
import stat
import unittest
from unittest.mock import patch

from test_sync import SyncFixture


class StatusTests(SyncFixture, unittest.TestCase):
    def test_double_slash_status_alias_cannot_overwrite_protected_inputs(self):
        app = self.app()
        for protected in (self.key_path, self.writer_path, self.root / "config.json"):
            with self.subTest(input=protected.name):
                self.config["status_file"] = "/" + str(protected)
                config_path = self.save()
                before = {p: p.read_bytes() for p in
                          (self.key_path, self.writer_path, config_path)}
                with self.assertRaises(app.SyncError) as ctx:
                    app.load_config(config_path)
                self.assertEqual(str(ctx.exception), "config-invalid")
                self.assertEqual(self.server.requests, [])
                for path, content in before.items():
                    self.assertEqual(path.read_bytes(), content)

    def test_status_records_only_success_timestamps_with_private_mode(self):
        path = self.root / "status.json"
        self.config["status_file"] = str(path)
        with patch("google.oauth2.service_account.Credentials.refresh", self.refresh):
            self.run_once()
        data = json.loads(path.read_text())
        self.assertEqual(set(data), {"last_success", "expires_at"})
        from datetime import datetime, timezone
        self.assertLess(datetime.fromisoformat(data["last_success"]), datetime.now(timezone.utc))
        self.assertGreater(datetime.fromisoformat(data["expires_at"]), datetime.now(timezone.utc))
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        for secret in ["synthetic-google-token", "synthetic-writer-token", "PRIVATE KEY"]:
            self.assertNotIn(secret, path.read_text())
        self.assertEqual(sorted(p.name for p in self.root.iterdir()),
                         ["account.json", "config.json", "status.json", "writer.token"])

    def test_failed_mint_preserves_previous_success_status(self):
        app = self.app()
        path = self.root / "status.json"
        path.write_text('{"last_success":"previous"}')
        path.chmod(0o600)
        self.config["status_file"] = str(path)
        with patch("google.oauth2.service_account.Credentials.refresh", side_effect=RuntimeError("secret")):
            with self.assertRaises(app.SyncError):
                self.run_once()
        self.assertEqual(path.read_text(), '{"last_success":"previous"}')
        self.assertEqual(self.server.requests[0][0], "GET")

    def test_status_write_failure_reports_ambiguity_without_secrets(self):
        app = self.app()
        self.config["status_file"] = str(self.root / "status.json")
        with patch("google.oauth2.service_account.Credentials.refresh", self.refresh), patch(
            "av_google_token_sync.write_status", side_effect=OSError("REFLECTED-SECRET"),
        ):
            with self.assertRaises(app.SyncError) as ctx:
                self.run_once()
        self.assertEqual(str(ctx.exception), "status-write-failed")
        self.assertEqual(self.server.values, {"GOOGLE_ACCESS_TOKEN": "synthetic-google-token"})

    def test_unsafe_status_path_rejected_before_network(self):
        app = self.app()
        status = self.root / "unsafe.json"
        status.write_text("previous")
        status.chmod(0o644)
        symlink = self.root / "link"
        symlink.symlink_to(self.writer_path)
        hardlink = self.root / "hardlink"
        os.link(self.writer_path, hardlink)
        for path in [self.key_path, self.writer_path, self.root / "config.json", status,
                     symlink, hardlink, self.root / "missing" / "file.json"]:
            with self.subTest(path=path.name):
                self.config["status_file"] = str(path)
                with self.assertRaises(app.SyncError) as ctx:
                    self.run_once()
                self.assertEqual(str(ctx.exception), "config-invalid")
                self.assertEqual(self.server.requests, [])


if __name__ == "__main__":
    unittest.main()
