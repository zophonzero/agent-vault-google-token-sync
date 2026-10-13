from contextlib import contextmanager
import os
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

import requests

from test_sync import SyncFixture


class GoogleTransportTests(SyncFixture, unittest.TestCase):
    @contextmanager
    def routed(self):
        """Only rewrite the socket destination; real SDK + real HTTP bytes."""
        original = requests.adapters.HTTPAdapter.send
        self.sent_options = []
        outer = self

        def send(adapter, request, **kwargs):
            outer.sent_options.append((request.url, kwargs.copy()))
            if request.url == "https://oauth2.googleapis.com/token":
                request.url = outer.server.url + "/token"
            if not request.url.startswith(outer.server.url + "/"):
                raise AssertionError("tests must never access external network")
            # Never actually connect to a proxy, even during a failing RED run.
            if kwargs.get("proxies"):
                raise AssertionError("environment proxy was not ignored")
            return original(adapter, request, **kwargs)

        with patch.object(requests.adapters.HTTPAdapter, "send", send):
            yield

    def success(self):
        self.server.overrides[("POST", "/token")] = (200, {
            "access_token": "synthetic-google-token", "expires_in": 3600, "token_type": "Bearer",
        }, {})

    def test_official_sdk_signs_jwt_and_posts_with_bounded_timeout(self):
        self.success()
        with self.routed():
            self.run_once()
        self.assertEqual(self.server.values, {"GOOGLE_ACCESS_TOKEN": "synthetic-google-token"})
        token_request = next(r for r in self.server.requests if r[1] == "/token")
        self.assertNotIn("Authorization", token_request[2])
        form = parse_qs(token_request[3].decode())
        self.assertEqual(form["grant_type"], ["urn:ietf:params:oauth:grant-type:jwt-bearer"])
        from google.auth import jwt
        from cryptography.hazmat.primitives import serialization
        key = serialization.load_pem_private_key(self.key["private_key"].encode(), password=None)
        public_pem = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        claims = jwt.decode(form["assertion"][0], certs=public_pem)
        self.assertEqual(claims["iss"], self.config["service_account_email"])
        self.assertEqual(claims["scope"], " ".join(self.config["scopes"]))
        self.assertEqual(claims["aud"], "https://oauth2.googleapis.com/token")
        self.assertNotIn("sub", claims)
        for url, options in self.sent_options:
            self.assertEqual(options["timeout"], (5, 15), url)
            self.assertTrue(options["verify"])

    def test_both_transports_ignore_proxy_environment(self):
        self.success()
        with self.routed(), patch.dict(os.environ, {
            "HTTP_PROXY": self.server.url, "HTTPS_PROXY": self.server.url,
            "ALL_PROXY": self.server.url, "NO_PROXY": "", "no_proxy": "",
        }):
            self.run_once()
        self.assertEqual(self.server.values["GOOGLE_ACCESS_TOKEN"], "synthetic-google-token")

    def test_google_redirect_and_error_never_publishes_or_retries(self):
        app = self.app()
        for status in [301, 302, 303, 307, 308, 400, 401, 429, 500, 503]:
            with self.subTest(status=status):
                self.server.requests.clear()
                self.server.overrides[("POST", "/token")] = (
                    status, {"error": "REFLECTED-SECRET"}, {"Location": self.server.url + "/stolen"},
                )
                with self.routed(), self.assertRaises(app.SyncError) as ctx:
                    self.run_once()
                self.assertEqual(str(ctx.exception), "google-refresh-failed")
                self.assertEqual([r[1].split("?")[0] for r in self.server.requests],
                                 ["/v1/credentials", "/token"])
                self.assertEqual(self.server.values, {})

    def test_invalid_google_success_response_never_overwrites_existing_token(self):
        app = self.app()
        original = {"GOOGLE_ACCESS_TOKEN": "previous-token"}
        self.server.values.update(original)
        self.server.entries = [{"key": "GOOGLE_ACCESS_TOKEN", "type": "static"}]
        base = {"access_token": "synthetic-google-token", "expires_in": 3600, "token_type": "Bearer"}
        bodies = [
            b"REFLECTED-SECRET", [], {},
            base | {"access_token": ""}, base | {"access_token": None},
            base | {"access_token": "token\r\nInjected: value"},
            base | {"expires_in": 0}, base | {"expires_in": 599},
            base | {"expires_in": -1}, base | {"expires_in": None},
            base | {"expires_in": "garbage"}, base | {"expires_in": 99999999},
            base | {"token_type": "MAC"},
        ]
        for body in bodies:
            with self.subTest(body=body):
                self.server.requests.clear()
                self.server.overrides[("POST", "/token")] = (200, body, {})
                with self.routed(), self.assertRaises(app.SyncError):
                    self.run_once()
                self.assertEqual(self.server.values, original)
                self.assertEqual([r[1].split("?")[0] for r in self.server.requests],
                                 ["/v1/credentials", "/token"])

    def test_next_timer_retries_and_every_success_mints_fresh(self):
        app = self.app()
        self.server.values["GOOGLE_ACCESS_TOKEN"] = "previous-token"
        self.server.entries = [{"key": "GOOGLE_ACCESS_TOKEN", "type": "static"}]
        self.server.overrides[("POST", "/token")] = (503, {"error": "unavailable"}, {})
        with self.routed(), self.assertRaises(app.SyncError):
            self.run_once()
        self.assertEqual(self.server.values["GOOGLE_ACCESS_TOKEN"], "previous-token")
        self.success()
        with self.routed():
            self.run_once()
            self.run_once()
        self.assertEqual(self.server.values["GOOGLE_ACCESS_TOKEN"], "synthetic-google-token")
        self.assertEqual(sum(r[1] == "/token" for r in self.server.requests), 3)

    def test_redirect_bodies_are_not_consumed_by_requests(self):
        app = self.app()
        self.server.overrides[("POST", "/token")] = (
            307, b"REFLECTED-SECRET", {"Location": self.server.url + "/stolen"},
        )
        original = requests.Response.iter_content
        consumed = []
        def content(response, *args, **kwargs):
            consumed.append(response.status_code)
            return original(response, *args, **kwargs)
        with self.routed(), patch.object(requests.Response, "iter_content", content), self.assertRaises(app.SyncError):
            self.run_once()
        self.assertNotIn(307, consumed)

    def test_google_transport_rejects_endpoint_override(self):
        from av_google_token_sync.transport import GoogleRequest
        app = self.app()
        with requests.Session() as session:
            for url in [self.server.url + "/token", "https://evil.example/token"]:
                with self.subTest(url=url), self.assertRaises(app.SyncError):
                    GoogleRequest(session)(url, method="POST", body=b"secret")
        self.assertEqual(self.server.requests, [])

    def test_success_and_errors_do_not_log_token_body_even_at_debug(self):
        import logging
        from io import StringIO
        captured = StringIO()
        handler = logging.StreamHandler(captured)
        root = logging.getLogger()
        previous = root.level
        root.setLevel(logging.DEBUG)
        root.addHandler(handler)
        self.addCleanup(root.removeHandler, handler)
        self.addCleanup(root.setLevel, previous)
        self.success()
        with self.routed():
            self.run_once()
        self.server.overrides[("POST", "/token")] = (400, b"REFLECTED-SECRET", {})
        with self.routed(), self.assertRaises(self.app().SyncError):
            self.run_once()
        for secret in ["synthetic-google-token", "synthetic-writer-token", "REFLECTED-SECRET", "assertion=", "PRIVATE KEY"]:
            self.assertNotIn(secret, captured.getvalue())

    def test_oversized_success_response_fails_closed(self):
        app = self.app()
        for method, path in [("POST", "/token"), ("GET", "/v1/credentials")]:
            with self.subTest(path=path):
                self.server.overrides.clear()
                self.server.overrides[(method, path)] = (200, b"x" * (1024 * 1024 + 1), {})
                with self.routed(), self.assertRaises(app.SyncError):
                    self.run_once()
                self.assertEqual(self.server.values, {})

    def test_real_socket_read_timeout_fails_without_retry(self):
        app = self.app()
        self.success()
        self.server.delays[("POST", "/token")] = 0.2
        with self.routed(), patch("av_google_token_sync.transport.TIMEOUT", (0.05, 0.05)):
            with self.assertRaises(app.SyncError) as ctx:
                self.run_once()
        self.assertEqual(str(ctx.exception), "google-refresh-failed")
        self.assertEqual(sum(r[1] == "/token" for r in self.server.requests), 1)
        self.assertEqual(self.server.values, {})

    def test_transport_failure_is_sanitized_without_retry(self):
        from av_google_token_sync.transport import GoogleRequest
        app = self.app()
        with requests.Session() as session:
            with patch.object(session, "request", side_effect=requests.Timeout("SECRET")) as request:
                with self.assertRaises(app.SyncError) as ctx:
                    GoogleRequest(session)("https://oauth2.googleapis.com/token", method="POST")
                self.assertEqual(str(ctx.exception), "google-refresh-failed")
                self.assertEqual(request.call_count, 1)


if __name__ == "__main__":
    unittest.main()
