"""Synthetic local HTTP server; never forwards to a remote system."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time


class LocalServer:
    def __init__(self):
        self.requests = []
        self.entries = []
        self.values = {}
        self.overrides = {}
        self.delays = {}
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.respond()

            def do_POST(self):
                self.respond()

            def respond(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                outer.requests.append((self.command, self.path, dict(self.headers), body))
                key = (self.command, self.path.split("?")[0])
                time.sleep(outer.delays.get(key, 0))
                if key in outer.overrides:
                    status, data, headers = outer.overrides[key]
                elif self.command == "GET":
                    status, data, headers = 200, {
                        "keys": [e["key"] for e in outer.entries],
                        "credentials": outer.entries,
                    }, {}
                else:
                    payload = json.loads(body)
                    outer.values.update(payload["credentials"])
                    outer.entries = [{"key": k, "type": "static"} for k in outer.values]
                    status, data, headers = 200, {"set": list(payload["credentials"])}, {}
                encoded = data if isinstance(data, bytes) else json.dumps(data).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(encoded)))
                for name, value in headers.items():
                    self.send_header(name, value)
                self.end_headers()
                try:
                    self.wfile.write(encoded)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = "http://127.0.0.1:" + str(self.server.server_port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


def synthetic_key(email):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return {
        "type": "service_account", "client_email": email,
        "token_uri": "https://oauth2.googleapis.com/token",
        "private_key": key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
        "private_key_id": "synthetic-test-key",
    }
