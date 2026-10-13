"""Bounded requests transport with no redirects, retries, or error bodies."""
from types import SimpleNamespace

from . import SyncError
from .files import strict_json

TIMEOUT = (5, 15)
MAX_RESPONSE_BYTES = 1024 * 1024


def request_bytes(session, method, url, *, category, **kwargs):
    def reject_status(response, **_):
        # requests otherwise consumes a redirect body even with redirects off
        # while constructing Response.next. Reject in the response hook first.
        if response.status_code != 200:
            response.close()
            raise SyncError(category)
        return response

    try:
        with session.request(method, url, timeout=TIMEOUT, allow_redirects=False,
                             stream=True, hooks={"response": reject_status}, **kwargs) as response:
            if response.status_code != 200:
                raise ValueError
            body = bytearray()
            for chunk in response.iter_content(16384):
                body.extend(chunk)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise ValueError
            return bytes(body)
    except Exception:
        raise SyncError(category) from None


class GoogleRequest:
    """google-auth Request protocol using requests, without SDK body logging.

    Non-200 responses raise immediately, deliberately bypassing SDK retries.
    A later timer invocation retries the complete operation with a fresh JWT.
    """

    def __init__(self, session):
        self.session = session

    def __call__(self, url, method="GET", body=None, headers=None, timeout=None, **kwargs):
        from . import TOKEN_URI, _text
        if url != TOKEN_URI or method != "POST" or kwargs:
            raise SyncError("google-refresh-failed")
        data = request_bytes(self.session, method, url,
                             category="google-refresh-failed", data=body, headers=headers)
        try:
            payload = strict_json(data)
            if (not isinstance(payload, dict) or not _text(payload.get("access_token"))
                    or payload.get("token_type") != "Bearer"
                    or type(payload.get("expires_in")) is not int
                    or not 600 <= payload["expires_in"] <= 7200):
                raise ValueError
        except Exception:
            raise SyncError("google-token-invalid") from None
        return SimpleNamespace(status=200, data=data, headers={})


def request_json(session, method, url, **kwargs):
    body = request_bytes(session, method, url, category="vault-request-failed", **kwargs)
    try:
        return strict_json(body)
    except Exception:
        raise SyncError("vault-response-invalid") from None


def metadata(session, url, headers, config):
    data = request_json(session, "GET", url, headers=headers, params={
        "vault": config.vault, "key": config.credential_key, "reveal": "false",
    })
    try:
        if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
            raise ValueError
        keys = data["keys"]
        entries = data.get("credentials", [])
        if (not isinstance(entries, list) or any(not isinstance(k, str) for k in keys)
                or len(set(keys)) != len(keys)
                or any(not isinstance(e, dict) or not isinstance(e.get("key"), str) for e in entries)
                or sorted(e["key"] for e in entries) != sorted(keys)):
            raise ValueError
        target = [e for e in entries if e["key"] == config.credential_key]
        if target and target[0].get("type") != "static":
            raise ValueError
        return bool(target)
    except Exception:
        raise SyncError("vault-metadata-invalid") from None
