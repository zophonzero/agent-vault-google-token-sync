"""One-shot, fixed-identity Google service-account token synchronization."""

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import os
from pathlib import Path
import re
from typing import TypeGuard
from urllib.parse import urlsplit

from .files import protected_read, strict_json, validate_destination, write_status


ALLOWED_SCOPES = frozenset(
    "https://www.googleapis.com/auth/" + suffix
    for suffix in (
        "drive.readonly", "documents.readonly", "spreadsheets.readonly",
        "calendar.readonly", "calendar.events.readonly",
    )
)


class SyncError(Exception):
    """An error whose message is a constant category, never external data."""


def _text(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and 0 < len(value) <= 4096 and all(
        32 < ord(c) < 127 for c in value
    )


def _base_url(value: object, allow_http: bool) -> str:
    if not _text(value):
        raise ValueError
    parts = urlsplit(value)
    if (not parts.hostname or parts.username is not None or parts.password is not None
            or "?" in value or "#" in value or "\\" in value
            or parts.path not in ("", "/") or parts.port == 0):
        raise ValueError
    if parts.scheme == "http":
        if not allow_http:
            raise ValueError
        if parts.hostname != "localhost" and not ipaddress.ip_address(parts.hostname).is_loopback:
            raise ValueError
    elif parts.scheme != "https":
        raise ValueError
    return value.rstrip("/")


@dataclass(frozen=True)
class Config:
    service_account_email: str
    scopes: tuple[str, ...]
    vault: str
    credential_key: str
    av_base_url: str
    service_account_file: Path
    writer_token_file: Path
    status_file: Path | None = None


def load_config(path: str | Path) -> Config:
    try:
        data = strict_json(protected_read(Path(path).absolute()))
        required = set(Config.__dataclass_fields__) - {"status_file"}
        alternatives = {"service_account_credential", "writer_token_credential", "status_file"}
        if not isinstance(data, dict) or data.keys() - required - alternatives - {"allow_loopback_http"}:
            raise ValueError
        for stem in ("service_account", "writer_token"):
            filename, credential = stem + "_file", stem + "_credential"
            if (filename in data) == (credential in data):
                raise ValueError
            if credential in data:
                name = data[credential]
                directory = os.environ.get("CREDENTIALS_DIRECTORY", "")
                if (not _text(name) or name in (".", "..") or "/" in name
                        or not directory or not Path(directory).is_absolute()):
                    raise ValueError
                data[filename] = str(Path(directory) / name)
        if not required <= data.keys():
            raise ValueError
        if not all(_text(data[k]) for k in required - {"scopes"}):
            raise ValueError
        if not re.fullmatch(r"[a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+\.iam\.gserviceaccount\.com", data["service_account_email"]):
            raise ValueError
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", data["credential_key"]):
            raise ValueError
        scopes = data["scopes"]
        if (not isinstance(scopes, list) or not scopes
                or any(not isinstance(s, str) or s not in ALLOWED_SCOPES for s in scopes)
                or len(scopes) != len(set(scopes))):
            raise ValueError
        allow_http = data.get("allow_loopback_http", False)
        if type(allow_http) is not bool:
            raise ValueError
        base = _base_url(data["av_base_url"], allow_http)
        for key in ("service_account_file", "writer_token_file"):
            if not Path(data[key]).is_absolute():
                raise ValueError
        status = None
        if "status_file" in data:
            if not _text(data["status_file"]):
                raise ValueError
            status = Path(data["status_file"])
            if status in (Path(path).absolute(), Path(data["service_account_file"]), Path(data["writer_token_file"])):
                raise ValueError
            validate_destination(status)
        return Config(
            service_account_email=data["service_account_email"],
            scopes=tuple(scopes), vault=data["vault"],
            credential_key=data["credential_key"], av_base_url=base,
            service_account_file=Path(data["service_account_file"]),
            writer_token_file=Path(data["writer_token_file"]), status_file=status,
        )
    except Exception:
        raise SyncError("config-invalid") from None


TOKEN_URI = "https://oauth2.googleapis.com/token"


def load_credentials(config: Config):
    """Validate local material without network access."""
    from google.oauth2 import service_account

    try:
        info = strict_json(protected_read(config.service_account_file))
        if (not isinstance(info, dict) or info.get("type") != "service_account"
                or info.get("client_email") != config.service_account_email
                or info.get("token_uri") != TOKEN_URI
                or "subject" in info or "sub" in info
                or info.get("universe_domain", "googleapis.com") != "googleapis.com"):
            raise ValueError
        writer = protected_read(config.writer_token_file).decode("ascii").rstrip("\r\n")
        if not _text(writer):
            raise ValueError
        # Forward only required fields: never honor additional claims, subjects,
        # universe overrides or future SDK fields from a downloaded JSON file.
        safe_info = {k: info[k] for k in ("client_email", "token_uri", "private_key")}
        credentials = service_account.Credentials.from_service_account_info(
            safe_info, scopes=config.scopes, always_use_jwt_access=False,
        )
        return credentials, writer
    except Exception:
        raise SyncError("credentials-invalid") from None


def run_once(config: Config) -> None:
    import requests

    from .transport import GoogleRequest, metadata, request_json
    credentials, writer = load_credentials(config)
    with requests.Session() as session:
        session.trust_env = False
        headers = {"Authorization": "Bearer " + writer}
        url = config.av_base_url + "/v1/credentials"
        metadata(session, url, headers, config)
        try:
            with requests.Session() as google_session:
                google_session.trust_env = False
                credentials.refresh(GoogleRequest(google_session))
        except Exception:
            raise SyncError("google-refresh-failed") from None
        try:
            expiry = credentials.expiry
            if not isinstance(expiry, datetime) or not _text(credentials.token):
                raise ValueError
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if not 600 <= (expiry - datetime.now(timezone.utc)).total_seconds() <= 7200:
                raise ValueError
        except Exception:
            raise SyncError("google-token-invalid") from None
        result = request_json(session, "POST", url, headers=headers, json={
            "vault": config.vault, "credentials": {config.credential_key: credentials.token},
        })
        if not isinstance(result, dict) or result.get("set") != [config.credential_key]:
            raise SyncError("vault-response-invalid")
        if not metadata(session, url, headers, config):
            raise SyncError("vault-verification-failed")
        if config.status_file is not None:
            try:
                write_status(config.status_file, {
                    "last_success": datetime.now(timezone.utc).isoformat(),
                    "expires_at": expiry.isoformat(),
                })
            except Exception:
                raise SyncError("status-write-failed") from None
