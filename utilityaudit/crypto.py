"""Authenticated encryption with row/tenant binding and explicit key custody."""

import hmac
import json
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from utilityaudit.errors import ConfigurationError, DataIntegrityError


class Cipher:
    def __init__(self, keys: list[bytes]):
        try:
            self.fernet = MultiFernet([Fernet(key) for key in keys])
        except (ValueError, TypeError) as exc:
            raise ConfigurationError("Supply valid Fernet keys; never put keys in source control.") from exc

    def encrypt(self, data: bytes, context: str) -> bytes:
        envelope = json.dumps({"context": context, "data": data.hex()}, separators=(",", ":")).encode()
        return self.fernet.encrypt(envelope)

    def decrypt(self, data: bytes, context: str) -> bytes:
        try:
            envelope = json.loads(self.fernet.decrypt(data))
            if not hmac.compare_digest(envelope["context"], context):
                raise DataIntegrityError("Encrypted data does not belong to this record.")
            return bytes.fromhex(envelope["data"])
        except (InvalidToken, KeyError, ValueError, TypeError) as exc:
            raise DataIntegrityError(
                "Encrypted data could not be authenticated. Check key custody and restore procedures."
            ) from exc


def load_cipher(directory: Path, *, server_mode: bool = False) -> Cipher:
    configured = os.environ.get("UTILITYAUDIT_ENCRYPTION_KEYS")
    if configured:
        return Cipher([key.strip().encode("ascii") for key in configured.split(",")])
    if server_mode:
        raise ConfigurationError("Server mode requires UTILITYAUDIT_ENCRYPTION_KEYS from a secret manager.")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / "encryption.key"
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        if path.stat().st_mode & 0o077:
            raise ConfigurationError("Local encryption.key permissions must be 0600.")
        return Cipher([path.read_bytes().strip()])
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(Fernet.generate_key())
        stream.flush()
        os.fsync(stream.fileno())
    return Cipher([path.read_bytes()])
