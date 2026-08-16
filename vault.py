"""
vault.py
Encrypted password vault.

Security design:
- Master password is never stored. It's run through PBKDF2-HMAC-SHA256
  (390,000 iterations, per OWASP 2023 guidance) with a random per-vault salt
  to derive a symmetric key.
- That key drives Fernet (AES-128-CBC + HMAC-SHA256 authenticated encryption)
  to encrypt the vault contents at rest.
- The salt is stored alongside the ciphertext (salts don't need to be secret),
  but the derived key and master password never touch disk.
"""

import base64
import json
import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS = 390_000
SALT_SIZE = 16


class VaultError(Exception):
    pass


class Vault:
    def __init__(self, path: str):
        self.path = Path(path)

    def _derive_key(self, master_password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        key = kdf.derive(master_password.encode("utf-8"))
        return base64.urlsafe_b64encode(key)

    def exists(self) -> bool:
        return self.path.exists()

    def create(self, master_password: str) -> None:
        """Initialize a brand-new empty vault file."""
        if self.exists():
            raise VaultError("Vault already exists at this path.")
        salt = secrets.token_bytes(SALT_SIZE)
        key = self._derive_key(master_password, salt)
        fernet = Fernet(key)
        empty_payload = json.dumps({"entries": {}}).encode("utf-8")
        token = fernet.encrypt(empty_payload)

        on_disk = {
            "salt": base64.b64encode(salt).decode("utf-8"),
            "iterations": PBKDF2_ITERATIONS,
            "ciphertext": token.decode("utf-8"),
        }
        self.path.write_text(json.dumps(on_disk, indent=2))
        os.chmod(self.path, 0o600)  # owner read/write only

    def _load_raw(self) -> dict:
        if not self.exists():
            raise VaultError("Vault file not found. Create one first.")
        return json.loads(self.path.read_text())

    def unlock(self, master_password: str) -> dict:
        """Decrypt and return the vault's entries dict. Raises VaultError on bad password."""
        raw = self._load_raw()
        salt = base64.b64decode(raw["salt"])
        key = self._derive_key(master_password, salt)
        fernet = Fernet(key)
        try:
            payload = fernet.decrypt(raw["ciphertext"].encode("utf-8"))
        except InvalidToken:
            raise VaultError("Incorrect master password or corrupted vault.")
        return json.loads(payload.decode("utf-8"))["entries"]

    def save(self, master_password: str, entries: dict) -> None:
        """Re-encrypt and persist the full entries dict."""
        raw = self._load_raw()
        salt = base64.b64decode(raw["salt"])
        key = self._derive_key(master_password, salt)
        fernet = Fernet(key)
        payload = json.dumps({"entries": entries}).encode("utf-8")
        token = fernet.encrypt(payload)
        raw["ciphertext"] = token.decode("utf-8")
        self.path.write_text(json.dumps(raw, indent=2))
        os.chmod(self.path, 0o600)

    def add_entry(self, master_password: str, service: str, username: str, password: str) -> None:
        entries = self.unlock(master_password)
        entries[service] = {"username": username, "password": password}
        self.save(master_password, entries)

    def get_entry(self, master_password: str, service: str) -> dict:
        entries = self.unlock(master_password)
        if service not in entries:
            raise VaultError(f"No entry found for '{service}'.")
        return entries[service]

    def delete_entry(self, master_password: str, service: str) -> None:
        entries = self.unlock(master_password)
        if service not in entries:
            raise VaultError(f"No entry found for '{service}'.")
        del entries[service]
        self.save(master_password, entries)

    def list_services(self, master_password: str) -> list:
        return sorted(self.unlock(master_password).keys())
