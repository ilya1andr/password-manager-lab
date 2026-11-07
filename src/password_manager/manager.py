"""Password manager core logic."""

import base64
import hashlib
import json
import os
import secrets
import string
from pathlib import Path
from typing import Any, cast

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class PasswordManager:
    """Manages password entries with master-password protection."""

    def __init__(self, storage_path: Path | str = "vault.json") -> None:
        """Initialize manager with path to storage file."""
        self.storage_path = Path(storage_path)
        self._data: dict[str, Any] = {}
        self._key: bytes | None = None
        self._unlocked: bool = False

    def init_master(self, password: str) -> None:
        """Create master password hash and salt. Fails if already initialized."""
        if self.storage_path.exists():
            raise RuntimeError("Vault already initialized. Use --unlock.")

        salt = os.urandom(16)
        pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)


        self._data = {
            "salt": salt.hex(),
            "master_hash": pwd_hash.hex(),
            "entries": {},
        }
        self._persist()

    def unlock(self, password: str) -> bool:
        """Verify master password. Returns True on success."""
        self._load()
        salt = bytes.fromhex(cast(str, self._data["salt"]))
        expected = bytes.fromhex(cast(str, self._data["master_hash"]))
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
        if actual == expected:
            self._unlocked = True
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=600_000,
            )
            self._key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            return True
        return False

    def add_entry(self, name: str, login: str, pwd: str) -> None:
        """Add a new entry. Requires unlocked state."""
        if not self._unlocked or self._key is None:
            raise RuntimeError("Vault is locked. Unlock first.")
        self._load()

        f = Fernet(self._key)
        encrypted_pwd = f.encrypt(pwd.encode("utf-8")).decode("utf-8")

        self._data["entries"][name] = {"login": login, "password": encrypted_pwd}
        self._persist()

    def list_entries(self) -> list[str]:
        """Return list of entry names (without passwords)."""
        if not self._unlocked:
            raise RuntimeError("Vault is locked. Unlock first.")
        self._load()
        return list(self._data.get("entries", {}).keys())

    def get_entry(self, name: str) -> tuple[str, str]:
        """Return (login, password) for entry. Requires unlocked state."""
        if not self._unlocked or self._key is None:
            raise RuntimeError("Vault is locked. Unlock first.")
        self._load()
        entry = self._data["entries"].get(name)
        if entry is None:
            raise KeyError(f"Entry '{name}' not found")
        f = Fernet(self._key)

        try:
            decrypted_pwd = f.decrypt(entry["password"].encode("utf-8")).decode("utf-8")
        except InvalidToken as e:
            raise RuntimeError("Failed to decrypt password. Data corrupted or wrong key.") from e

        return entry["login"], decrypted_pwd

    def delete_entry(self, name: str) -> None:
        """Delete entry by name."""
        if not self._unlocked:
            raise RuntimeError("Vault is locked. Unlock first.")
        self._load()
        if name not in self._data.get("entries", {}):
            raise KeyError(f"Entry '{name}' not found")
        del self._data["entries"][name]
        self._persist()

    def generate_password(self, length: int = 16) -> str:
        """Generate a strong random password."""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return "".join(secrets.choice(alphabet) for _ in range(length))

    def _load(self) -> None:
        """Read JSON file into self._data."""
        if self.storage_path.exists():
            with open(self.storage_path, encoding="utf-8") as f:
                self._data = json.load(f)
        else:
            self._data = {}

    def _persist(self) -> None:
        """Write self._data to JSON file."""
        with open(self.storage_path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2)
