from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from threading import RLock
from typing import Any

from cryptography.fernet import Fernet


class ConfigStore:
    def __init__(self) -> None:
        self.path = Path(os.getenv("MAILTRACE_CONFIG", "data/config.json"))
        self.key_path = Path(os.getenv("MAILTRACE_KEY", "data/master.key"))
        self._lock = RLock()

    def _fernet(self) -> Fernet:
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.key_path.exists():
            self.key_path.write_bytes(Fernet.generate_key())
            try:
                self.key_path.chmod(0o600)
            except OSError:
                pass
        return Fernet(self.key_path.read_bytes().strip())

    def load(self) -> dict[str, Any]:
        with self._lock:
            if not self.path.exists():
                return {"configured": False, "session_secret": secrets.token_urlsafe(32)}
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            for key in ("database_url", "ssh_password", "ssh_private_key", "ssh_key_passphrase"):
                if payload.get(key):
                    payload[key] = self._fernet().decrypt(payload[key].encode()).decode()
            return payload

    def save(self, config: dict[str, Any]) -> None:
        with self._lock:
            current = self.load() if self.path.exists() else {}
            merged = {**current, **config}
            merged.setdefault("session_secret", secrets.token_urlsafe(32))
            stored = dict(merged)
            for key in ("database_url", "ssh_password", "ssh_private_key", "ssh_key_passphrase"):
                if stored.get(key):
                    stored[key] = self._fernet().encrypt(stored[key].encode()).decode()
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temp = self.path.with_suffix(".tmp")
            temp.write_text(json.dumps(stored, ensure_ascii=False, indent=2), encoding="utf-8")
            temp.replace(self.path)

    @staticmethod
    def public(config: dict[str, Any]) -> dict[str, Any]:
        hidden = {"admin_password_hash", "database_url", "ssh_password", "ssh_private_key", "ssh_key_passphrase", "session_secret"}
        result = {k: v for k, v in config.items() if k not in hidden}
        result["has_ssh_password"] = bool(config.get("ssh_password"))
        result["has_ssh_key"] = bool(config.get("ssh_private_key"))
        result["has_database"] = bool(config.get("database_url"))
        return result


store = ConfigStore()
