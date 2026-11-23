"""
Módulo de persistencia segura en ficheros JSON para VaultSign.
"""

import json
import os
from pathlib import Path
from typing import Any


class SecureStorage:
    """Gestiona los ficheros de usuarios, bóvedas, auditoría y documentos firmados."""

    def __init__(self, base_dir: str = "data") -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._restrict_dir_permissions(self.base_dir)

    @staticmethod
    def _restrict_dir_permissions(path: Path) -> None:
        if os.name == "posix":
            os.chmod(path, 0o700)

    @staticmethod
    def _restrict_file_permissions(path: Path) -> None:
        if os.name == "posix":
            os.chmod(path, 0o600)

    def _path(self, filename: str) -> Path:
        return self.base_dir / filename

    def load_json(self, filename: str, default: Any) -> Any:
        file_path = self._path(filename)
        if not file_path.exists():
            return default
        with file_path.open("r", encoding="utf-8") as fh:
            return json.load(fh)

    def save_json(self, filename: str, data: Any) -> None:
        file_path = self._path(filename)
        with file_path.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        self._restrict_file_permissions(file_path)

    def users_file(self) -> str:
        return "users.json"

    def vault_file(self, username: str) -> str:
        return f"vault_{username}.json"

    def audit_file(self, username: str) -> str:
        return f"audit_{username}.json"

    def signed_file(self) -> str:
        return "signed_docs.json"
    