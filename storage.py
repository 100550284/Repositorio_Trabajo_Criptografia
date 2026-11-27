"""
Módulo de persistencia segura en ficheros JSON para CadenaFría.
"""

import json
import os
from pathlib import Path
from typing import Any


class SecureStorage:
    """Gestiona los ficheros de operadores, lotes, telemetría y albaranes firmados."""

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

    def operadores_file(self) -> str:
        return "operadores.json"

    def lotes_file(self, operador: str) -> str:
        return f"lotes_{operador}.json"

    def telemetria_file(self, operador: str) -> str:
        return f"telemetria_{operador}.json"

    def albaranes_file(self) -> str:
        return "albaranes_firmados.json"
    