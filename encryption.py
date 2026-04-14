"""Шифрование чувствительных полей (Fernet). Ключ: ENCRYPTION_KEY в .env (результат Fernet.generate_key())."""

from __future__ import annotations

import json
import os
from typing import Any

from cryptography.fernet import Fernet, InvalidToken


class EncryptionError(Exception):
    pass


def _fernet() -> Fernet:
    key = os.environ.get("ENCRYPTION_KEY", "").strip().encode("ascii")
    if not key:
        raise EncryptionError(
            "В .env задайте ENCRYPTION_KEY — результат Fernet.generate_key().decode() из cryptography."
        )
    try:
        return Fernet(key)
    except Exception as e:
        raise EncryptionError("ENCRYPTION_KEY невалиден для Fernet.") from e


def require_encryption_ready() -> None:
    """Проверка ключа при старте приложения."""
    _fernet()


def encrypt_json(data: dict[str, Any]) -> bytes:
    raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
    return _fernet().encrypt(raw)


def decrypt_json(blob: bytes) -> dict[str, Any]:
    try:
        raw = _fernet().decrypt(blob)
    except InvalidToken as e:
        raise EncryptionError("Не удалось расшифровать данные (неверный ключ или повреждённые данные).") from e
    return json.loads(raw.decode("utf-8"))
