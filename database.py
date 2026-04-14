"""SQLite-хранилище пользователей IPHunder (data.db)."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

DB_PATH = Path(__file__).resolve().parent / "data.db"


@dataclass(frozen=True)
class UserRecord:
    telegram_id: int
    has_subscription: bool
    is_admin: bool
    subscription_until: Optional[datetime]


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    conn = _connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                telegram_id INTEGER PRIMARY KEY,
                has_subscription INTEGER NOT NULL DEFAULT 0,
                is_admin INTEGER NOT NULL DEFAULT 0,
                subscription_until TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sbp_intents (
                transaction_id TEXT PRIMARY KEY,
                telegram_id INTEGER NOT NULL,
                amount_rub REAL NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS yandex_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_id INTEGER NOT NULL,
                credentials_encrypted BLOB NOT NULL,
                summary TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        _ensure_yandex_display_name_column(conn)
        _ensure_yandex_identity_key_column(conn)
        _ensure_yandex_active_hunts_table(conn)


def _ensure_yandex_display_name_column(conn: sqlite3.Connection) -> None:
    cols = {row[1] for row in conn.execute("PRAGMA table_info(yandex_accounts)").fetchall()}
    if "display_name" not in cols:
        conn.execute("ALTER TABLE yandex_accounts ADD COLUMN display_name TEXT NOT NULL DEFAULT ''")


def _ensure_yandex_identity_key_column(conn: sqlite3.Connection) -> None:
    cols = {row[1] for row in conn.execute("PRAGMA table_info(yandex_accounts)").fetchall()}
    if "identity_key" not in cols:
        conn.execute("ALTER TABLE yandex_accounts ADD COLUMN identity_key TEXT NOT NULL DEFAULT ''")


def _ensure_yandex_active_hunts_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS yandex_active_hunts (
            telegram_id INTEGER PRIMARY KEY,
            chat_id INTEGER NOT NULL,
            account_ids_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )


def save_sbp_intent(transaction_id: str, telegram_id: int, amount_rub: float) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO sbp_intents (transaction_id, telegram_id, amount_rub, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (transaction_id, telegram_id, amount_rub, now),
        )


def get_sbp_intent(transaction_id: str) -> Optional[tuple[int, float]]:
    """Возвращает (telegram_id, amount_rub) или None."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT telegram_id, amount_rub FROM sbp_intents WHERE transaction_id = ?",
            (transaction_id,),
        ).fetchone()
    if not row:
        return None
    return int(row["telegram_id"]), float(row["amount_rub"])


def delete_sbp_intent(transaction_id: str) -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM sbp_intents WHERE transaction_id = ?", (transaction_id,))


MAX_YANDEX_ACCOUNTS_PER_USER = 10


def count_yandex_accounts(telegram_id: int) -> int:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS c FROM yandex_accounts WHERE telegram_id = ?",
            (telegram_id,),
        ).fetchone()
    return int(row["c"]) if row else 0


def yandex_identity_taken(telegram_id: int, identity_key: str) -> bool:
    """Тот же OAuth + тот же каталог (folder) у этого пользователя уже сохранены."""
    key = (identity_key or "").strip()
    if not key:
        return False
    with get_connection() as conn:
        row = conn.execute(
            "SELECT 1 AS x FROM yandex_accounts WHERE telegram_id = ? AND identity_key = ? LIMIT 1",
            (telegram_id, key),
        ).fetchone()
    return row is not None


def insert_yandex_account(
    telegram_id: int,
    credentials_encrypted: bytes,
    summary: str,
    display_name: str,
    identity_key: str,
) -> int:
    now = datetime.now(timezone.utc).isoformat()
    dn = (display_name or "").strip()[:40]
    ik = (identity_key or "").strip()
    with get_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO yandex_accounts (
                telegram_id, credentials_encrypted, summary, display_name, identity_key, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (telegram_id, credentials_encrypted, summary, dn, ik, now),
        )
        return int(cur.lastrowid)


def list_yandex_accounts(telegram_id: int) -> list[tuple[int, str, str]]:
    """Список (id, display_name, summary) для кнопок и дашборда."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, display_name, summary FROM yandex_accounts WHERE telegram_id = ? ORDER BY id",
            (telegram_id,),
        ).fetchall()
    return [
        (int(r["id"]), str(r["display_name"] or ""), str(r["summary"]))
        for r in rows
    ]


def get_yandex_account_row(telegram_id: int, account_id: int) -> Optional[bytes]:
    """BLOB credentials или None, если не ваш."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT credentials_encrypted FROM yandex_accounts WHERE id = ? AND telegram_id = ?",
            (account_id, telegram_id),
        ).fetchone()
    if not row:
        return None
    return bytes(row["credentials_encrypted"])


def delete_yandex_account(telegram_id: int, account_id: int) -> bool:
    with get_connection() as conn:
        cur = conn.execute(
            "DELETE FROM yandex_accounts WHERE id = ? AND telegram_id = ?",
            (account_id, telegram_id),
        )
        return cur.rowcount > 0


def update_yandex_display_name(telegram_id: int, account_id: int, display_name: str) -> bool:
    dn = (display_name or "").strip()[:40]
    with get_connection() as conn:
        cur = conn.execute(
            "UPDATE yandex_accounts SET display_name = ? WHERE id = ? AND telegram_id = ?",
            (dn, account_id, telegram_id),
        )
        return cur.rowcount > 0


def update_yandex_account_blob(telegram_id: int, account_id: int, blob: bytes, summary: str) -> bool:
    with get_connection() as conn:
        cur = conn.execute(
            """
            UPDATE yandex_accounts
            SET credentials_encrypted = ?, summary = ?
            WHERE id = ? AND telegram_id = ?
            """,
            (blob, summary, account_id, telegram_id),
        )
        return cur.rowcount > 0


def set_yandex_active_hunt(telegram_id: int, chat_id: int, account_ids: list[int]) -> None:
    now = datetime.now(timezone.utc).isoformat()
    payload = json.dumps(account_ids, separators=(",", ":"))
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO yandex_active_hunts (telegram_id, chat_id, account_ids_json, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(telegram_id) DO UPDATE SET
                chat_id = excluded.chat_id,
                account_ids_json = excluded.account_ids_json,
                created_at = excluded.created_at
            """,
            (telegram_id, chat_id, payload, now),
        )


def clear_yandex_active_hunt(telegram_id: int) -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM yandex_active_hunts WHERE telegram_id = ?", (telegram_id,))


def get_yandex_active_hunt(telegram_id: int) -> Optional[tuple[int, list[int]]]:
    """(chat_id, account_ids) или None."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT chat_id, account_ids_json FROM yandex_active_hunts WHERE telegram_id = ?",
            (telegram_id,),
        ).fetchone()
    if not row:
        return None
    try:
        ids = json.loads(str(row["account_ids_json"]))
        if not isinstance(ids, list):
            return None
        acc_ids = [int(x) for x in ids]
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    return int(row["chat_id"]), acc_ids


def list_yandex_active_hunts() -> list[tuple[int, int, list[int]]]:
    """Все незавершённые охоты для восстановления после перезапуска: (telegram_id, chat_id, account_ids)."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT telegram_id, chat_id, account_ids_json FROM yandex_active_hunts"
        ).fetchall()
    out: list[tuple[int, int, list[int]]] = []
    for r in rows:
        try:
            ids = json.loads(str(r["account_ids_json"]))
            if not isinstance(ids, list):
                continue
            acc_ids = [int(x) for x in ids]
        except (json.JSONDecodeError, TypeError, ValueError):
            continue
        out.append((int(r["telegram_id"]), int(r["chat_id"]), acc_ids))
    return out


def ensure_user(telegram_id: int, *, is_admin: bool = False) -> UserRecord:
    """Создаёт пользователя при отсутствии; при is_admin выставляет флаг админа."""
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO users (telegram_id, has_subscription, is_admin, subscription_until)
            VALUES (?, 0, ?, NULL)
            ON CONFLICT(telegram_id) DO NOTHING
            """,
            (telegram_id, 1 if is_admin else 0),
        )
        if is_admin:
            conn.execute(
                "UPDATE users SET is_admin = 1 WHERE telegram_id = ?",
                (telegram_id,),
            )
        row = conn.execute(
            "SELECT telegram_id, has_subscription, is_admin, subscription_until "
            "FROM users WHERE telegram_id = ?",
            (telegram_id,),
        ).fetchone()
    assert row is not None
    return _row_to_user(row)


def get_user(telegram_id: int) -> Optional[UserRecord]:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT telegram_id, has_subscription, is_admin, subscription_until "
            "FROM users WHERE telegram_id = ?",
            (telegram_id,),
        ).fetchone()
    return _row_to_user(row) if row else None


def set_subscription(
    telegram_id: int,
    *,
    active: bool,
    until: Optional[datetime] = None,
) -> None:
    until_str = None
    if until is not None:
        if until.tzinfo is None:
            until = until.replace(tzinfo=timezone.utc)
        until_str = until.isoformat()
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE users
            SET has_subscription = ?, subscription_until = ?
            WHERE telegram_id = ?
            """,
            (1 if active else 0, until_str, telegram_id),
        )


def count_users() -> int:
    with get_connection() as conn:
        row = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()
    return int(row["c"]) if row else 0


def _row_to_user(row: sqlite3.Row) -> UserRecord:
    sub_until_raw = row["subscription_until"]
    sub_until: Optional[datetime] = None
    if sub_until_raw:
        sub_until = datetime.fromisoformat(sub_until_raw)
    return UserRecord(
        telegram_id=int(row["telegram_id"]),
        has_subscription=bool(row["has_subscription"]),
        is_admin=bool(row["is_admin"]),
        subscription_until=sub_until,
    )
