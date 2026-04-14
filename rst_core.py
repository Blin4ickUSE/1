"""
Ядро RST (Selectel / RegCloud): сеть, лимиты, БД, цикл охоты, сценарии Telegram.
Логика провайдеров вынесена в workers/selectel.py, regcloud.py.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import importlib
import ipaddress
import json
import logging
import random
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Coroutine, Iterator, Optional

import requests
from requests.adapters import HTTPAdapter
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

try:
    from urllib3.util.retry import Retry
except ImportError:
    Retry = None  # type: ignore[misc, assignment]

import encryption
from workers.hunt_dashboard import HuntDashboard
from workers.yandex_cloud import HUNT_LOOP_PAUSE_SEC, ip_matches_any

log = logging.getLogger(__name__)

DB_PATH = Path(__file__).resolve().parent / "data.db"

MAX_RST_ACCOUNTS_PER_PROVIDER = 10

DISPLAY_NAME_MAX = 40

# ── сценарии добавления ──
FLOW_RST_SEL_PROJECT = "rst_sel_project"
FLOW_RST_SEL_ACCOUNT = "rst_sel_account"
FLOW_RST_SEL_USER = "rst_sel_user"
FLOW_RST_SEL_PASS = "rst_sel_pass"
FLOW_RST_SEL_PNAME = "rst_sel_pname"
FLOW_RST_SEL_NAME = "rst_sel_name"
FLOW_RST_SEL_TARGETS = "rst_sel_targets"

FLOW_RST_RC_LOGIN = "rst_rc_login"
FLOW_RST_RC_PASS = "rst_rc_pass"
FLOW_RST_RC_SERVICE = "rst_rc_service"

FLOW_RST_EDIT_RENAME = "rst_edit_rename"


class DailyLimitError(Exception):
    def __init__(self, message: str, resume_at: str = ""):
        super().__init__(message)
        self.resume_at = resume_at


@dataclass
class ProviderResult:
    ip: str
    resource_id: str
    region: str
    raw: dict[str, Any] = field(default_factory=dict)


def parse_proxy(proxy_str: str) -> Optional[dict[str, Any]]:
    if not proxy_str or not proxy_str.strip():
        return None
    proxy_str = proxy_str.strip()
    if "://" in proxy_str:
        scheme, rest = proxy_str.split("://", 1)
    else:
        scheme = "socks5"
        rest = proxy_str
    username = password = None
    if "@" in rest:
        auth, hostport = rest.rsplit("@", 1)
        if ":" in auth:
            username, password = auth.split(":", 1)
        else:
            username = auth
    else:
        hostport = rest
    if ":" in hostport:
        host, port_str = hostport.rsplit(":", 1)
        port = int(port_str)
    else:
        host = hostport
        port = 1080
    return {
        "scheme": scheme,
        "host": host,
        "port": port,
        "username": username,
        "password": password,
    }


def apply_proxy_to_session(session: requests.Session, proxy_cfg: Optional[dict[str, Any]]) -> None:
    if not proxy_cfg:
        return
    scheme = proxy_cfg["scheme"]
    host = proxy_cfg["host"]
    port = proxy_cfg["port"]
    user = proxy_cfg.get("username") or ""
    pw = proxy_cfg.get("password") or ""
    if scheme == "socks5":
        scheme = "socks5h"
    elif scheme == "socks4":
        scheme = "socks4a"
    if user and pw:
        proxy_url = f"{scheme}://{user}:{pw}@{host}:{port}"
    elif user:
        proxy_url = f"{scheme}://{user}@{host}:{port}"
    else:
        proxy_url = f"{scheme}://{host}:{port}"
    session.proxies = {"http": proxy_url, "https": proxy_url}


def make_http_session(
    *,
    token: str = "",
    auth_header: str = "X-Auth-Token",
    proxy: Optional[dict[str, Any]] = None,
) -> requests.Session:
    s = requests.Session()
    if Retry is not None:
        retry_strategy = Retry(
            total=3,
            backoff_factor=1.0,
            status_forcelist=[502, 503, 504],
            allowed_methods=["GET", "POST", "DELETE"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=5, pool_maxsize=10)
    else:
        adapter = HTTPAdapter(pool_connections=5, pool_maxsize=10)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    s.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
    if token:
        if auth_header == "Authorization":
            s.headers[auth_header] = f"Bearer {token}"
        else:
            s.headers[auth_header] = token
    if proxy:
        apply_proxy_to_session(s, proxy)
    return s


def parse_subnets(raw: str) -> set:
    nets = set()
    for item in raw.split(","):
        item = item.strip()
        if item:
            nets.add(ipaddress.ip_network(item, strict=False))
    return nets


def fast_match(ip_str: str, subnet_set: set) -> Optional[str]:
    try:
        net24 = ipaddress.ip_network(f"{ip_str}/24", strict=False)
        if net24 in subnet_set:
            return str(net24)
        addr = ipaddress.ip_address(ip_str)
        for net in subnet_set:
            if net.prefixlen != 24 and addr in net:
                return str(net)
    except ValueError:
        pass
    return None


def backoff_delay(errors_in_row: int, base: float = 2.0, cap: float = 60.0) -> float:
    delay = min(base * (2**errors_in_row), cap)
    return delay * random.uniform(0.7, 1.3)


class AdaptiveRateLimiter:
    def __init__(self, rpm_max: int = 20):
        self.rpm_max = rpm_max
        self.rpm = rpm_max
        self.window: list[float] = []
        self._lock = threading.Lock()
        self._successes_since_drop = 0

    def wait_if_needed(self, cost: int = 2) -> None:
        while True:
            sleep_for = 0.0
            with self._lock:
                now = time.time()
                self.window = [t for t in self.window if now - t < 60]
                if len(self.window) + cost <= self.rpm:
                    t = time.time()
                    for _ in range(cost):
                        self.window.append(t)
                    return
                if self.window:
                    sleep_for = 60 - (now - self.window[0]) + 1.0
                else:
                    sleep_for = 2.0
            if sleep_for > 0:
                time.sleep(sleep_for)

    def on_success(self) -> None:
        with self._lock:
            self._successes_since_drop += 1
            if self._successes_since_drop >= 20 and self.rpm < self.rpm_max:
                self.rpm = min(self.rpm + 1, self.rpm_max)
                self._successes_since_drop = 0

    def on_rate_limit(self) -> None:
        with self._lock:
            old = self.rpm
            self.rpm = max(4, int(self.rpm * 0.7))
            self._successes_since_drop = 0
            if self.rpm != old:
                log.debug("RPM ↓ %s (429)", self.rpm)


# ── SQLite (отдельно от database.py) ──


@contextmanager
def _conn() -> Iterator[sqlite3.Connection]:
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init_rst_db() -> None:
    with _conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS rst_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_id INTEGER NOT NULL,
                provider TEXT NOT NULL,
                credentials_encrypted BLOB NOT NULL,
                summary TEXT NOT NULL,
                display_name TEXT NOT NULL DEFAULT '',
                identity_key TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS rst_active_hunts (
                telegram_id INTEGER PRIMARY KEY,
                chat_id INTEGER NOT NULL,
                provider TEXT NOT NULL,
                account_ids_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )


def count_rst_accounts(telegram_id: int, provider: str) -> int:
    with _conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS c FROM rst_accounts WHERE telegram_id = ? AND provider = ?",
            (telegram_id, provider),
        ).fetchone()
    return int(row["c"]) if row else 0


def rst_identity_taken(telegram_id: int, provider: str, identity_key: str) -> bool:
    key = (identity_key or "").strip()
    if not key:
        return False
    with _conn() as conn:
        row = conn.execute(
            "SELECT 1 AS x FROM rst_accounts WHERE telegram_id = ? AND provider = ? AND identity_key = ? LIMIT 1",
            (telegram_id, provider, key),
        ).fetchone()
    return row is not None


def insert_rst_account(
    telegram_id: int,
    provider: str,
    credentials_encrypted: bytes,
    summary: str,
    display_name: str,
    identity_key: str,
) -> int:
    now = datetime.now(timezone.utc).isoformat()
    dn = (display_name or "").strip()[:DISPLAY_NAME_MAX]
    ik = (identity_key or "").strip()
    with _conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO rst_accounts (
                telegram_id, provider, credentials_encrypted, summary, display_name, identity_key, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (telegram_id, provider, credentials_encrypted, summary, dn, ik, now),
        )
        return int(cur.lastrowid)


def list_rst_accounts(telegram_id: int, provider: str) -> list[tuple[int, str, str]]:
    with _conn() as conn:
        rows = conn.execute(
            """
            SELECT id, display_name, summary FROM rst_accounts
            WHERE telegram_id = ? AND provider = ? ORDER BY id
            """,
            (telegram_id, provider),
        ).fetchall()
    return [(int(r["id"]), str(r["display_name"] or ""), str(r["summary"])) for r in rows]


def get_rst_account_blob(telegram_id: int, account_id: int) -> Optional[bytes]:
    with _conn() as conn:
        row = conn.execute(
            "SELECT credentials_encrypted FROM rst_accounts WHERE id = ? AND telegram_id = ?",
            (account_id, telegram_id),
        ).fetchone()
    if not row:
        return None
    return bytes(row["credentials_encrypted"])


def delete_rst_account(telegram_id: int, account_id: int) -> bool:
    with _conn() as conn:
        cur = conn.execute(
            "DELETE FROM rst_accounts WHERE id = ? AND telegram_id = ?",
            (account_id, telegram_id),
        )
        return cur.rowcount > 0


def update_rst_display_name(telegram_id: int, account_id: int, display_name: str) -> bool:
    dn = (display_name or "").strip()[:DISPLAY_NAME_MAX]
    with _conn() as conn:
        cur = conn.execute(
            "UPDATE rst_accounts SET display_name = ? WHERE id = ? AND telegram_id = ?",
            (dn, account_id, telegram_id),
        )
        return cur.rowcount > 0


def update_rst_account_blob(telegram_id: int, account_id: int, blob: bytes, summary: str) -> bool:
    with _conn() as conn:
        cur = conn.execute(
            """
            UPDATE rst_accounts SET credentials_encrypted = ?, summary = ? WHERE id = ? AND telegram_id = ?
            """,
            (blob, summary, account_id, telegram_id),
        )
        return cur.rowcount > 0


def set_rst_active_hunt(telegram_id: int, chat_id: int, provider: str, account_ids: list[int]) -> None:
    now = datetime.now(timezone.utc).isoformat()
    payload = json.dumps(account_ids, separators=(",", ":"))
    with _conn() as conn:
        conn.execute(
            """
            INSERT INTO rst_active_hunts (telegram_id, chat_id, provider, account_ids_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(telegram_id) DO UPDATE SET
                chat_id = excluded.chat_id,
                provider = excluded.provider,
                account_ids_json = excluded.account_ids_json,
                created_at = excluded.created_at
            """,
            (telegram_id, chat_id, provider, payload, now),
        )


def clear_rst_active_hunt(telegram_id: int) -> None:
    with _conn() as conn:
        conn.execute("DELETE FROM rst_active_hunts WHERE telegram_id = ?", (telegram_id,))


def get_rst_active_hunt(telegram_id: int) -> Optional[tuple[int, str, list[int]]]:
    with _conn() as conn:
        row = conn.execute(
            "SELECT chat_id, provider, account_ids_json FROM rst_active_hunts WHERE telegram_id = ?",
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
    return int(row["chat_id"]), str(row["provider"]), acc_ids


def list_rst_active_hunts() -> list[tuple[int, int, str, list[int]]]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT telegram_id, chat_id, provider, account_ids_json FROM rst_active_hunts"
        ).fetchall()
    out: list[tuple[int, int, str, list[int]]] = []
    for r in rows:
        try:
            ids = json.loads(str(r["account_ids_json"]))
            if not isinstance(ids, list):
                continue
            acc_ids = [int(x) for x in ids]
        except (json.JSONDecodeError, TypeError, ValueError):
            continue
        out.append((int(r["telegram_id"]), int(r["chat_id"]), str(r["provider"]), acc_ids))
    return out


# ── охота ──

RUNNING_RST: dict[int, asyncio.Task] = {}


def _running_rst_task(user_id: int) -> Optional[asyncio.Task]:
    t = RUNNING_RST.get(user_id)
    if t is None:
        return None
    if t.done():
        RUNNING_RST.pop(user_id, None)
        return None
    return t


def active_rst_hunt_count(user_id: int) -> int:
    if _running_rst_task(user_id) is not None:
        return 1
    if get_rst_active_hunt(user_id) is not None:
        return 1
    return 0


def cancel_rst_hunt(user_id: int) -> bool:
    had_db = get_rst_active_hunt(user_id) is not None
    clear_rst_active_hunt(user_id)
    t = RUNNING_RST.get(user_id)
    if t is None or t.done():
        RUNNING_RST.pop(user_id, None)
        return had_db
    t.cancel()
    return True


def schedule_rst_hunt(
    user_id: int,
    coro_factory: Callable[[], Coroutine[Any, Any, None]],
) -> bool:
    if _running_rst_task(user_id) is not None:
        return False

    async def _wrap() -> None:
        try:
            await coro_factory()
        finally:
            RUNNING_RST.pop(user_id, None)
            clear_rst_active_hunt(user_id)

    t = asyncio.create_task(_wrap())
    RUNNING_RST[user_id] = t
    return True


def _bot_mod():
    return importlib.import_module("bot")


def _default_subnet_string(provider: str) -> str:
    from workers import regcloud
    from workers import selectel as sel

    m = {
        "selectel": sel.SELECTEL_SUBNETS,
        "regcloud": regcloud.REGRU_SUBNETS,
    }
    return m.get(provider, "")


def _subnet_set_for_cred(cred: dict[str, Any], provider: str) -> set:
    custom = (cred.get("custom_subnets") or "").strip()
    raw = custom if custom else _default_subnet_string(provider)
    return parse_subnets(raw) if raw else set()


def _hit(ip: str, subnet_set: set, targets: list[str]) -> tuple[bool, Optional[str]]:
    m = fast_match(ip, subnet_set)
    if m:
        return True, m
    if targets and ip_matches_any(ip, targets):
        return True, "шаблон"
    return False, None


def _process_result_sync(
    result: ProviderResult,
    subnet_set: set,
    targets: list[str],
    loop: asyncio.AbstractEventLoop,
    send_coro_factory: Callable[[str], Coroutine[Any, Any, Any]],
    provider_name: str,
    label: str,
    n: int,
    *,
    dashboard: Optional[HuntDashboard] = None,
    account_id: Optional[int] = None,
) -> bool:
    matched = _hit(result.ip, subnet_set, targets)
    if matched[0]:
        sub = matched[1] or "?"
        msg = (
            f"🎉 <b>Поймано!</b> ({provider_name}{label})\n"
            f"IP: <code>{html.escape(result.ip)}</code>\n"
            f"ID: <code>{html.escape(result.resource_id)}</code>\n"
            f"Регион: <code>{html.escape(result.region)}</code>\n"
            f"Подсеть/шаблон: <code>{html.escape(sub)}</code>\n"
            f"Попытка: #{n}"
        )
        asyncio.run_coroutine_threadsafe(send_coro_factory(msg), loop)
        if dashboard is not None and account_id is not None:
            asyncio.run_coroutine_threadsafe(dashboard.inc_hit(account_id), loop)
            asyncio.run_coroutine_threadsafe(dashboard.push_update(), loop)
        return True
    # Промахи не шлём в чат — только сводка в HuntDashboard (редактируется по таймеру).
    return False


@dataclass
class HuntRuntimeConfig:
    rpm_limit: int = 20
    attempts_per_provider: int = 150
    circuit_breaker_threshold: int = 5
    circuit_breaker_cooldown: int = 120
    connect_timeout: int = 10
    request_timeout: int = 30


def provider_worker_sync(
    provider: Any,
    subnet_set: set,
    cfg: HuntRuntimeConfig,
    limiter: AdaptiveRateLimiter,
    stop_event: threading.Event,
    loop: asyncio.AbstractEventLoop,
    send_coro_factory: Callable[[str], Coroutine[Any, Any, Any]],
    cred: dict[str, Any],
    *,
    account_id: int,
    dashboard: Optional[HuntDashboard] = None,
) -> None:
    from workers.regcloud import RegcloudProvider
    from workers.selectel import SelectelProvider

    label = getattr(provider, "current_account_label", "") or ""
    thread_name = f"[{provider.name.upper()}{label}]"
    provider_name = provider.name
    targets = list(cred.get("targets") or [])

    if isinstance(provider, RegcloudProvider):
        provider.stop_event = stop_event

    region_hits: dict[str, int] = {}

    def pick_region() -> str:
        regions = provider.get_regions()
        if not regions:
            return ""
        if not region_hits or random.random() < 0.3:
            return random.choice(regions)
        total = sum(region_hits.get(r, 0) for r in regions)
        if total == 0:
            return random.choice(regions)
        weights = [region_hits.get(r, 0) + 1 for r in regions]
        return random.choices(regions, weights=weights, k=1)[0]

    use_batch = False
    batch_sz = 1
    if isinstance(provider, SelectelProvider) and getattr(provider, "batch_size", 1) > 1:
        use_batch = True
        batch_sz = provider.batch_size
    elif isinstance(provider, RegcloudProvider):
        # RegCloud: только последовательный режим.
        # 1 сервер -> проверка -> удаление (если не подошёл) -> ожидание удаления -> следующий.
        use_batch = False
        batch_sz = 1

    timeout = (cfg.connect_timeout, cfg.request_timeout)
    provider.timeout = timeout

    n_global = 0
    while not stop_event.is_set():
        region = pick_region()
        if not region:
            time.sleep(2.0)
            continue
        regional_attempts = 0
        max_regional = min(cfg.attempts_per_provider, 50)

        while regional_attempts < max_regional and not stop_event.is_set():
            limiter.wait_if_needed(cost=batch_sz + 1 if use_batch and batch_sz > 1 else 2)
            n_global += 1
            regional_attempts += 1
            n = n_global

            if dashboard is not None:
                asyncio.run_coroutine_threadsafe(dashboard.inc_attempt(account_id), loop)

            try:
                if use_batch and batch_sz > 1:
                    results = provider.create_ip_batch(region, batch_sz)
                    provider.errors_in_row = 0
                    limiter.on_success()
                    to_delete: list[tuple[str, str]] = []
                    for res in results:
                        if not res.ip or not res.resource_id:
                            continue
                        log.info(
                            "%s создан #%s %s → %s id=%s",
                            thread_name,
                            n,
                            region,
                            res.ip,
                            res.resource_id,
                        )
                        found = _process_result_sync(
                            res,
                            subnet_set,
                            targets,
                            loop,
                            send_coro_factory,
                            provider_name,
                            label,
                            n,
                            dashboard=dashboard,
                            account_id=account_id,
                        )
                        if found:
                            region_hits[region] = region_hits.get(region, 0) + 1
                        else:
                            to_delete.append((res.resource_id, res.ip))
                    for rid, ip in to_delete:
                        if stop_event.is_set():
                            break
                        try:
                            log.info(
                                "%s удаление %s ip=%s id=%s",
                                thread_name,
                                region,
                                ip,
                                rid,
                            )
                            provider.delete_ip(rid)
                        except Exception as de:
                            log.warning("%s delete: %s", thread_name, de)
                else:
                    result = provider.create_ip(region)
                    provider.errors_in_row = 0
                    limiter.on_success()
                    if not result.ip or not result.resource_id:
                        continue
                    log.info(
                        "%s создан #%s %s → %s id=%s",
                        thread_name,
                        n,
                        region,
                        result.ip,
                        result.resource_id,
                    )
                    found = _process_result_sync(
                        result,
                        subnet_set,
                        targets,
                        loop,
                        send_coro_factory,
                        provider_name,
                        label,
                        n,
                        dashboard=dashboard,
                        account_id=account_id,
                    )
                    if found:
                        region_hits[region] = region_hits.get(region, 0) + 1
                    else:
                        try:
                            log.info(
                                "%s удаление %s ip=%s id=%s",
                                thread_name,
                                region,
                                result.ip,
                                result.resource_id,
                            )
                            provider.delete_ip(result.resource_id)
                        except Exception as de:
                            log.warning("%s delete: %s", thread_name, de)
                            # Для RegCloud создаём новый сервер ТОЛЬКО после подтверждённого удаления старого.
                            # Если удаление сорвалось — останавливаем поток, чтобы не копить "висяки".
                            if isinstance(provider, RegcloudProvider):
                                asyncio.run_coroutine_threadsafe(
                                    send_coro_factory(
                                        f"⛔ <b>{provider_name}</b>{html.escape(label)}: "
                                        "не удалось удалить предыдущий сервер. "
                                        "Новые серверы не создаются до ручной проверки."
                                    ),
                                    loop,
                                )
                                return
                            time.sleep(random.uniform(2.0, 4.0))

            except PermissionError as e:
                log.error("%s %s — останавливаю поток", thread_name, e)
                asyncio.run_coroutine_threadsafe(
                    send_coro_factory(f"⛔ <b>{provider_name}</b>{html.escape(label)}: {html.escape(str(e)[:400])}"),
                    loop,
                )
                return

            except DailyLimitError as e:
                log.warning("%s %s", thread_name, e)
                resume = e.resume_at
                asyncio.run_coroutine_threadsafe(
                    send_coro_factory(
                        f"⏸ <b>{provider_name}</b>{html.escape(label)}: суточный лимит. "
                        f"Сброс: <code>{html.escape(resume or '—')}</code>"
                    ),
                    loop,
                )
                if resume:
                    try:
                        resume_dt = datetime.fromisoformat(resume.replace("Z", "+00:00"))
                        now_utc = datetime.now().astimezone()
                        wait_secs = (resume_dt - now_utc).total_seconds()
                        if wait_secs > 0:
                            waited = 0.0
                            while waited < wait_secs and not stop_event.is_set():
                                time.sleep(min(30.0, wait_secs - waited))
                                waited += 30.0
                            if not stop_event.is_set():
                                provider.errors_in_row = 0
                            break
                    except (ValueError, TypeError):
                        pass
                waited = 0.0
                while waited < 3600 and not stop_event.is_set():
                    time.sleep(30.0)
                    waited += 30.0
                break

            except requests.ConnectionError as e:
                provider.errors_in_row += 1
                log.warning("%s ConnectionError: %s", thread_name, e)
                time.sleep(random.uniform(2.0, 5.0))
                if provider.errors_in_row >= cfg.circuit_breaker_threshold:
                    _cb_wait(stop_event, cfg.circuit_breaker_cooldown)
                    provider.errors_in_row = 0

            except requests.Timeout as e:
                provider.errors_in_row += 1
                log.warning("%s Timeout: %s", thread_name, e)
                time.sleep(random.uniform(3.0, 8.0))
                if provider.errors_in_row >= cfg.circuit_breaker_threshold:
                    _cb_wait(stop_event, cfg.circuit_breaker_cooldown)
                    provider.errors_in_row = 0

            except RuntimeError as e:
                err_msg = str(e)
                if "(429)" in err_msg:
                    provider.errors_in_row += 1
                    limiter.on_rate_limit()
                    time.sleep(min(10.0 * provider.errors_in_row, 60.0))
                    continue
                if "(409)" in err_msg or "quota" in err_msg.lower():
                    time.sleep(3.0)
                else:
                    provider.errors_in_row += 1
                    time.sleep(backoff_delay(provider.errors_in_row, cap=30.0))

            except Exception as e:
                provider.errors_in_row += 1
                log.warning("%s ошибка: %s", thread_name, e)
                time.sleep(backoff_delay(provider.errors_in_row))

            if regional_attempts % random.randint(5, 10) == 0:
                region = pick_region()


def _cb_wait(stop_event: threading.Event, cooldown: int) -> None:
    waited = 0
    while waited < cooldown and not stop_event.is_set():
        time.sleep(min(10, cooldown - waited))
        waited += 10


def _build_provider_from_cred(cred: dict[str, Any], proxy: Optional[dict[str, Any]]) -> Any:
    from workers.regcloud import RegcloudProvider
    from workers.selectel import SelectelProvider

    p = cred.get("provider")
    if p == "selectel":
        from workers.selectel import DEFAULT_SELECTEL_REGIONS

        extra: dict[str, Any] = {
            "project_id": cred.get("project_id", ""),
            "regions": cred.get("regions") or list(DEFAULT_SELECTEL_REGIONS),
            "api_base": cred.get("api_base") or "https://api.selectel.ru/vpc/resell/",
            "batch_size": int(cred.get("batch_size") or 3),
            "account_id": cred.get("account_id", ""),
            "username": cred.get("username", ""),
            "password": cred.get("password", ""),
            "project_name": cred.get("project_name", ""),
        }
        cfg = {"enabled": True, "token": "", "extra": extra}
        prov = SelectelProvider(cfg, proxy=proxy, instance_label="")
        prov.init_session()
        return prov
    if p == "regcloud":
        cookies = (cred.get("cookies") or cred.get("panel_token") or "").strip()
        login = (cred.get("login") or "").strip()
        pwd = cred.get("password") or ""
        token = cred.get("token") or ""
        if not token and login and pwd:
            token = "login_mode"
        cfg = {
            "enabled": True,
            "token": token or cookies or "login_mode",
            "extra": {
                "service_id": (cred.get("service_id") or "").strip(),
                "login": login,
                "password": pwd,
                "region": cred.get("region", "openstack-msk1"),
                "image": cred.get("image", "ubuntu-24-04-amd64"),
                "plan": cred.get("plan", "c1-m1-d10-hp"),
                "cookies": cookies,
            },
        }
        prov = RegcloudProvider(cfg, proxy=proxy)
        prov.init_session()
        return prov
    raise ValueError(f"unknown provider {p}")


def _cred_to_runtime_cfg(cred: dict[str, Any]) -> HuntRuntimeConfig:
    return HuntRuntimeConfig(
        rpm_limit=int(cred.get("rpm_limit") or 20),
        attempts_per_provider=int(cred.get("attempts_per_provider") or 150),
        circuit_breaker_threshold=int(cred.get("circuit_breaker_threshold") or 5),
        circuit_breaker_cooldown=int(cred.get("circuit_breaker_cooldown") or 120),
        connect_timeout=int(cred.get("connect_timeout") or 10),
        request_timeout=int(cred.get("request_timeout") or 30),
    )


async def _execute_rst_parallel_hunt(
    bot,
    uid: int,
    chat_id: int,
    provider_key: str,
    pairs: list[tuple[int, dict[str, Any]]],
    labels: list[tuple[int, str]],
) -> None:
    set_rst_active_hunt(uid, chat_id, provider_key, [p[0] for p in pairs])
    dash = HuntDashboard(bot, chat_id, labels)
    await dash.start()
    stop_event = threading.Event()
    loop = asyncio.get_running_loop()

    async def send_html(text: str) -> None:
        await bot.send_message(chat_id=chat_id, text=text, parse_mode=ParseMode.HTML)

    rt_cfg = HuntRuntimeConfig()
    if pairs:
        rt_cfg = _cred_to_runtime_cfg(pairs[0][1])

    threads: list[threading.Thread] = []

    def run_one(acc_id: int, cred: dict[str, Any], display_name: str) -> None:
        proxy = parse_proxy((cred.get("proxy") or "").strip())
        try:
            prov = _build_provider_from_cred(cred, proxy)
        except Exception as e:
            asyncio.run_coroutine_threadsafe(dash.set_error(acc_id, str(e)[:200]), loop)
            asyncio.run_coroutine_threadsafe(dash.push_update(), loop)
            return
        lim = AdaptiveRateLimiter(rpm_max=rt_cfg.rpm_limit)
        subnet_set = _subnet_set_for_cred(cred, provider_key)
        lab_esc = html.escape((display_name or "").strip() or f"#{acc_id}", quote=False)

        async def send_wrapped(msg: str) -> None:
            await send_html(f"🔹 <b>{lab_esc}</b>\n{msg}")

        def send_coro_factory(msg: str) -> Coroutine[Any, Any, None]:
            return send_wrapped(msg)

        try:
            provider_worker_sync(
                prov,
                subnet_set,
                rt_cfg,
                lim,
                stop_event,
                loop,
                send_coro_factory,
                cred,
                account_id=acc_id,
                dashboard=dash,
            )
        except Exception as e:
            log.exception("rst worker %s: %s", acc_id, e)
            asyncio.run_coroutine_threadsafe(dash.set_error(acc_id, str(e)[:200]), loop)
            asyncio.run_coroutine_threadsafe(dash.push_update(), loop)

    for acc_id, cred in pairs:
        dn = ""
        for aid, name in labels:
            if aid == acc_id:
                dn = name
                break
        th = threading.Thread(
            target=run_one,
            args=(acc_id, cred, dn),
            name=f"rst-{provider_key}-{acc_id}",
            daemon=True,
        )
        threads.append(th)
        th.start()

    try:
        while True:
            await asyncio.sleep(0.5)
            if all(not t.is_alive() for t in threads):
                break
    except asyncio.CancelledError:
        stop_event.set()
        for t in threads:
            t.join(timeout=15.0)
        raise
    finally:
        stop_event.set()
        for t in threads:
            t.join(timeout=5.0)
        await dash.close()

# appended to rst_core.py — не импортировать отдельно

import database as db
from workers.yandex_cloud import parse_targets_line, PRESET_ALL_OPERATORS, PRESET_ALMOST_ALL


def add_provider_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("Yandex Cloud", callback_data="add_provider_yc")],
            [InlineKeyboardButton("Selectel", callback_data="add_provider_sel")],
            [InlineKeyboardButton("RegCloud", callback_data="add_provider_rc")],
            [InlineKeyboardButton("◀ Назад", callback_data="app_main")],
        ]
    )


def my_accounts_root_keyboard(telegram_id: int) -> InlineKeyboardMarkup:
    ny = db.count_yandex_accounts(telegram_id)
    ns = count_rst_accounts(telegram_id, "selectel")
    nr = count_rst_accounts(telegram_id, "regcloud")
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton(f"Yandex Cloud ({ny})", callback_data="myacc_yc")],
            [InlineKeyboardButton(f"Selectel ({ns})", callback_data="myacc_sel")],
            [InlineKeyboardButton(f"RegCloud ({nr})", callback_data="myacc_rc")],
            [InlineKeyboardButton("◀ Назад", callback_data="app_main")],
        ]
    )


def rst_my_accounts_keyboard(telegram_id: int, provider: str) -> InlineKeyboardMarkup:
    title = {"selectel": "Selectel", "regcloud": "RegCloud"}[provider]
    rows = []
    for acc_id, display_name, summary in list_rst_accounts(telegram_id, provider):
        dn = (display_name or "").strip()
        label = dn if dn else f"{title} #{acc_id}"
        tail = summary[:28] + "…" if len(summary) > 28 else summary
        btn = f"{label} · {tail}" if tail else label
        if len(btn) > 64:
            btn = btn[:61] + "…"
        prefix = {"selectel": "rssi", "regcloud": "rsri"}[provider]
        rows.append([InlineKeyboardButton(btn, callback_data=f"{prefix}:{acc_id}")])
    rows.append([InlineKeyboardButton("◀ К провайдерам", callback_data="my_accounts")])
    return InlineKeyboardMarkup(rows)


def _rst_targets_keyboard(prefix: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("Все операторы (51.250.)", callback_data=f"{prefix}p:all")],
            [InlineKeyboardButton("Почти все (84.201.)", callback_data=f"{prefix}p:almost")],
            [InlineKeyboardButton("❌ Отмена", callback_data="rst_cancel")],
        ]
    )


def _clear_rst_add(ud: dict) -> None:
    for k in list(ud.keys()):
        if k.startswith("rst_"):
            ud.pop(k, None)


def _identity_selectel(d: dict) -> str:
    pid = (d.get("project_id") or "").strip()
    return hashlib.sha256(
        f"{pid}\n{d.get('account_id','')}\n{d.get('username','')}".encode()
    ).hexdigest()


def _identity_regcloud(d: dict) -> str:
    login = (d.get("login") or "").strip().lower()
    sid = (d.get("service_id") or "").strip()
    if login and sid:
        return hashlib.sha256(f"{login}\n{sid}".encode()).hexdigest()
    if login:
        return hashlib.sha256(login.encode()).hexdigest()
    return hashlib.sha256(
        f"{d.get('service_id','')}\n{(d.get('cookies') or '')[:200]}".encode()
    ).hexdigest()


def _summary_selectel(d: dict) -> str:
    pid = (d.get("project_id") or "").strip()
    short = pid[:12] + ("…" if len(pid) > 12 else "")
    return f"{short} · Keystone"


def _summary_regcloud(d: dict) -> str:
    em = (d.get("login") or "").strip()
    sid = (d.get("service_id") or "").strip()
    id_tail = f" · id …{sid[-6:]}" if len(sid) >= 6 else (f" · id {sid}" if sid else "")
    if em:
        base = (f"{em[:18]}…") if len(em) > 18 else em
        return f"{base} · OpenStack{id_tail}"
    return f"{sid or '—'} · {d.get('region', '')}"


def _selectel_cred_from_add_ud(ud: dict[str, Any]) -> dict[str, Any]:
    from workers.selectel import DEFAULT_SELECTEL_REGIONS

    return {
        "provider": "selectel",
        "project_id": (ud.get("rst_sel_project_id") or "").strip(),
        "regions": list(DEFAULT_SELECTEL_REGIONS),
        "batch_size": 3,
        "targets": ud.get("rst_sel_targets") or [],
        "custom_subnets": "",
        "proxy": "",
        "account_id": (ud.get("rst_sel_account_id") or "").strip(),
        "username": (ud.get("rst_sel_username") or "").strip(),
        "password": (ud.get("rst_sel_password") or "").strip(),
        "project_name": (ud.get("rst_sel_project_name") or "").strip(),
    }


def _regcloud_cred_from_add_ud(ud: dict[str, Any]) -> dict[str, Any]:
    return {
        "provider": "regcloud",
        "login": (ud.get("rst_rc_login") or "").strip(),
        "password": ud.get("rst_rc_password") or "",
        "cookies": "",
        "service_id": (ud.get("rst_rc_service_id") or "").strip(),
        "region": "openstack-msk1",
        "plan": "c1-m1-d10-hp",
        "image": "ubuntu-24-04-amd64",
        "targets": [],
        "custom_subnets": "",
        "proxy": "",
        "token": "login_mode",
    }


async def _finalize_rst_account(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    *,
    provider: str,
    cred: dict[str, Any],
    display_name: str,
) -> None:
    q = update.callback_query
    msg = update.message
    uid = update.effective_user.id if update.effective_user else None
    if not uid:
        return
    try:
        blob = encryption.encrypt_json(cred)
    except encryption.EncryptionError as e:
        err = html.escape(str(e))
        t = f"Ошибка шифрования: {err}"
        if q and q.message:
            await q.message.edit_text(t)
        elif msg:
            await msg.reply_text(t)
        return

    ik = {
        "selectel": _identity_selectel,
        "regcloud": _identity_regcloud,
    }[provider](cred)
    if rst_identity_taken(uid, provider, ik):
        err = "Такой аккаунт уже сохранён (те же ключи/проект)."
        if q and q.message:
            await q.message.edit_text(err)
        elif msg:
            await msg.reply_text(err)
        return

    summ = {
        "selectel": _summary_selectel,
        "regcloud": _summary_regcloud,
    }[provider](cred)
    insert_rst_account(uid, provider, blob, summ, display_name[:DISPLAY_NAME_MAX], ik)
    _clear_rst_add(context.user_data)
    if context.user_data.get("add_flow", "").startswith("rst_"):
        context.user_data.pop("add_flow", None)

    title = {"selectel": "Selectel", "regcloud": "RegCloud"}[provider]
    done = f"<b>{title}: аккаунт сохранён.</b>\n\n"
    if display_name.strip():
        done += f"Имя: <b>{html.escape(display_name.strip())}</b>\n"
    done += f"Кратко: <code>{html.escape(summ)}</code>"
    bm = _bot_mod()
    yc = importlib.import_module("workers.yandex_cloud")
    active = yc.active_hunt_count(uid) + active_rst_hunt_count(uid)
    if q and q.message:
        await q.message.edit_text(done, parse_mode=ParseMode.HTML)
        await context.bot.send_message(
            chat_id=q.message.chat_id,
            text=bm.build_app_main_text(active),
            parse_mode=ParseMode.HTML,
            reply_markup=bm.subscribed_main_keyboard(uid),
        )
    elif msg:
        await msg.reply_text(done, parse_mode=ParseMode.HTML)
        await context.bot.send_message(
            chat_id=msg.chat_id,
            text=bm.build_app_main_text(active),
            parse_mode=ParseMode.HTML,
            reply_markup=bm.subscribed_main_keyboard(uid),
        )


def _platform_menu_kb(provider: str, uid: int) -> InlineKeyboardMarkup:
    label = {"selectel": "Selectel", "regcloud": "RegCloud"}[provider]
    prefix = {"selectel": "rsel", "regcloud": "rrc"}[provider]
    accs = list_rst_accounts(uid, provider)
    rows = []
    if accs:
        rows.append(
            [
                InlineKeyboardButton(
                    f"▶️ Запустить все ({len(accs)})",
                    callback_data=f"{prefix}run_all",
                )
            ]
        )
    add_cb = {"selectel": "add_provider_sel", "regcloud": "add_provider_rc"}[provider]
    rows.append([InlineKeyboardButton(f"➕ Новый аккаунт {label}", callback_data=add_cb)])
    rows.append([InlineKeyboardButton("◀ Платформы", callback_data="run_script")])
    return InlineKeyboardMarkup(rows)


async def resume_stored_rst_hunts(bot) -> None:
    rows = list_rst_active_hunts()
    if not rows:
        return
    log.info("Восстановление RST-охот: %s", len(rows))
    await asyncio.sleep(0.5)
    for uid, chat_id, provider, acc_ids in rows:
        id_set = set(acc_ids)
        pairs: list[tuple[int, dict[str, Any]]] = []
        labels: list[tuple[int, str]] = []
        for acc_id, display_name, _ in list_rst_accounts(uid, provider):
            if acc_id not in id_set:
                continue
            blob = get_rst_account_blob(uid, acc_id)
            if not blob:
                continue
            try:
                cred = encryption.decrypt_json(blob)
            except encryption.EncryptionError:
                continue
            pairs.append((acc_id, cred))
            labels.append((acc_id, display_name or ""))
        if not pairs:
            clear_rst_active_hunt(uid)
            continue
        ok = schedule_rst_hunt(
            uid,
            lambda u=uid, c=chat_id, p=pairs, l=labels, pr=provider, b=bot: _execute_rst_parallel_hunt(
                b, u, c, pr, p, l
            ),
        )
        if not ok:
            log.warning("resume RST: user %s занят", uid)


async def handle_rst_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    if not update.effective_user or not update.message or not update.message.text:
        return False
    uid = update.effective_user.id
    if not _bot_mod().user_has_subscription(uid):
        return False
    flow = context.user_data.get("add_flow")
    text = update.message.text.strip()

    if flow == FLOW_RST_EDIT_RENAME:
        aid = context.user_data.get("rst_edit_account_id")
        prov = context.user_data.get("rst_edit_provider")
        if not isinstance(aid, int) or prov not in ("selectel", "regcloud"):
            context.user_data.pop("add_flow", None)
            return False
        name = text[:DISPLAY_NAME_MAX].strip()
        if not name:
            await update.message.reply_text("Введите непустое имя.")
            return True
        if not update_rst_display_name(uid, aid, name):
            await update.message.reply_text("Аккаунт не найден.")
            return True
        context.user_data.pop("add_flow", None)
        pfx = {"selectel": "rssi", "regcloud": "rsri"}[prov]
        await update.message.reply_text(
            f"Имя обновлено: <b>{html.escape(name)}</b>",
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀ К аккаунту", callback_data=f"{pfx}:{aid}")]]),
        )
        return True

    if flow == FLOW_RST_SEL_PROJECT:
        context.user_data["rst_sel_project_id"] = text.strip()
        context.user_data["add_flow"] = FLOW_RST_SEL_ACCOUNT
        await update.message.reply_text(
            "<b>Selectel — шаг 2/7</b>\n\n"
            "<b>Account ID</b> (номер аккаунта Selectel).\n"
            "Откройте <a href=\"https://my.selectel.ru/profile/profile\">Профиль</a> "
            "и скопируйте поле <b>«Номер аккаунта»</b> — его и пришлите одной строкой.",
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="rst_cancel")]]),
        )
        return True

    if flow == FLOW_RST_SEL_ACCOUNT:
        context.user_data["rst_sel_account_id"] = text.strip()
        context.user_data["add_flow"] = FLOW_RST_SEL_USER
        await update.message.reply_text(
            "<b>Selectel — шаг 3/7</b>\n\n"
            "<b>Имя сервисного пользователя</b> (Keystone), <b>не</b> логин от личного кабинета.\n"
            "1) Откройте <a href=\"https://my.selectel.ru/iam/service-users\">Сервисные пользователи</a>.\n"
            "2) Создайте пользователя и выдайте роль <b>member</b> на нужный VPC-проект.\n"
            "3) Пришлите сюда <b>username</b> этого сервисного пользователя (как в панели).",
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="rst_cancel")]]),
        )
        return True

    if flow == FLOW_RST_SEL_USER:
        context.user_data["rst_sel_username"] = text.strip()
        context.user_data["add_flow"] = FLOW_RST_SEL_PASS
        await update.message.reply_text(
            "<b>Selectel — шаг 4/7</b>\n\n"
            "Пароль сервисного пользователя. Сообщение будет удалено после отправки.",
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="rst_cancel")]]),
        )
        return True

    if flow == FLOW_RST_SEL_PASS:
        context.user_data["rst_sel_password"] = text
        try:
            await update.message.delete()
        except Exception:
            pass
        context.user_data["add_flow"] = FLOW_RST_SEL_PNAME
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text="<b>Selectel — шаг 5/7</b>\n\n"
            "<b>Название проекта</b> в IAM — как в списке на "
            "<a href=\"https://my.selectel.ru/iam/projects\">странице проектов</a> "
            "(нужно для scope Keystone вместе с Project ID).\n"
            "Если по документации Selectel достаточно scope только по домену — отправьте <code>-</code>.",
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="rst_cancel")]]),
        )
        return True

    if flow == FLOW_RST_SEL_PNAME:
        v = text.strip()
        context.user_data["rst_sel_project_name"] = "" if v == "-" else v
        context.user_data["add_flow"] = FLOW_RST_SEL_NAME
        await update.message.reply_text(
            "<b>Selectel — шаг 6/7</b>\n\n"
            "Придумайте <b>короткое имя</b> этого аккаунта в боте (до 40 символов) — как в списке «Мои аккаунты» и в сводке при поиске.",
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="rst_cancel")]]),
        )
        return True

    if flow == FLOW_RST_SEL_NAME:
        context.user_data["rst_sel_display_name"] = text[:DISPLAY_NAME_MAX].strip()
        if not context.user_data["rst_sel_display_name"]:
            await update.message.reply_text("Введите непустое имя.")
            return True
        context.user_data["add_flow"] = FLOW_RST_SEL_TARGETS
        await update.message.reply_text(
            "<b>Selectel — шаг 7/7</b>\n\n"
            "Укажите, какие адреса считать «пойманными».\n\n"
            "Можно отправить текстом через запятую:\n"
            "• префикс: <code>185.91.</code>\n"
            "• подсеть: <code>81.200.148.0/24</code>\n"
            "• диапазон: <code>81.200.148.0-81.200.151.255</code>\n\n"
            "Или выберите готовый вариант:",
            parse_mode=ParseMode.HTML,
            reply_markup=_rst_targets_keyboard("rsel"),
        )
        return True

    if flow == FLOW_RST_SEL_TARGETS:
        targets = parse_targets_line(text)
        if not targets:
            await update.message.reply_text("Укажите хотя бы один шаблон через запятую.")
            return True
        context.user_data["rst_sel_targets"] = targets
        cred = _selectel_cred_from_add_ud(context.user_data)
        dn = context.user_data.get("rst_sel_display_name", "")
        await _finalize_rst_account(update, context, provider="selectel", cred=cred, display_name=dn)
        return True

    if flow == FLOW_RST_RC_LOGIN:
        em = text.strip()
        if "@" not in em or "." not in em.split("@", 1)[-1]:
            await update.message.reply_text("Пришлите корректный email (логин аккаунта reg.ru).")
            return True
        context.user_data["rst_rc_login"] = em
        context.user_data["add_flow"] = FLOW_RST_RC_PASS
        await update.message.reply_text(
            "<b>RegCloud — шаг 2/3</b>\n\nПароль от этого аккаунта на reg.ru.\n\n"
            "<i>Регион и тариф по умолчанию (openstack-msk1, минимальный план). "
            "«Пойманные» IP — только из встроенного списка подсетей Reg.ru.</i>",
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="rst_cancel")]]),
        )
        return True

    if flow == FLOW_RST_RC_PASS:
        context.user_data["rst_rc_password"] = text.strip()
        context.user_data["add_flow"] = FLOW_RST_RC_SERVICE
        await update.message.reply_text(
            "<b>RegCloud — шаг 3/3</b>\n\n"
            "<b>OpenStack service-id</b> — число из заголовка <code>service-id</code> в запросах к API панели.\n\n"
            "Как взять:\n"
            "1) Откройте <a href=\"https://cloud.reg.ru\">cloud.reg.ru</a> в браузере и войдите.\n"
            "2) F12 → вкладка <b>Network</b> (Сеть).\n"
            "3) Обновите страницу или откройте раздел с серверами.\n"
            "4) Найдите запрос к <code>cloudvps-graphql-server.svc.reg.ru</code>.\n"
            "5) В <b>Request Headers</b> скопируйте значение заголовка <code>service-id</code> "
            "(только число, одной строкой).\n\n"
            "Пришлите это число сюда.",
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="rst_cancel")]]),
        )
        return True

    if flow == FLOW_RST_RC_SERVICE:
        raw = text.strip()
        sid = "".join(c for c in raw if c.isdigit())
        if not sid or len(sid) < 4:
            await update.message.reply_text(
                "Нужен числовой <b>service-id</b> (обычно от 4 цифр). "
                "Скопируйте значение заголовка без лишнего текста.",
                parse_mode=ParseMode.HTML,
            )
            return True
        context.user_data["rst_rc_service_id"] = sid
        em = (context.user_data.get("rst_rc_login") or "").strip()
        dn = (em.split("@", 1)[0] if em else "reg.cloud")[:DISPLAY_NAME_MAX]
        cred = _regcloud_cred_from_add_ud(context.user_data)
        await _finalize_rst_account(
            update,
            context,
            provider="regcloud",
            cred=cred,
            display_name=dn,
        )
        return True

    return False


async def handle_rst_callback(update: Update, context: ContextTypes.DEFAULT_TYPE, data: str) -> bool:
    q = update.callback_query
    if not q or not q.message or not update.effective_user:
        return False
    uid = update.effective_user.id
    bm = _bot_mod()
    if not bm.user_has_subscription(uid):
        await q.answer("Нужна подписка.", show_alert=True)
        return True

    if data == "rst_list_noop":
        await q.answer("Сначала остановите поиск.", show_alert=True)
        return True

    if data == "rst_cancel":
        await q.answer()
        _clear_rst_add(context.user_data)
        context.user_data.pop("add_flow", None)
        yc = importlib.import_module("workers.yandex_cloud")
        await q.message.edit_text(
            bm.build_app_main_text(yc.active_hunt_count(uid) + active_rst_hunt_count(uid)),
            parse_mode=ParseMode.HTML,
            reply_markup=bm.subscribed_main_keyboard(uid),
        )
        return True

    if data == "add_provider_sel":
        if count_rst_accounts(uid, "selectel") >= MAX_RST_ACCOUNTS_PER_PROVIDER:
            await q.answer("Лимит аккаунтов Selectel.", show_alert=True)
            return True
        await q.answer()
        context.user_data["add_flow"] = FLOW_RST_SEL_PROJECT
        await q.message.edit_text(
            "<b>Selectel — шаг 1/7</b>\n\n"
            "Отправьте свой <b>Project ID</b> (UUID VPC-проекта) — на странице "
            "<a href=\"https://my.selectel.ru/iam/projects\">Проекты IAM</a>.",
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="rst_cancel")]]),
        )
        return True

    if data == "add_provider_rc":
        if count_rst_accounts(uid, "regcloud") >= MAX_RST_ACCOUNTS_PER_PROVIDER:
            await q.answer("Лимит RegCloud.", show_alert=True)
            return True
        await q.answer()
        context.user_data["add_flow"] = FLOW_RST_RC_LOGIN
        await q.message.edit_text(
            "<b>RegCloud (cloud.reg.ru) — шаг 1/3</b>\n\n"
            "Пришлите <b>email</b> (логин), которым вы заходите в "
            "<a href=\"https://cloud.reg.ru\">cloud.reg.ru</a>.",
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="rst_cancel")]]),
        )
        return True

    if data in ("rselp:all", "rselp:almost"):
        await q.answer()
        context.user_data["rst_sel_targets"] = (
            [PRESET_ALL_OPERATORS] if data.endswith("p:all") else [PRESET_ALMOST_ALL]
        )
        cred = _selectel_cred_from_add_ud(context.user_data)
        await _finalize_rst_account(
            update,
            context,
            provider="selectel",
            cred=cred,
            display_name=context.user_data.get("rst_sel_display_name", ""),
        )
        return True

    if data in ("myacc_sel", "myacc_rc"):
        await q.answer()
        pr = {"myacc_sel": "selectel", "myacc_rc": "regcloud"}[data]
        title = {"selectel": "Selectel", "regcloud": "RegCloud"}[pr]
        n = count_rst_accounts(uid, pr)
        await q.message.edit_text(
            f"<b>{title}</b> ({n})\n\nВыберите аккаунт:",
            parse_mode=ParseMode.HTML,
            reply_markup=rst_my_accounts_keyboard(uid, pr),
        )
        return True

    for pfx, pr in (("rssi", "selectel"), ("rsri", "regcloud")):
        if data.startswith(f"{pfx}:"):
            try:
                aid = int(data.split(":", 1)[1])
            except ValueError:
                await q.answer("Ошибка.", show_alert=True)
                return True
            blob = get_rst_account_blob(uid, aid)
            if not blob:
                await q.answer("Не найдено.", show_alert=True)
                return True
            try:
                c = encryption.decrypt_json(blob)
            except encryption.EncryptionError:
                await q.answer("Ошибка чтения.", show_alert=True)
                return True
            hunt_on = active_rst_hunt_count(uid) > 0 or importlib.import_module(
                "workers.yandex_cloud"
            ).active_hunt_count(uid) > 0
            dn = ""
            for i, dname, sm in list_rst_accounts(uid, pr):
                if i == aid:
                    dn = dname
                    break
            title = html.escape(dn.strip() or f"{pr} #{aid}", quote=False)
            tg = html.escape(", ".join(str(x) for x in (c.get("targets") or [])[:10]), quote=False)
            extra = (
                "\n\n<i>Смена данных и удаление — после остановки поиска.</i>" if hunt_on else ""
            )
            await q.answer()
            await q.message.edit_text(
                f"<b>{title}</b>\n\n"
                f"Шаблоны: <code>{tg}</code>"
                f"{extra}",
                parse_mode=ParseMode.HTML,
                reply_markup=_rst_account_actions_kb(aid, pr, hunt_on),
            )
            return True

    for pfx, pr in (("rssi", "selectel"), ("rsri", "regcloud")):
        if data.startswith(f"{pfx}ren:"):
            aid = int(data.split(":")[1])
            await q.answer()
            context.user_data["add_flow"] = FLOW_RST_EDIT_RENAME
            context.user_data["rst_edit_account_id"] = aid
            context.user_data["rst_edit_provider"] = pr
            await q.message.edit_text(
                "Новое имя (до 40 символов):",
                reply_markup=InlineKeyboardMarkup(
                    [[InlineKeyboardButton("◀ Отмена", callback_data=f"{pfx}:{aid}")]]
                ),
            )
            return True
        if data.startswith(f"{pfx}del:"):
            aid = int(data.split(":")[1])
            if active_rst_hunt_count(uid) > 0 or importlib.import_module(
                "workers.yandex_cloud"
            ).active_hunt_count(uid) > 0:
                await q.answer("Сначала остановите поиск.", show_alert=True)
                return True
            await q.answer()
            await q.message.edit_text(
                "Удалить аккаунт?",
                reply_markup=InlineKeyboardMarkup(
                    [
                        [InlineKeyboardButton("Да", callback_data=f"{pfx}dok:{aid}")],
                        [InlineKeyboardButton("Нет", callback_data=f"{pfx}:{aid}")],
                    ]
                ),
            )
            return True
        if data.startswith(f"{pfx}dok:"):
            aid = int(data.split(":")[1])
            if active_rst_hunt_count(uid) > 0:
                await q.answer("Сначала остановите поиск.", show_alert=True)
                return True
            delete_rst_account(uid, aid)
            await q.answer("Удалено.")
            await q.message.edit_text(
                f"Аккаунт удалён. Осталось: {count_rst_accounts(uid, pr)}",
                reply_markup=rst_my_accounts_keyboard(uid, pr),
            )
            return True

    if data == "plat_selectel":
        await q.answer()
        await q.message.edit_text(
            "<b>Selectel</b>\n\nПараллельный перебор floating IP по сохранённым аккаунтам.",
            parse_mode=ParseMode.HTML,
            reply_markup=_platform_menu_kb("selectel", uid),
        )
        return True

    if data == "plat_regcloud":
        await q.answer()
        await q.message.edit_text(
            "<b>RegCloud</b>\n\nСоздание серверов с floating IP через GraphQL панели (как в ip_hunter).",
            parse_mode=ParseMode.HTML,
            reply_markup=_platform_menu_kb("regcloud", uid),
        )
        return True

    for prefix, pr in (("rsel", "selectel"), ("rrc", "regcloud")):
        if data == f"{prefix}run_all":
            yc = importlib.import_module("workers.yandex_cloud")
            if yc.active_hunt_count(uid) > 0 or active_rst_hunt_count(uid) > 0:
                await q.answer("Уже идёт поиск. Остановите скрипт.", show_alert=True)
                return True
            pairs: list[tuple[int, dict[str, Any]]] = []
            labels: list[tuple[int, str]] = []
            for acc_id, display_name, _ in list_rst_accounts(uid, pr):
                blob = get_rst_account_blob(uid, acc_id)
                if not blob:
                    continue
                try:
                    pairs.append((acc_id, encryption.decrypt_json(blob)))
                    labels.append((acc_id, display_name or ""))
                except encryption.EncryptionError:
                    continue
            if not pairs:
                await q.answer("Нет аккаунтов.", show_alert=True)
                return True
            chat_id = q.message.chat_id
            ok = schedule_rst_hunt(
                uid,
                lambda: _execute_rst_parallel_hunt(context.bot, uid, chat_id, pr, pairs, labels),
            )
            await q.message.edit_text(
                bm.build_app_main_text(yc.active_hunt_count(uid) + active_rst_hunt_count(uid)),
                parse_mode=ParseMode.HTML,
                reply_markup=bm.subscribed_main_keyboard(uid),
            )
            if ok:
                await q.answer()
            else:
                await q.answer("Поиск уже запущен.", show_alert=True)
            return True

    if data == "myacc_yc":
        await q.answer()
        yf = importlib.import_module("yandex_flow")
        n = db.count_yandex_accounts(uid)
        await q.message.edit_text(
            f"<b>Yandex Cloud</b> ({n})\n\nВыберите аккаунт:",
            parse_mode=ParseMode.HTML,
            reply_markup=yf.my_accounts_keyboard(uid),
        )
        return True

    return False


def _rst_account_actions_kb(acc_id: int, provider: str, hunt_on: bool) -> InlineKeyboardMarkup:
    pfx = {"selectel": "rssi", "regcloud": "rsri"}[provider]
    back = {"selectel": "myacc_sel", "regcloud": "myacc_rc"}[provider]
    rows = [[InlineKeyboardButton("✏️ Переименовать", callback_data=f"{pfx}ren:{acc_id}")]]
    if hunt_on:
        rows.append(
            [InlineKeyboardButton("🗑 Удалить (нужен стоп)", callback_data="rst_list_noop")],
        )
    else:
        rows.append([InlineKeyboardButton("🗑 Удалить", callback_data=f"{pfx}del:{acc_id}")])
    rows.append([InlineKeyboardButton("◀ К списку", callback_data=back)])
    return InlineKeyboardMarkup(rows)
