"""
Yandex Cloud: IAM по OAuth, список каталогов, создание/удаление внешнего IPv4 (аналог yc vpc address).
Поиск IP по префиксам / CIDR / диапазонам.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import random
import time
import uuid
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Coroutine

import httpx

import database as db

log = logging.getLogger(__name__)

YC_OAUTH_AUTHORIZE_URL = (
    "https://oauth.yandex.ru/authorize?"
    "response_type=token&client_id=1a6990aa636648e9b2ef855fa7bec2fb"
)

IAM_TOKEN_URL = "https://iam.api.cloud.yandex.net/iam/v1/tokens"
RM_CLOUDS_URL = "https://resource-manager.api.cloud.yandex.net/resource-manager/v1/clouds"
RM_FOLDERS_URL = "https://resource-manager.api.cloud.yandex.net/resource-manager/v1/folders"
VPC_ADDRESSES_URL = "https://vpc.api.cloud.yandex.net/vpc/v1/addresses"
OPERATION_URL = "https://operation.api.cloud.yandex.net/operations"

ZONES = ("ru-central1-a", "ru-central1-b", "ru-central1-d", "ru-central1-e")

PRESET_ALL_OPERATORS = "51.250."
PRESET_ALMOST_ALL = "84.201."

DEFAULT_TIMEOUT = 60.0
POLL_INTERVAL = 0.5
POLL_MAX_WAIT = 120.0

# Пауза между итерациями охоты: после удаления адреса, при ошибке API, на «защищённом» IP.
HUNT_LOOP_PAUSE_SEC = 3.0

# VPC create/delete при 429 (rate limit): повторы и пауза.
VPC_RATE_LIMIT_MAX_RETRIES = 10
VPC_RATE_LIMIT_BASE_SEC = 2.0
VPC_RATE_LIMIT_CAP_SEC = 90.0

RUNNING_HUNTS: dict[int, asyncio.Task] = {}

# Макс. длина JSON в логах (полный ответ API урезается).
_LOG_JSON_MAX = 12000


def _log_payload(label: str, obj: Any) -> None:
    """Текст или JSON в консоль (без IAM)."""
    if isinstance(obj, str):
        s = obj
    else:
        try:
            s = json.dumps(obj, ensure_ascii=False, default=str)
        except TypeError:
            s = repr(obj)
    if len(s) > _LOG_JSON_MAX:
        s = s[:_LOG_JSON_MAX] + "…(truncated)"
    log.info("%s %s", label, s)


class YandexCloudError(Exception):
    def __init__(self, message: str, *, status_code: int | None = None, details: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.details = details


def is_quota_error(message: str) -> bool:
    m = (message or "").lower()
    return "quota" in m or "квот" in m or "limit" in m


def _retry_after_seconds(response: httpx.Response) -> float | None:
    """Секунды ожидания из Retry-After (число секунд или HTTP-date)."""
    raw = (response.headers.get("Retry-After") or "").strip()
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        pass
    try:
        dt = parsedate_to_datetime(raw)
        if dt is not None:
            return max(0.0, dt.timestamp() - time.time())
    except (TypeError, ValueError, OSError):
        pass
    return None


async def _sleep_rate_limit(attempt: int, response: httpx.Response | None) -> None:
    ra = _retry_after_seconds(response) if response is not None else None
    backoff = min(
        VPC_RATE_LIMIT_CAP_SEC,
        VPC_RATE_LIMIT_BASE_SEC * (2**attempt),
    )
    delay = max(backoff, ra or 0.0) * random.uniform(0.85, 1.15)
    delay = min(delay, VPC_RATE_LIMIT_CAP_SEC * 1.5)
    log.warning(
        "YC VPC: rate limit / перегрузка → пауза %.1f с (попытка %s/%s)",
        delay,
        attempt + 1,
        VPC_RATE_LIMIT_MAX_RETRIES,
    )
    await asyncio.sleep(delay)


def ip_matches_pattern(ip: str, pattern: str) -> bool:
    """Префикс (51.250.), CIDR (51.250.0.0/17), диапазон (51.250.0.0-51.250.255.255)."""
    p = pattern.strip()
    if not p:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if "/" in p:
        try:
            net = ipaddress.ip_network(p, strict=False)
            return addr in net
        except ValueError:
            return False
    left_dash = p.find("-")
    if left_dash > 0:
        left, right = p[:left_dash].strip(), p[left_dash + 1 :].strip()
        if left.count(".") == 3 and right.count(".") == 3:
            try:
                lo = ipaddress.ip_address(left)
                hi = ipaddress.ip_address(right)
                return lo <= addr <= hi
            except ValueError:
                pass
    pref = p if p.endswith(".") else p
    if pref.replace(".", "").isdigit() or all(c in "0123456789." for c in pref):
        if not pref.endswith("."):
            pref = pref + "."
        return ip.startswith(pref)
    return ip.startswith(p)


def ip_matches_any(ip: str, patterns: list[str]) -> bool:
    return any(ip_matches_pattern(ip, x) for x in patterns if x.strip())


async def exchange_oauth_for_iam(oauth_token: str) -> str:
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
        r = await client.post(IAM_TOKEN_URL, json={"yandexPassportOauthToken": oauth_token.strip()})
        if r.status_code >= 400:
            raise YandexCloudError(
                "Не удалось обменять OAuth на IAM (проверьте токен и срок действия).",
                status_code=r.status_code,
                details=r.text,
            )
        data = r.json()
    token = data.get("iamToken") or data.get("iam_token")
    if not token:
        raise YandexCloudError("В ответе IAM нет iamToken", details=data)
    return str(token)


def _auth_headers(iam_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {iam_token}"}


async def list_all_folders(iam_token: str) -> list[dict[str, str]]:
    headers = _auth_headers(iam_token)
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
        cr = await client.get(RM_CLOUDS_URL, headers=headers)
        if cr.status_code >= 400:
            raise YandexCloudError("Не удалось получить список облаков", status_code=cr.status_code, details=cr.text)
        clouds = cr.json().get("clouds") or []
        out: list[dict[str, str]] = []
        for c in clouds:
            cid = c.get("id")
            if not cid:
                continue
            cname = c.get("name") or cid
            fr = await client.get(RM_FOLDERS_URL, params={"cloudId": cid}, headers=headers)
            if fr.status_code >= 400:
                log.warning("folders list failed cloud=%s: %s", cid, fr.text)
                continue
            for f in fr.json().get("folders") or []:
                fid = f.get("id")
                if not fid:
                    continue
                fname = f.get("name") or fid
                out.append(
                    {
                        "id": fid,
                        "name": fname,
                        "cloud_name": cname,
                    }
                )
    return out


async def _wait_operation(client: httpx.AsyncClient, iam_token: str, operation: dict[str, Any]) -> dict[str, Any]:
    op_id = operation.get("id")
    if not op_id:
        if operation.get("done") and operation.get("response"):
            return operation
        raise YandexCloudError("Операция без id", details=operation)
    if operation.get("done"):
        if operation.get("error"):
            err = operation["error"]
            raise YandexCloudError(err.get("message", str(err)), details=err)
        return operation
    loop = asyncio.get_running_loop()
    deadline = loop.time() + POLL_MAX_WAIT
    headers = _auth_headers(iam_token)
    while loop.time() < deadline:
        await asyncio.sleep(POLL_INTERVAL)
        r = await client.get(f"{OPERATION_URL}/{op_id}", headers=headers)
        if r.status_code >= 400:
            raise YandexCloudError("Ошибка опроса операции", status_code=r.status_code, details=r.text)
        op = r.json()
        if op.get("done"):
            if op.get("error"):
                err = op["error"]
                raise YandexCloudError(err.get("message", str(err)), details=err)
            return op
    raise YandexCloudError("Таймаут ожидания операции Yandex Cloud")


async def _fetch_address_ip(client: httpx.AsyncClient, iam_token: str, address_id: str) -> str:
    r = await client.get(f"{VPC_ADDRESSES_URL}/{address_id}", headers=_auth_headers(iam_token))
    if r.status_code >= 400:
        return ""
    body = r.json()
    ext = body.get("externalIpv4Address") or body.get("external_ipv4_address") or {}
    return str(ext.get("address") or "")


async def create_external_address(iam_token: str, folder_id: str, zone_id: str) -> tuple[str, str]:
    """Создаёт внешний IPv4. Возвращает (address_id, ip)."""
    # Имя без «iphunder» — иначе возможны блокировки со стороны Yandex Cloud.
    body = {
        "folderId": folder_id,
        "name": f"a-{uuid.uuid4().hex[:20]}",
        "externalIpv4AddressSpec": {"zoneId": zone_id},
    }
    headers = {**_auth_headers(iam_token), "Content-Type": "application/json"}
    log.info(
        "YC VPC create START folder_id=%s zone_id=%s address_name=%s url=%s",
        folder_id,
        zone_id,
        body["name"],
        VPC_ADDRESSES_URL,
    )
    _log_payload("YC VPC create request_body", body)
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
        r: httpx.Response | None = None
        for attempt in range(VPC_RATE_LIMIT_MAX_RETRIES):
            r = await client.post(VPC_ADDRESSES_URL, json=body, headers=headers)
            log.info(
                "YC VPC create POST_RESPONSE status=%s folder_id=%s attempt=%s",
                r.status_code,
                folder_id,
                attempt + 1,
            )
            if r.status_code == 429 or r.status_code == 503:
                _log_payload("YC VPC create POST_RATE_LIMIT_BODY", r.text[:_LOG_JSON_MAX])
                if attempt + 1 >= VPC_RATE_LIMIT_MAX_RETRIES:
                    break
                await _sleep_rate_limit(attempt, r)
                continue
            if r.status_code >= 400:
                _log_payload("YC VPC create POST_ERROR_BODY", r.text[:_LOG_JSON_MAX])
                log.error(
                    "YC VPC create FAILED folder_id=%s zone_id=%s status=%s",
                    folder_id,
                    zone_id,
                    r.status_code,
                )
                raise YandexCloudError(
                    f"create address: {r.text[:500]}",
                    status_code=r.status_code,
                    details=r.text,
                )
            break

        assert r is not None
        if r.status_code >= 400:
            _log_payload("YC VPC create POST_ERROR_BODY", r.text[:_LOG_JSON_MAX])
            log.error(
                "YC VPC create FAILED after retries folder_id=%s zone_id=%s status=%s",
                folder_id,
                zone_id,
                r.status_code,
            )
            raise YandexCloudError(
                f"create address (rate limit): {r.text[:500]}",
                status_code=r.status_code,
                details=r.text,
            )
        try:
            op = r.json()
        except Exception as e:
            log.error("YC VPC create POST body not JSON: %s raw=%r", e, r.text[:2000])
            raise
        _log_payload("YC VPC create operation_initial", op)
        op = await _wait_operation(client, iam_token, op)
        _log_payload("YC VPC create operation_done", op)
        resp = op.get("response") or {}
        addr_id = resp.get("id") or (op.get("metadata") or {}).get("addressId")
        ext = resp.get("externalIpv4Address") or resp.get("external_ipv4_address") or {}
        ip = ext.get("address") or ""
        if addr_id and not ip:
            log.info(
                "YC VPC create FETCH_IP address_id=%s (empty in operation response)",
                addr_id,
            )
            ip = await _fetch_address_ip(client, iam_token, str(addr_id))
            log.info("YC VPC create FETCH_IP result address_id=%s ip=%r", addr_id, ip)
        if not addr_id or not ip:
            log.error(
                "YC VPC create INCOMPLETE folder_id=%s zone_id=%s addr_id=%r ip=%r resp_keys=%s",
                folder_id,
                zone_id,
                addr_id,
                ip,
                list(resp.keys()) if isinstance(resp, dict) else type(resp),
            )
            raise YandexCloudError("В ответе нет id или IP адреса", details=resp)
        log.info(
            "YC VPC create OK folder_id=%s zone_id=%s address_id=%s ip=%s",
            folder_id,
            zone_id,
            addr_id,
            ip,
        )
        return str(addr_id), str(ip)


async def delete_address(iam_token: str, address_id: str) -> None:
    url = f"{VPC_ADDRESSES_URL}/{address_id}"
    headers = _auth_headers(iam_token)
    log.info("YC VPC delete START address_id=%s url=%s", address_id, url)
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
        r: httpx.Response | None = None
        for attempt in range(VPC_RATE_LIMIT_MAX_RETRIES):
            r = await client.delete(url, headers=headers)
            log.info(
                "YC VPC delete DELETE_RESPONSE address_id=%s status=%s attempt=%s",
                address_id,
                r.status_code,
                attempt + 1,
            )
            if r.status_code == 429 or r.status_code == 503:
                _log_payload("YC VPC delete DELETE_RATE_LIMIT_BODY", r.text[:_LOG_JSON_MAX])
                if attempt + 1 >= VPC_RATE_LIMIT_MAX_RETRIES:
                    break
                await _sleep_rate_limit(attempt, r)
                continue
            if r.status_code >= 400:
                _log_payload("YC VPC delete DELETE_ERROR_BODY", r.text[:_LOG_JSON_MAX])
                log.error(
                    "YC VPC delete FAILED address_id=%s status=%s",
                    address_id,
                    r.status_code,
                )
                raise YandexCloudError(
                    f"delete address: {r.text[:300]}",
                    status_code=r.status_code,
                    details=r.text,
                )
            break

        assert r is not None
        if r.status_code >= 400:
            _log_payload("YC VPC delete DELETE_ERROR_BODY", r.text[:_LOG_JSON_MAX])
            log.error(
                "YC VPC delete FAILED after retries address_id=%s status=%s",
                address_id,
                r.status_code,
            )
            raise YandexCloudError(
                f"delete address (rate limit): {r.text[:300]}",
                status_code=r.status_code,
                details=r.text,
            )
        try:
            op = r.json()
        except Exception as e:
            log.error("YC VPC delete DELETE body not JSON: %s raw=%r", e, r.text[:2000])
            raise
        _log_payload("YC VPC delete operation_initial", op)
        op = await _wait_operation(client, iam_token, op)
        _log_payload("YC VPC delete operation_done", op)
        log.info("YC VPC delete OK address_id=%s", address_id)


def _running_hunt_task(user_id: int) -> asyncio.Task | None:
    t = RUNNING_HUNTS.get(user_id)
    if t is None:
        return None
    if t.done():
        RUNNING_HUNTS.pop(user_id, None)
        return None
    return t


def active_hunt_count(user_id: int) -> int:
    """Задача в памяти или запись в БД (охота до resume после перезапуска)."""
    if _running_hunt_task(user_id) is not None:
        return 1
    if db.get_yandex_active_hunt(user_id) is not None:
        return 1
    return 0


def cancel_hunt(user_id: int) -> bool:
    """Останавливает asyncio-задачу и снимает сохранённую охоту с диска."""
    had_db = db.get_yandex_active_hunt(user_id) is not None
    db.clear_yandex_active_hunt(user_id)
    t = RUNNING_HUNTS.get(user_id)
    if t is None or t.done():
        RUNNING_HUNTS.pop(user_id, None)
        return had_db
    t.cancel()
    return True


def schedule_hunt(
    user_id: int,
    coro_factory: Callable[[], Coroutine[Any, Any, None]],
) -> bool:
    """Запускает одну активную охоту на пользователя. False, если уже есть asyncio-задача."""
    if _running_hunt_task(user_id) is not None:
        return False

    async def _wrap() -> None:
        try:
            await coro_factory()
        finally:
            RUNNING_HUNTS.pop(user_id, None)
            db.clear_yandex_active_hunt(user_id)

    t = asyncio.create_task(_wrap())
    RUNNING_HUNTS[user_id] = t
    return True


async def run_ip_hunt(
    *,
    chat_id: int,
    oauth_token: str,
    folder_id: str,
    zone_id: str,
    targets: list[str],
    important_ip: str | None,
    send_message: Callable[[str], Coroutine[Any, Any, Any]],
    notify_on_cancel: bool = True,
    dashboard: Any = None,
    account_id: int | None = None,
) -> None:
    """
    Цикл как в zalupa.sh: создать IP → проверить шаблоны → удалить или бинго.
    При переданном dashboard счётчики и квота отражаются в одном сообщении (см. HuntDashboard).
    """
    count = 0
    important = (important_ip or "").strip()
    use_dash = dashboard is not None and account_id is not None
    try:
        while True:
            count += 1
            if use_dash:
                await dashboard.inc_attempt(account_id)
            try:
                iam = await exchange_oauth_for_iam(oauth_token)
                addr_id, ip = await create_external_address(iam, folder_id, zone_id)
            except YandexCloudError as e:
                if is_quota_error(str(e)):
                    if use_dash:
                        await dashboard.set_error(account_id, "Квота полна!")
                        await dashboard.push_update()
                    else:
                        await send_message(
                            "⛔ <b>Квота адресов исчерпана.</b>\n"
                            "Удалите лишние внешние IP в консоли Yandex Cloud и запустите снова.",
                        )
                    return
                if use_dash:
                    log.warning("yc hunt acc=%s iter=%s: %s", account_id, count, e)
                else:
                    await send_message(f"⚠️ Ошибка API (попытка {count}): {html_escape(str(e)[:400])}")
                await asyncio.sleep(HUNT_LOOP_PAUSE_SEC)
                continue
            if important and ip == important:
                if not use_dash:
                    await send_message(
                        f"🛡 Защищённый IP (как в скрипте): <code>{html_escape(ip)}</code> — не трогаем, следующая итерация."
                    )
                await asyncio.sleep(HUNT_LOOP_PAUSE_SEC)
                continue
            if ip_matches_any(ip, targets):
                if use_dash:
                    await dashboard.inc_hit(account_id)
                    await dashboard.push_update()
                await send_message(
                    f"🎉 <b>Поймано!</b>\nIP: <code>{html_escape(ip)}</code>\nID: <code>{html_escape(addr_id)}</code>",
                )
                return
            try:
                await delete_address(iam, addr_id)
            except YandexCloudError as de:
                if not use_dash:
                    await send_message(
                        f"⚠️ Не удалось удалить <code>{html_escape(ip)}</code>: {html_escape(str(de)[:200])}"
                    )
                else:
                    log.warning("yc delete failed acc=%s ip=%s: %s", account_id, ip, de)
            if count % 5 == 0 and not use_dash:
                await send_message(
                    f"… итерация {count}, последний IP: <code>{html_escape(ip)}</code> — не подошёл, удалён."
                )
            await asyncio.sleep(HUNT_LOOP_PAUSE_SEC)
    except asyncio.CancelledError:
        if notify_on_cancel:
            try:
                await send_message("⏹ Поиск остановлен.")
            except Exception:
                log.debug("send_message after cancel failed", exc_info=True)
        raise


async def run_all_yandex_hunts(
    *,
    chat_id: int,
    accounts: list[tuple[int, dict[str, Any]]],
    send_message: Callable[[str], Coroutine[Any, Any, Any]],
    dashboard: Any = None,
) -> None:
    """Параллельный поиск по всем аккаунтам; каждый цикл завершается при «бинго» или квоте."""
    if not accounts:
        return

    async def one(acc_id: int, creds: dict[str, Any]) -> None:
        oauth = creds["oauth"]
        folder_id = creds["folder_id"]
        zone = creds["zone"]
        targets = list(creds.get("targets") or [])
        important = (creds.get("important_ip") or "").strip() or None

        async def send_wrapped(t: str) -> None:
            await send_message(f"🔹 <b>Аккаунт #{acc_id}</b>\n{t}")

        await run_ip_hunt(
            chat_id=chat_id,
            oauth_token=oauth,
            folder_id=folder_id,
            zone_id=zone,
            targets=targets,
            important_ip=important,
            send_message=send_message if dashboard is not None else send_wrapped,
            notify_on_cancel=False,
            dashboard=dashboard,
            account_id=acc_id if dashboard is not None else None,
        )

    tasks = [asyncio.create_task(one(aid, c)) for aid, c in accounts]
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise


def html_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def parse_targets_line(line: str) -> list[str]:
    parts = [x.strip() for x in line.split(",") if x.strip()]
    return parts
