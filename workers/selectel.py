"""Selectel VPC Resell: Floating IP через API (логика из ip_hunter_v6)."""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any, Optional

import requests
from requests.adapters import HTTPAdapter

try:
    from urllib3.util.retry import Retry
except ImportError:
    Retry = None  # type: ignore[misc, assignment]

import rst_core

log = logging.getLogger(__name__)

SELECTEL_SUBNETS = (
    "5.101.50.0/23,5.159.103.0/24,5.178.85.0/24,5.188.56.0/24,5.188.112.0/22,"
    "5.188.118.0/23,5.188.158.0/23,5.189.239.0/24,31.41.157.0/24,31.172.128.0/24,"
    "31.184.211.0/24,31.184.215.0/24,31.184.218.0/24,31.184.253.0/24,31.184.254.0/24,"
    "37.9.4.0/24,37.9.13.0/24,45.80.129.0/24,78.24.181.0/24,80.93.187.0/24,"
    "80.249.145.0/24,80.249.146.0/23,81.163.22.0/23,81.177.221.0/24,82.202.192.0/19,"
    "82.202.224.0/22,82.202.228.0/24,82.202.230.0/23,82.202.233.0/24,82.202.234.0/23,"
    "82.202.236.0/22,82.202.240.0/20,84.38.181.0/24,84.38.182.0/24,84.38.185.0/24,"
    "87.228.101.0/24,90.156.158.0/24,91.236.197.0/24,178.72.178.0/24,185.91.53.0/24,"
    "185.91.54.0/24,188.68.218.0/24"
)


DEFAULT_SELECTEL_REGIONS = ("ru-1", "ru-2", "ru-3")


def _floatingip_resource_id(fip: dict) -> str:
    """ID для DELETE /v2/floatingips/{id} — разные версии API могут отдавать поле по-разному."""
    rid = fip.get("id") or fip.get("floatingip_id") or fip.get("uuid") or ""
    if rid is not None and not isinstance(rid, str):
        rid = str(rid)
    nested = fip.get("floatingip")
    if (not rid) and isinstance(nested, dict):
        rid = nested.get("id") or nested.get("floatingip_id") or nested.get("uuid") or ""
        if rid is not None and not isinstance(rid, str):
            rid = str(rid)
    return (rid or "").strip()


class KeystoneTokenManager:
    KEYSTONE_URL = "https://cloud.api.selcloud.ru/identity/v3/auth/tokens"
    RESELL_TOKENS_URL = "https://api.selectel.ru/vpc/resell/v2/tokens"

    def __init__(
        self,
        account_id: str = "",
        username: str = "",
        password: str = "",
        api_key: str = "",
        project_name: str = "",
        project_id: str = "",
        proxy: Optional[dict[str, Any]] = None,
    ):
        self.account_id = account_id
        self.username = username
        self.password = password
        self.api_key = api_key
        self.project_name = project_name
        self.project_id = project_id
        self._proxy = proxy
        self._token: str = ""
        self._token_expires: Optional[float] = None
        self._lock = threading.Lock()

        if username and password and account_id:
            self._mode = "keystone"
        elif api_key and account_id:
            self._mode = "resell"
        else:
            self._mode = "static"

    @property
    def mode(self) -> str:
        return self._mode

    def get_token(self, force_refresh: bool = False) -> str:
        if self._mode == "static":
            return self._token

        with self._lock:
            need_refresh = (
                force_refresh
                or not self._token
                or (self._token_expires and time.time() > self._token_expires - 600)
            )
            if need_refresh:
                if self._mode == "keystone":
                    self._refresh_keystone()
                elif self._mode == "resell":
                    self._refresh_resell()
            return self._token

    def set_static_token(self, token: str) -> None:
        self._token = token
        self._token_expires = None

    def _refresh_keystone(self) -> None:
        if self.project_name:
            scope: dict[str, Any] = {"project": {"name": self.project_name, "domain": {"name": self.account_id}}}
        else:
            scope = {"domain": {"name": self.account_id}}

        payload = {
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": self.username,
                            "domain": {"name": self.account_id},
                            "password": self.password,
                        }
                    },
                },
                "scope": scope,
            }
        }

        log.info("Selectel: обновление Keystone-токена…")
        try:
            s = requests.Session()
            if self._proxy:
                rst_core.apply_proxy_to_session(s, self._proxy)
            resp = s.post(
                self.KEYSTONE_URL,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=15,
            )
            s.close()
            if resp.status_code == 201:
                new_token = resp.headers.get("X-Subject-Token", "")
                if new_token:
                    self._token = new_token
                    self._token_expires = time.time() + 23 * 3600
                    log.info("Selectel: Keystone-токен обновлён")
                    return
                raise RuntimeError("X-Subject-Token отсутствует")
            raise RuntimeError(f"Keystone HTTP {resp.status_code}: {resp.text[:300]}")
        except requests.RequestException as e:
            log.error("Selectel: ошибка Keystone: %s", e)
            raise

    def _refresh_resell(self) -> None:
        log.info("Selectel: обновление Resell-токена…")
        try:
            s = requests.Session()
            if self._proxy:
                rst_core.apply_proxy_to_session(s, self._proxy)
            resp = s.post(
                self.RESELL_TOKENS_URL,
                json={"token": {"account_name": self.account_id}},
                headers={"Content-Type": "application/json", "X-Token": self.api_key},
                timeout=15,
            )
            s.close()
            if resp.status_code in (200, 201):
                data = resp.json()
                new_token = data.get("token", {}).get("id", "")
                if new_token:
                    self._token = new_token
                    self._token_expires = time.time() + 23 * 3600
                    log.info("Selectel: Resell-токен обновлён")
                    return
                raise RuntimeError(f"Нет token.id: {json.dumps(data)[:200]}")
            raise RuntimeError(f"Resell HTTP {resp.status_code}: {resp.text[:300]}")
        except requests.RequestException as e:
            log.error("Selectel: ошибка Resell: %s", e)
            raise


def _make_adapter() -> HTTPAdapter:
    if Retry is not None:
        retry_strategy = Retry(
            total=3,
            backoff_factor=1.0,
            status_forcelist=[502, 503, 504],
            allowed_methods=["GET", "POST", "DELETE"],
            raise_on_status=False,
        )
        return HTTPAdapter(max_retries=retry_strategy, pool_connections=5, pool_maxsize=10)
    return HTTPAdapter(pool_connections=5, pool_maxsize=10)


class SelectelProvider:
    name = "selectel"

    def __init__(
        self,
        cfg: dict[str, Any],
        timeout: tuple[int, int] = (10, 30),
        proxy: Optional[dict[str, Any]] = None,
        account_override: Optional[dict[str, Any]] = None,
        instance_label: str = "",
    ):
        self.cfg = cfg
        self.timeout = timeout
        self.proxy = proxy
        self._account_override = account_override
        self._instance_label = instance_label
        self.batch_size = 1
        self.session: Optional[requests.Session] = None
        self.errors_in_row = 0
        self.project_id = ""
        self.token_mgr: KeystoneTokenManager

    @property
    def current_account_label(self) -> str:
        return self._instance_label

    def init_session(self) -> None:
        extra = self.cfg.get("extra", {})
        self.base = extra.get("api_base", "https://api.selectel.ru/vpc/resell/").rstrip("/")
        self.batch_size = int(extra.get("batch_size", 3) or 1)

        if self._account_override:
            acct = self._account_override
        else:
            acct = {
                "account_id": extra.get("account_id", ""),
                "username": extra.get("username", ""),
                "password": extra.get("password", ""),
                "api_key": extra.get("api_key", ""),
                "project_id": extra.get("project_id", ""),
                "project_name": extra.get("project_name", ""),
            }

        self.project_id = str(acct["project_id"])

        self.token_mgr = KeystoneTokenManager(
            account_id=str(acct.get("account_id", "")),
            username=str(acct.get("username", "")),
            password=str(acct.get("password", "")),
            api_key=str(acct.get("api_key", "")),
            project_name=str(acct.get("project_name", "")),
            project_id=self.project_id,
            proxy=self.proxy,
        )

        if self.token_mgr.mode == "static":
            self.token_mgr.set_static_token(str(acct.get("token", "") or self.cfg.get("token", "")))
            log.info("Selectel%s: статический токен", self._instance_label)
        else:
            try:
                self.token_mgr.get_token()
                log.info("Selectel%s: авто-обновление (%s)", self._instance_label, self.token_mgr.mode)
            except Exception as e:
                log.warning("Selectel%s: fallback на статический (%s)", self._instance_label, e)
                self.token_mgr.set_static_token(str(acct.get("token", "") or self.cfg.get("token", "")))

        self._rebuild_session()

    def _rebuild_session(self) -> None:
        token = self.token_mgr.get_token()
        if self.session:
            self.session.headers["X-Auth-Token"] = token
        else:
            self.session = requests.Session()
            adapter = _make_adapter()
            self.session.mount("https://", adapter)
            self.session.mount("http://", adapter)
            self.session.headers.update(
                {"Accept": "application/json", "Content-Type": "application/json", "X-Auth-Token": token}
            )
            if self.proxy:
                rst_core.apply_proxy_to_session(self.session, self.proxy)

    def _refresh_and_retry(self) -> None:
        if self.token_mgr.mode == "static":
            raise PermissionError("Токен истёк, авто-обновление не настроено")
        log.warning("Selectel%s: токен истёк, обновляю…", self._instance_label)
        self.token_mgr.get_token(force_refresh=True)
        self._rebuild_session()

    def get_regions(self) -> list[str]:
        return list(self.cfg.get("extra", {}).get("regions", list(DEFAULT_SELECTEL_REGIONS)))

    def create_ip(self, region: str) -> rst_core.ProviderResult:
        assert self.session is not None
        url = f"{self.base}/v2/floatingips/projects/{self.project_id}"
        payload = {"floatingips": [{"quantity": 1, "region": region}]}

        for attempt in range(2):
            resp = self.session.post(url, json=payload, timeout=self.timeout)

            if resp.status_code == 401 and attempt == 0:
                self._refresh_and_retry()
                continue

            if resp.status_code == 429:
                raise RuntimeError("Rate limit (429)")
            if resp.status_code == 409:
                raise RuntimeError(f"Конфликт/квота (409): {resp.text[:300]}")
            if resp.status_code == 403:
                raise PermissionError(f"Нет прав: {resp.text[:200]}")
            if resp.status_code != 200:
                raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:300]}")

            fips = resp.json().get("floatingips", [])
            if not fips:
                raise RuntimeError("Пустой ответ")
            fip = fips[0]
            return rst_core.ProviderResult(
                ip=fip.get("floating_ip_address", ""),
                resource_id=_floatingip_resource_id(fip),
                region=region,
                raw=fip,
            )
        raise RuntimeError("Не удалось после обновления токена")

    def create_ip_batch(self, region: str, quantity: int) -> list[rst_core.ProviderResult]:
        assert self.session is not None
        url = f"{self.base}/v2/floatingips/projects/{self.project_id}"
        payload = {"floatingips": [{"quantity": quantity, "region": region}]}

        for attempt in range(2):
            resp = self.session.post(url, json=payload, timeout=self.timeout)

            if resp.status_code == 401 and attempt == 0:
                self._refresh_and_retry()
                continue

            if resp.status_code == 429:
                raise RuntimeError("Rate limit (429)")
            if resp.status_code == 409:
                raise RuntimeError(f"Конфликт/квота (409): {resp.text[:300]}")
            if resp.status_code == 403:
                raise PermissionError(f"Нет прав: {resp.text[:200]}")
            if resp.status_code != 200:
                raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:300]}")

            fips = resp.json().get("floatingips", [])
            results: list[rst_core.ProviderResult] = []
            for fip in fips:
                ip = fip.get("floating_ip_address", "")
                rid = _floatingip_resource_id(fip)
                if ip and rid:
                    results.append(rst_core.ProviderResult(ip=ip, resource_id=rid, region=region, raw=fip))
            return results
        raise RuntimeError("Не удалось после обновления токена")

    def delete_ip(self, resource_id: str) -> None:
        assert self.session is not None
        url = f"{self.base}/v2/floatingips/{resource_id}"
        for attempt in range(2):
            resp = self.session.delete(url, timeout=self.timeout)
            if resp.status_code == 401 and attempt == 0:
                self._refresh_and_retry()
                continue
            # 404 — плавающий адрес уже снят или id устарел; для охоты это нормально.
            if resp.status_code == 404:
                log.debug("Selectel delete 404 (уже нет): %s", resource_id)
                return
            if resp.status_code not in (200, 204):
                raise RuntimeError(f"Delete HTTP {resp.status_code}")
            return
