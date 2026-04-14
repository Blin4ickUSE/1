"""Reg Cloud (Reg.ru cloud.reg.ru): GraphQL API, логика из ip_hunter_v6."""

from __future__ import annotations

import base64
import json
import logging
import random
import re
import threading
import time
from typing import Any, Optional

import requests

import rst_core
from rst_core import ProviderResult

log = logging.getLogger(__name__)

# ── Браузерные fingerprints для Reg.ru ──
# Каждый fingerprint — это консистентный набор: UA + Sec-Ch-Ua + platform.
# При создании сессии выбирается один и используется всё время жизни сессии.

_REGRU_FINGERPRINTS = [
    {
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": '"Windows"',
        "platform": "Win32",
    },
    {
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": '"macOS"',
        "platform": "MacIntel",
    },
    {
        "ua": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": '"Linux"',
        "platform": "Linux x86_64",
    },
    {
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="145", "Not-A.Brand";v="24", "Google Chrome";v="145"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": '"Windows"',
        "platform": "Win32",
    },
    {
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0",
        "sec_ch_ua": '"Chromium";v="146", "Microsoft Edge";v="146", "Not-A.Brand";v="24"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": '"Windows"',
        "platform": "Win32",
    },
    {
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0",
        "sec_ch_ua": "",
        "sec_ch_ua_mobile": "",
        "sec_ch_ua_platform": "",
        "platform": "Win32",
    },
    {
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="145", "Not-A.Brand";v="24", "Google Chrome";v="145"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": '"macOS"',
        "platform": "MacIntel",
    },
    {
        "ua": "Mozilla/5.0 (X11; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0",
        "sec_ch_ua": "",
        "sec_ch_ua_mobile": "",
        "sec_ch_ua_platform": "",
        "platform": "Linux x86_64",
    },
    {
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15",
        "sec_ch_ua": "",
        "sec_ch_ua_mobile": "",
        "sec_ch_ua_platform": "",
        "platform": "MacIntel",
    },
    {
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0",
        "sec_ch_ua": '"Chromium";v="146", "Microsoft Edge";v="146", "Not-A.Brand";v="24"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": '"macOS"',
        "platform": "MacIntel",
    },
]

# Случайные имена серверов (чтобы не дублировались)
_REGRU_ADJECTIVES = [
    "Red", "Blue", "Green", "Purple", "Golden", "Silver", "Dark", "Bright",
    "Swift", "Calm", "Bold", "Wild", "Iron", "Copper", "Neon", "Frozen",
    "Amber", "Violet", "Coral", "Lunar", "Solar", "Crimson", "Azure", "Jade",
]
_REGRU_NOUNS = [
    "Falcon", "Phoenix", "Panther", "Dragon", "Vortex", "Nebula", "Prism",
    "Quasar", "Titan", "Comet", "Spark", "Pulse", "Storm", "Flare", "Orbit",
    "Glacier", "Fluorum", "Helium", "Photon", "Neutron", "Kernel", "Matrix",
]


def _regru_random_name() -> str:
    return f"{random.choice(_REGRU_ADJECTIVES)} {random.choice(_REGRU_NOUNS)}"


class RegcloudProvider:
    """
    Reg.ru — создание/удаление OpenStack-серверов через GraphQL API панели cloud.reg.ru.

    Эмуляция браузера:
      • Консистентный fingerprint (один UA + заголовки на всю сессию)
      • Origin/Referer = https://cloud.reg.ru (как SPA)
      • Sec-Fetch-* заголовки (Site: same-site, Mode: cors, Dest: empty)
      • Sec-Ch-Ua / Sec-Ch-Ua-Platform (для Chromium-based UA)
      • Accept-Language с q-factors
      • Human-like задержки (jitter) между GraphQL запросами

    Стратегия подбора IP:
      1. createServer с enableFloatingIp=true → сервер получает Floating IP
      2. Поллинг server query до получения IP (status=active)
      3. Проверка IP → если не совпадает с целевой подсетью — removeServer
      4. Если совпадает — IP сохраняется, сервер НЕ удаляется (IP привязан к серверу)

    Конфигурация (cfg["extra"]):
      • service_id  — идентификатор сервиса (заголовок service-id)
      • region      — регион OpenStack (default: openstack-msk1)
      • image       — образ ОС (default: ubuntu-24-04-amd64)
      • plan        — тарифный план (default: c1-m1-d10-hp, самый дешёвый)
    """
    name = "regcloud"

    GRAPHQL_URL = "https://cloudvps-graphql-server.svc.reg.ru/api"

    # Origin / Referer — как если бы запрос шёл из SPA cloud.reg.ru
    ORIGIN = "https://cloud.reg.ru"
    REFERER = "https://cloud.reg.ru/"

    # Запросы к login.reg.ru (authenticate / refresh / bootstrap) — иначе CSRF_CHECK_FAILED:
    # сервер ожидает Origin/Referer с хоста логина и Sec-Fetch-Site: same-origin.
    LOGIN_ORIGIN = "https://login.reg.ru"
    # Referer должен быть корнем логина (со слэшем), не URL самого /authenticate.
    LOGIN_REFERER = "https://login.reg.ru/"
    # Важно: GET / и /login/ часто отдают 404 без Set-Cookie. csrftoken выставляется именно здесь:
    LOGIN_CSRF_URL = "https://login.reg.ru/authenticate"
    LOGIN_BOOTSTRAP_URLS = (
        "https://login.reg.ru/authenticate",
        "https://login.reg.ru/",
        "https://login.reg.ru/login/",
    )

    # GraphQL операции — полные запросы
    CREATE_SERVER_MUTATION = """
mutation createServer(
  $name: String!,
  $region: String!,
  $image: String!,
  $plan: String!,
  $sshKey: String!,
  $enableBackups: Boolean!,
  $enableFloatingIp: Boolean!,
  $promocode: String!,
  $volumeIds: [Int!]!,
  $protectedIPPlan: String!,
  $commercialSoftwarePlan: String
) {
  server {
    create(params: {
      name: $name,
      region: $region,
      image: $image,
      plan: $plan,
      sshKey: $sshKey,
      enableBackups: $enableBackups,
      enableFloatingIp: $enableFloatingIp,
      promocode: $promocode,
      volumeIds: $volumeIds,
      protectedIPPlan: $protectedIPPlan,
      commercialSoftwarePlan: $commercialSoftwarePlan
    }) {
      __typename
      ... on Server {
        id
        name
        status
        ipv4
      }
    }
  }
}
""".strip()

    SERVER_QUERY = """
query server($serverId: Int!) {
  server(serverId: $serverId) {
    __typename
    ... on Server {
      id
      name
      ipv4
      status
      floatingIPs {
        address
      }
    }
  }
}
""".strip()

    # Отдельный запрос: если в схеме нет id у floatingIPs, не ломаем поллинг выше.
    SERVER_FLOATING_IDS_QUERY = """
query serverFloatingIds($serverId: Int!) {
  server(serverId: $serverId) {
    __typename
    ... on Server {
      id
      floatingIPs {
        id
      }
    }
  }
}
""".strip()

    REMOVE_SERVER_MUTATION = """
mutation removeServer(
  $serverId: Int!,
  $releaseFloatingIPs: [Int!]!,
  $releaseVolumes: [Int!]!
) {
  server {
    remove(params: {
      serverId: $serverId,
      releaseFloatingIPs: $releaseFloatingIPs,
      releaseVolumes: $releaseVolumes
    }) {
      __typename
      ... on Server {
        id
        status
      }
    }
  }
}
""".strip()

    # Максимальное время ожидания Floating IP (секунды)
    IP_POLL_TIMEOUT = 120
    IP_POLL_INTERVAL = 3

    # Human-like задержки между GraphQL запросами (секунды)
    HUMAN_DELAY_MIN = 0.2
    HUMAN_DELAY_MAX = 0.8
    # Увеличенная пауза после mutation (create/remove)
    MUTATION_DELAY_MIN = 0.5
    MUTATION_DELAY_MAX = 1.5

    # Последовательный режим: один сервер за итерацию.
    BATCH_SIZE = 1
    DELETE_WAIT_TIMEOUT = 90
    DELETE_WAIT_POLL_SEC = 2

    # URL для обновления JWT токена
    REFRESH_URL = "https://login.reg.ru/refresh"
    AUTHENTICATE_URL = "https://login.reg.ru/authenticate"

    def __init__(self, cfg: dict, timeout: tuple = (10, 30), proxy: Optional[dict] = None):
        self.cfg = cfg
        self.timeout = timeout
        self.proxy = proxy
        self.session = None
        self.errors_in_row = 0
        self.stop_event = None
        self._service_id = ""
        self._region = "openstack-msk1"
        self._image = "ubuntu-24-04-amd64"
        self._plan = "c1-m1-d10-hp"
        self._fingerprint: dict = {}  # Выбранный fingerprint на всю сессию
        self._request_count = 0       # Счётчик запросов (для периодической ротации)
        self._jwt: str = ""           # Текущий JWT токен
        self._jwt_expires: float = 0  # Unix timestamp истечения JWT
        self._session_id: str = ""    # SESSION_ID cookie (долгоживущий)
        self._cookies: dict = {}      # Все cookie для авторизации
        self._jwt_lock = threading.Lock()  # Лок для обновления JWT
        self._login: str = ""
        self._password: str = ""
        self._has_credentials: bool = False

    def _should_stop(self) -> bool:
        ev = getattr(self, "stop_event", None)
        return ev is not None and ev.is_set()

    def _pick_fingerprint(self) -> dict:
        """Выбрать случайный браузерный fingerprint. Фиксируется на всю сессию."""
        return random.choice(_REGRU_FINGERPRINTS)

    def _build_browser_headers(self) -> dict:
        """
        Сформировать полный набор браузерных заголовков на основе fingerprint.
        Вызывается один раз при init_session(), заголовки идут в session.headers.
        """
        fp = self._fingerprint
        is_firefox = "Firefox" in fp["ua"]
        is_safari = "Safari" in fp["ua"] and "Chrome" not in fp["ua"]
        is_chromium = not is_firefox and not is_safari

        headers = {
            "User-Agent": fp["ua"],
            "Accept": "*/*",
            "Accept-Language": random.choice([
                "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
                "ru,en-US;q=0.9,en;q=0.8",
                "ru-RU,ru;q=0.9,en;q=0.8",
                "en-US,en;q=0.9,ru;q=0.8",
                "ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3",
            ]),
            "Accept-Encoding": "gzip, deflate, br",
            "Content-Type": "application/json",
            "Origin": self.ORIGIN,
            "Referer": self.REFERER,
            "Connection": "keep-alive",
        }

        # Sec-Fetch-* — все современные браузеры шлют это
        # same-site потому что cloud.reg.ru → cloudvps-graphql-server.svc.reg.ru (*.reg.ru)
        headers["Sec-Fetch-Site"] = "same-site"
        headers["Sec-Fetch-Mode"] = "cors"
        headers["Sec-Fetch-Dest"] = "empty"

        # Sec-Ch-Ua — только Chromium-based браузеры (Chrome, Edge)
        if is_chromium and fp.get("sec_ch_ua"):
            headers["Sec-Ch-Ua"] = fp["sec_ch_ua"]
            headers["Sec-Ch-Ua-Mobile"] = fp.get("sec_ch_ua_mobile", "?0")
            headers["Sec-Ch-Ua-Platform"] = fp.get("sec_ch_ua_platform", '"Windows"')

        # DNT — иногда включен
        if random.random() < 0.3:
            headers["DNT"] = "1"

        # Priority — Chrome 131+ шлёт это
        if is_chromium and "131" in fp.get("sec_ch_ua", ""):
            headers["Priority"] = "u=1, i"

        return headers

    def _human_delay(self, is_mutation: bool = False):
        """
        Имитация человеческой задержки между запросами.
        Mutation (create/remove) = дольше (человек читает UI перед кликом).
        """
        if is_mutation:
            delay = random.uniform(self.MUTATION_DELAY_MIN, self.MUTATION_DELAY_MAX)
        else:
            delay = random.uniform(self.HUMAN_DELAY_MIN, self.HUMAN_DELAY_MAX)
        time.sleep(delay)

    def _maybe_rotate_fingerprint(self):
        """
        Периодическая ротация fingerprint'а — имитация нового браузера/вкладки.
        Ротация каждые 30-60 запросов (как если бы пользователь обновил страницу).
        """
        self._request_count += 1
        # Ротируем каждые 30-60 запросов
        if self._request_count >= random.randint(30, 60):
            old_ua = self._fingerprint["ua"].split("/")[-1][:20]
            self._fingerprint = self._pick_fingerprint()
            new_headers = self._build_browser_headers()
            # Обновляем только браузерные заголовки, не трогая Auth и service-id
            for key in list(self.session.headers.keys()):
                if key.lower() not in ("authorization", "service-id"):
                    del self.session.headers[key]
            self.session.headers.update(new_headers)
            self._request_count = 0
            new_ua = self._fingerprint["ua"].split("/")[-1][:20]
            log.info("Reg.ru: ротация fingerprint (%s → %s)", old_ua, new_ua)

    def _parse_jwt_expiry(self, jwt_token: str) -> float:
        """Извлекает exp из JWT payload (без верификации подписи)."""
        try:
            parts = jwt_token.split(".")
            if len(parts) < 2:
                return 0
            payload_b64 = parts[1]
            payload_b64 += "=" * (4 - len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            return float(payload.get("exp", 0))
        except Exception:
            return 0

    @staticmethod
    def _token_like(value: str) -> bool:
        v = (value or "").strip()
        return bool(v and "." in v and len(v) > 50)

    @staticmethod
    def _extract_cookie_like_token(text: str, key: str) -> str:
        if not text:
            return ""
        patterns = (
            rf"{key}=([^;,\s]+)",
            rf'"{key}"\s*:\s*"([^"]+)"',
            rf"'{key}'\s*:\s*'([^']+)'",
            rf"{key}\s*:\s*([A-Za-z0-9._-]+)",
        )
        for pat in patterns:
            m = re.search(pat, text, re.I)
            if not m:
                continue
            cand = (m.group(1) or "").strip().strip('"').strip("'")
            if key == "JWT":
                if RegcloudProvider._token_like(cand):
                    return cand
            elif cand:
                return cand
        return ""

    def _extract_jwt_pair_from_response(self, resp: requests.Response) -> tuple[str, str]:
        """Надёжное извлечение JWT/JWT_REFRESH из ответа refresh."""
        new_jwt = ""
        new_refresh = ""

        # 1) requests cookiejar
        for cookie in resp.cookies:
            if cookie.name == "JWT" and self._token_like(cookie.value):
                new_jwt = cookie.value
            elif cookie.name == "JWT_REFRESH" and len(cookie.value) > 10:
                new_refresh = cookie.value

        # 2) raw Set-Cookie lines (самый надёжный источник)
        raw_lines: list[str] = []
        try:
            raw_lines = resp.raw._original_response.headers.get_all("Set-Cookie") or []
        except Exception:
            raw_lines = []
        if not raw_lines:
            try:
                raw_lines = resp.raw.headers.getlist("Set-Cookie") or []
            except Exception:
                raw_lines = []
        for line in raw_lines:
            if not new_jwt:
                cand = self._extract_cookie_like_token(line, "JWT")
                if self._token_like(cand):
                    new_jwt = cand
            if not new_refresh:
                cand = self._extract_cookie_like_token(line, "JWT_REFRESH")
                if cand:
                    new_refresh = cand

        # 3) fallback: объединённый set-cookie/header/body (иногда прокси режет cookiejar)
        if not new_jwt or not new_refresh:
            merged = " || ".join(
                [
                    str(resp.headers.get("Set-Cookie", "") or ""),
                    str(resp.text or ""),
                ]
            )
            if not new_jwt:
                cand = self._extract_cookie_like_token(merged, "JWT")
                if self._token_like(cand):
                    new_jwt = cand
            if not new_refresh:
                cand = self._extract_cookie_like_token(merged, "JWT_REFRESH")
                if cand:
                    new_refresh = cand
        return new_jwt, new_refresh

    def _login_nav_headers(self) -> dict[str, str]:
        """GET страницы логина — как обычная навигация браузера."""
        fp = self._fingerprint
        h: dict[str, str] = {
            "User-Agent": fp.get("ua", ""),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        }
        is_chromium = "Firefox" not in fp.get("ua", "") and not (
            "Safari" in fp.get("ua", "") and "Chrome" not in fp.get("ua", "")
        )
        if is_chromium and fp.get("sec_ch_ua"):
            h["Sec-Ch-Ua"] = fp["sec_ch_ua"]
            h["Sec-Ch-Ua-Mobile"] = fp.get("sec_ch_ua_mobile", "?0")
            h["Sec-Ch-Ua-Platform"] = fp.get("sec_ch_ua_platform", '"Windows"')
        return h

    def _login_api_headers(self, *, cookie_header: str, with_body: bool) -> dict[str, str]:
        """POST на login.reg.ru (/authenticate, /refresh) — XHR с того же origin."""
        fp = self._fingerprint
        is_firefox = "Firefox" in fp.get("ua", "")
        is_safari = "Safari" in fp.get("ua", "") and "Chrome" not in fp.get("ua", "")
        is_chromium = not is_firefox and not is_safari
        h: dict[str, str] = {
            "User-Agent": fp.get("ua", ""),
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
            "Origin": self.LOGIN_ORIGIN,
            "Referer": self.LOGIN_REFERER,
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Cookie": cookie_header,
        }
        if with_body:
            h["Content-Type"] = "application/json"
        else:
            h["Content-Length"] = "0"
        if is_chromium and fp.get("sec_ch_ua"):
            h["Sec-Ch-Ua"] = fp["sec_ch_ua"]
            h["Sec-Ch-Ua-Mobile"] = fp.get("sec_ch_ua_mobile", "?0")
            h["Sec-Ch-Ua-Platform"] = fp.get("sec_ch_ua_platform", '"Windows"')
        return h

    @staticmethod
    def _merge_set_cookie_lines(resp: requests.Response, into: dict[str, str]) -> None:
        """Добавить куки из сырого Set-Cookie (на случай если jar requests не всё подхватил)."""
        try:
            lines = resp.raw.headers.getlist("Set-Cookie") or []
        except Exception:
            lines = []
        for line in lines:
            if "=" not in line or not line.strip():
                continue
            name, rest = line.split("=", 1)
            name = name.strip()
            val = rest.split(";", 1)[0].strip()
            if name and val:
                into[name] = val

    @staticmethod
    def _csrf_from_html(html: str) -> str:
        if not html:
            return ""
        patterns = (
            r'name=["\']csrfmiddlewaretoken["\']\s+value=["\']([^"\']+)["\']',
            r'value=["\']([^"\']+)["\']\s+name=["\']csrfmiddlewaretoken["\']',
            r'"csrfToken"\s*:\s*"([^"]+)"',
            r"'csrfToken'\s*:\s*'([^']+)'",
            r"csrfToken:\s*['\"]([^'\"]+)['\"]",
        )
        for pat in patterns:
            m = re.search(pat, html, re.I)
            if m:
                return m.group(1).strip()
        return ""

    def _bootstrap_login_cookies(self) -> None:
        """csrftoken перед POST /authenticate — обязателен для Django CSRF на login.reg.ru."""
        try:
            s = requests.Session()
            s.headers.update(self._login_nav_headers())
            last_html = ""
            for url in self.LOGIN_BOOTSTRAP_URLS:
                try:
                    r = s.get(url, timeout=15, allow_redirects=True)
                    last_html = r.text or ""
                    self._merge_set_cookie_lines(r, self._cookies)
                    for c in r.cookies:
                        self._cookies[c.name] = c.value
                        if c.name == "SESSION_ID":
                            self._session_id = c.value
                    if self._cookies.get("csrftoken"):
                        break
                except Exception as e:
                    log.debug("Reg.ru: bootstrap GET %s: %s", url, e)
            for c in s.cookies:
                self._cookies[c.name] = c.value
                if c.name == "SESSION_ID":
                    self._session_id = c.value
            csrf_html = self._csrf_from_html(last_html)
            if csrf_html and not self._cookies.get("csrftoken"):
                self._cookies["csrftoken"] = csrf_html
            if self._cookies.get("csrftoken"):
                log.debug("Reg.ru: csrftoken получен (bootstrap)")
            else:
                log.warning(
                    "Reg.ru: csrftoken не получен после GET %s — проверьте сеть/DNS до login.reg.ru",
                    ", ".join(self.LOGIN_BOOTSTRAP_URLS[:2]),
                )
            s.close()
        except Exception as e:
            log.warning("Reg.ru: bootstrap login.reg.ru: %s", e)

    def _sync_cookies_to_session(self) -> None:
        if not self.session:
            return
        for k, v in self._cookies.items():
            self.session.cookies.set(k, v, domain=".reg.ru")
            self.session.cookies.set(k, v, domain="login.reg.ru")

    @staticmethod
    def _is_csrf_authenticate_fail(resp: requests.Response, body: dict) -> bool:
        raw = (resp.text or "").lower()
        if "csrf_check_failed" in raw:
            return True
        for item in body.get("message") or []:
            if isinstance(item, dict) and str(item.get("code", "")).upper() == "CSRF_CHECK_FAILED":
                return True
        return False

    def _do_full_login(self) -> None:
        """POST /authenticate + /refresh на login.reg.ru (отдельная сессия, без SOCKS)."""
        s = requests.Session()
        try:
            resp: requests.Response | None = None
            body: dict = {}
            for attempt in range(2):
                csrf = (self._cookies.get("csrftoken") or "").strip()
                cookie_header = "; ".join(f"{k}={v}" for k, v in self._cookies.items())
                auth_headers = self._login_api_headers(cookie_header=cookie_header, with_body=True)
                if csrf:
                    auth_headers["X-CSRFToken"] = csrf
                    auth_headers["x-csrf-token"] = csrf
                resp = s.post(
                    self.AUTHENTICATE_URL,
                    json={"login": self._login, "password": self._password},
                    headers=auth_headers,
                    timeout=15,
                )
                for cookie in resp.cookies:
                    self._cookies[cookie.name] = cookie.value
                    if cookie.name == "SESSION_ID":
                        self._session_id = cookie.value
                try:
                    body = resp.json() if resp.text else {}
                except json.JSONDecodeError:
                    body = {}
                if resp.status_code == 200 and body.get("success"):
                    break
                if attempt == 0 and self._is_csrf_authenticate_fail(resp, body):
                    log.info("Reg.ru: CSRF при authenticate — новый bootstrap и повтор")
                    self._bootstrap_login_cookies()
                    self._sync_cookies_to_session()
                    continue
                if resp.status_code != 200:
                    log.error("Reg.ru: authenticate HTTP %s: %s", resp.status_code, resp.text[:300])
                    return
                log.error("Reg.ru: authenticate failed: %s", body.get("result", body))
                return
            if not resp or not body.get("success"):
                return
            refresh_cookie = "; ".join(f"{k}={v}" for k, v in self._cookies.items())
            refresh_headers = self._login_api_headers(cookie_header=refresh_cookie, with_body=False)
            csrf_new = (self._cookies.get("csrftoken") or "").strip()
            if csrf_new:
                refresh_headers["X-CSRFToken"] = csrf_new
                refresh_headers["x-csrf-token"] = csrf_new
            resp2 = s.post(self.REFRESH_URL, headers=refresh_headers, timeout=15)
            new_jwt, new_refresh = self._extract_jwt_pair_from_response(resp2)
            if self._token_like(new_jwt):
                self._jwt = new_jwt
                self._jwt_expires = self._parse_jwt_expiry(new_jwt)
                if new_refresh and len(new_refresh) > 10:
                    self._cookies["JWT_REFRESH"] = new_refresh
                self._sync_cookies_to_session()
                ttl = max(0, int(self._jwt_expires - time.time()))
                log.info("Reg.ru: логин/refresh OK, JWT TTL ~%ss", ttl)
            else:
                log.error(
                    "Reg.ru: после логина JWT не получен (HTTP %s, set-cookie=%s, body=%s)",
                    resp2.status_code,
                    bool(resp2.headers.get("Set-Cookie")),
                    (resp2.text or "")[:220],
                )
        except Exception as e:
            log.error("Reg.ru: полный логин: %s", e)
        finally:
            s.close()

    def _service_ids_from_next_data(self, html: str) -> list[str]:
        m = re.search(
            r'<script[^>]*\bid=["\']__NEXT_DATA__["\'][^>]*>(?P<j>.*?)</script>',
            html,
            re.I | re.DOTALL,
        )
        if not m:
            return []
        raw = (m.group("j") or "").strip()
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
        found: list[str] = []

        def walk(obj: Any, depth: int) -> None:
            if depth > 50:
                return
            if isinstance(obj, dict):
                for k, v in obj.items():
                    kl = re.sub(r"[_-]", "", k.lower())
                    if kl in ("serviceid", "openstackserviceid", "serviceidheader"):
                        if isinstance(v, int):
                            s = str(v)
                        elif isinstance(v, str) and v.strip().isdigit():
                            s = v.strip()
                        else:
                            s = ""
                        if len(s) >= 4:
                            found.append(s)
                    else:
                        walk(v, depth + 1)
            elif isinstance(obj, list):
                for it in obj[:800]:
                    walk(it, depth + 1)

        walk(data, 0)
        return found

    def _discover_service_id(self) -> str:
        """Пытается вытащить OpenStack service-id из HTML/JSON cloud.reg.ru."""
        if self._service_id:
            return self._service_id
        patterns = (
            r'"serviceId"\s*:\s*"?(\d{4,})"?',
            r'"openstackServiceId"\s*:\s*"?(\d{4,})"?',
            r'"service_id"\s*:\s*"?(\d{4,})"?',
            r'service-id["\']?\s*[:=]\s*["\']?(\d{4,})',
            r'serviceId["\']?\s*[:=]\s*["\']?(\d{4,})',
            r'"cloudVpsServiceId"\s*:\s*(\d{4,})',
        )
        urls = (
            "https://cloud.reg.ru/",
            "https://cloud.reg.ru/dashboard",
            "https://cloud.reg.ru/servers",
        )
        for url in urls:
            try:
                r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                txt = r.text or ""
                for pat in patterns:
                    m = re.search(pat, txt, re.I)
                    if m:
                        sid = m.group(1).strip()
                        log.info("Reg.ru: service-id из HTML (%s): %s…", url.split("/")[-1] or "/", sid[:8])
                        return sid
                for sid in self._service_ids_from_next_data(txt):
                    if len(sid) >= 4:
                        log.info("Reg.ru: service-id из __NEXT_DATA__: %s…", sid[:8])
                        return sid
            except Exception as e:
                log.debug("Reg.ru: service-id GET %s: %s", url, e)
        log.warning("Reg.ru: service-id не найден ни по одному URL")
        return ""

    def _refresh_jwt(self):
        """
        Обновляет JWT токен через POST https://login.reg.ru/refresh
        Пробует через прокси (тот же IP что и GraphQL), затем напрямую.
        Передаёт cookie через заголовок Cookie: явно.
        """
        with self._jwt_lock:
            if time.time() < self._jwt_expires - 30:
                return

            log.info(f"Reg.ru: обновление JWT токена...")

            # Собираем cookie-строку для заголовка
            cookie_parts = []
            for k, v in self._cookies.items():
                cookie_parts.append(f"{k}={v}")
            if self._jwt:
                # Обновляем JWT в cookie-строке
                cookie_parts = [p for p in cookie_parts if not p.startswith("JWT=")]
                cookie_parts.append(f"JWT={self._jwt}")
            cookie_header = "; ".join(cookie_parts)

            csrf = (self._cookies.get("csrftoken") or "").strip()
            headers = self._login_api_headers(cookie_header=cookie_header, with_body=False)
            if csrf:
                headers["X-CSRFToken"] = csrf
                headers["x-csrf-token"] = csrf

            # login.reg.ru недоступен через SOCKS-прокси — сразу direct
            attempts = [("direct", None)]

            for label, proxy_cfg in attempts:
                try:
                    s = requests.Session()
                    if proxy_cfg:
                        rst_core.apply_proxy_to_session(s, proxy_cfg)

                    resp = s.post(self.REFRESH_URL, headers=headers, timeout=15)

                    if resp.status_code != 200:
                        log.warning(f"Reg.ru: refresh ({label}) HTTP {resp.status_code}")
                        s.close()
                        continue

                    new_jwt, new_refresh = self._extract_jwt_pair_from_response(resp)

                    s.close()

                    if self._token_like(new_jwt):
                        self._jwt = new_jwt
                        self._jwt_expires = self._parse_jwt_expiry(new_jwt)
                        ttl = int(self._jwt_expires - time.time())

                        # Обновляем JWT в основной сессии
                        self.session.cookies.set("JWT", new_jwt, domain=".reg.ru")

                        # Обновляем JWT_REFRESH — критично для следующего refresh!
                        if new_refresh and new_refresh != '""' and len(new_refresh) > 10:
                            self._cookies["JWT_REFRESH"] = new_refresh
                            log.info(f"Reg.ru: JWT_REFRESH обновлён: {new_refresh[:8]}...")
                        else:
                            log.warning(f"Reg.ru: JWT_REFRESH не обнаружен в ответе!")

                        log.info(f"Reg.ru: JWT обновлён via {label} (TTL: {ttl}с)")
                        return
                    else:
                        log.warning(
                            "Reg.ru: refresh (%s) — JWT не найден (set-cookie=%s, body=%s)",
                            label,
                            bool(resp.headers.get("Set-Cookie")),
                            (resp.text or "")[:220],
                        )

                except Exception as e:
                    log.warning(f"Reg.ru: refresh ({label}) ошибка: {e}")

            log.warning("Reg.ru: не удалось обновить JWT ни через прокси, ни напрямую")
            if self._has_credentials:
                log.info("Reg.ru: пробую полный логин по email/паролю…")
                self._do_full_login()

    def _ensure_jwt_valid(self):
        """Проверяет JWT и обновляет если истекает в ближайшие 60с."""
        if time.time() > self._jwt_expires - 60:
            self._refresh_jwt()

    def init_session(self):
        extra = self.cfg.get("extra", {})
        token = (self.cfg.get("token") or "").strip()
        self._login = str(extra.get("login", "")).strip()
        self._password = str(extra.get("password", ""))
        self._has_credentials = bool(self._login and self._password)

        self._service_id = str(extra.get("service_id", "")).strip()
        self._region = extra.get("region", "openstack-msk1")
        self._image = extra.get("image", "ubuntu-24-04-amd64")
        self._plan = extra.get("plan", "c1-m1-d10-hp")

        cookies_str = (extra.get("cookies") or "").strip() or token
        parsed_cookies: dict[str, str] = {}
        if cookies_str and cookies_str not in ("login_mode", "-"):
            if "=" in cookies_str and ";" in cookies_str:
                for part in cookies_str.split(";"):
                    part = part.strip()
                    if "=" in part:
                        k, v = part.split("=", 1)
                        parsed_cookies[k.strip()] = v.strip()
            elif cookies_str.startswith("eyJ"):
                parsed_cookies["JWT"] = cookies_str
            elif len(cookies_str) > 10:
                parsed_cookies["SESSION_ID"] = cookies_str

        self._session_id = parsed_cookies.get("SESSION_ID", "")
        self._jwt = parsed_cookies.get("JWT", "")
        self._cookies = dict(parsed_cookies)

        if not self._has_credentials and not self._session_id and not self._jwt:
            raise RuntimeError(
                "Нет данных для Reg.ru: укажите email и пароль от аккаунта reg.ru "
                "(или сохранённую cookie-строку для старого формата)."
            )

        if self._jwt:
            self._jwt_expires = self._parse_jwt_expiry(self._jwt)
            ttl = max(0, int(self._jwt_expires - time.time()))
            log.info("Reg.ru: JWT TTL: %ss", ttl)
        else:
            self._jwt_expires = 0.0
        if self._session_id:
            log.info("Reg.ru: SESSION_ID: %s…", self._session_id[:8])
        if self._has_credentials:
            log.info("Reg.ru: режим email/пароль (%s)", self._login)

        self._fingerprint = self._pick_fingerprint()
        browser_headers = self._build_browser_headers()
        self.session = rst_core.make_http_session(proxy=self.proxy)
        self.session.headers.update(browser_headers)
        self.session.headers.pop("Authorization", None)
        self._sync_cookies_to_session()

        ua_short = self._fingerprint["ua"].split(")")[-1].strip()[:40] or self._fingerprint["ua"][-40:]
        log.info("Reg.ru: fingerprint → %s", ua_short)

        if self._has_credentials:
            self._bootstrap_login_cookies()
            self._sync_cookies_to_session()
            with self._jwt_lock:
                if not self._jwt or time.time() > self._jwt_expires - 60:
                    self._do_full_login()
        elif self._session_id and (not self._jwt or time.time() > self._jwt_expires):
            log.info("Reg.ru: JWT отсутствует/просрочен, обновляю через refresh…")
            self._refresh_jwt()

        if self._service_id:
            tail = self._service_id[-8:] if len(self._service_id) > 8 else self._service_id
            log.info("Reg.ru: service-id из настроек (…%s)", tail)
        else:
            self._service_id = self._discover_service_id()
        if not self._service_id:
            raise RuntimeError(
                "Не указан и не удалось определить OpenStack service-id (заголовок GraphQL). "
                "В боте при добавлении RegCloud укажите его на шаге 3 или вручную в настройках: "
                "F12 → Network → запрос к cloudvps-graphql-server.svc.reg.ru → заголовок service-id."
            )
        self.session.headers["service-id"] = self._service_id

        # Проверяем доступность API
        log.info("Reg.ru: проверка GraphQL API…")
        self._human_delay()
        try:
            test_resp = self.session.post(
                self.GRAPHQL_URL,
                json={
                    "operationName": "server",
                    "variables": {"serverId": 0},
                    "query": self.SERVER_QUERY,
                },
                timeout=self.timeout,
            )
            if test_resp.status_code == 401:
                raise PermissionError("Токен/cookie невалидны (401)")
            if test_resp.status_code == 403:
                raise PermissionError("Доступ запрещён (403)")

            # Проверяем не Unauthorized ли в ответе
            try:
                body = test_resp.json()
                data = body.get("data", {})
                srv = data.get("server", {})
                if isinstance(srv, dict) and srv.get("__typename") == "Unauthorized":
                    raise PermissionError("API вернул Unauthorized — обновите cookie (SESSION_ID)")
            except (json.JSONDecodeError, AttributeError):
                pass

            log.info(f"Reg.ru: GraphQL API доступен (HTTP {test_resp.status_code})")
        except requests.RequestException as e:
            log.warning(f"Reg.ru: API недоступен ({e}) — продолжаю, ошибки возможны")

    def get_regions(self) -> list[str]:
        return [self._region]

    def _graphql(self, operation_name: str, query: str, variables: dict,
                 is_mutation: bool = False) -> dict:
        """
        Выполнить GraphQL запрос с браузерной эмуляцией и авто-обновлением JWT.
        """
        # Проверяем/обновляем JWT перед запросом
        self._ensure_jwt_valid()

        # Имитируем человека: задержка перед каждым запросом
        self._human_delay(is_mutation=is_mutation)

        # Периодическая ротация fingerprint'а
        self._maybe_rotate_fingerprint()

        payload = {
            "operationName": operation_name,
            "variables": variables,
            "query": query,
        }

        for attempt in range(2):
            # Обновляем Cookie заголовок с актуальным JWT
            cookie_parts = []
            for k, v in self._cookies.items():
                if k != "JWT":
                    cookie_parts.append(f"{k}={v}")
            if self._jwt:
                cookie_parts.append(f"JWT={self._jwt}")
            self.session.headers["Cookie"] = "; ".join(cookie_parts)

            resp = self.session.post(self.GRAPHQL_URL, json=payload, timeout=self.timeout)

            if resp.status_code == 429:
                raise RuntimeError("Rate limit (429)")
            if resp.status_code == 401:
                if attempt == 0 and self._session_id:
                    log.warning(f"Reg.ru: 401, пробую обновить JWT...")
                    self._refresh_jwt()
                    continue
                raise PermissionError("Токен/cookie невалидны (401)")
            if resp.status_code == 403:
                raise PermissionError(f"Доступ запрещён (403): {resp.text[:300]}")
            if resp.status_code not in (200, 201):
                raise RuntimeError(f"GraphQL HTTP {resp.status_code}: {resp.text[:400]}")

            body = resp.json()
            if "errors" in body and body["errors"]:
                err_msgs = "; ".join(e.get("message", str(e)) for e in body["errors"])
                raise RuntimeError(f"GraphQL errors: {err_msgs}")

            data = body.get("data", {})

            # Проверяем на Unauthorized в ответе (API может вернуть 200 с __typename: Unauthorized)
            # Ищем Unauthorized в любом месте ответа
            data_str = json.dumps(data)
            if '"Unauthorized"' in data_str:
                if attempt == 0 and self._session_id:
                    log.warning(f"Reg.ru: Unauthorized в ответе, обновляю JWT...")
                    self._refresh_jwt()
                    continue
                raise PermissionError("API вернул Unauthorized — SESSION_ID невалиден")

            return data

        raise RuntimeError("Не удалось после обновления JWT")

    def _create_single_server(self, region: str) -> tuple:
        """
        Создаёт один сервер, возвращает (server_id, server_name) или выбрасывает ошибку.
        НЕ ждёт IP — только создаёт.
        """
        server_name = _regru_random_name()

        variables = {
            "name": server_name,
            "region": region,
            "image": self._image,
            "plan": self._plan,
            "sshKey": "",
            "enableBackups": False,
            "enableFloatingIp": True,
            "promocode": "",
            "volumeIds": [],
            "protectedIPPlan": "",
            "commercialSoftwarePlan": None,
        }

        data = self._graphql("createServer", self.CREATE_SERVER_MUTATION, variables,
                             is_mutation=True)

        create_result = data.get("server", {}).get("create", {})

        typename = create_result.get("__typename", "")

        # ServerLimitReached — слишком много серверов одновременно
        if typename == "ServerLimitReached":
            raise RuntimeError("ServerLimitReached — лимит серверов на аккаунте")

        if create_result.get("message") and not create_result.get("id"):
            err_msg = create_result.get("message", str(create_result))
            if "лимит" in err_msg.lower() or "limit" in err_msg.lower():
                raise rst_core.DailyLimitError(f"Reg.ru: {err_msg}")
            if "баланс" in err_msg.lower() or "balance" in err_msg.lower() or "средств" in err_msg.lower():
                raise PermissionError(f"Reg.ru: {err_msg}")
            raise RuntimeError(f"createServer: {err_msg}")

        server_id = create_result.get("id")
        if not server_id:
            raise RuntimeError(f"createServer: нет id в ответе: {json.dumps(create_result)[:300]}")

        return int(server_id), server_name

    def _poll_server_ip(self, server_id: int) -> Optional[str]:
        """
        Одиночный поллинг сервера — возвращает IP если назначен, None если ещё нет.
        Выбрасывает RuntimeError при ошибке сервера.
        """
        data = self._graphql("server", self.SERVER_QUERY, {"serverId": server_id})
        server = data.get("server", {})

        if server.get("message") and not server.get("id"):
            raise RuntimeError(f"Ошибка сервера #{server_id}: {server.get('message')}")

        status = server.get("status", "")

        # Если сервер в ошибке
        if status in ("error", "failed", "deleting", "deleted"):
            raise RuntimeError(f"Сервер #{server_id} в статусе '{status}'")

        # Проверяем floatingIPs (может появиться до ACTIVE)
        for fip in server.get("floatingIPs", []):
            addr = fip.get("address", "")
            if addr and addr != "0.0.0.0":
                return addr

        # Fallback: ipv4
        ipv4 = server.get("ipv4", "")
        if ipv4 and ipv4 != "0.0.0.0":
            return ipv4

        return None

    def create_ip(self, region: str) -> ProviderResult:
        """
        Создаёт OpenStack-сервер с Floating IP, дожидается IP, возвращает результат.
        resource_id — это serverId (int как строка), используется для delete_ip.
        """
        server_id, server_name = self._create_single_server(region)
        log.info(f"Reg.ru: сервер #{server_id} '{server_name}' создаётся...")

        # Поллинг IP
        deadline = time.time() + self.IP_POLL_TIMEOUT
        while time.time() < deadline:
            if self._should_stop():
                try:
                    self._remove_server(server_id)
                except Exception:
                    pass
                raise RuntimeError("Остановлено пользователем")

            try:
                ip = self._poll_server_ip(server_id)
                if ip:
                    return ProviderResult(ip=ip, resource_id=str(server_id), region=region)
            except RuntimeError:
                try:
                    self._remove_server(server_id)
                except Exception as del_err:
                    log.warning(f"Reg.ru: не удалось удалить #{server_id}: {del_err}")
                raise

            time.sleep(self.IP_POLL_INTERVAL + random.uniform(-0.5, 1.0))

        # Таймаут — удаляем сервер
        try:
            self._remove_server(server_id)
        except Exception as del_err:
            log.warning(f"Reg.ru: не удалось удалить #{server_id} после таймаута: {del_err}")
        raise RuntimeError(f"Таймаут {self.IP_POLL_TIMEOUT}с: сервер #{server_id} не получил IP")

    def create_ip_batch(self, region: str, quantity: int) -> list:
        """
        Параллельное создание нескольких серверов.
        Создаёт quantity серверов, поллит все одновременно, возвращает ProviderResult'ы.
        """
        servers = []  # [(server_id, server_name), ...]

        # Создаём серверы
        for i in range(quantity):
            if self._should_stop():
                break
            try:
                sid, name = self._create_single_server(region)
                servers.append((sid, name))
                log.info(f"Reg.ru: [{i+1}/{quantity}] сервер #{sid} '{name}' создаётся...")
            except Exception as e:
                log.warning(f"Reg.ru: ошибка создания сервера {i+1}/{quantity}: {e}")
                break

        if not servers:
            raise RuntimeError("Не удалось создать ни одного сервера")

        # Поллим все серверы одновременно
        results = []  # ProviderResult
        pending = dict(servers)  # {server_id: server_name}
        delete_queue: list[int] = []
        deadline = time.time() + self.IP_POLL_TIMEOUT

        while pending and time.time() < deadline and not self._should_stop():
            for sid in list(pending.keys()):
                try:
                    ip = self._poll_server_ip(sid)
                    if ip:
                        results.append(ProviderResult(ip=ip, resource_id=str(sid), region=region))
                        del pending[sid]
                except RuntimeError as e:
                    log.warning(f"Reg.ru: сервер #{sid} ошибка: {e}")
                    del pending[sid]
                    delete_queue.append(sid)

            if pending:
                time.sleep(self.IP_POLL_INTERVAL + random.uniform(-0.5, 1.0))

        # Удаляем серверы, которые не дали IP до таймаута
        for sid in pending:
            delete_queue.append(sid)

        # Важный барьер: перед возвратом из батча гарантируем, что все "лишние" серверы удалены.
        for sid in delete_queue:
            try:
                self._remove_server(sid)
            except Exception as e:
                log.warning("Reg.ru: не удалось удалить #%s: %s", sid, e)

        return results

    def _server_release_ids(self, server_id: int) -> list[int]:
        """ID плавающих IP для releaseFloatingIPs (пустой список часто не снимает FIP с сервера)."""
        fip_ids: list[int] = []
        try:
            data = self._graphql(
                "serverFloatingIds",
                self.SERVER_FLOATING_IDS_QUERY,
                {"serverId": server_id},
            )
            srv = data.get("server", {}) or {}
            if not isinstance(srv, dict):
                return fip_ids
            for fip in srv.get("floatingIPs") or []:
                if not isinstance(fip, dict):
                    continue
                fid = fip.get("id")
                if fid is None:
                    continue
                try:
                    fip_ids.append(int(fid))
                except (TypeError, ValueError):
                    pass
        except Exception as e:
            log.debug("Reg.ru: не удалось прочитать FIP для #%s: %s", server_id, e)
        return fip_ids

    def _remove_server_once(
        self,
        server_id: int,
        *,
        release_fips: list[int],
        release_vols: list[int],
    ) -> None:
        variables = {
            "serverId": server_id,
            "releaseFloatingIPs": release_fips,
            "releaseVolumes": release_vols,
        }
        data = self._graphql("removeServer", self.REMOVE_SERVER_MUTATION, variables,
                             is_mutation=True)
        remove_result = data.get("server", {}).get("remove", {}) or {}
        tn = str(remove_result.get("__typename", ""))
        if tn and tn not in ("Server", ""):
            msg = remove_result.get("message") or tn
            raise RuntimeError(f"removeServer: {msg}")
        if remove_result.get("message") and not remove_result.get("id"):
            raise RuntimeError(f"removeServer: {remove_result['message']}")
        log.info("Reg.ru: removeServer #%s (FIP=%s vol=%s)", server_id, release_fips, release_vols)

    @staticmethod
    def _is_server_not_found_error(err: Exception | str) -> bool:
        txt = str(err).lower()
        return any(
            k in txt
            for k in (
                "servernotfound",
                "server not found",
                "не найден",
                "does not exist",
                "not found",
            )
        )

    def _is_server_deleted(self, server_id: int) -> bool:
        """
        Проверка фактического удаления сервера.
        True: сервер уже удалён/недоступен для query.
        """
        try:
            data = self._graphql("server", self.SERVER_QUERY, {"serverId": server_id})
        except Exception as e:
            msg = str(e).lower()
            if any(x in msg for x in ("not found", "не найден", "unknown", "does not exist")):
                return True
            return False
        srv = data.get("server", {})
        if not isinstance(srv, dict) or not srv.get("id"):
            return True
        status = str(srv.get("status", "")).lower()
        floating = srv.get("floatingIPs") or []
        if status == "deleted":
            return True
        # Для удаления важно, чтобы Floating IP уже отцепился.
        if status in ("deleting",) and not floating:
            return True
        return False

    def _wait_server_deleted(self, server_id: int, timeout_sec: int) -> None:
        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            if self._is_server_deleted(server_id):
                return
            if self._should_stop():
                break
            time.sleep(self.DELETE_WAIT_POLL_SEC)
        raise RuntimeError(f"сервер #{server_id} не удалился за {timeout_sec}с")

    def _remove_server(self, server_id: int):
        """Удаляет сервер: сначала узнаём FIP/volume id, несколько попыток (API и провижнинг)."""
        last_err: Optional[Exception] = None
        for attempt in range(5):
            if self._should_stop() and attempt > 0:
                break
            try:
                fips = self._server_release_ids(server_id)
                self._remove_server_once(server_id, release_fips=fips, release_vols=[])
                self._wait_server_deleted(server_id, timeout_sec=self.DELETE_WAIT_TIMEOUT)
                return
            except Exception as e:
                if self._is_server_not_found_error(e):
                    log.info("Reg.ru: сервер #%s уже удалён (ServerNotFound)", server_id)
                    return
                last_err = e
                logfn = log.warning if attempt >= 2 else log.debug
                logfn(
                    "Reg.ru: remove #%s попытка %s/5: %s",
                    server_id,
                    attempt + 1,
                    e,
                )
                time.sleep(min(2.0 * (attempt + 1), 12.0) + random.uniform(0.3, 1.2))
        if last_err:
            raise last_err


    def delete_ip(self, resource_id: str):
        """Удаляет сервер по resource_id (serverId). IP освобождается вместе с сервером."""
        try:
            server_id = int(resource_id)
        except (ValueError, TypeError):
            log.warning(f"Reg.ru: невалидный resource_id для удаления: {resource_id}")
            return
        self._remove_server(server_id)


REGRU_SUBNETS = (
    "79.174.91.0/24,79.174.92.0/24,79.174.93.0/24,79.174.94.0/24,79.174.95.0/24,"
    "31.31.196.0/24,31.31.197.0/24,31.31.198.0/24,"
    "37.140.192.0/24,37.140.193.0/24,37.140.194.0/24,37.140.195.0/24,"
    "213.189.204.0/24"
)
