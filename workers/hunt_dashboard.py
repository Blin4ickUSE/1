"""Одно сообщение со сводкой по всем аккаунтам; правка с тем же шагом, что пауза охоты."""

from __future__ import annotations

import asyncio
import html
import logging
from typing import Any, Optional

from telegram.constants import ParseMode

from workers.yandex_cloud import HUNT_LOOP_PAUSE_SEC

log = logging.getLogger(__name__)


class HuntDashboard:
    def __init__(
        self,
        bot,
        chat_id: int,
        account_labels: list[tuple[int, str]],
    ):
        """
        account_labels: (account_id, display_name) — пустое имя даёт подпись «Аккаунт #id».
        """
        self.bot = bot
        self.chat_id = chat_id
        self.ids_ordered = sorted(aid for aid, _ in account_labels)
        self.labels: dict[int, str] = {}
        for aid, name in account_labels:
            n = (name or "").strip()
            self.labels[aid] = n if n else f"Аккаунт #{aid}"
        self.lock = asyncio.Lock()
        self.stats: dict[int, dict[str, Any]] = {
            aid: {"attempts": 0, "hits": 0, "error": None} for aid in self.ids_ordered
        }
        self.message_id: Optional[int] = None
        self._refresh_task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()

    def _format_html(self) -> str:
        lines = []
        for aid in self.ids_ordered:
            label = self.labels[aid]
            st = self.stats[aid]
            err = st.get("error")
            if err:
                lines.append(f"❗ {html.escape(label, quote=False)}. {html.escape(err, quote=False)}")
            else:
                lines.append(
                    f"🔹 {html.escape(label, quote=False)}. Попыток: {st['attempts']}. Попаданий: {st['hits']}"
                )
        return "\n".join(lines)

    async def start(self) -> None:
        text = self._format_html()
        m = await self.bot.send_message(
            self.chat_id,
            text,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )
        self.message_id = m.message_id
        self._refresh_task = asyncio.create_task(self._refresh_loop())

    async def _refresh_loop(self) -> None:
        while not self._stop.is_set():
            await asyncio.sleep(HUNT_LOOP_PAUSE_SEC)
            if self._stop.is_set():
                break
            await self._edit_safe()

    async def _edit_safe(self) -> None:
        if self.message_id is None:
            return
        async with self.lock:
            txt = self._format_html()
        try:
            await self.bot.edit_message_text(
                chat_id=self.chat_id,
                message_id=self.message_id,
                text=txt,
                parse_mode=ParseMode.HTML,
            )
        except Exception as e:
            if "message is not modified" not in str(e).lower():
                log.debug("dashboard edit: %s", e)

    async def push_update(self) -> None:
        await self._edit_safe()

    async def inc_attempt(self, account_id: int) -> None:
        async with self.lock:
            st = self.stats.get(account_id)
            if st is not None and st.get("error") is None:
                st["attempts"] += 1

    async def inc_hit(self, account_id: int) -> None:
        async with self.lock:
            st = self.stats.get(account_id)
            if st is not None:
                st["hits"] += 1

    async def set_error(self, account_id: int, message: str) -> None:
        async with self.lock:
            st = self.stats.get(account_id)
            if st is not None:
                st["error"] = message

    async def close(self) -> None:
        self._stop.set()
        if self._refresh_task and not self._refresh_task.done():
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except asyncio.CancelledError:
                pass
        self._refresh_task = None
