"""Сценарии Yandex Cloud: добавление аккаунта (OAuth → каталог → зона → шаблоны) и запуск поиска IP."""

from __future__ import annotations

import asyncio
import hashlib
import html
import importlib
import logging

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

import database as db
import encryption
from workers import yandex_cloud as yc
from workers.hunt_dashboard import HuntDashboard

log = logging.getLogger(__name__)

FLOW_YC_OAUTH = "yc_oauth"
FLOW_YC_NAME = "yc_name"
FLOW_YC_TARGETS = "yc_targets"
FLOW_YC_EDIT_RENAME = "yc_edit_rename"

YC_DISPLAY_NAME_MAX = 40


def _yandex_identity_key(oauth: str, folder_id: str) -> str:
    return hashlib.sha256(f"{oauth.strip()}\n{folder_id.strip()}".encode()).hexdigest()


def _clear_yc_edit_flow(context: ContextTypes.DEFAULT_TYPE) -> None:
    for k in ("yc_edit_account_id",):
        context.user_data.pop(k, None)
    if context.user_data.get("add_flow") == FLOW_YC_EDIT_RENAME:
        context.user_data.pop("add_flow", None)


def _bot_mod():
    """Поздний импорт, чтобы избежать цикла с bot.py."""
    return importlib.import_module("bot")


def _clear_yc_flow(context: ContextTypes.DEFAULT_TYPE) -> None:
    ud = context.user_data
    for k in (
        "add_flow",
        "yc_oauth",
        "yc_folders",
        "yc_folder_id",
        "yc_folder_label",
        "yc_zone",
        "yc_display_name",
    ):
        ud.pop(k, None)


def app_main_text_with_hunts(user_id: int) -> str:
    n = yc.active_hunt_count(user_id)
    return _bot_mod().build_app_main_text(n)


async def cmd_stop_search(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_user or not update.message:
        return
    uid = update.effective_user.id
    if not _bot_mod().user_has_subscription(uid):
        await update.message.reply_text("Команда доступна с подпиской.")
        return
    if yc.cancel_hunt(uid):
        await update.message.reply_text(
            "Поиск остановлен (все параллельные потоки Yandex). "
            "На главной снова будет «Запустить скрипт» — откройте /start или то же меню."
        )
    else:
        await update.message.reply_text("Активного поиска нет.")


def add_provider_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("Yandex Cloud", callback_data="add_provider_yc")],
            [InlineKeyboardButton("◀ Назад", callback_data="app_main")],
        ]
    )


def yandex_folder_keyboard(folders: list[dict], page: int = 0) -> InlineKeyboardMarkup:
    per_page = 8
    start = page * per_page
    chunk = folders[start : start + per_page]
    rows = []
    for i, f in enumerate(chunk):
        idx = start + i
        label = f.get("name") or f["id"]
        if len(label) > 28:
            label = label[:25] + "…"
        rows.append([InlineKeyboardButton(label, callback_data=f"ycf:{idx}")])
    nav = []
    if start > 0:
        nav.append(InlineKeyboardButton("◀", callback_data=f"ycfp:{page - 1}"))
    if start + per_page < len(folders):
        nav.append(InlineKeyboardButton("▶", callback_data=f"ycfp:{page + 1}"))
    if nav:
        rows.append(nav)
    rows.append([InlineKeyboardButton("❌ Отмена", callback_data="yc_cancel")])
    return InlineKeyboardMarkup(rows)


def yandex_zone_keyboard() -> InlineKeyboardMarkup:
    rows = []
    for i, z in enumerate(yc.ZONES):
        rows.append([InlineKeyboardButton(z, callback_data=f"ycz:{i}")])
    rows.append([InlineKeyboardButton("◀ Назад к каталогам", callback_data="yc_back_folders")])
    rows.append([InlineKeyboardButton("❌ Отмена", callback_data="yc_cancel")])
    return InlineKeyboardMarkup(rows)


def yandex_name_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("◀ Назад к зонам", callback_data="yc_back_zones")],
            [InlineKeyboardButton("❌ Отмена", callback_data="yc_cancel")],
        ]
    )


def yandex_targets_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("Все операторы (51.250.)", callback_data="ycp:all")],
            [InlineKeyboardButton("Почти все операторы (84.201.)", callback_data="ycp:almost")],
            [InlineKeyboardButton("◀ Назад к имени", callback_data="yc_back_name")],
            [InlineKeyboardButton("❌ Отмена", callback_data="yc_cancel")],
        ]
    )


def yandex_platform_menu_keyboard(user_id: int) -> InlineKeyboardMarkup:
    accounts = db.list_yandex_accounts(user_id)
    rows: list[list[InlineKeyboardButton]] = []
    if accounts:
        rows.append(
            [
                InlineKeyboardButton(
                    f"▶️ Запустить все ({len(accounts)} акк.)",
                    callback_data="ycrun_all",
                )
            ]
        )
    rows.append([InlineKeyboardButton("➕ Новый аккаунт Yandex", callback_data="add_provider_yc")])
    rows.append([InlineKeyboardButton("◀ Назад к платформам", callback_data="run_script")])
    return InlineKeyboardMarkup(rows)


def my_accounts_keyboard(user_id: int) -> InlineKeyboardMarkup:
    accounts = db.list_yandex_accounts(user_id)
    rows = []
    for acc_id, display_name, summary in accounts:
        dn = (display_name or "").strip()
        label = dn if dn else f"YC #{acc_id}"
        tail = summary[:28] + "…" if len(summary) > 28 else summary
        btn = f"{label} · {tail}" if tail else label
        if len(btn) > 64:
            btn = btn[:61] + "…"
        rows.append(
            [
                InlineKeyboardButton(
                    btn,
                    callback_data=f"ycinfo:{acc_id}",
                )
            ]
        )
    rows.append([InlineKeyboardButton("◀ Назад", callback_data="app_main")])
    return InlineKeyboardMarkup(rows)


def _account_actions_keyboard(acc_id: int, *, hunt_active: bool) -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton("✏️ Переименовать", callback_data=f"ycren:{acc_id}")],
    ]
    if hunt_active:
        rows.append(
            [
                InlineKeyboardButton(
                    "🌍 Сменить зону (остановите поиск)",
                    callback_data="ycnoop",
                )
            ]
        )
        rows.append(
            [
                InlineKeyboardButton(
                    "🗑 Удалить (остановите поиск)",
                    callback_data="ycnoop",
                )
            ]
        )
    else:
        rows.append([InlineKeyboardButton("🌍 Сменить зону", callback_data=f"yczon:{acc_id}")])
        rows.append([InlineKeyboardButton("🗑 Удалить", callback_data=f"ycdel:{acc_id}")])
    rows.append([InlineKeyboardButton("◀ К списку аккаунтов", callback_data="my_accounts")])
    return InlineKeyboardMarkup(rows)


def _zone_pick_for_account_keyboard(acc_id: int) -> InlineKeyboardMarkup:
    rows = []
    for i, z in enumerate(yc.ZONES):
        rows.append([InlineKeyboardButton(z, callback_data=f"yczac:{acc_id}:{i}")])
    rows.append([InlineKeyboardButton("◀ Назад", callback_data=f"ycinf:{acc_id}")])
    return InlineKeyboardMarkup(rows)


async def _account_detail_html(uid: int, acc_id: int) -> tuple[str, bool] | None:
    """(html, hunt_active) или None."""
    blob = db.get_yandex_account_row(uid, acc_id)
    if not blob:
        return None
    try:
        c = encryption.decrypt_json(blob)
    except encryption.EncryptionError:
        return None
    meta = None
    for aid, dn, summ in db.list_yandex_accounts(uid):
        if aid == acc_id:
            meta = (dn, summ)
            break
    if not meta:
        return None
    display_name, summary = meta
    dn = (display_name or "").strip()
    title = html.escape(dn if dn else f"YC #{acc_id}", quote=False)
    zone = html.escape(str(c.get("zone") or ""), quote=False)
    folder_id = html.escape(str(c.get("folder_id") or ""), quote=False)
    targets = c.get("targets") or []
    tg = html.escape(", ".join(str(x) for x in targets[:12]), quote=False)
    if len(targets) > 12:
        tg += "…"
    summ_esc = html.escape(summary, quote=False)
    hunt_active = yc.active_hunt_count(uid) > 0
    extra = (
        "\n\n<i>Чтобы сменить зону или удалить аккаунт, сначала остановите поиск "
        "(«Остановить скрипт» или /stop_search).</i>"
        if hunt_active
        else ""
    )
    text = (
        f"<b>{title}</b>\n\n"
        f"Кратко: <code>{summ_esc}</code>\n"
        f"Каталог (folder id): <code>{folder_id}</code>\n"
        f"Зона: <code>{zone}</code>\n"
        f"Шаблоны: <code>{tg}</code>"
        f"{extra}"
    )
    return text, hunt_active


async def _execute_yandex_parallel_hunt(
    bot,
    uid: int,
    chat_id: int,
    pairs: list[tuple[int, dict]],
    labels: list[tuple[int, str]],
) -> None:
    db.set_yandex_active_hunt(uid, chat_id, [p[0] for p in pairs])
    dash = HuntDashboard(bot, chat_id, labels)
    await dash.start()
    try:

        async def send_html(t: str) -> None:
            await bot.send_message(chat_id=chat_id, text=t, parse_mode=ParseMode.HTML)

        await yc.run_all_yandex_hunts(
            chat_id=chat_id,
            accounts=pairs,
            send_message=send_html,
            dashboard=dash,
        )
    finally:
        await dash.close()


async def resume_stored_yandex_hunts(bot) -> None:
    """После перезапуска бота продолжает охоту по записям в БД."""
    rows = db.list_yandex_active_hunts()
    if not rows:
        return
    log.info("Восстановление охот Yandex из БД: %s пользователей", len(rows))
    await asyncio.sleep(1.0)
    for uid, chat_id, acc_ids in rows:
        id_set = set(acc_ids)
        by_id: dict[int, tuple[str, dict]] = {}
        for acc_id, display_name, _summ in db.list_yandex_accounts(uid):
            if acc_id not in id_set:
                continue
            blob = db.get_yandex_account_row(uid, acc_id)
            if not blob:
                continue
            try:
                creds = encryption.decrypt_json(blob)
            except encryption.EncryptionError:
                log.warning("resume hunt: skip acc %s user %s (decrypt)", acc_id, uid)
                continue
            by_id[acc_id] = (display_name or "", creds)
        pairs: list[tuple[int, dict]] = []
        labels: list[tuple[int, str]] = []
        for aid in acc_ids:
            if aid not in by_id:
                continue
            dn, cred = by_id[aid]
            pairs.append((aid, cred))
            labels.append((aid, dn))
        if not pairs:
            log.warning("resume hunt: user %s — нет валидных аккаунтов, снимаю запись", uid)
            db.clear_yandex_active_hunt(uid)
            continue
        ok = yc.schedule_hunt(
            uid,
            lambda u=uid, c=chat_id, p=pairs, l=labels, b=bot: _execute_yandex_parallel_hunt(b, u, c, p, l),
        )
        if not ok:
            log.warning("resume hunt: user %s — уже есть задача, пропуск", uid)


async def _finalize_yandex_account(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    *,
    targets: list[str],
) -> None:
    q = update.callback_query
    msg = update.message
    ud = context.user_data
    oauth = ud.get("yc_oauth")
    folder_id = ud.get("yc_folder_id")
    folder_label = ud.get("yc_folder_label") or folder_id
    zone = ud.get("yc_zone")
    uid = update.effective_user.id if update.effective_user else None
    if not uid or not oauth or not folder_id or not zone:
        _clear_yc_flow(context)
        text = "Сессия добавления сброшена. Начните снова через «Добавить аккаунт»."
        if q and q.message:
            await q.message.edit_text(text)
        elif msg:
            await msg.reply_text(text)
        return

    creds = {
        "oauth": oauth,
        "folder_id": folder_id,
        "zone": zone,
        "targets": targets,
        "important_ip": "",
    }
    try:
        blob = encryption.encrypt_json(creds)
    except encryption.EncryptionError as e:
        err = html.escape(str(e))
        if q and q.message:
            await q.message.edit_text(f"Ошибка шифрования: {err}")
        elif msg:
            await msg.reply_text(f"Ошибка шифрования: {err}")
        return

    summary = f"{folder_label} · {zone}"
    display_name = (ud.get("yc_display_name") or "").strip()[:YC_DISPLAY_NAME_MAX]
    ik = _yandex_identity_key(oauth, folder_id)
    if db.yandex_identity_taken(uid, ik):
        err = (
            "Такой аккаунт уже добавлен: <b>тот же токен и тот же каталог</b>.\n"
            "Можно добавить другой каталог с тем же токеном или другой токен."
        )
        if q and q.message:
            await q.message.edit_text(err, parse_mode=ParseMode.HTML)
        elif msg:
            await msg.reply_text(err, parse_mode=ParseMode.HTML)
        return
    db.insert_yandex_account(uid, blob, summary, display_name, ik)
    _clear_yc_flow(context)
    name_line = (
        f"Имя: <b>{html.escape(display_name)}</b>\n" if display_name else ""
    )
    done = (
        "<b>Аккаунт Yandex Cloud сохранён.</b>\n\n"
        + name_line
        + f"Каталог: {html.escape(str(folder_label))}\n"
        f"Зона: <code>{html.escape(zone)}</code>\n"
        f"Шаблоны: <code>{html.escape(', '.join(targets))}</code>"
    )
    bm = _bot_mod()
    if q and q.message:
        await q.message.edit_text(done, parse_mode=ParseMode.HTML)
        await context.bot.send_message(
            chat_id=q.message.chat_id,
            text=app_main_text_with_hunts(uid),
            parse_mode=ParseMode.HTML,
            reply_markup=bm.subscribed_main_keyboard(uid),
        )
    elif msg:
        await msg.reply_text(done, parse_mode=ParseMode.HTML)
        await context.bot.send_message(
            chat_id=msg.chat_id,
            text=app_main_text_with_hunts(uid),
            parse_mode=ParseMode.HTML,
            reply_markup=bm.subscribed_main_keyboard(uid),
        )


async def handle_yandex_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """Обрабатывает текст в сценарии добавления Yandex. True = поглощено."""
    if not update.effective_user or not update.message or not update.message.text:
        return False
    uid = update.effective_user.id
    if not _bot_mod().user_has_subscription(uid):
        return False
    flow = context.user_data.get("add_flow")
    text = update.message.text.strip()

    if flow == FLOW_YC_EDIT_RENAME:
        acc_id = context.user_data.get("yc_edit_account_id")
        if not isinstance(acc_id, int):
            _clear_yc_edit_flow(context)
            return False
        name = text[:YC_DISPLAY_NAME_MAX].strip()
        if not name:
            await update.message.reply_text(
                f"Введите непустое имя (до {YC_DISPLAY_NAME_MAX} символов)."
            )
            return True
        if not db.update_yandex_display_name(uid, acc_id, name):
            await update.message.reply_text("Аккаунт не найден.")
            _clear_yc_edit_flow(context)
            return True
        _clear_yc_edit_flow(context)
        await update.message.reply_text(
            f"Имя обновлено: <b>{html.escape(name, quote=False)}</b>",
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("◀ К аккаунту", callback_data=f"ycinf:{acc_id}")]]
            ),
        )
        return True

    if flow == FLOW_YC_OAUTH:
        token = _extract_oauth_token(text)
        if len(token) < 10:
            await update.message.reply_text("Похоже на неверный токен. Пришлите access_token целиком.")
            return True
        try:
            iam = await yc.exchange_oauth_for_iam(token)
        except yc.YandexCloudError as e:
            await update.message.reply_text(f"Не принято: {html.escape(str(e)[:400])}", parse_mode=ParseMode.HTML)
            return True
        try:
            folders = await yc.list_all_folders(iam)
        except yc.YandexCloudError as e:
            await update.message.reply_text(f"Не удалось получить каталоги: {html.escape(str(e)[:400])}")
            return True
        if not folders:
            await update.message.reply_text("Каталогов не найдено. Проверьте права аккаунта в Yandex Cloud.")
            return True
        context.user_data["yc_oauth"] = token
        context.user_data["yc_folders"] = folders
        context.user_data.pop("add_flow", None)
        chat_id = update.effective_chat.id
        try:
            await update.message.delete()
        except Exception as e:
            log.warning("Не удалось удалить сообщение с токеном: %s", e)
        await context.bot.send_message(
            chat_id=chat_id,
            text="<b>Yandex Cloud — шаг 2/5</b>\n\nВыберите каталог (folder):",
            parse_mode=ParseMode.HTML,
            reply_markup=yandex_folder_keyboard(folders, 0),
        )
        return True

    if flow == FLOW_YC_NAME:
        name = text[:YC_DISPLAY_NAME_MAX].strip()
        if not name:
            await update.message.reply_text(
                f"Введите непустое имя (до {YC_DISPLAY_NAME_MAX} символов) или нажмите «Назад» в меню выше."
            )
            return True
        context.user_data["yc_display_name"] = name
        context.user_data["add_flow"] = FLOW_YC_TARGETS
        await update.message.reply_text(
            "<b>Yandex Cloud — шаг 5/5</b>\n\n"
            "Укажите, какие адреса считать «пойманными».\n\n"
            "Можно отправить текстом через запятую:\n"
            "• префикс: <code>51.250.</code>\n"
            "• подсеть: <code>51.250.0.0/17</code>\n"
            "• диапазон: <code>51.250.0.0-51.250.255.255</code>\n\n"
            "Или выберите готовый вариант:",
            parse_mode=ParseMode.HTML,
            reply_markup=yandex_targets_keyboard(),
        )
        return True

    if flow == FLOW_YC_TARGETS:
        targets = yc.parse_targets_line(text)
        if not targets:
            await update.message.reply_text("Укажите хотя бы один шаблон через запятую.")
            return True
        await _finalize_yandex_account(update, context, targets=targets)
        return True

    return False


def _extract_oauth_token(raw: str) -> str:
    s = raw.strip()
    if "access_token=" in s:
        part = s.split("access_token=", 1)[1]
        return part.split("&", 1)[0].strip()
    return s


async def handle_yandex_callback(update: Update, context: ContextTypes.DEFAULT_TYPE, data: str) -> bool:
    """Возвращает True, если callback обработан."""
    q = update.callback_query
    if not q or not q.message or not update.effective_user:
        return False
    user = update.effective_user
    uid = user.id
    bm = _bot_mod()

    if not bm.user_has_subscription(uid):
        await q.answer("Нужна подписка.", show_alert=True)
        return True

    if data == "add_provider_yc":
        if db.count_yandex_accounts(uid) >= db.MAX_YANDEX_ACCOUNTS_PER_USER:
            await q.answer("Лимит 10 аккаунтов Yandex.", show_alert=True)
            return True
        await q.answer()
        context.user_data["add_flow"] = FLOW_YC_OAUTH
        await q.message.edit_text(
            "<b>Yandex Cloud — шаг 1/5</b>\n\n"
            f'<a href="{yc.YC_OAUTH_AUTHORIZE_URL}">Откройте ссылку и авторизуйтесь в нужном аккаунте:</a>\n'
            f'https://oauth.yandex.ru/authorize?response_type=token&client_id=1a6990aa636648e9b2ef855fa7bec2fb\n\n'
            "<i>После авторизации вы получите токен, который нужно отправить сюда.</i>",
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="yc_cancel")]]),
        )
        return True

    if data == "yc_cancel":
        await q.answer()
        _clear_yc_flow(context)
        _clear_yc_edit_flow(context)
        await q.message.edit_text(
            app_main_text_with_hunts(uid),
            parse_mode=ParseMode.HTML,
            reply_markup=bm.subscribed_main_keyboard(uid),
        )
        return True

    if data.startswith("ycfp:"):
        page = int(data.split(":")[1])
        folders = context.user_data.get("yc_folders") or []
        if not folders:
            await q.answer("Сессия устарела.", show_alert=True)
            return True
        await q.answer()
        await q.message.edit_reply_markup(reply_markup=yandex_folder_keyboard(folders, page))
        return True

    if data.startswith("yczac:"):
        parts = data.split(":")
        if len(parts) != 3:
            await q.answer("Неверный запрос.", show_alert=True)
            return True
        try:
            acc_id = int(parts[1])
            zi = int(parts[2])
        except ValueError:
            await q.answer("Неверный запрос.", show_alert=True)
            return True
        if zi < 0 or zi >= len(yc.ZONES):
            await q.answer("Неверная зона.", show_alert=True)
            return True
        if yc.active_hunt_count(uid) > 0:
            await q.answer("Сначала остановите поиск.", show_alert=True)
            return True
        blob = db.get_yandex_account_row(uid, acc_id)
        if not blob:
            await q.answer("Аккаунт не найден.", show_alert=True)
            return True
        try:
            creds = encryption.decrypt_json(blob)
        except encryption.EncryptionError:
            await q.answer("Ошибка чтения аккаунта.", show_alert=True)
            return True
        new_zone = yc.ZONES[zi]
        creds["zone"] = new_zone
        summ_row = None
        for aid, _dn, sm in db.list_yandex_accounts(uid):
            if aid == acc_id:
                summ_row = sm
                break
        if not summ_row:
            await q.answer("Аккаунт не найден.", show_alert=True)
            return True
        left, sep, _oldz = summ_row.rpartition(" · ")
        folder_label = left if sep else (creds.get("folder_id") or "")
        new_summary = f"{folder_label} · {new_zone}"
        try:
            new_blob = encryption.encrypt_json(creds)
        except Exception as e:
            log.warning("encrypt after zone change: %s", e)
            await q.answer("Ошибка сохранения.", show_alert=True)
            return True
        if not db.update_yandex_account_blob(uid, acc_id, new_blob, new_summary):
            await q.answer("Не удалось сохранить.", show_alert=True)
            return True
        await q.answer("Зона обновлена.")
        det = await _account_detail_html(uid, acc_id)
        if det:
            body, hunt_active = det
            await q.message.edit_text(
                body,
                parse_mode=ParseMode.HTML,
                reply_markup=_account_actions_keyboard(acc_id, hunt_active=hunt_active),
            )
        return True

    if data.startswith("ycf:") and not data.startswith("ycfp:"):
        idx = int(data.split(":")[1])
        folders = context.user_data.get("yc_folders") or []
        if idx < 0 or idx >= len(folders):
            await q.answer("Неверный каталог.", show_alert=True)
            return True
        f = folders[idx]
        context.user_data["yc_folder_id"] = f["id"]
        context.user_data["yc_folder_label"] = f"{f.get('cloud_name', '')} / {f.get('name', '')}".strip(" /")
        await q.answer()
        await q.message.edit_text(
            "<b>Yandex Cloud — шаг 3/5</b>\n\nВыберите зону доступности:",
            parse_mode=ParseMode.HTML,
            reply_markup=yandex_zone_keyboard(),
        )
        return True

    if data == "yc_back_folders":
        folders = context.user_data.get("yc_folders") or []
        if not folders:
            await q.answer()
            return True
        await q.answer()
        await q.message.edit_text(
            "<b>Yandex Cloud — шаг 2/5</b>\n\nВыберите каталог (folder):",
            parse_mode=ParseMode.HTML,
            reply_markup=yandex_folder_keyboard(folders, 0),
        )
        return True

    if data.startswith("ycz:"):
        zi = int(data.split(":")[1])
        if zi < 0 or zi >= len(yc.ZONES):
            await q.answer("Неверная зона.", show_alert=True)
            return True
        context.user_data["yc_zone"] = yc.ZONES[zi]
        context.user_data.pop("yc_display_name", None)
        context.user_data["add_flow"] = FLOW_YC_NAME
        await q.answer()
        await q.message.edit_text(
            "<b>Yandex Cloud — шаг 4/5</b>\n\n"
            "Придумайте <b>короткое имя</b> аккаунта (как будет отображаться в списке и при поиске).\n"
            f"Отправьте текстом, до {YC_DISPLAY_NAME_MAX} символов.",
            parse_mode=ParseMode.HTML,
            reply_markup=yandex_name_keyboard(),
        )
        return True

    if data == "yc_back_zones":
        await q.answer()
        await q.message.edit_text(
            "<b>Yandex Cloud — шаг 3/5</b>\n\nВыберите зону доступности:",
            parse_mode=ParseMode.HTML,
            reply_markup=yandex_zone_keyboard(),
        )
        return True

    if data == "yc_back_name":
        await q.answer()
        context.user_data.pop("yc_display_name", None)
        context.user_data["add_flow"] = FLOW_YC_NAME
        await q.message.edit_text(
            "<b>Yandex Cloud — шаг 4/5</b>\n\n"
            "Придумайте <b>короткое имя</b> аккаунта (как будет отображаться в списке и при поиске).\n"
            f"Отправьте текстом, до {YC_DISPLAY_NAME_MAX} символов.",
            parse_mode=ParseMode.HTML,
            reply_markup=yandex_name_keyboard(),
        )
        return True

    if data == "ycp:all":
        await q.answer()
        await _finalize_yandex_account(update, context, targets=[yc.PRESET_ALL_OPERATORS])
        return True

    if data == "ycp:almost":
        await q.answer()
        await _finalize_yandex_account(update, context, targets=[yc.PRESET_ALMOST_ALL])
        return True

    if data == "ycrun_all":
        if yc.active_hunt_count(uid) > 0:
            await q.answer(
                "Уже идёт поиск. Остановите кнопкой «Остановить скрипт» на главной или /stop_search",
                show_alert=True,
            )
            return True
        pairs: list[tuple[int, dict]] = []
        labels: list[tuple[int, str]] = []
        for acc_id, display_name, _summary in db.list_yandex_accounts(uid):
            blob = db.get_yandex_account_row(uid, acc_id)
            if not blob:
                continue
            try:
                pairs.append((acc_id, encryption.decrypt_json(blob)))
                labels.append((acc_id, display_name or ""))
            except encryption.EncryptionError:
                log.warning("Не удалось расшифровать Yandex акк %s для user %s", acc_id, uid)
        if not pairs:
            await q.answer("Нет сохранённых аккаунтов.", show_alert=True)
            return True
        chat_id = q.message.chat_id

        ok = yc.schedule_hunt(
            uid,
            lambda: _execute_yandex_parallel_hunt(context.bot, uid, chat_id, pairs, labels),
        )
        await q.message.edit_text(
            app_main_text_with_hunts(uid),
            parse_mode=ParseMode.HTML,
            reply_markup=bm.subscribed_main_keyboard(uid),
        )
        if ok:
            await q.answer()
        else:
            await q.answer("Поиск уже запущен.", show_alert=True)
        return True

    if data == "ycnoop":
        await q.answer("Сначала остановите поиск.", show_alert=True)
        return True

    if data.startswith("ycren:"):
        try:
            acc_id = int(data.split(":", 1)[1])
        except (IndexError, ValueError):
            await q.answer("Неверный запрос.", show_alert=True)
            return True
        if db.get_yandex_account_row(uid, acc_id) is None:
            await q.answer("Аккаунт не найден.", show_alert=True)
            return True
        await q.answer()
        context.user_data["add_flow"] = FLOW_YC_EDIT_RENAME
        context.user_data["yc_edit_account_id"] = acc_id
        await q.message.edit_text(
            "<b>Переименование</b>\n\n"
            f"Отправьте новое имя аккаунта текстом (до {YC_DISPLAY_NAME_MAX} символов).",
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("◀ Отмена", callback_data=f"ycinf:{acc_id}")]]
            ),
        )
        return True

    if data.startswith("yczon:"):
        try:
            acc_id = int(data.split(":", 1)[1])
        except (IndexError, ValueError):
            await q.answer("Неверный запрос.", show_alert=True)
            return True
        if yc.active_hunt_count(uid) > 0:
            await q.answer("Сначала остановите поиск.", show_alert=True)
            return True
        if db.get_yandex_account_row(uid, acc_id) is None:
            await q.answer("Аккаунт не найден.", show_alert=True)
            return True
        await q.answer()
        await q.message.edit_text(
            "<b>Смена зоны</b>\n\nВыберите новую зону доступности:",
            parse_mode=ParseMode.HTML,
            reply_markup=_zone_pick_for_account_keyboard(acc_id),
        )
        return True

    if data.startswith("ycdel:"):
        try:
            acc_id = int(data.split(":", 1)[1])
        except (IndexError, ValueError):
            await q.answer("Неверный запрос.", show_alert=True)
            return True
        if yc.active_hunt_count(uid) > 0:
            await q.answer("Сначала остановите поиск.", show_alert=True)
            return True
        if db.get_yandex_account_row(uid, acc_id) is None:
            await q.answer("Аккаунт не найден.", show_alert=True)
            return True
        await q.answer()
        await q.message.edit_text(
            "<b>Удалить аккаунт?</b>\n\nЭто действие необратимо.",
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup(
                [
                    [InlineKeyboardButton("✅ Да, удалить", callback_data=f"ycdok:{acc_id}")],
                    [InlineKeyboardButton("Отмена", callback_data=f"ycinf:{acc_id}")],
                ]
            ),
        )
        return True

    if data.startswith("ycdok:"):
        try:
            acc_id = int(data.split(":", 1)[1])
        except (IndexError, ValueError):
            await q.answer("Неверный запрос.", show_alert=True)
            return True
        if yc.active_hunt_count(uid) > 0:
            await q.answer("Сначала остановите поиск.", show_alert=True)
            return True
        if not db.delete_yandex_account(uid, acc_id):
            await q.answer("Аккаунт не найден.", show_alert=True)
            return True
        await q.answer("Удалено.")
        n = db.count_yandex_accounts(uid)
        await q.message.edit_text(
            f"<b>Мои аккаунты</b> (Yandex Cloud: {n})\n\nАккаунт удалён.",
            parse_mode=ParseMode.HTML,
            reply_markup=my_accounts_keyboard(uid),
        )
        return True

    if data.startswith("ycinf:") or data.startswith("ycinfo:"):
        _, _, tail = data.partition(":")
        try:
            acc_id = int(tail)
        except ValueError:
            await q.answer("Неверный запрос.", show_alert=True)
            return True
        _clear_yc_edit_flow(context)
        det = await _account_detail_html(uid, acc_id)
        if not det:
            await q.answer("Аккаунт не найден.", show_alert=True)
            return True
        body, hunt_active = det
        await q.answer()
        await q.message.edit_text(
            body,
            parse_mode=ParseMode.HTML,
            reply_markup=_account_actions_keyboard(acc_id, hunt_active=hunt_active),
        )
        return True

    return False
