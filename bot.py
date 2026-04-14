"""Telegram-бот IPHunder."""

from __future__ import annotations

import atexit
import html
import logging
import os
import re
import sys
from pathlib import Path

from dotenv import load_dotenv
from telegram import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message, Update
from telegram.constants import ParseMode
from telegram.error import BadRequest, Conflict
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

import database as db
import encryption
import platega
import rst_core
import yandex_flow
from workers import yandex_cloud as yc

_PROJECT_DIR = Path(__file__).resolve().parent
_INSTANCE_LOCK_PATH = _PROJECT_DIR / ".bot_instance.lock"
_lock_fd: int | None = None

load_dotenv(_PROJECT_DIR / ".env")

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    level=logging.INFO,
)
logging.getLogger("httpx").setLevel(logging.WARNING)
log = logging.getLogger(__name__)


def _telegram_benign_bad_request(err: BaseException) -> bool:
    """Ошибки Telegram, после которых можно спокойно продолжать (не логируем как crash)."""
    if not isinstance(err, BadRequest):
        return False
    m = str(err).lower()
    return any(
        p in m
        for p in (
            "message is not modified",
            "message to edit not found",
            "message can't be edited",
            "query is too old",
            "query id is invalid",
        )
    )


async def safe_callback_answer(q: CallbackQuery, *args, **kwargs) -> None:
    try:
        await q.answer(*args, **kwargs)
    except BadRequest as e:
        if not _telegram_benign_bad_request(e):
            raise


async def safe_callback_edit_message(q: CallbackQuery, text: str, **kwargs) -> None:
    if not q.message:
        return
    try:
        await q.edit_message_text(text, **kwargs)
    except BadRequest as e:
        if not _telegram_benign_bad_request(e):
            raise


async def safe_message_edit_text(message: Message, text: str, **kwargs) -> None:
    try:
        await message.edit_text(text, **kwargs)
    except BadRequest as e:
        if not _telegram_benign_bad_request(e):
            raise


ACCESS_PRICE_RUB = 999.0
SUPPORT_HANDLE = "theflyke"
RETURN_URL = f"https://t.me/{SUPPORT_HANDLE}"

UUID_IN_CALLBACK = re.compile(
    r"^sbp_paid:([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$"
)


def _admin_id() -> int | None:
    raw = os.environ.get("ADMIN_ID", "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _is_admin(telegram_id: int) -> bool:
    aid = _admin_id()
    return aid is not None and telegram_id == aid


def build_guest_welcome_text() -> str:
    return (
        "<b>IPHunder</b>\n\n"
        "Помогаем быстро искать IP в белых списках\n"
        f"Если что-то непонятно, пиши в поддержку @{SUPPORT_HANDLE}\n\n"
        "<b>Активной подписки нет.</b> Нажми «Купить доступ», чтобы получить скрипт."
    )


def build_app_main_text(active_searches: int = 0) -> str:
    return (
        "<b>IPHunder</b>\n\n"
        "Помогаем быстро искать IP в белых списках\n"
        f"Если что-то непонятно, пиши в поддержку @{SUPPORT_HANDLE}\n\n"
        f"Активных поисков: {active_searches}"
    )


def total_active_hunt_count(telegram_id: int) -> int:
    return yc.active_hunt_count(telegram_id) + rst_core.active_rst_hunt_count(telegram_id)


def app_main_text(telegram_id: int) -> str:
    return build_app_main_text(total_active_hunt_count(telegram_id))


def build_purchase_intro_text() -> str:
    return (
        "<b>Купить доступ</b>\n\n"
        f"За <b>{int(ACCESS_PRICE_RUB)} ₽</b> вы получаете <b>скрипт навсегда</b> "
        "- без срока действия, с обновлениями по мере выхода.\n\n"
        "После оплаты нажмите <b>Я оплатил</b>, чтобы мы проверили платёж \n\n"
        "<b>Выберите способ оплаты:</b>"
    )


def build_sbp_payment_text(*, expires_hint: str | None = None) -> str:
    lines = [
        "<b>Оплата по СБП</b>",
        "",
        f"Сумма: <b>{int(ACCESS_PRICE_RUB)} ₽</b>",
        "",
        "1) Нажмите <b>«Перейти к оплате»</b> и оплатите по QR в приложении банка.",
        "2) Затем нажмите <b>Я оплатил</b> - бот запросит статус в Platega.",
    ]
    if expires_hint:
        lines.extend(["", f"⏱ Срок ссылки: <code>{expires_hint}</code>."])
    else:
        lines.extend(["", "⏱ Ссылка на оплату действует ограниченное время."])
    return "\n".join(lines)


def guest_main_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("Купить доступ", callback_data="buy_access")]]
    )


def subscribed_main_keyboard(telegram_id: int) -> InlineKeyboardMarkup:
    if total_active_hunt_count(telegram_id) > 0:
        first = InlineKeyboardButton("⏹ Остановить скрипт", callback_data="stop_script")
    else:
        first = InlineKeyboardButton("🚀 Запустить скрипт", callback_data="run_script")
    return InlineKeyboardMarkup(
        [
            [first],
            [InlineKeyboardButton("➕ Добавить аккаунт", callback_data="add_account")],
            [InlineKeyboardButton("📱 Мои аккаунты", callback_data="my_accounts")],
        ]
    )


def script_platform_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("Все", callback_data="plat_all"),
                InlineKeyboardButton("Yandex Cloud", callback_data="plat_yandex"),
            ],
            [
                InlineKeyboardButton("RegCloud", callback_data="plat_regcloud"),
                InlineKeyboardButton("Selectel", callback_data="plat_selectel"),
            ],
            [InlineKeyboardButton("◀ Назад", callback_data="app_main")],
        ]
    )


def purchase_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("Купить по СБП", callback_data="buy_sbp")],
            [InlineKeyboardButton("Купить криптой", url=f"https://t.me/{SUPPORT_HANDLE}")],
            [InlineKeyboardButton("◀ В главное меню", callback_data="main_menu")],
        ]
    )


def sbp_pay_keyboard(redirect_url: str, transaction_id: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("Перейти к оплате", url=redirect_url)],
            [InlineKeyboardButton("Я оплатил", callback_data=f"sbp_paid:{transaction_id}")],
            [InlineKeyboardButton("◀ Назад к способам оплаты", callback_data="purchase_menu")],
        ]
    )


def user_has_subscription(telegram_id: int) -> bool:
    row = db.get_user(telegram_id)
    return bool(row and row.has_subscription)


async def notify_admin_subscription_paid(
    bot,
    *,
    payer_id: int,
    from_user,
) -> None:
    admin = _admin_id()
    if admin is None or payer_id == admin:
        return
    username = from_user.username if from_user else None
    un = f"@{username}" if username else "без username"
    full = (from_user.full_name if from_user else "") or "—"
    text = (
        "<b>Оплата подписки</b>\n\n"
        f"Telegram ID: <code>{payer_id}</code>\n"
        f"Username: {html.escape(un)}\n"
        f"Имя: {html.escape(full)}"
    )
    try:
        await bot.send_message(chat_id=admin, text=text, parse_mode=ParseMode.HTML)
    except Exception:
        log.exception("Не удалось отправить уведомление админу об оплате")


def platega_credentials() -> tuple[str, str] | None:
    mid = os.environ.get("PLATEGA_MERCHANT_ID", "").strip()
    secret = os.environ.get("PLATEGA_SECRET_KEY", "").strip()
    if not mid or not secret:
        return None
    return mid, secret


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_user or not update.message:
        return
    uid = update.effective_user.id
    admin_id_raw = os.environ.get("ADMIN_ID", "").strip()
    try:
        admin_id = int(admin_id_raw) if admin_id_raw else -1
    except ValueError:
        log.error("ADMIN_ID в .env должен быть целым числом")
        admin_id = -1
    is_admin = uid == admin_id
    record = db.ensure_user(uid, is_admin=is_admin)

    if record.has_subscription:
        text = app_main_text(uid)
        keyboard = subscribed_main_keyboard(uid)
    else:
        text = build_guest_welcome_text()
        keyboard = guest_main_keyboard()

    await update.message.reply_text(
        text,
        parse_mode=ParseMode.HTML,
        reply_markup=keyboard,
    )


async def cmd_grant(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_user or not update.message:
        return
    if not _is_admin(update.effective_user.id):
        await update.message.reply_text("Недостаточно прав.")
        return
    if not context.args or len(context.args) != 1:
        await update.message.reply_text(
            "Использование: <code>/grant TG_ID</code>",
            parse_mode=ParseMode.HTML,
        )
        return
    try:
        tid = int(context.args[0].strip())
    except ValueError:
        await update.message.reply_text("TG_ID должен быть целым числом (Telegram user id).")
        return
    db.ensure_user(tid)
    db.set_subscription(tid, active=True, until=None)
    await update.message.reply_text(
        f"Подписка выдана: <code>{tid}</code>",
        parse_mode=ParseMode.HTML,
    )


async def cmd_stop_search_all(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_user or not update.message:
        return
    uid = update.effective_user.id
    if not user_has_subscription(uid):
        await update.message.reply_text("Команда доступна с подпиской.")
        return
    y_ok = yc.cancel_hunt(uid)
    r_ok = rst_core.cancel_rst_hunt(uid)
    if y_ok or r_ok:
        await update.message.reply_text(
            "Поиск остановлен (Yandex Cloud и/или Selectel · RegCloud). "
            "На главной снова будет «Запустить скрипт» — откройте /start или меню."
        )
    else:
        await update.message.reply_text("Активного поиска нет.")


async def cmd_take(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_user or not update.message:
        return
    if not _is_admin(update.effective_user.id):
        await update.message.reply_text("Недостаточно прав.")
        return
    if not context.args or len(context.args) != 1:
        await update.message.reply_text(
            "Использование: <code>/take TG_ID</code>",
            parse_mode=ParseMode.HTML,
        )
        return
    try:
        tid = int(context.args[0].strip())
    except ValueError:
        await update.message.reply_text("TG_ID должен быть целым числом (Telegram user id).")
        return
    db.ensure_user(tid)
    db.set_subscription(tid, active=False, until=None)
    await update.message.reply_text(
        f"Подписка снята: <code>{tid}</code>",
        parse_mode=ParseMode.HTML,
    )


async def on_plain_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if await yandex_flow.handle_yandex_message(update, context):
        return
    if await rst_core.handle_rst_message(update, context):
        return


async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    if not q or not q.message:
        return
    user = update.effective_user
    if not user:
        await safe_callback_answer(q)
        return

    data = (q.data or "").strip()
    m = UUID_IN_CALLBACK.match(data)

    if await yandex_flow.handle_yandex_callback(update, context, data):
        return
    if await rst_core.handle_rst_callback(update, context, data):
        return

    if data == "buy_access":
        if user_has_subscription(user.id):
            await safe_callback_answer(q, "У вас уже есть доступ.", show_alert=True)
            await safe_callback_edit_message(q,
                app_main_text(user.id),
                parse_mode=ParseMode.HTML,
                reply_markup=subscribed_main_keyboard(user.id),
            )
            return
        await safe_callback_answer(q)
        await safe_callback_edit_message(q,
            build_purchase_intro_text(),
            parse_mode=ParseMode.HTML,
            reply_markup=purchase_keyboard(),
        )
    elif data == "purchase_menu":
        await safe_callback_answer(q)
        await safe_callback_edit_message(q,
            build_purchase_intro_text(),
            parse_mode=ParseMode.HTML,
            reply_markup=purchase_keyboard(),
        )
    elif data == "buy_sbp":
        if user_has_subscription(user.id):
            await safe_callback_answer(q, "У вас уже есть доступ.", show_alert=True)
            await safe_callback_edit_message(q,
                app_main_text(user.id),
                parse_mode=ParseMode.HTML,
                reply_markup=subscribed_main_keyboard(user.id),
            )
            return
        creds = platega_credentials()
        if not creds:
            log.warning("Platega: не заданы PLATEGA_MERCHANT_ID / PLATEGA_SECRET_KEY")
            await safe_callback_answer(
                q,
                "Оплата по СБП сейчас недоступна. Напишите в поддержку.",
                show_alert=True,
            )
            return
        await safe_callback_answer(q)
        merchant_id, secret = creds
        payload = platega.build_telegram_payload(user.id)
        try:
            created = await platega.create_sbp_transaction(
                merchant_id=merchant_id,
                secret=secret,
                amount_rub=ACCESS_PRICE_RUB,
                description="IPHunder — полный доступ к скрипту (навсегда)",
                payload=payload,
                return_url=RETURN_URL,
                failed_url=RETURN_URL,
            )
        except platega.PlategaError as e:
            log.exception("Platega create_sbp_transaction: %s", e)
            await q.message.reply_text(
                "Не удалось создать платёж. Попробуйте позже или напишите в поддержку.",
            )
            return
        except Exception:
            log.exception("Неожиданная ошибка при создании платежа Platega")
            await q.message.reply_text(
                "Техническая ошибка при создании платежа. Попробуйте позже.",
            )
            return

        db.save_sbp_intent(created.transaction_id, user.id, ACCESS_PRICE_RUB)
        pay_text = build_sbp_payment_text(expires_hint=created.expires_in)
        await safe_callback_edit_message(q,
            pay_text,
            parse_mode=ParseMode.HTML,
            reply_markup=sbp_pay_keyboard(created.redirect_url, created.transaction_id),
        )

    elif data == "main_menu":
        await safe_callback_answer(q)
        if user_has_subscription(user.id):
            await safe_callback_edit_message(q,
                app_main_text(user.id),
                parse_mode=ParseMode.HTML,
                reply_markup=subscribed_main_keyboard(user.id),
            )
        else:
            await safe_callback_edit_message(q,
                build_guest_welcome_text(),
                parse_mode=ParseMode.HTML,
                reply_markup=guest_main_keyboard(),
            )

    elif data == "app_main":
        if not user_has_subscription(user.id):
            await safe_callback_answer(q, "Нет активной подписки.", show_alert=True)
            return
        await safe_callback_answer(q)
        await safe_callback_edit_message(q,
            app_main_text(user.id),
            parse_mode=ParseMode.HTML,
            reply_markup=subscribed_main_keyboard(user.id),
        )

    elif data == "stop_script":
        if not user_has_subscription(user.id):
            await safe_callback_answer(q, "Нет активной подписки.", show_alert=True)
            return
        await safe_callback_answer(q)
        yc.cancel_hunt(user.id)
        rst_core.cancel_rst_hunt(user.id)
        await safe_callback_edit_message(q,
            app_main_text(user.id),
            parse_mode=ParseMode.HTML,
            reply_markup=subscribed_main_keyboard(user.id),
        )

    elif data == "run_script":
        if not user_has_subscription(user.id):
            await safe_callback_answer(q, "Нет активной подписки.", show_alert=True)
            return
        if total_active_hunt_count(user.id) > 0:
            await safe_callback_answer(q, "Поиск уже идёт. Остановите кнопкой на главной.", show_alert=True)
            return
        await safe_callback_answer(q)
        await safe_callback_edit_message(q,
            "<b>Запуск скрипта</b>\n\nВыберите платформу:",
            parse_mode=ParseMode.HTML,
            reply_markup=script_platform_keyboard(),
        )

    elif data == "plat_yandex":
        if not user_has_subscription(user.id):
            await safe_callback_answer(q, "Нет активной подписки.", show_alert=True)
            return
        await safe_callback_answer(q)
        await safe_callback_edit_message(q,
            "<b>Yandex Cloud</b>\n\n"
            "Кнопка ниже запускает поиск <b>сразу на всех</b> сохранённых аккаунтах (параллельно). "
            "Добавьте аккаунты через «Новый аккаунт», если список пуст.",
            parse_mode=ParseMode.HTML,
            reply_markup=yandex_flow.yandex_platform_menu_keyboard(user.id),
        )

    elif data == "plat_all":
        if not user_has_subscription(user.id):
            await safe_callback_answer(q, "Нет активной подписки.", show_alert=True)
            return
        await safe_callback_answer(q, "Сначала выберите платформу в списке — режим «все провайдеры сразу» не подключён.", show_alert=True)

    elif data == "add_account":
        if not user_has_subscription(user.id):
            await safe_callback_answer(q, "Нет активной подписки.", show_alert=True)
            return
        await safe_callback_answer(q)
        await safe_callback_edit_message(q,
            "<b>Добавить аккаунт</b>\n\nДо 10 аккаунтов на каждого провайдера (Yandex / Selectel / RegCloud). Выберите провайдера:",
            parse_mode=ParseMode.HTML,
            reply_markup=rst_core.add_provider_keyboard(),
        )

    elif data == "my_accounts":
        if not user_has_subscription(user.id):
            await safe_callback_answer(q, "Нет активной подписки.", show_alert=True)
            return
        await safe_callback_answer(q)
        n = db.count_yandex_accounts(user.id)
        ns = rst_core.count_rst_accounts(user.id, "selectel")
        nr = rst_core.count_rst_accounts(user.id, "regcloud")
        await safe_callback_edit_message(q,
            f"<b>Мои аккаунты</b>\n\n"
            f"Yandex Cloud: {n} · Selectel: {ns} · RegCloud: {nr}\n\n"
            "Выберите провайдера:",
            parse_mode=ParseMode.HTML,
            reply_markup=rst_core.my_accounts_root_keyboard(user.id),
        )
    elif m:
        transaction_id = m.group(1)
        await handle_sbp_paid(q, user.id, transaction_id)
    else:
        await safe_callback_answer(q)


async def handle_sbp_paid(q: CallbackQuery, telegram_id: int, transaction_id: str) -> None:
    creds = platega_credentials()
    if not creds:
        await safe_callback_answer(q, "Платёжная система недоступна.", show_alert=True)
        return

    intent = db.get_sbp_intent(transaction_id)
    if intent is None:
        await safe_callback_answer(q, "Этот платёж не найден у бота. Создайте новый через «Купить по СБП».", show_alert=True)
        return
    owner_id, amount_expected = intent
    if owner_id != telegram_id:
        await safe_callback_answer(q, "Этот платёж оформлен не вами.", show_alert=True)
        return

    merchant_id, secret = creds
    try:
        status = await platega.get_transaction_status(
            merchant_id=merchant_id,
            secret=secret,
            transaction_id=transaction_id,
        )
    except platega.PlategaError as e:
        log.warning("Platega get_transaction_status %s: %s", transaction_id, e)
        await safe_callback_answer(q, "Не удалось проверить платёж. Попробуйте через минуту.", show_alert=True)
        return

    expected_payload = platega.build_telegram_payload(telegram_id)
    pay_raw = (status.payload or "").strip()
    if pay_raw and pay_raw != expected_payload:
        log.error(
            "Platega payload mismatch tx=%s expected=%r got=%r",
            transaction_id,
            expected_payload,
            status.payload,
        )
        await safe_callback_answer(q, "Ошибка проверки платежа. Обратитесь в поддержку.", show_alert=True)
        return

    if status.amount is not None and status.currency:
        if status.currency.upper() != "RUB":
            await safe_callback_answer(q, "Неверная валюта платежа.", show_alert=True)
            return
        if abs(float(status.amount) - float(amount_expected)) > 0.01:
            await safe_callback_answer(q, "Сумма платежа не совпадает. Обратитесь в поддержку.", show_alert=True)
            return

    st = status.status.upper()
    if st == "CONFIRMED":
        db.set_subscription(telegram_id, active=True, until=None)
        db.delete_sbp_intent(transaction_id)
        await safe_callback_answer(q, "Оплата подтверждена.")
        bot = q.get_bot()
        await notify_admin_subscription_paid(bot, payer_id=telegram_id, from_user=q.from_user)
        if q.message:
            await safe_message_edit_text(
                q.message,
                "<b>Оплата прошла успешно.</b> Доступ открыт.\n\n"
                + app_main_text(telegram_id),
                parse_mode=ParseMode.HTML,
                reply_markup=subscribed_main_keyboard(telegram_id),
            )
        return

    if st == "PENDING":
        await safe_callback_answer(
            q,
            "Платёж ещё не подтверждён. Подождите минуту после оплаты и нажмите снова.",
            show_alert=True,
        )
        return

    if st in ("CANCELED", "CHARGEBACKED"):
        db.delete_sbp_intent(transaction_id)
        await safe_callback_answer(
            q,
            "Платёж отменён или возвращён. При необходимости создайте новый счёт.",
            show_alert=True,
        )
        return

    await safe_callback_answer(
        q,
        f"Статус платежа: {status.status}. Попробуйте позже или напишите в поддержку.",
        show_alert=True,
    )


def _release_instance_lock() -> None:
    global _lock_fd
    try:
        if _lock_fd is not None:
            os.close(_lock_fd)
            _lock_fd = None
        if _INSTANCE_LOCK_PATH.is_file():
            _INSTANCE_LOCK_PATH.unlink()
    except OSError:
        pass


def _acquire_instance_lock() -> None:
    """Один процесс polling на токен: второй запуск сразу выходит с подсказкой."""
    global _lock_fd
    try:
        _lock_fd = os.open(
            _INSTANCE_LOCK_PATH,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
        )
        os.write(_lock_fd, str(os.getpid()).encode("ascii", errors="replace"))
    except FileExistsError:
        log.critical(
            "Уже запущен другой экземпляр бота (или остался %s после падения процесса). "
            "Закройте второй python/Cursor-терминал с ботом или удалите этот файл.",
            _INSTANCE_LOCK_PATH.name,
        )
        sys.exit(1)


async def _post_init(app: Application) -> None:
    """Снимает webhook, чтобы не конфликтовать с long polling."""
    await app.bot.delete_webhook(drop_pending_updates=True)
    await yandex_flow.resume_stored_yandex_hunts(app.bot)
    await rst_core.resume_stored_rst_hunts(app.bot)


async def _error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    err = context.error
    if isinstance(err, Conflict):
        log.error(
            "Conflict getUpdates: параллельно кто-то ещё опрашивает этого бота "
            "(второй процесс, другой ПК или включён webhook). Оставьте один polling."
        )
        return
    if _telegram_benign_bad_request(err):
        log.debug("telegram (ожидаемо): %s", err)
        return
    log.exception("Необработанная ошибка", exc_info=err)


def main() -> None:
    token = os.environ.get("BOT_TOKEN", "").strip()
    if not token:
        log.error("В .env не задан BOT_TOKEN")
        sys.exit(1)

    atexit.register(_release_instance_lock)
    _acquire_instance_lock()

    db.init_db()
    rst_core.init_rst_db()
    try:
        encryption.require_encryption_ready()
    except encryption.EncryptionError as e:
        log.critical("Нужен ENCRYPTION_KEY в .env (%s)", e)
        sys.exit(1)

    admin_raw = os.environ.get("ADMIN_ID", "").strip()
    if admin_raw:
        try:
            db.ensure_user(int(admin_raw), is_admin=True)
        except ValueError:
            log.warning("ADMIN_ID не распознан как число, пропуск синхронизации админа")

    app = (
        Application.builder()
        .token(token)
        .post_init(_post_init)
        .build()
    )
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("grant", cmd_grant))
    app.add_handler(CommandHandler("take", cmd_take))
    app.add_handler(CommandHandler("stop_search", cmd_stop_search_all))
    app.add_handler(CallbackQueryHandler(on_callback))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_plain_text), group=1)
    app.add_error_handler(_error_handler)

    log.info("Бот запущен (один экземпляр; lock: %s)", _INSTANCE_LOCK_PATH.name)
    app.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)


if __name__ == "__main__":
    main()
