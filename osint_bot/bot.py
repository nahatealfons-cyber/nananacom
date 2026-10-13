"""OSINT recon bot — только для авторизованных pentest/red-team engagement'ов.

Единственный источник данных — Shodan InternetDB (пассивный, публичный,
без активного сканирования цели ботом). См. README.md про scope/ограничения.
"""
from __future__ import annotations

import logging

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import Application, CommandHandler, ContextTypes

import audit
from config import load_settings
from osint.internetdb import LookupError, format_result, lookup

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s: %(message)s", level=logging.INFO
)
logger = logging.getLogger("osint_bot")

HELP_TEXT = (
    "Этот бот — recon-инструмент для *авторизованных* pentest/red-team "
    "engagement'ов. Он берёт данные только из публичного Shodan InternetDB "
    "(открытые порты, CVE, hostnames по IP) — ничего не сканирует сам.\n\n"
    "Перед использованием зафиксируйте scope:\n"
    "`/scope <engagement/проект, в рамках которого вы работаете>`\n\n"
    "Затем:\n"
    "`/lookup <ip-или-домен>` — получить данные по цели.\n\n"
    "Не используйте бота для сбора данных о людях без авторизации — он для "
    "этого и не предназначен (у него нет источников персональных данных)."
)


def _is_allowed(user_id: int, settings) -> bool:
    if not settings.allowed_user_ids:
        return True
    return user_id in settings.allowed_user_ids


async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(HELP_TEXT, parse_mode=ParseMode.MARKDOWN)


async def scope_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    settings = context.bot_data["settings"]
    if not _is_allowed(user.id, settings):
        await update.message.reply_text("У вас нет доступа к этому боту.")
        return

    scope_text = " ".join(context.args).strip()
    if not scope_text:
        await update.message.reply_text(
            "Укажите описание engagement'а: `/scope <проект/договор/bug bounty scope>`",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    audit.set_scope(user.id, user.username, scope_text)
    await update.message.reply_text(
        "Scope зафиксирован. Теперь доступен /lookup <ip-или-домен>."
    )


async def lookup_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    settings = context.bot_data["settings"]
    if not _is_allowed(user.id, settings):
        await update.message.reply_text("У вас нет доступа к этому боту.")
        return

    if not audit.get_scope(user.id):
        await update.message.reply_text(
            "Сначала зафиксируйте scope: `/scope <engagement/проект>`",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    if not context.args:
        await update.message.reply_text("Использование: `/lookup <ip-или-домен>`", parse_mode=ParseMode.MARKDOWN)
        return

    target = context.args[0].strip()
    audit.log_lookup(user.id, user.username, target)

    try:
        result = await lookup(target)
    except LookupError as exc:
        await update.message.reply_text(f"Ошибка: {exc}")
        return
    except Exception:
        logger.exception("Unexpected error during lookup of %s", target)
        await update.message.reply_text("Внутренняя ошибка при обработке запроса.")
        return

    await update.message.reply_text(format_result(result), parse_mode=ParseMode.MARKDOWN)


def main() -> None:
    settings = load_settings()
    app = Application.builder().token(settings.bot_token).build()
    app.bot_data["settings"] = settings

    app.add_handler(CommandHandler("start", start_cmd))
    app.add_handler(CommandHandler("help", start_cmd))
    app.add_handler(CommandHandler("scope", scope_cmd))
    app.add_handler(CommandHandler("lookup", lookup_cmd))

    logger.info("osint_bot запущен")
    app.run_polling()


if __name__ == "__main__":
    main()
