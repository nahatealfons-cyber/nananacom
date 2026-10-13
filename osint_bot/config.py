"""Конфигурация бота: читает .env и переменные окружения."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv()


def _parse_ids(raw: str) -> set[int]:
    ids: set[int] = set()
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if chunk:
            ids.add(int(chunk))
    return ids


@dataclass(frozen=True)
class Settings:
    bot_token: str
    allowed_user_ids: set[int] = field(default_factory=set)


def load_settings() -> Settings:
    token = os.getenv("BOT_TOKEN", "").strip()
    if not token:
        raise RuntimeError(
            "BOT_TOKEN не задан. Скопируйте .env.example в .env и впишите токен."
        )
    allowed = _parse_ids(os.getenv("ALLOWED_USER_IDS", ""))
    return Settings(bot_token=token, allowed_user_ids=allowed)
