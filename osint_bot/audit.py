"""Простой audit-лог: кто и когда фиксировал scope и делал lookup.

Это не security-контроль, а accountability-механизм: при расследовании
инцидента должно быть видно, кто инициировал запрос и в рамках какого
заявленного engagement. Хранится локально построчно (JSON lines).
"""
from __future__ import annotations

import json
import time
from pathlib import Path

AUDIT_LOG_PATH = Path(__file__).parent / "audit.log"

# user_id -> последний зафиксированный scope (держим в памяти процесса;
# при перезапуске бота оператор снова задаёт /scope).
_scopes: dict[int, str] = {}


def _append(record: dict) -> None:
    record["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with AUDIT_LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def set_scope(user_id: int, username: str | None, scope_text: str) -> None:
    _scopes[user_id] = scope_text
    _append(
        {
            "event": "scope_set",
            "user_id": user_id,
            "username": username,
            "scope": scope_text,
        }
    )


def get_scope(user_id: int) -> str | None:
    return _scopes.get(user_id)


def log_lookup(user_id: int, username: str | None, target: str) -> None:
    _append(
        {
            "event": "lookup",
            "user_id": user_id,
            "username": username,
            "scope": _scopes.get(user_id),
            "target": target,
        }
    )
