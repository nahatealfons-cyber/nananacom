"""Клиент для Shodan InternetDB.

InternetDB (https://internetdb.shodan.io/) — бесплатный публичный API,
который отдаёт уже собранные пассивные данные по IP: открытые порты,
CPE/баннеры, известные CVE, связанные hostnames и теги. Запрос к нему —
это единственное сетевое взаимодействие с "целью", и это обращение к
Shodan, а не к самой цели: бот ничего не сканирует напрямую.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass

import httpx

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
TIMEOUT = 10.0


class LookupError(Exception):
    pass


@dataclass
class InternetDBResult:
    ip: str
    hostnames: list[str]
    ports: list[int]
    cpes: list[str]
    vulns: list[str]
    tags: list[str]


def resolve_to_ip(target: str) -> str:
    """Если target — домен, резолвит в IPv4/IPv6. Если уже IP — возвращает как есть."""
    target = target.strip()
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise LookupError(f"Не удалось резолвить '{target}': {exc}") from exc


async def lookup(target: str) -> InternetDBResult:
    ip = resolve_to_ip(target)
    url = INTERNETDB_URL.format(ip=ip)
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        resp = await client.get(url)
    if resp.status_code == 404:
        raise LookupError(f"Нет данных InternetDB для {ip} (скорее всего, Shodan его не видел).")
    if resp.status_code != 200:
        raise LookupError(f"InternetDB вернул статус {resp.status_code} для {ip}.")
    data = resp.json()
    return InternetDBResult(
        ip=data.get("ip", ip),
        hostnames=data.get("hostnames", []),
        ports=data.get("ports", []),
        cpes=data.get("cpes", []),
        vulns=data.get("vulns", []),
        tags=data.get("tags", []),
    )


def format_result(result: InternetDBResult) -> str:
    lines = [f"🔎 *{result.ip}*"]
    if result.hostnames:
        lines.append("*Hostnames:* " + ", ".join(result.hostnames))
    if result.ports:
        lines.append("*Открытые порты:* " + ", ".join(str(p) for p in sorted(result.ports)))
    if result.cpes:
        lines.append("*CPE:*\n" + "\n".join(f"  • {c}" for c in result.cpes))
    if result.vulns:
        lines.append(
            "*Известные CVE:*\n" + "\n".join(f"  • {v}" for v in sorted(result.vulns))
        )
    if result.tags:
        lines.append("*Теги:* " + ", ".join(result.tags))
    if len(lines) == 1:
        lines.append("Данных по портам/CVE/тегам не найдено.")
    return "\n".join(lines)
