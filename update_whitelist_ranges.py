#!/usr/bin/env python3
"""
update_whitelist_ranges.py

Собирает белый список IP/CIDR-подсетей сервисов, которые остаются
доступны в режиме ограниченного интернета (нулевой рейтинг / "белые списки"
операторов вроде YOTA): Яндекс, ВКонтакте, Mail.ru, Rutube и т.д. — берём
готовые актуальные подсети из открытого репозитория vattik/ipranges.

Для сервисов без готового CIDR-списка (например, MAX) — резолвим домены
через DNS и добавляем полученные IP как /32 (для IPv4) и /128 (для IPv6).

Результат пишется в whitelist_ips.txt — плоский список CIDR, по одному
на строку, с комментариями-заголовками по сервисам. Пустые строки и
строки, начинающиеся с '#', игнорируются коллектором.

Источники подсетей (vattik/ipranges, https://github.com/vattik/ipranges):
  - google, mail.ru, ru-government, rutube, valve, vkontakte, yandex
Домены для DNS-резолва (сервисы без готового списка): задаются в
whitelist_domains.txt (по одному домену на строку, поддержка '#'-комментариев).
"""

import socket
import sys
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# Готовые списки CIDR из vattik/ipranges: (Название для комментария, URL)
IPRANGES_SOURCES = [
    ("Yandex", "https://raw.githubusercontent.com/vattik/ipranges/main/yandex/yandex.txt"),
    ("VKontakte", "https://raw.githubusercontent.com/vattik/ipranges/main/vkontakte/vkontakte.txt"),
    ("Mail.Ru and Odnoklassniki", "https://raw.githubusercontent.com/vattik/ipranges/main/mail.ru/mail.ru.txt"),
    ("Rutube", "https://raw.githubusercontent.com/vattik/ipranges/main/rutube/rutube.txt"),
]

# Домены сервисов без готового CIDR-списка — резолвим сами через DNS.
DEFAULT_DOMAINS = {
    "MAX": [
        "max.ru",
        "platform-api2.max.ru",
        "dev.max.ru",
        "business.max.ru",
    ],
}

DOMAINS_FILE = "whitelist_domains.txt"
OUTPUT_FILE = "whitelist_ips.txt"
USER_AGENT = "Mozilla/5.0 (White-parser-tg whitelist updater)"
TIMEOUT = 15


def fetch_text(url: str) -> str:
    req = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=TIMEOUT) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def parse_cidr_lines(raw: str) -> list[str]:
    lines = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


def load_extra_domains() -> dict:
    """Читает whitelist_domains.txt, если он есть, в формате:
    # Заголовок сервиса
    domain1.example
    domain2.example
    Возвращает dict {service_name: [domains]}, дополняющий DEFAULT_DOMAINS.
    """
    extra = {}
    try:
        with open(DOMAINS_FILE, "r", encoding="utf-8") as f:
            current_service = "Custom"
            for raw_line in f:
                line = raw_line.strip()
                if not line:
                    continue
                if line.startswith("#"):
                    current_service = line.lstrip("#").strip() or current_service
                    continue
                extra.setdefault(current_service, []).append(line)
    except FileNotFoundError:
        pass
    return extra


def resolve_domain(domain: str) -> list[str]:
    ips = set()
    try:
        _, _, ipv4_list = socket.gethostbyname_ex(domain)
        ips.update(ipv4_list)
    except (socket.gaierror, socket.herror) as e:
        print(f"  [warn] не удалось резолвить {domain} (IPv4): {e}", file=sys.stderr)

    try:
        for info in socket.getaddrinfo(domain, None, socket.AF_INET6):
            ips.add(info[4][0])
    except (socket.gaierror, socket.herror):
        pass  # IPv6 может отсутствовать — не критично

    return sorted(ips)


def to_cidr(ip: str) -> str:
    return f"{ip}/32" if "." in ip else f"{ip}/128"


def main():
    sections: list[tuple[str, list[str]]] = []

    print("Скачиваю готовые CIDR-списки из vattik/ipranges...")
    for name, url in IPRANGES_SOURCES:
        try:
            raw = fetch_text(url)
            cidrs = parse_cidr_lines(raw)
            print(f"  [ok] {name}: {len(cidrs)} подсетей")
            sections.append((name, cidrs))
        except (URLError, HTTPError, TimeoutError) as e:
            print(f"  [error] {name} ({url}): {e}", file=sys.stderr)

    print("Резолвлю домены сервисов без готового списка (MAX и др.)...")
    domains_by_service = dict(DEFAULT_DOMAINS)
    for service, domains in load_extra_domains().items():
        domains_by_service.setdefault(service, []).extend(domains)

    for service, domains in domains_by_service.items():
        cidrs = []
        for domain in domains:
            ips = resolve_domain(domain)
            if ips:
                print(f"  [ok] {domain}: {', '.join(ips)}")
            else:
                print(f"  [warn] {domain}: IP не получены", file=sys.stderr)
            cidrs.extend(to_cidr(ip) for ip in ips)
        if cidrs:
            sections.append((service, sorted(set(cidrs))))

    total = sum(len(cidrs) for _, cidrs in sections)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
        out.write("# whitelist_ips.txt — автосгенерировано update_whitelist_ranges.py\n")
        out.write("# Источники: github.com/vattik/ipranges + DNS-резолв доменов (MAX и др.)\n")
        out.write("# Не редактировать вручную — правки будут перезаписаны при следующем запуске.\n")
        out.write(f"# Не перезаписывать этот файл вручную. Доп. домены — в {DOMAINS_FILE}\n\n")
        for name, cidrs in sections:
            if not cidrs:
                continue
            out.write(f"# {name}\n")
            for cidr in cidrs:
                out.write(f"{cidr}\n")
            out.write("\n")

    print(f"Готово: {OUTPUT_FILE} — {total} подсетей из {len(sections)} источников.")


if __name__ == "__main__":
    main()
