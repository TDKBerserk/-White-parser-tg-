#!/usr/bin/env python3
"""
update_whitelist_ranges.py — v2

Собирает данные для определения "белых" конфигов (тех, что маскируются
под трафик, пропускаемый в режиме ограниченного интернета операторов
вроде YOTA).

Вместо привязки к спискам конкретных сервисов (Яндекс/ВК/CDN) используется
связка из двух файлов, которую поддерживает открытый проект
RKPchannel/RKP_bypass_configs (https://github.com/RKPchannel/RKP_bypass_configs):

  - ip_list.txt  — первые ДВА октета IP (напр. "5.44"), покрывающие
    диапазоны, которые реально пропускаются при включённом "белом
    списке" — это официальный/наблюдаемый список, а не наш подбор.
  - sni_list.txt — список доменов (SNI), которые тоже пропускаются
    в этом режиме.

Конфиг считается "белым" (в collector.py), только если ОДНОВРЕМЕННО:
  1) первые два октета его IP входят в ip_list.txt, И
  2) его SNI/домен входит в sni_list.txt (с учётом поддоменов).

Если совпадает только одно из двух условий или ни одного — конфиг
классифицируется как чёрный.

Дополнительно: домены сервисов без записи в готовых списках (например,
MAX) можно добавить вручную в whitelist_domains.txt — они добавляются
в sni-список как есть, а их резолвленные IP — как префиксы в ip-список.

Результат:
  whitelist_ip_prefixes.txt — первые два октета IP, по одному на строку
  whitelist_sni.txt         — домены, по одному на строку
"""

import socket
import sys
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

IP_LIST_URL = "https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/main/ip_list.txt"
SNI_LIST_URL = "https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/main/sni_list.txt"

DOMAINS_FILE = "whitelist_domains.txt"
OUT_IP_PREFIXES = "whitelist_ip_prefixes.txt"
OUT_SNI = "whitelist_sni.txt"

# Домены сервисов без записи в готовых списках — добавляем вручную
DEFAULT_EXTRA_DOMAINS = {
    "MAX": [
        "max.ru",
        "platform-api2.max.ru",
        "dev.max.ru",
        "business.max.ru",
    ],
}

USER_AGENT = "Mozilla/5.0 (White-parser-tg whitelist updater)"
TIMEOUT = 20


def fetch_text(url: str) -> str:
    req = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=TIMEOUT) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def clean_lines(raw: str) -> list[str]:
    return [line.strip() for line in raw.splitlines() if line.strip() and not line.strip().startswith("#")]


def load_extra_domains() -> dict:
    extra = {}
    try:
        with open(DOMAINS_FILE, "r", encoding="utf-8") as f:
            current = "Custom"
            for raw_line in f:
                line = raw_line.strip()
                if not line:
                    continue
                if line.startswith("#"):
                    current = line.lstrip("#").strip() or current
                    continue
                extra.setdefault(current, []).append(line)
    except FileNotFoundError:
        pass
    return extra


def resolve_ip_prefixes(domain: str) -> list[str]:
    prefixes = set()
    try:
        _, _, ipv4_list = socket.gethostbyname_ex(domain)
        for ip in ipv4_list:
            parts = ip.split(".")
            if len(parts) == 4:
                prefixes.add(f"{parts[0]}.{parts[1]}")
    except (socket.gaierror, socket.herror) as e:
        print(f"  [warn] не удалось резолвить {domain}: {e}", file=sys.stderr)
    return sorted(prefixes)


def main():
    ip_prefixes: set[str] = set()
    sni_domains: set[str] = set()

    print("Скачиваю ip_list.txt из RKPchannel/RKP_bypass_configs...")
    try:
        ip_prefixes.update(clean_lines(fetch_text(IP_LIST_URL)))
        print(f"  [ok] получено {len(ip_prefixes)} префиксов")
    except (URLError, HTTPError, TimeoutError) as e:
        print(f"  [error] не удалось скачать ip_list.txt: {e}", file=sys.stderr)

    print("Скачиваю sni_list.txt из RKPchannel/RKP_bypass_configs...")
    try:
        sni_domains.update(clean_lines(fetch_text(SNI_LIST_URL)))
        print(f"  [ok] получено {len(sni_domains)} доменов")
    except (URLError, HTTPError, TimeoutError) as e:
        print(f"  [error] не удалось скачать sni_list.txt: {e}", file=sys.stderr)

    print("Добавляю доп. сервисы без готовых списков (MAX и др.)...")
    extra_domains = dict(DEFAULT_EXTRA_DOMAINS)
    for service, domains in load_extra_domains().items():
        extra_domains.setdefault(service, []).extend(domains)

    for service, domains in extra_domains.items():
        for domain in domains:
            sni_domains.add(domain)
            prefixes = resolve_ip_prefixes(domain)
            if prefixes:
                print(f"  [ok] {service}/{domain}: префиксы {', '.join(prefixes)}")
                ip_prefixes.update(prefixes)
            else:
                print(f"  [warn] {service}/{domain}: IP не получены (только SNI-запись)", file=sys.stderr)

    with open(OUT_IP_PREFIXES, "w", encoding="utf-8") as f:
        f.write("# whitelist_ip_prefixes.txt — автосгенерировано update_whitelist_ranges.py\n")
        f.write("# Источник: github.com/RKPchannel/RKP_bypass_configs (ip_list.txt) + доп. домены\n")
        f.write("# Не редактировать вручную — правки перезапишутся при следующем запуске.\n\n")
        for prefix in sorted(ip_prefixes):
            f.write(f"{prefix}\n")

    with open(OUT_SNI, "w", encoding="utf-8") as f:
        f.write("# whitelist_sni.txt — автосгенерировано update_whitelist_ranges.py\n")
        f.write("# Источник: github.com/RKPchannel/RKP_bypass_configs (sni_list.txt) + доп. домены\n")
        f.write("# Не редактировать вручную — правки перезапишутся при следующем запуске.\n\n")
        for domain in sorted(sni_domains):
            f.write(f"{domain}\n")

    print(f"Готово: {OUT_IP_PREFIXES} ({len(ip_prefixes)} префиксов), {OUT_SNI} ({len(sni_domains)} доменов).")


if __name__ == "__main__":
    main()
