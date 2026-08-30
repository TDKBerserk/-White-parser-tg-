#!/usr/bin/env python3
"""
collector.py — White-parser-tg

Собирает VPN-подписки/ключи из Telegram-каналов (channels.txt), проверяет
их через HTTP GET, и делит на белый/чёрный список по IP сервера:

  - "Белый" — IP сервера входит в whitelist_ips.txt (подсети сервисов,
    доступных в режиме ограниченного интернета: Яндекс, ВК, MAX и т.д.).
    Такой конфиг маскируется под разрешённый трафик.
  - "Чёрный" — всё остальное (обычный обход блокировок при доступном
    интернете).

Источники берутся ТОЛЬКО из Telegram-каналов (без внешнего sources.txt):
  1. Публичная страница https://t.me/s/<channel> парсится на предмет:
     а) прямых ключей-URI (vless://, trojan://, ss://, vmess://);
     б) http(s)-ссылок на подписки — они скачиваются через HTTP GET,
        декодируются (base64 или plain text), и из них также
        извлекаются ключи.
  2. Каждый найденный ключ проверяется на доступность через HTTP GET
     к host:port сервера (см. check_alive).
  3. Живые ключи резолвятся в IP и сверяются с whitelist_ips.txt.

Результат пишется в output/:
  white_configs.txt, black_configs.txt, all_configs.txt,
  white_base64.txt, black_base64.txt, summary.json
"""

import base64
import json
import re
import socket
import sys
import ipaddress
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from pathlib import Path

import requests

CHANNELS_FILE = "channels.txt"
WHITELIST_FILE = "whitelist_ips.txt"
OUTPUT_DIR = Path("output")

TELEGRAM_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
HTTP_TIMEOUT = 10
CHECK_TIMEOUT = 5

KEY_PREFIXES = ("vless://", "trojan://", "ss://", "vmess://")

# Заведомый мусор в постах Telegram — не тянем такие ссылки как подписки
LINK_JUNK_MARKERS = (
    "t.me/", "telegram.org", "telesco.pe",
    ".jpg", ".jpeg", ".png", ".gif", ".webp",
    "youtube.com", "youtu.be",
)

LINE_URL_RE = re.compile(r'https?://\S+')
KEY_RE = re.compile(r'(?:vless|trojan|ss|vmess)://\S+')


# --------------------------------------------------------------------------
# Сбор ссылок и ключей из Telegram-каналов
# --------------------------------------------------------------------------

def fetch_channel_html(channel: str) -> str | None:
    url = f"https://t.me/s/{channel}"
    try:
        resp = requests.get(url, headers={"User-Agent": TELEGRAM_UA}, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        return resp.text
    except requests.RequestException as e:
        print(f"  [error] канал {channel}: {e}", file=sys.stderr)
        return None


def is_junk_link(url: str) -> bool:
    low = url.lower()
    return any(marker in low for marker in LINK_JUNK_MARKERS)


def extract_from_html(html: str) -> tuple[set[str], set[str]]:
    """Возвращает (прямые_ключи, ссылки_на_подписки) найденные в тексте постов."""
    direct_keys = set()
    sub_links = set()

    for line in html.splitlines():
        for match in KEY_RE.findall(line):
            direct_keys.add(match.rstrip('"\'<>).,'))
        for match in LINE_URL_RE.findall(line):
            clean = match.rstrip('"\'<>).,')
            if not is_junk_link(clean):
                sub_links.add(clean)

    return direct_keys, sub_links


def fetch_subscription(url: str) -> set[str]:
    """Скачивает содержимое ссылки-подписки и извлекает из неё ключи."""
    try:
        resp = requests.get(url, headers={"User-Agent": TELEGRAM_UA}, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        raw = resp.text
    except requests.RequestException:
        return set()

    keys = set()

    # Пытаемся как base64 (частый формат для подписок)
    try:
        padded = raw.strip() + "=" * (-len(raw.strip()) % 4)
        decoded = base64.b64decode(padded, validate=False).decode("utf-8", errors="ignore")
        if any(p in decoded for p in KEY_PREFIXES):
            raw = raw + "\n" + decoded
    except Exception:
        pass

    for match in KEY_RE.findall(raw):
        keys.add(match.strip().rstrip('"\'<>).,'))

    return keys


# --------------------------------------------------------------------------
# Разбор ключей: извлечение host:port
# --------------------------------------------------------------------------

def parse_host_port(key: str) -> tuple[str, int] | None:
    try:
        if key.startswith("vmess://"):
            payload = key[len("vmess://"):]
            payload += "=" * (-len(payload) % 4)
            data = json.loads(base64.b64decode(payload).decode("utf-8", errors="ignore"))
            host = data.get("add")
            port = int(data.get("port"))
            if host and port:
                return host, port
            return None

        # vless / trojan / ss (URI-формат host:port в netloc)
        parsed = urlparse(key)
        if parsed.hostname and parsed.port:
            return parsed.hostname, parsed.port

        # ss:// старого формата ss://base64(method:pass@host:port)
        if key.startswith("ss://"):
            body = key[len("ss://"):].split("#")[0]
            if "@" not in body:
                padded = body + "=" * (-len(body) % 4)
                decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
                if "@" in decoded:
                    _, hostport = decoded.rsplit("@", 1)
                    host, port = hostport.split(":")
                    return host, int(port)
        return None
    except Exception:
        return None


# --------------------------------------------------------------------------
# Проверка доступности через HTTP GET
# --------------------------------------------------------------------------

def check_alive(host: str, port: int) -> bool:
    """Проверяет отзывчивость host:port через HTTP GET.

    Прокси-протоколы (vless/trojan/ss/vmess) не говорят на HTTP, поэтому
    полноценного HTTP-ответа чаще всего не будет — но сама попытка
    установить соединение и получить любой ответ/явный отказ от сервиса
    (а не таймаут/RST при отсутствии сервиса на порту) говорит о том,
    что порт слушает и сервер жив.
    """
    for scheme in ("http", "https"):
        try:
            requests.get(
                f"{scheme}://{host}:{port}/",
                timeout=CHECK_TIMEOUT,
                verify=False,
            )
            return True  # получили HTTP-ответ любого рода — сервер отвечает
        except requests.exceptions.SSLError:
            return True  # TLS-хендшейк начался — порт открыт и слушает
        except requests.exceptions.ConnectionError as e:
            # "Connection reset"/"Connection refused сразу после connect"
            # обычно означает, что порт открыт, но не говорит по HTTP —
            # это нормально для vless/trojan/vmess. Явный refused/timeout
            # на уровне TCP — недоступен.
            msg = str(e).lower()
            if "refused" in msg and "reset" not in msg:
                continue
            if "reset" in msg:
                return True
            continue
        except requests.exceptions.Timeout:
            continue
        except Exception:
            continue
    return False


def resolve_ip(host: str) -> str | None:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


# --------------------------------------------------------------------------
# Белый/чёрный список
# --------------------------------------------------------------------------

def load_whitelist_networks(path: str) -> list:
    networks = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    networks.append(ipaddress.ip_network(line, strict=False))
                except ValueError:
                    continue
    except FileNotFoundError:
        print(f"  [warn] {path} не найден — все конфиги попадут в чёрный список. "
              f"Запусти update_whitelist_ranges.py перед сбором.", file=sys.stderr)
    return networks


def classify(ip_str: str, networks: list) -> str:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return "black"
    for net in networks:
        if ip in net:
            return "white"
    return "black"


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def process_key(key: str, networks: list) -> dict | None:
    hp = parse_host_port(key)
    if not hp:
        return None
    host, port = hp

    if not check_alive(host, port):
        return None

    ip = resolve_ip(host)
    if not ip:
        return None

    category = classify(ip, networks)
    return {"key": key, "host": host, "port": port, "ip": ip, "category": category}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--channel-workers", type=int, default=5)
    parser.add_argument("--check-workers", type=int, default=20)
    args = parser.parse_args()

    channels = [
        line.strip() for line in Path(CHANNELS_FILE).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    networks = load_whitelist_networks(WHITELIST_FILE)

    all_direct_keys: set[str] = set()
    all_sub_links: set[str] = set()

    print(f"Обхожу {len(channels)} каналов...")
    with ThreadPoolExecutor(max_workers=args.channel_workers) as pool:
        futures = {pool.submit(fetch_channel_html, ch): ch for ch in channels}
        for fut in as_completed(futures):
            ch = futures[fut]
            html = fut.result()
            if not html:
                continue
            keys, links = extract_from_html(html)
            print(f"  [{ch}] прямых ключей: {len(keys)}, ссылок-подписок: {len(links)}")
            all_direct_keys.update(keys)
            all_sub_links.update(links)

    print(f"Скачиваю {len(all_sub_links)} ссылок-подписок...")
    with ThreadPoolExecutor(max_workers=args.check_workers) as pool:
        futures = {pool.submit(fetch_subscription, url): url for url in all_sub_links}
        for fut in as_completed(futures):
            all_direct_keys.update(fut.result())

    print(f"Всего уникальных ключей: {len(all_direct_keys)}. Проверяю через HTTP GET...")

    results = []
    with ThreadPoolExecutor(max_workers=args.check_workers) as pool:
        futures = {pool.submit(process_key, key, networks): key for key in all_direct_keys}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                results.append(res)

    white = [r for r in results if r["category"] == "white"]
    black = [r for r in results if r["category"] == "black"]

    print(f"Живых конфигов: {len(results)} (белых: {len(white)}, чёрных: {len(black)})")

    OUTPUT_DIR.mkdir(exist_ok=True)

    def write_list(path: Path, items: list[dict]):
        path.write_text("\n".join(r["key"] for r in items) + ("\n" if items else ""), encoding="utf-8")

    def write_base64(path: Path, items: list[dict]):
        blob = "\n".join(r["key"] for r in items)
        path.write_text(base64.b64encode(blob.encode("utf-8")).decode("ascii"), encoding="utf-8")

    write_list(OUTPUT_DIR / "white_configs.txt", white)
    write_list(OUTPUT_DIR / "black_configs.txt", black)
    write_list(OUTPUT_DIR / "all_configs.txt", results)
    write_base64(OUTPUT_DIR / "white_base64.txt", white)
    write_base64(OUTPUT_DIR / "black_base64.txt", black)

    summary = {
        "total_keys_found": len(all_direct_keys),
        "alive": len(results),
        "white": len(white),
        "black": len(black),
        "channels": channels,
    }
    (OUTPUT_DIR / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print("Готово. Результаты в output/.")


if __name__ == "__main__":
    main()
