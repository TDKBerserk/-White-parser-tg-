# White-parser-tg

Парсер VPN-подписок из Telegram-каналов с делением конфигов на белый и чёрный список по IP сервера.

## Как это работает

1. **channels.txt** — список Telegram-каналов. Парсер заходит на публичную страницу `https://t.me/s/<channel>` каждого канала и вытаскивает:
   - прямые ключи (`vless://`, `trojan://`, `ss://`, `vmess://`);
   - ссылки на подписки (http/https), которые затем скачиваются и тоже разбираются на ключи.
2. Каждый найденный ключ проверяется на живость через HTTP GET к `host:port` сервера.
3. Живые ключи резолвятся в IP и сверяются с `whitelist_ips.txt`:
   - IP входит в подсети известных "разрешённых" сервисов (Яндекс, ВКонтакте, MAX и т.д.) → **белый** список;
   - всё остальное → **чёрный** список.

## Файлы

- `channels.txt` — список каналов-источников (по одному имени на строку, без `@` и `https://t.me/`).
- `whitelist_domains.txt` *(опционально, создать вручную)* — доп. домены для DNS-резолва в белый список, в формате:
  ```
  # Название сервиса
  domain1.example
  domain2.example
  ```
- `whitelist_ips.txt` — автогенерируется `update_whitelist_ranges.py`, вручную не редактировать.
- `update_whitelist_ranges.py` — тянет готовые CIDR-подсети из [vattik/ipranges](https://github.com/vattik/ipranges) (Яндекс, ВК, Mail.ru, Rutube) + резолвит домены MAX и любые из `whitelist_domains.txt`.
- `collector.py` — основной сборщик и классификатор конфигов.
- `.github/workflows/update.yml` — почасовой запуск в GitHub Actions, коммитит `whitelist_ips.txt` и `output/` обратно в репозиторий.

## Результат (`output/`)

- `white_configs.txt`, `black_configs.txt`, `all_configs.txt` — списки ключей;
- `white_base64.txt`, `black_base64.txt` — те же списки в base64 (для подписок в клиентах);
- `summary.json` — статистика последнего запуска.

## Запуск вручную

```bash
pip install -r requirements.txt
python update_whitelist_ranges.py
python collector.py
```

## Важный нюанс про белый список

Официальные CIDR-подсети сервисов (особенно широкие облачные диапазоны) не гарантируют, что именно они пропускаются оператором в режиме ограничений — реальную работоспособность конкретного конфига нужно проверять на практике. `whitelist_ips.txt` определяет **кандидатов** на белый список; финальная проверка живости всё равно идёт через HTTP GET в `collector.py`.
