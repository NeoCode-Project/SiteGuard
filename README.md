# SiteGuard

Безопасный проверяльщик ссылок на Node.js.

## Запуск
1. Установи Node.js 20+.
2. В папке проекта: `npm install`
3. Затем: `npm start`
4. Открой `http://localhost:3000`

## Google Safe Browsing (необязательно)
Создай API-ключ Google Safe Browsing и перед запуском задай переменную окружения:

Windows PowerShell:
`$env:GOOGLE_SAFE_BROWSING_KEY="ТВОЙ_КЛЮЧ"; npm start`

Ключ хранится только на сервере, не в браузерном JavaScript.

## Что уже защищено
- Только http/https.
- Блокировка localhost, .local, IPv4 private/link-local/CGNAT и основных IPv6 private/link-local диапазонов.
- Каждый redirect повторно проверяется перед запросом.
- Таймаут загрузки и лимит размера HTML.
- Никакого iframe/исполнения JavaScript проверяемого сайта в браузере.

## Важно
Ни один автоматический сервис не может обещать 100% безопасность. Для публичного проекта лучше добавить rate limiting, журналирование без сохранения чувствительных URL, строгую CSP и второй reputation provider (например VirusTotal) при соблюдении его условий использования.
