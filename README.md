# keylens

Ищет утекшие API-ключи и токены в файлах.

Зачем: легко случайно закоммитить ключ. Это находит такое до того, как заметят другие.

## Что умеет

- находит ключи GitHub, AWS, Slack, OpenAI, Telegram, PEM-ключи и просто `API_KEY = "..."`;
- показывает значение в замаскированном виде: `ghp_...cdef`;
- работает с JSON и возвращает код ошибки, удобно для CI.

## Запуск

```bash
python -m keylens scan .
```

Или после установки:

```bash
pip install .
keylens scan ./project
```

## Флаги

```bash
keylens scan . --json
keylens scan . --exclude vendor
keylens scan . --max-size 5
```

## Коды возврата

- `0` — ничего не найдено
- `1` — найдены ключи
- `2` — ошибка, например неверный путь

## Тесты

```bash
python -m unittest discover -s tests -v
```

Репозиторий: https://github.com/acciv/keylens

Сделал acciv.
