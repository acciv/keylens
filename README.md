# keylens

Ищет утекшие API-ключи и токены в файлах.

Зачем: легко случайно закоммитить ключ. Это находит такое до того, как заметят другие.

## Что умеет

- находит ключи GitHub, AWS, Slack, OpenAI, Telegram, PEM-ключи и просто `API_KEY = "..."`;
- показывает значение в замаскированном виде: `ghp_...cdef`;
- работает с JSON и возвращает код ошибки, удобно для CI;
- четыре реализации с одинаковым поведением: Python, Go, Rust и C++.

## Реализации

| Язык | Запуск из исходников | Особенность |
|---|---|---|
| Python | `python -m keylens scan .` | базовая версия, без зависимостей |
| Go | `cd go && go run ./cmd/keylens scan .` | один статический бинарник |
| Rust | `cd rust && cargo run --release -- scan .` | безопасная реализация, без внешних crates |
| C++ | `make -C cpp && ./cpp/keylens scan .` | C++17, никаких зависимостей |

Собрать всё сразу: `make build`.

## Запуск

```bash
python -m keylens scan .
```

Или после установки:

```bash
pip install .
keylens scan ./project
```

Для остальных реализаций CLI тот же — см. таблицу выше.

## Флаги

```bash
keylens scan . --json
keylens scan . --exclude vendor
keylens scan . --max-size 5
keylens scan . --quiet
keylens --version
```

## JSON

```bash
keylens scan . --json
```

Каждая находка — объект с полями `file`, `line`, `pattern`, `severity`, `match`.
`match` всегда замаскирован.

## Коды возврата

- `0` — ничего не найдено
- `1` — найдены ключи
- `2` — ошибка, например неверный путь

## Тесты

```bash
make test
```

Или по отдельности:

```bash
python -m unittest discover -s tests -v
cd go && go test ./...
cd rust && cargo test
make -C cpp test
```

CI (`Tests`) гоняет все четыре набора тестов на каждом пуше.

Репозиторий: https://github.com/acciv/keylens

Сделал acciv.
