<div align="center">

# 🔍 keylens

**Поиск утекших API-ключей и токенов в файлах и репозиториях.**

[![Tests](https://github.com/acciv/keylens/actions/workflows/test.yml/badge.svg)](https://github.com/acciv/keylens/actions/workflows/test.yml)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-65D067?style=flat-square)](LICENSE)

</div>

---

`keylens` — маленькая CLI-утилита без внешних зависимостей. Она проходит по файлам, находит похожие на секреты строки и показывает их в замаскированном виде, чтобы случайно не светить ключ ещё раз.

## Что ищет

- GitHub PAT (classic / fine-grained), OAuth-токены
- AWS Access Key ID
- Slack-токены
- OpenAI API keys (`sk-...`)
- Telegram bot tokens
- Приватные ключи (PEM)
- Присваивания вида `API_KEY = "..."`, `secret: "..."` и т.п.

## Установка

```bash
pip install .
```

Или без установки:

```bash
python -m keylens scan .
```

## Использование

```bash
# просканировать текущий каталог
keylens scan

# конкретная папка
keylens scan ./my-project

# JSON для CI
keylens scan . --json

# исключить каталог и увеличить лимит размера файла
keylens scan . --exclude vendor --max-size 5
```

Пример вывода:

```text
🔍 keylens: просмотрено файлов: 12
⚠️  Найдено потенциальных секретов: 1

  [high] ghp_...cdef   config.py:14 — GitHub PAT (classic)
```

## Коды возврата

| Код | Значение |
| --- | -------- |
| `0` | секретов не найдено |
| `1` | найдены потенциальные секреты |
| `2` | ошибка (например, путь не найден) |

Это позволяет использовать `keylens` в CI как guard: коммит с ключом не пройдёт.

## Развитие

```bash
python -m unittest discover -s tests -v
```

---

Сделано **acciv** · API keys, auth, security 🔐
