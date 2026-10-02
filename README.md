# 1c-onec-db

pytest-фикстуры для тестов **уровня логики 1С** контура [1c-zcode](https://github.com/ntin60775/1c-zcode):
тонкий MCP-клиент `onec_db` (execute_code / execute_query через [1c-mcp-toolkit](https://github.com/ROCTUP/1c-mcp-toolkit))
и HTTP-заглушка внешних систем `stub_server`. Только stdlib — ноль pip-зависимостей.

Это то, чем заменяется юнит-наследие (yAxUnit): инварианты модулей, расчёты,
проверки заполнения — обычные pytest-тесты, вызов логики через BSL на тестовой базе.

## Установка

```bash
pip install git+https://github.com/ntin60775/1c-onec-db.git@v0.1.0
```

Пакет — pytest-плагин (entry-point `pytest11`): фикстуры `onec_db` и
`stub_server` доступны во всех тестах проекта сразу, conftest не нужен.

## Фикстуры

```python
import json

def test_сумма_ндс(onec_db, json):
    data = onec_db.execute("""
        Результат = ЗаписатьJSON(Новый ЗаписьJSON, Расчёты.СуммаНДС(62000));
    """)
    assert json.loads(data) == 10333.34

def test_создание_контрагента(onec_db):
    obj = onec_db.create_object("Контрагенты", {"Наименование": "МокТест", "ИНН": "7700000000"})
    try:
        rows = onec_db.query('ВЫБРАТЬ Код ИЗ Справочник.Контрагенты ГДЕ Наименование = "Е2Е-МокТест"')
        assert rows["data"], "контрагент не найден"
    finally:
        onec_db.delete_object(obj["type"], obj["guid"])

def test_интеграция_с_заглушкой(onec_db, stub_server):
    stub_server.route("POST", "/api/bid", 200, '{"status": "ok"}')
    onec_db.set_constant("АдресСервисаЗаявок", stub_server.url)  # канон мока: URL из константы
    # ... вызов логики, которая ходит в сервис ...
    assert ("POST", "/api/bid") in [tuple(c.values()) for c in stub_server.calls]
```

## Контракты

- **execute_code**: BSL выполняется на сервере тестовой базы; результат читается
  из переменной `Результат`, которую код обязан установить. Сложные значения —
  `ЗаписатьJSON` (`execute_json` вернёт python-объект). Сериализатор тулкита
  отдаёт значения строкой: строки — JSON-литералом, коллекции — JSON;
  клиент распаковывает валидный JSON, остальное возвращает строкой как есть.
- **create_object/delete_object**: только менеджерный путь
  (`Справочники.X.СоздатьЭлемент()`); `Новый(Тип("СправочникОбъект.X"))` в
  окружении `Выполнить` тулкита ломает установку реквизитов («Элемент не
  выбран»). Генерируемые переменные носят префикс `Е2Е` — имя `Объект`
  резолвится в реквизит формы обработки. Данные помечаются маркером `Е2Е-`.
- **URL 1c-db**: env `ONEC_DB_URL` → `.zcode/1c/contour.json` (`1c_db.url`) →
  `http://127.0.0.1:6003/mcp`.
- **Безопасность**: тестовый прокси разрешает `Записать`/`Удалить` (данные
  фикстур); COM, файловые операции, монопольный/привилегированный режимы
  заблокированы. В прод-контуре execute_code блокируется гейтом
  [1c-zcode](https://github.com/ntin60775/1c-zcode) — фикстуры только для
  тестовых деревьев.

## Зависимости

Единственная внешняя точка — MCP-сервер `1c-db` (прокси `onec_mcp_toolkit_proxy`,
поднимается скриптом контура `start_1c_db.sh` вместе с клиентом 1С).
От testpilot, unica и ZCode-хоста пакет не зависит.

## Разработка

```bash
python -m venv .venv && .venv/bin/pip install -e . pytest
.venv/bin/python -m pytest tests/ -q
```

Тесты — против фейкового MCP-сервера (handshake, tools/call, семантика
сериализатора); живая проверка на стенде 1С описана в контуре 1c-zcode.

Лицензия: MIT.
