"""pytest-плагин: фикстуры onec_db и stub_server для тестов уровня логики 1С.

После установки пакета фикстуры доступны во всех тестах без conftest.
URL 1c-db: env ONEC_DB_URL → .zcode/1c/contour.json (1c_db.url) → дефолт
http://127.0.0.1:6003/mcp. Клиент 1c-db поднимает scripts/start_1c_db.sh
контура; прод защищён mcp_gate — фикстуры только для тестовых деревьев.

Проба принадлежности базы: фикстура сверяет базу, которую отдаёт прокси
(``СтрокаСоединенияИнформационнойБазы()``), с привязкой дерева из
local-слоя (v8project.local.yaml → v8project.yaml; ``File=`` / ``Srvr+Ref``).
Рассинхрон — типовая ловушка git-ворктри: дефолт :6003 указывает на прокси
основного дерева, и юниты молча пишут в чужую базу. Прогон не стартует.
"""
import json
import os
import pathlib
import re

import pytest

from .core import OnecDB, StubServer

__all__ = ["onec_db", "stub_server", "OnecDB", "StubServer"]

_PROBE_CODE = "Результат = СтрокаСоединенияИнформационнойБазы();"
_BASE_KEYS = ("File", "Srvr", "Ref")


def _resolve_url() -> str:
	url = os.environ.get("ONEC_DB_URL")
	if url:
		return url
	cfg = pathlib.Path(".zcode/1c/contour.json")
	if cfg.is_file():
		try:
			stored = json.loads(cfg.read_text(encoding="utf-8")) \
				.get("1c_db", {}).get("url")
			if stored:
				return stored
		except json.JSONDecodeError:
			pass
	return "http://127.0.0.1:6003/mcp"


def _find_root():
	"""Корень проекта контура от cwd (v8project.yaml или .zcode/1c) или None."""
	here = pathlib.Path.cwd()
	for cand in (here, *here.parents):
		if (cand / "v8project.yaml").is_file() or (cand / ".zcode" / "1c").is_dir():
			return cand
	return None


def _conn_keys(connection: str) -> dict:
	"""Строка соединения 1С (``File="p";Srvr="s";Ref="b"``) → dict без кавычек."""
	parts = {}
	for chunk in str(connection).split(";"):
		chunk = chunk.strip()
		if "=" not in chunk:
			continue
		key, _, value = chunk.partition("=")
		parts[key.strip()] = value.strip().strip('"')
	return parts


def _expected_connection(root) -> str:
	"""Привязка базы дерева из local-слоя; пусто — не найдена.

	Канон 0.15 — ``infobases.origin.connection`` (0.12-синоним —
	``infobase.connection``); файл: v8project.local.yaml → v8project.yaml.
	"""
	for name in ("v8project.local.yaml", "v8project.yaml"):
		path = pathlib.Path(root) / name
		if not path.is_file():
			continue
		section, in_origin = None, False
		for line in path.read_text(encoding="utf-8").splitlines():
			if re.match(r"^\S", line):
				section = line.split(":", 1)[0].strip()
				in_origin = False
				continue
			stripped = line.strip()
			if section == "infobases" and stripped.rstrip(":") == "origin":
				in_origin = True
				continue
			m = re.match(r"^connection\s*:\s*(.+?)\s*$", stripped)
			if m and (section == "infobase"
			          or (section == "infobases" and in_origin)):
				return m.group(1).strip().strip("'\"")
	return ""


def _base_keys(connection: str, root, resolve_relative: bool) -> dict:
	"""Несущая базу часть строки соединения (File/Srvr/Ref).

	Относительный File= резолвится от корня ТОЛЬКО для привязки дерева
	(resolve_relative=True): cwd клиента 1С фикстуре неизвестен, поэтому
	относительный ответ прокси неоднозначен и резолвиться не должен.
	"""
	keys = _conn_keys(connection)
	if "File" in keys:
		path = keys["File"]
		if path.startswith("/"):
			keys["File"] = os.path.realpath(path)
		elif resolve_relative:
			keys["File"] = os.path.realpath(os.path.join(str(root), path))
	return {k: keys[k] for k in _BASE_KEYS if k in keys}


def _fmt_base(keys: dict) -> str:
	return ";".join(f"{k}={keys[k]}" for k in _BASE_KEYS if k in keys)


def _assert_owns_base(client: OnecDB, url: str) -> None:
	"""Проба принадлежности: база прокси = база дерева, иначе прогон не стартует."""
	root = _find_root()
	if root is None:
		raise RuntimeError(
			"onec_db: корень проекта контура не найден от cwd "
			"(нет v8project.yaml и .zcode/1c) — принадлежность базы не сверить; "
			"запусти прогон из корня дерева")
	expected_raw = _expected_connection(root)
	if not expected_raw:
		raise RuntimeError(
			f"onec_db: привязка базы не найдена в local-слое {root} "
			"(infobases.origin.connection в v8project.local.yaml) — "
			"принадлежность базы не сверить; прогони bootstrap контура")
	expected = _base_keys(expected_raw, root, resolve_relative=True)
	if not expected:
		raise RuntimeError(
			f"onec_db: в привязке дерева нет File=/Srvr+Ref: {expected_raw!r}")
	try:
		actual_raw = client.execute(_PROBE_CODE)
	except Exception as e:  # noqa: BLE001 — внятный фейл вместо трейса
		raise RuntimeError(
			f"onec_db: проба принадлежности не прошла — прокси {url} не отдал "
			f"строку соединения ({e})") from e
	actual = _base_keys(str(actual_raw), root, resolve_relative=False)
	if not actual:
		raise RuntimeError(
			f"onec_db: прокси {url} не отдал строку соединения, получено: "
			f"{str(actual_raw)[:200]!r}")
	if expected != actual:
		hint = ""
		actual_file = _conn_keys(str(actual_raw)).get("File")
		if actual_file and not actual_file.startswith("/"):
			hint = ("  Прокси отдал относительный File= — стенд поднят старым "
			        "раннером: перезапусти его (start_1c_db.sh <корень> "
			        "--stop → --headless); раннер контура запускает клиент "
			        "с абсолютным путём.\n")
		raise RuntimeError(
			"onec_db: канал 1c-db ведёт на ЧУЖУЮ базу — прогон не стартует.\n"
			f"  дерево ({root}): {_fmt_base(expected)}\n"
			f"  прокси  ({url}): {_fmt_base(actual)}\n"
			+ hint +
			"Типовая ловушка git-ворктри: дефолт :6003 — прокси ОСНОВНОГО дерева, "
			"юниты молча пишут в чужую базу. Подними свой стенд: "
			"bash .zcode/1c/scripts/start_1c_db.sh <корень-дерева> (порт из "
			"contour.json дерева, :6003 с основным не делить); URL — в "
			"contour.json дерева (1c_db.url) или env ONEC_DB_URL.")


@pytest.fixture(scope="session")
def onec_db() -> OnecDB:
	url = _resolve_url()
	try:
		client = OnecDB(url)
		client.execute("Результат = Истина;")
	except Exception as e:  # noqa: BLE001 — внятный фейл вместо трейса внутри фикстуры
		raise RuntimeError(
			"1c-db не отвечает — подними тестовый клиент контура: "
			"bash .zcode/1c/scripts/start_1c_db.sh (прод-гейт execute_code блокирует)"
		) from e
	_assert_owns_base(client, url)
	return client


@pytest.fixture()
def stub_server():
	server = StubServer()
	httpd = server.start()
	yield server
	httpd.shutdown()
	httpd.server_close()
