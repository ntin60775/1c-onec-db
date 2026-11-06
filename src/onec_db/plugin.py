"""pytest-плагин: фикстуры onec_db, solo_base и stub_server для тестов
уровня логики 1С.

После установки пакета фикстуры доступны во всех тестах без conftest.
URL 1c-db: env ONEC_DB_URL → .zcode/1c/contour.json (1c_db.url) → дефолт
http://127.0.0.1:6003/mcp. Клиент 1c-db поднимает scripts/start_1c_db.sh
контура; прод защищён mcp_gate — фикстуры только для тестовых деревьев.

Проба принадлежности базы: фикстура сверяет базу, которую отдаёт прокси
(``СтрокаСоединенияИнформационнойБазы()``), с привязкой дерева из
local-слоя (v8project.local.yaml → v8project.yaml; ``File=`` / ``Srvr+Ref``).
Рассинхрон — типовая ловушка git-ворктри: дефолт :6003 указывает на прокси
основного дерева, и юниты молча пишут в чужую базу. Прогон не стартует.

Соло-режим GUI-тестов (``solo_base``): GUI-тест и клиент 1c-db на одной
файловой базе вешают друг друга навечно, поэтому модуль с фикстурой идёт
соло — клиенты базы гасятся перед модулем (``--stop --base`` скрипта
контура, по строке соединения) и поднимаются после (mono или
``--instance`` по каналу из url); прокси не трогается. Использование
фикстуры хоть одним тестом модуля вешает на весь модуль маркер
``e2e_solo`` — run_e2e делит выборку на сеансы по collect-only.
"""
import json
import os
import pathlib
import re
import subprocess
import urllib.parse

import pytest

from .core import OnecDB, StubServer

__all__ = ["onec_db", "stub_server", "solo_base", "OnecDB", "StubServer"]

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


def _resolve_solo_connection(root) -> str:
	"""Строка соединения базы для гашения по базе (``--stop --base``).

	Источник — привязка дерева из local-слоя (тот же, что в пробе
	принадлежности); относительный ``File=`` резолвится от корня — скрипт
	контура гасит по realpath-форме, как поднимает клиента.
	"""
	raw = _expected_connection(root)
	if not raw:
		raise RuntimeError(
			f"onec_db: привязка базы не найдена в local-слое {root} "
			"(infobases.origin.connection в v8project.local.yaml) — "
			"соло-фикстуре не по чему гасить клиентов; прогони bootstrap контура")
	keys = _base_keys(raw, root, resolve_relative=True)
	if not keys:
		raise RuntimeError(
			f"onec_db: в привязке дерева нет File=/Srvr+Ref: {raw!r}")
	return _fmt_base(keys)


def _channel_from_url(url: str) -> str:
	"""Канал изоляции из url (``?channel=…``); пусто — mono-стенд."""
	query = urllib.parse.urlparse(url).query
	values = urllib.parse.parse_qs(query).get("channel") or []
	return values[0] if values else ""


def _yaml_inline_value(val: str) -> str:
	"""Значение YAML-поля: inline-комментарий (вне кавычек) прочь, кавычки
	снимаются — ``channel: 'quoted1' # инлайн`` → ``quoted1``."""
	out, in_q = "", None
	for ch in val:
		if in_q:
			if ch == in_q:
				in_q = None
				continue
			out += ch
			continue
		if ch in "'\"":
			in_q = ch
			continue
		if ch == "#" and out.endswith(" "):
			break
		out += ch
	return out.strip()


def _instance_for_channel(root, url: str) -> str:
	"""Имя инстанса для восстановления по каналу из url; пусто — mono.

	Канал инстанса — поле ``channel`` записи или её имя (дефолт раннера).
	Канал в url без инстанса — громкий отказ: молчаливый mono вернул бы
	клиент без канала и свёл бы два стенда в один.
	"""
	channel = _channel_from_url(url)
	if not channel:
		return ""
	path = pathlib.Path(root) / ".zcode" / "1c" / "db-instances.yaml"
	if not path.is_file():
		raise RuntimeError(
			f"onec_db: канал {channel} в url ({url}), но нет {path} — "
			"инстанс для восстановления не найти; подними инстанс или "
			"убери channel из url")
	by_name = {}
	current = None
	in_instances = False
	for line in path.read_text(encoding="utf-8-sig").splitlines():
		stripped = line.strip()
		if not stripped or stripped.startswith("#") or stripped == "---":
			continue
		if not line[:1].isspace():
			in_instances = stripped.rstrip(":") == "instances"
			current = None
			continue
		if not in_instances:
			continue
		indent = len(line) - len(line.lstrip())
		key, _, val = stripped.partition(":")
		key = key.strip().strip("'\"")
		val = _yaml_inline_value(val)
		if indent == 2 and not val:
			current = key
			by_name[current] = current  # дефолт канала раннера — имя инстанса
		elif current and key == "channel" and val:
			by_name[current] = val
	for name, ch in by_name.items():
		if ch == channel:
			return name
	known = ", ".join(f"{n}→{c}" for n, c in by_name.items()) or "записей нет"
	raise RuntimeError(
		f"onec_db: канал {channel} в url ({url}), но в {path} нет инстанса "
		f"с этим каналом ({known}) — восстанови клиента руками или задай "
		"channel в записи")


def _run_starter(script, root, *args: str) -> subprocess.CompletedProcess:
	"""Вызов скрипта контура с результатом; вызыватель решает, громкий ли сбой.

	Потолок 600 с: старт стенда ждёт подключения клиента до ~7 мин
	(WAIT_DEADLINE раннера) плюс прогрев словаря анонимизации.
	"""
	return subprocess.run(["bash", str(script), str(root), *args],
	                      capture_output=True, text=True, timeout=600)


@pytest.fixture(scope="module")
def solo_base():
	"""Соло-режим модуля GUI-тестов на базе 1c-db.

	Перед первым тестом модуля клиенты базы гасятся (``--stop --base``
	скрипта контура, гашение всегда по строке соединения), после модуля —
	в ``finally``, включая падение по ассерту, клиент поднимается обратно:
	mono или ``--instance`` по каналу из url (способ подъёма фиксируется
	до гашения). Прокси фикстура не гасит и не поднимает (один прокси на
	проект); клиента до гашения не было — восстановление ничего не
	поднимает. Живой прокси — предусловие среды, как у ``onec_db``.
	"""
	root = _find_root()
	if root is None:
		raise RuntimeError(
			"onec_db: корень проекта контура не найден от cwd "
			"(нет v8project.yaml и .zcode/1c) — соло-фикстуре не по чему "
			"гасить клиентов; запусти прогон из корня дерева")
	script = pathlib.Path(root) / ".zcode" / "1c" / "scripts" / "start_1c_db.sh"
	if not script.is_file():
		raise RuntimeError(
			f"onec_db: нет {script} — соло-фикстура гасит/поднимает клиента "
			"скриптом контура; доставь скрипт (маппинг scripts/ контура "
			"кладёт его в .zcode/1c/scripts) или убери solo_base")
	conn = _resolve_solo_connection(root)
	if "Srvr=" in conn:
		raise RuntimeError(
			f"onec_db: соло-фикстура поддержана для файловых баз (строка "
			f"File=), привязка дерева: {conn} — серверную базу гасят "
			"поимённо (--stop --instance контура)")
	instance = _instance_for_channel(root, _resolve_url())
	stop = _run_starter(script, root, "--stop", "--base", conn)
	if stop.returncode != 0:
		raise RuntimeError(
			f"onec_db: --stop --base не прошёл (rc {stop.returncode}): "
			f"{stop.stderr.strip()[:300]}")
	had_client = "не найдено" not in stop.stdout
	try:
		yield
	finally:
		if had_client:
			args = ("--instance", instance) if instance else ()
			restore = _run_starter(script, root, *args)
			if restore.returncode != 0:
				label = f" --instance {instance}" if instance else ""
				raise RuntimeError(
					"onec_db: восстановление клиента после соло-модуля не "
					f"прошло ({label or 'mono'}, rc {restore.returncode}): "
					f"{restore.stderr.strip()[:300]}")


def pytest_configure(config):
	config.addinivalue_line(
		"markers",
		"e2e_solo: модуль идёт соло на базе 1c-db (плагин вешает по "
		"использованию solo_base; run_e2e делит выборку по маркеру)")


def pytest_collection_modifyitems(config, items):
	"""Соло-фикстура и маркер e2e_solo на весь модуль соло.

	Использование ``solo_base`` хоть одним тестом модуля делает соло весь
	модуль: module-scoped фикстура добавляется остальным тестам модуля
	(гашение до первого теста), маркер вешается на все item — литерал
	маркера в файле теста не обязателен.
	"""
	by_module = {}
	for item in items:
		module = getattr(item, "module", None)
		if module is not None:
			by_module.setdefault(module, []).append(item)
	for group in by_module.values():
		if not any("solo_base" in item.fixturenames for item in group):
			continue
		for item in group:
			if "solo_base" not in item.fixturenames:
				item.fixturenames.append("solo_base")
			if not item.get_closest_marker("e2e_solo"):
				item.add_marker(pytest.mark.e2e_solo)
