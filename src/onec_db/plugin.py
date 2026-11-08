"""pytest-плагин: фикстуры onec_db, solo_base и stub_server для тестов
уровня логики 1С.

После установки пакета фикстуры доступны во всех тестах без conftest.
URL 1c-db: env ONEC_DB_URL → .zcode/1c/contour.json (1c_db.url) → дефолт
http://127.0.0.1:6003/mcp. Клиент 1c-db поднимает
.zcode/1c/scripts/start_1c_db.sh контура; прод защищён mcp_gate —
фикстуры только для тестовых деревьев.

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

Финализация сеанса (``pytest_sessionfinish``): клиенты, поднятые
фикстурами плагина за сеанс (сегодня — соло-восстановление), гасятся в
конце сеанса правилом гашения контура (короткие одиночные kill +
перепроверка, добивание по pid). Перечень — реестр подъёмов, не
cmdline-матч по базе: клиент, поднятый не фикстурами плагина (GUI-клиент
testpilot, ручной старт), финализации не принадлежит — его гасят
``--stop --base``; чистку сирот несёт старт контура (Т5 юнита #56,
ещё не отгружен). Прокси финализация не гасит никогда (общий на
проект); граница: kill -9 самого pytest финализацию не выполняет —
зомби-прокси и сироты останутся до следующего старта (Т4/Т5 юнита
#56, ещё не отгружены).
"""
import json
import os
import pathlib
import re
import signal
import subprocess
import sys
import time
import urllib.parse

import pytest

from .core import OnecDB, StubServer

__all__ = ["onec_db", "solo_base", "stub_server", "OnecDB", "StubServer"]

_PROBE_CODE = "Результат = СтрокаСоединенияИнформационнойБазы();"
_BASE_KEYS = ("File", "Srvr", "Ref")

# Реестр клиентов, поднятых фикстурами плагина за сеанс (юнит #56 Т3):
# пары (pid, путь базы). Носитель перечня — факт подъёма фикстурой, не
# cmdline-матч по базе: клиент той же базы, поднятый мимо сеанса, чужой.
# pid — из контракта вывода скрипта контура «• клиент запущен (pid N)».
_SESSION_CLIENTS: list = []
_CLIENT_PID_RE = re.compile(r"• клиент запущен \(pid (\d+)\)")


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
	"""Строка соединения базы mono-стенда для гашения (``--stop --base``).

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
		# сырая привязка не печатается: в ней могут стоять Usr/Pwd
		raise RuntimeError(
			f"onec_db: в привязке дерева {root} нет несущих базу ключей "
			"File=/Srvr+Ref — гашение адресуется строкой соединения")
	return _fmt_base(keys)


def _channel_from_url(url: str) -> str:
	"""Канал изоляции из url (``?channel=…``); пусто — mono-стенд."""
	query = urllib.parse.urlparse(url).query
	values = urllib.parse.parse_qs(query).get("channel") or []
	if len(values) > 1:
		raise RuntimeError(f"onec_db: в url несколько channel: {url}")
	return values[0] if values else ""


def _yaml_inline_value(val: str) -> str:
	"""Значение YAML-поля: inline-комментарий (вне кавычек) прочь, кавычки
	снимаются — ``channel: 'quoted1' # инлайн`` → ``quoted1``. Подмножество
	контракта instances_py раннера: файл, который раннер отвергнет, может
	читаться здесь иначе — старт инстанса вскрыл бы расхождение раньше."""
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


def _instance_for_channel(root, url: str):
	"""(имя инстанса, его connection) для восстановления по каналу из url;
	``("", "")`` — mono-стенд.

	Канал инстанса — поле ``channel`` записи или её имя (дефолт раннера);
	отступ имён не фиксируется — раннер берёт его из первой вложенной
	строки, здесь так же. Канал в url без инстанса, ведущий к нескольким
	или от записи без connection — громкий отказ: молчаливый mono вернул бы
	клиент без канала и свёл бы два стенда в один.
	"""
	channel = _channel_from_url(url)
	if not channel:
		return "", ""
	path = pathlib.Path(root) / ".zcode" / "1c" / "db-instances.yaml"
	if not path.is_file():
		raise RuntimeError(
			f"onec_db: канал {channel} в url ({url}), но нет {path} — "
			"инстанс для восстановления не найти; подними инстанс или "
			"убери channel из url")
	entries = {}  # имя → {channel, connection}
	current = None
	name_indent = None
	in_instances = False
	for lineno, line in enumerate(
			path.read_text(encoding="utf-8-sig").splitlines(), 1):
		stripped = line.strip()
		if not stripped or stripped.startswith("#") or stripped == "---":
			continue
		lead = line[: len(line) - len(line.lstrip())]
		if "\t" in lead:
			raise RuntimeError(
				f"onec_db: {path}: строка {lineno}: таб в отступе — YAML "
				"табов не допускает (раннер такой файл тоже отвергнет)")
		if not line[:1].isspace():
			in_instances = stripped.rstrip(":") == "instances"
			current = None
			continue
		if not in_instances:
			continue
		indent = len(lead)
		key, _, val = stripped.partition(":")
		key = key.strip().strip("'\"")
		val = _yaml_inline_value(val)
		if name_indent is None:
			name_indent = indent  # раннер берёт отступ из первой вложенной
		if indent == name_indent:
			if val:
				raise RuntimeError(
					f"onec_db: {path}: строка {lineno}: «{key}:» с значением "
					"на отступе имени инстанса — ожидался вложенный список "
					"полей (раннер такой файл тоже отвергнет)")
			current = key
			entries[current] = {"channel": "", "connection": ""}
		elif current is not None and key in ("channel", "connection"):
			entries[current][key] = val
	matches = [n for n, e in entries.items()
	           if (e["channel"] or n) == channel]
	if len(matches) > 1:
		raise RuntimeError(
			f"onec_db: канал {channel} ведёт к нескольким инстансам "
			f"({', '.join(sorted(matches))}) в {path} — восстановление "
			"неоднозначно; разведи каналы в записях")
	if not matches:
		known = ", ".join(f"{n}→{e['channel'] or n}"
		                  for n, e in entries.items()) or "записей нет"
		raise RuntimeError(
			f"onec_db: канал {channel} в url ({url}), но в {path} нет инстанса "
			f"с этим каналом ({known}) — восстанови клиента руками или задай "
			"channel в записи")
	name = matches[0]
	conn = entries[name]["connection"]
	if not conn:
		raise RuntimeError(
			f"onec_db: у инстанса {name} в {path} нет connection — гашение "
			"адресуется строкой соединения записи; заполни поле")
	return name, conn


def _run_starter(script, root, *args: str) -> subprocess.CompletedProcess:
	"""Вызов скрипта контура с результатом; вызыватель решает, громкий ли сбой.

	Потолок — дедлайн ожидания стенда раннера (env WAIT_DEADLINE, дефолт
	420 с; тяжёлые базы его поднимают — скилл 1c-db-data) плюс запас на
	прогрев словаря анонимизации. TimeoutExpired оборачивается внятно:
	клиент стартует через setsid и может продолжать подъём в фоне.
	"""
	try:
		deadline = int(os.environ.get("WAIT_DEADLINE", "420")) + 180
	except ValueError:
		raise RuntimeError(
			f"onec_db: WAIT_DEADLINE не число: "
			f"{os.environ.get('WAIT_DEADLINE')!r}") from None
	try:
		return subprocess.run(["bash", str(script), str(root), *args],
		                      capture_output=True, text=True, timeout=deadline)
	except subprocess.TimeoutExpired as e:
		raise RuntimeError(
			f"onec_db: {' '.join(args) or 'старт'} не уложился в потолок "
			f"{deadline} с — подъём может продолжаться в фоне (setsid); "
			"проверь стенд руками") from e


def _solo_base_setup():
	"""Резолв и гашение перед соло-модулем; state — для _solo_base_restore."""
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
	# Гашение адресуется базой стенда: инстанс — строка соединения своей
	# записи (база инстанса отлична от привязки дерева по построению
	# stand-замка «один клиент на файловую базу»), mono — привязка дерева.
	# Восстановление фиксируется до гашения: инстанс — из канала url.
	# Относительный File= резолвится от корня — скрипт поднимает клиента
	# с абсолютной строкой, адрес по одной realpath-форме с ним.
	instance, instance_conn = _instance_for_channel(root, _resolve_url())
	keys = _base_keys(instance_conn or _resolve_solo_connection(root),
	                  root, resolve_relative=True)
	if not keys:
		raise RuntimeError(
			"onec_db: в строке соединения стенда нет несущих базу ключей "
			"File=/Srvr+Ref — гашение адресуется строкой соединения")
	conn = _fmt_base(keys)
	if not conn.startswith("File="):
		raise RuntimeError(
			f"onec_db: соло-фикстура поддержана для файловых баз (строка "
			f"File=); серверную базу гасят поимённо (--stop --instance "
			"контура)")
	stop = _run_starter(script, root, "--stop", "--base", conn)
	if stop.returncode != 0:
		raise RuntimeError(
			f"onec_db: --stop --base не прошёл (rc {stop.returncode}): "
			f"{stop.stderr.strip()[:300]}")
	# контракт вывода раннера: «• клиентов базы остановлено: N» — клиенты
	# были; «не найдено» (или иной вывод) — гасить нечего, не восстанавливаем
	had_client = "остановлено" in stop.stdout
	return {"script": script, "root": root, "instance": instance,
	        "had_client": had_client, "file": keys.get("File", "")}


def _register_client_pid(stdout, file_path: str) -> bool:
	"""pid из контракта вывода скрипта «• клиент запущен (pid N)» — в реестр
	сеанса. Возвращает, назван ли pid."""
	if isinstance(stdout, bytes):
		stdout = stdout.decode("utf-8", "replace")
	m = _CLIENT_PID_RE.search(stdout or "")
	if not m:
		return False
	_SESSION_CLIENTS.append((int(m.group(1)), file_path))
	return True


def _solo_base_restore(state):
	if not state["had_client"]:
		return
	args = ("--instance", state["instance"]) if state["instance"] else ()
	try:
		restore = _run_starter(state["script"], state["root"], *args)
	except RuntimeError as e:
		# pid печатается скриптом до ожидания подключения: клиент мог
		# подняться и при сорванном по потолку старте — сеанс не должен
		# оставить поднятого без реестра (TimeoutExpired — его причина)
		_register_client_pid(getattr(e.__cause__, "stdout", None),
		                     state["file"])
		raise
	if restore.returncode != 0:
		# то же при неудачном rc: «не прошло» говорит о фазе ожидания,
		# не о факте подъёма — клиент мог подняться
		_register_client_pid(restore.stdout, state["file"])
		label = (f" --instance {state['instance']}"
		         if state["instance"] else "mono")
		raise RuntimeError(
			"onec_db: восстановление клиента после соло-модуля не "
			f"прошло ({label}, rc {restore.returncode}): "
			f"{restore.stderr.strip()[:300]}")
	if not _register_client_pid(restore.stdout, state["file"]):
		# клиент поднят, но финализации он не принадлежит: имени нет
		print("onec_db: старт не назвал pid клиента — финализация его не "
		      "гасит; чистку сирот несёт старт контура (Т5 юнита #56, "
		      "ещё впереди)", file=sys.stderr)


def _alive(pid: int) -> bool:
	# /proc/<pid>/stat есть и у зомби (канон ib_lock._stand_owner_alive,
	# stop_base_py Т1): нет файла = мёртв; нечитаемый (hidepid) = жив;
	# состояние Z после закрывающей скобки comm = зомби, мёртв
	try:
		st = open(f"/proc/{pid}/stat", encoding="utf-8").read()
	except FileNotFoundError:
		return False
	except OSError:
		return True
	return st.rsplit(")", 1)[-1].split()[0] != "Z"


def _cmdline_files(pid: int) -> list:
	"""realpath значений File= из cmdline процесса (по одному на аргумент);
	пусто — процесс не клиент файловой базы.

	Отступления от канона stop_base_py, оба безопасны: относительный путь
	резолвится от cwd (реестровый клиент всегда абсолютен — так его
	поднимает скрипт контура), пустой File= пропускается без fail() —
	гвард сканирует чужие cmdline, конфигурационный отказ не годится."""
	files = []
	try:
		raw = open(f"/proc/{pid}/cmdline", "rb").read()
	except OSError:
		return files
	for arg in raw.split(b"\0"):
		for part in arg.decode("utf-8", "replace").split(";"):
			if part.lower().startswith("file="):
				val = part[5:].strip().strip('"')
				if val:
					files.append(os.path.realpath(val))
				break  # File= один на аргумент; хвост соединения не сканируем
	return files


def _send(pid: int, sig: int):
	try:
		os.kill(pid, sig)
		return None
	except ProcessLookupError:
		return None
	except PermissionError:
		return f"pid {pid}: kill не доставлен (чужой процесс)"


def _finalize_clients():
	"""Гасит клиентов сеанса из реестра; возвращает переживших kill.

	Правило гашения контура (Т1): короткие одиночные kill + перепроверка
	свежей пробы /proc/<pid>/stat, добивание SIGKILL по pid. Перед kill —
	проверка, что процесс до сих пор несёт File= поднятой базы: pid мог
	переиспользоваться чужим процессом, чужое не гасится. Прокси и чужие
	клиенты базы в реестре не живут — финализация их не сканирует вовсе.
	"""
	targets = []
	seen = set()
	for entry in _SESSION_CLIENTS:
		pid, file_path = entry
		if entry in seen:  # пара (pid, путь): тот же pid мог уйти другой базе
			continue
		seen.add(entry)
		if _alive(pid) and file_path in _cmdline_files(pid):
			targets.append(pid)
	for pid in targets:
		err = _send(pid, signal.SIGTERM)
		if err:
			print(f"onec_db: {err}", file=sys.stderr)
	deadline = time.time() + 8
	while targets and any(_alive(pid) for pid in targets) \
			and time.time() < deadline:
		time.sleep(0.5)
	left = [pid for pid in targets if _alive(pid)]
	if left:
		for pid in left:
			print(f"onec_db: pid {pid} пережил SIGTERM — добиваю",
			      file=sys.stderr)
			err = _send(pid, signal.SIGKILL)
			if err:
				print(f"onec_db: {err}", file=sys.stderr)
		deadline = time.time() + 5
		while any(_alive(pid) for pid in left) and time.time() < deadline:
			time.sleep(0.5)
		left = [pid for pid in targets if _alive(pid)]
	if targets:
		print(f"onec_db: финализация сеанса — клиентов остановлено: "
		      f"{len(targets) - len(left)}", file=sys.stderr)
	for pid in left:
		print(f"onec_db: pid {pid} пережил финализацию — гаси руками "
		      "(--stop --base скрипта контура), сирот снимает следующий "
		      "старт (юнит #56 Т5)", file=sys.stderr)
	_SESSION_CLIENTS.clear()
	return left


def pytest_sessionfinish(session, exitstatus):
	"""Финализация сеанса (юнит #56 Т3): гашение поднятых фикстурами клиентов.

	Перечень — реестр подъёмов фикстур плагина (сегодня —
	соло-восстановление; канал-фикстура onec_db процессов не поднимает —
	ей в реестре нечего носить); перед kill — сверка File= в cmdline,
	чтобы не гасить чужой процесс под переиспользованным pid. Гасится и
	на зелёном сеансе: сеанс не оставляет поднятых им клиентов — критерий
	3 тикета падший прогон не называет. Прокси не гасится никогда —
	общий на проект (решение владельца #37). Граница: kill -9 самого
	pytest финализацию не выполняет; зомби-прокси и сироты останутся до
	следующего старта (Т4/Т5 юнита #56 — впереди).
	"""
	_finalize_clients()


@pytest.fixture(scope="module")
def solo_base():
	"""Соло-режим модуля GUI-тестов на базе 1c-db.

	Перед первым тестом модуля клиенты базы гасятся (``--stop --base``
	скрипта контура: инстанс — по строке соединения своей записи,
	mono — по привязке дерева), после модуля — в ``finally``, включая
	падение по ассерту, клиент стенда поднимается обратно: mono или
	``--instance`` по каналу из url. Гашение по базе бьёт всех клиентов
	той базы, возвращается один клиент стенда; клиента до гашения не было
	— восстановление ничего не поднимает. Прокси фикстура не гасит и не
	поднимает; мёртвый прокси старт стенда поднимет сам — живой прокси
	остаётся предусловием среды, как у ``onec_db``.
	"""
	state = _solo_base_setup()
	try:
		yield
	finally:
		_solo_base_restore(state)


def pytest_configure(config):
	config.addinivalue_line(
		"markers",
		"e2e_solo: модуль идёт соло на базе 1c-db (плагин вешает по "
		"использованию solo_base; run_e2e юнита #56 Т8 делит выборку "
		"по маркеру)")


def pytest_collection_modifyitems(config, items):
	"""Соло-фикстура и маркер e2e_solo на весь модуль соло.

	Использование ``solo_base`` хоть одним тестом модуля делает соло весь
	модуль: module-scoped фикстура добавляется остальным тестам модуля
	(гашение до первого теста), маркер вешается на все item — литерал
	маркера в файле теста не обязателен. Смешение с сессионным ``onec_db``
	и локальное перекрытие плагинной фикстуры — громкий отказ на сборе.
	"""
	by_module = {}
	for item in items:
		module = getattr(item, "module", None)
		if module is not None:
			by_module.setdefault(module, []).append(item)
	for module, group in by_module.items():
		if not any("solo_base" in item.fixturenames for item in group):
			continue
		if any("onec_db" in item.fixturenames for item in group):
			pytest.fail(
				f"onec_db: модуль {module.__name__} смешивает solo_base и "
				"onec_db — соло-фикстура гасит клиента под живой сессионной "
				"фикстурой, канал протухнет в следующих тестах; разнеси их "
				"по разным модулям (run_e2e делит сеансы по маркеру "
				"e2e_solo)", pytrace=False)
		for item in group:
			defs = getattr(getattr(item, "_fixtureinfo", None),
			               "name2fixturedefs", {}).get("solo_base")
			if defs:
				owner = getattr(defs[-1].func, "__module__", "")
				if owner and owner != "onec_db.plugin":
					pytest.fail(
						f"onec_db: фикстура solo_base из {owner} перекрывает "
						"плагинную — копия рецепта тихо обходит проверки "
						"(путь скрипта, резолв инстанса); удали локальную "
						"и используй плагинную", pytrace=False)
			if "solo_base" not in item.fixturenames:
				item.fixturenames.append("solo_base")
			if not item.get_closest_marker("e2e_solo"):
				item.add_marker(pytest.mark.e2e_solo)
