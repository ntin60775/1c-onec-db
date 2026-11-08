"""Финализация сеанса — pytest_sessionfinish (юнит #56 Т3).

Критерии тикета процессами: после падшего сеанса клиентов сеанса в
/proc нет (pgrep-эквивалент — обход /proc по File=), прокси переживает
финализацию, из клиентов одной базы гасится только поднятый фикстурой
(«чужой» жив). Плюс правило гашения (TERM доставлен и проигнорирован,
затем SIGKILL), семантика перечня (зелёный сеанс гасит поднятых им;
сеанс без соло не гасит ничего), инвариант вывода (Usr/Pwd из cmdline
клиента не всплывают) и юнит-проверки реестра.

Клиент и прокси — настоящие спящие процессы; скрипт контура — фейк,
который гасит/поднимает настоящий процесс с File= и Usr/Pwd в cmdline
(как поднимает настоящий скрипт) и логирует argv. pytest-сеансы —
subprocess с PYTHONPATH этого дерева и явной загрузкой плагина
(``-p onec_db.plugin``, автозагрузка отключена — канон test_solo_base).
env сеансов герметичен по ONEC_DB_URL.

Приватные имена плагина импортируются внутри юнит-тестов, не сверху:
на базовом коммите (финализации нет) процессные тесты обязаны собираться
и падать поведенчески, а не срубаться ImportError'ом всего файла.
"""
import os
import subprocess
import time
from pathlib import Path

import pytest

from test_solo_base import (alive_proc, reap, run_pytest, sleeper,
                            write_test)

# ── фейк скрипта контура: клиент несёт File=<база>;Usr=…;Pwd=… в cmdline ──

FAKE_SCRIPT = """#!/bin/sh
# фейк start_1c_db.sh (Т3): лог argv; «клиент» — настоящий спящий процесс,
# File= базы в cmdline — по нему /proc-сканы тестов и финализация узнают
# клиента; Usr/Pwd в cmdline же — вывод плагина не имеет права их показать
LOG="{log}"
CLIENT="{pidfile}"
printf '%s\\n' "$*" >> "$LOG"
ROOT="$1"; shift
CMD="${{1:-}}"; [ $# -gt 0 ] && shift
IB="$(readlink -f "$ROOT/build/ib")"
TERM_MARK="${{FAKE_TERM_MARKER:-/nonexistent}}"
if [ "$CMD" = "--stop" ]; then
	if [ -f "$CLIENT" ] && kill -0 "$(cat "$CLIENT")" 2>/dev/null; then
		PID="$(cat "$CLIENT")"; kill "$PID"
		for _ in 1 2 3 4 5 6 7 8 9 10; do
			kill -0 "$PID" 2>/dev/null || break
			sleep 0.2
		done
		echo "• клиентов базы остановлено: 1"
	else
		echo "• клиентов базы не найдено"
	fi
else
	# редирект обязателен: наследованный stdout держит pipe родителя,
	# и subprocess.run ждёт смерти «клиента» вместо завершения (Т2).
	# FAKE_STUBBORN=1 — клиент, который TERM ловит маркером и игнорирует
	# (ветка добивания SIGKILL): TERM_MARK — куда положить доказательство
	if [ "${{FAKE_STUBBORN:-}}" = "1" ]; then
		setsid sh -c 'trap "touch \\"\\$2\\"" TERM; while :; do sleep 1; done' \\
			onec-db-fake-client "File=$IB;Usr=demo;Pwd=sekret" \\
			"$TERM_MARK" >/dev/null 2>&1 &
	else
		setsid sh -c 'while :; do sleep 1; done' \\
			onec-db-fake-client "File=$IB;Usr=demo;Pwd=sekret" \\
			"$TERM_MARK" >/dev/null 2>&1 &
	fi
	echo "$!" > "$CLIENT"
	echo "• клиент запущен (pid $(cat "$CLIENT")); лог: /tmp/none.log"
fi
"""

# Падший модуль: по SOLO_IB поднимает «чужого» клиента той же базы (как
# GUI-клиент testpilot — финализации сеанса он не принадлежит), затем
# роняет ассертом; финализация сеанса выполняется несмотря на падение
FALLING_MODULE = """\
import os
import subprocess
from pathlib import Path


def test_fails_and_raises_stranger(solo_base):
	ib = os.environ.get("SOLO_IB")
	if ib:
		with open(os.devnull, "w") as devnull:
			p = subprocess.Popen(
				["sh", "-c", "while :; do sleep 1; done",
				 "onec-db-stranger",
				 f"File={ib};Usr=stranger;Pwd=strangerpw"],
				stdout=devnull, stderr=devnull, start_new_session=True)
		Path(os.environ["STRANGER_PID"]).write_text(f"{p.pid}\\n")
	assert False  # падение по ассерту — финализация сеанса всё равно идёт
"""

GREEN_MODULE = "def test_passes(solo_base):\n    assert True\n"

PLAIN_MODULE = "def test_plain_without_fixtures():\n    assert True\n"


@pytest.fixture()
def clean_registry():
	"""Реестр — глобальное состояние модуля плагина: изоляция юнитов.
	Только им (процессные тесты живут в собственных subprocess-сеансах с
	чистым реестром); НЕ autouse, чтобы на базовом коммите собрать файл."""
	from onec_db.plugin import _SESSION_CLIENTS
	_SESSION_CLIENTS.clear()
	yield
	_SESSION_CLIENTS.clear()


def make_project(tmp: Path, url: str) -> Path:
	"""Проект контура с фейком скрипта, поднимающим клиента с File=."""
	root = tmp / "proj"
	(root / ".zcode" / "1c" / "scripts").mkdir(parents=True)
	(root / "build" / "ib").mkdir(parents=True)
	(root / "v8project.yaml").write_text("имя: demo\n", encoding="utf-8")
	(root / "v8project.local.yaml").write_text(
		"infobases:\n  origin:\n    connection: 'File=build/ib'\n",
		encoding="utf-8")
	(root / ".zcode" / "1c" / "contour.json").write_text(
		f'{{"1c_db": {{"url": "{url}"}}}}', encoding="utf-8")
	script = root / ".zcode" / "1c" / "scripts" / "start_1c_db.sh"
	script.write_text(FAKE_SCRIPT.format(log=tmp / "calls.log",
	                                     pidfile=tmp / "client.pid"),
	                  encoding="utf-8")
	script.chmod(0o755)
	return root.resolve()  # realpath: база ожиданий строится от него


def raise_client(root: Path):
	"""Клиент стенда до сеанса — поднят фейком (cmdline с File=)."""
	subprocess.run(["bash", str(root / ".zcode" / "1c" / "scripts"
	                            / "start_1c_db.sh"), str(root)],
	               capture_output=True, check=True)


def alive_pid(pid: int) -> bool:
	try:
		st = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
	except OSError:
		return False
	return st.rsplit(")", 1)[-1].split()[0] != "Z"


def pidfile_pid(pidfile: Path):
	"""pid из pid-файла фейка или None."""
	try:
		return int(pidfile.read_text())
	except (OSError, ValueError):
		return None


def scan_file_clients(base: Path) -> set:
	"""pgrep-эквивалент по тикету: обход /proc. Матч — сырой аргумент
	cmdline с префиксом ``File=<realpath базы>;``: контракт записи фейка
	(он печатает клиента ровно таким аргументом), без разбора строки —
	оракул не клонирует парсер плагина."""
	target = f"File={os.path.realpath(str(base))};"
	found = set()
	for name in os.listdir("/proc"):
		if not name.isdigit():
			continue
		try:
			raw = open(f"/proc/{name}/cmdline", "rb").read()
		except OSError:
			continue
		for arg in raw.split(b"\0"):
			if arg.decode("utf-8", "replace").startswith(target):
				found.add(int(name))
				break
	return found


def wait_scan_empty(base: Path, timeout: float = 3.0) -> set:
	"""Скан с допуском на reaping: погибший клиент исчезает из /proc не
	мгновенно; возвращает последний (нечистый) результат для отчёта."""
	deadline = time.monotonic() + timeout
	found = scan_file_clients(base)
	while found and time.monotonic() < deadline:
		time.sleep(0.2)
		found = scan_file_clients(base)
	return found


def kill_pidfile(pidfile: Path):
	if pidfile.exists():
		pid = pidfile.read_text().strip()
		if pid:
			subprocess.run(["kill", "-9", pid], capture_output=True)


# ── критерий 1: падший сеанс — клиентов сеанса в /proc нет ──

def test_fallen_session_leaves_no_clients(tmp_path):
	root = make_project(tmp_path, url="http://127.0.0.1:6003/mcp")
	base = root / "build" / "ib"
	raise_client(root)
	client = tmp_path / "client.pid"
	pid_a = pidfile_pid(client)  # клиент до сеанса: setup погасит его
	assert pid_a is not None
	falling = write_test(root, "test_fin_f.py", FALLING_MODULE)
	try:
		r = run_pytest(root, falling)
		assert r.returncode == 1 and "assert False" in r.stdout, \
			f"rc={r.returncode}, out={r.stdout[-400:]!r}"
		# положительный контроль восстановления: в pid-файле ДРУГОЙ pid —
		# фикстура реально поднимала клиента (иначе тест ниже вырождается)
		pid_b = pidfile_pid(client)
		assert pid_b is not None and pid_b != pid_a, \
			f"restore не поднимал клиента: pid-файл не сменился ({pid_b})"
		# поднятый фикстурой погашен финализацией…
		assert not alive_pid(pid_b), \
			f"поднятый фикстурой клиент {pid_b} пережил сеанс"
		# …и по базе в /proc пусто (pgrep-эквивалент тикета)
		left = wait_scan_empty(base)
		assert not left, f"после сеанса живы клиенты базы: {left}"
		# доказательство, что погасила финализация плагина, а не пустой стенд
		assert "финализация сеанса" in r.stderr, r.stderr
	finally:
		kill_pidfile(client)


# ── критерий 2: прокси финализация не трогает ──

def test_proxy_survives_finalization(tmp_path):
	root = make_project(tmp_path, url="http://127.0.0.1:6003/mcp")
	base = root / "build" / "ib"
	raise_client(root)
	# мок прокси: cmdline несёт имя и порт настоящего прокси (без File=) —
	# широкое гашение по имени/порту зацепило бы его, если бы плагин так гасил
	proxy = subprocess.Popen(
		["sh", "-c", "while :; do sleep 1; done", "onec-mcp-proxy-mock",
		 "python", "-m", "onec_mcp_toolkit_proxy", "--port", "6003"])
	falling = write_test(root, "test_fin_p.py", FALLING_MODULE)
	try:
		r = run_pytest(root, falling)
		assert r.returncode == 1, r.stdout[-300:]
		# поведенческий маркер финализации: клиентов базы в /proc нет
		assert wait_scan_empty(base) == set(), "клиенты базы пережили сеанс"
		assert alive_pid(proxy.pid), \
			"прокси пережить финализацию сеанса не смог"
		# и это была финализация плагина, не пустой стенд
		assert "финализация сеанса" in r.stderr, r.stderr
	finally:
		reap(proxy)
		kill_pidfile(tmp_path / "client.pid")


# ── критерий 3: гасится только поднятый сеансом, «чужой» жив ──

def test_solo_raised_killed_stranger_kept(tmp_path):
	root = make_project(tmp_path, url="http://127.0.0.1:6003/mcp")
	base = root / "build" / "ib"
	raise_client(root)  # клиент до сеанса: setup погасит, restore поднимет
	client = tmp_path / "client.pid"
	pid_a = pidfile_pid(client)
	assert pid_a is not None
	stranger_pidfile = tmp_path / "stranger.pid"
	falling = write_test(root, "test_fin_s.py", FALLING_MODULE)
	try:
		env = {"STRANGER_PID": str(stranger_pidfile), "SOLO_IB": str(base)}
		r = run_pytest(root, falling, extra_env=env)
		assert r.returncode == 1, r.stdout[-300:]
		assert stranger_pidfile.exists(), "чужой клиент не поднят тестом"
		stranger = int(stranger_pidfile.read_text())
		# положительный контроль: поднятый фикстурой клиент (другой pid,
		# restore перезаписал pid-файл) погашен
		pid_b = pidfile_pid(client)
		assert pid_b is not None and pid_b != pid_a, \
			f"restore не поднимал клиента: pid-файл не сменился ({pid_b})"
		assert not alive_pid(pid_b), \
			f"поднятый фикстурой клиент {pid_b} пережил сеанс"
		# на базе жив ровно чужой
		left = wait_scan_empty(base)
		assert left == {stranger}, \
			f"ожидался живым только чужой {stranger}, /proc несёт {left}"
		assert alive_pid(stranger)
	finally:
		if stranger_pidfile.exists():
			stranger = stranger_pidfile.read_text().strip()
			subprocess.run(["kill", "-9", stranger], capture_output=True)
		kill_pidfile(client)


# ── правило гашения: упрямый клиент — TERM доставлен и проигнорирован,
# затем добивание SIGKILL ──

def test_stubborn_client_gets_sigkill(tmp_path):
	root = make_project(tmp_path, url="http://127.0.0.1:6003/mcp")
	base = root / "build" / "ib"
	raise_client(root)  # обычный: setup погасит, restore поднимет упрямого
	client = tmp_path / "client.pid"
	pid_a = pidfile_pid(client)
	assert pid_a is not None
	term_mark = tmp_path / "term.delivered"
	falling = write_test(root, "test_fin_k.py", FALLING_MODULE)
	try:
		env = {"FAKE_STUBBORN": "1", "FAKE_TERM_MARKER": str(term_mark)}
		r = run_pytest(root, falling, extra_env=env)
		assert r.returncode == 1, r.stdout[-300:]
		# положительный контроль: TERM до упрямого доставлен (маркер
		# trap'а) — и он всё равно мёртв, то есть было добивание SIGKILL
		pid_b = pidfile_pid(client)
		assert pid_b is not None and pid_b != pid_a, \
			f"restore не поднимал упрямого клиента ({pid_b})"
		assert term_mark.exists(), "SIGTERM до клиента не доставлен"
		assert wait_scan_empty(base, timeout=5.0) == set(), \
			"упрямый клиент пережил финализацию"
		assert not alive_pid(pid_b)
	finally:
		kill_pidfile(client)


# ── семантика перечня: зелёный сеанс тоже гасит поднятых им ──

def test_green_session_also_finalizes(tmp_path):
	root = make_project(tmp_path, url="http://127.0.0.1:6003/mcp")
	base = root / "build" / "ib"
	raise_client(root)
	client = tmp_path / "client.pid"
	pid_a = pidfile_pid(client)
	assert pid_a is not None
	green = write_test(root, "test_fin_g.py", GREEN_MODULE)
	try:
		r = run_pytest(root, green)
		assert r.returncode == 0, r.stdout + r.stderr
		pid_b = pidfile_pid(client)
		assert pid_b is not None and pid_b != pid_a, \
			f"restore не поднимал клиента ({pid_b})"
		assert not alive_pid(pid_b), \
			"зелёный сеанс оставил поднятого им клиента"
		assert wait_scan_empty(base) == set(), \
			"зелёный сеанс оставил поднятого им клиента"
		assert "финализация сеанса" in r.stderr, r.stderr
	finally:
		kill_pidfile(client)


# ── граница перечня: сеанс без соло ничего не гасит ──

def test_plain_session_touches_nothing(tmp_path):
	root = make_project(tmp_path, url="http://127.0.0.1:6003/mcp")
	base = root / "build" / "ib"
	raise_client(root)
	client = tmp_path / "client.pid"
	pid_a = pidfile_pid(client)
	assert pid_a is not None
	plain = write_test(root, "test_fin_n.py", PLAIN_MODULE)
	try:
		r = run_pytest(root, plain)
		assert r.returncode == 0, r.stdout + r.stderr
		assert alive_pid(pid_a), \
			"финализация погасила клиента, которого сеанс не поднимал"
		assert scan_file_clients(base), "клиент исчез из /proc"
		assert "финализация" not in r.stderr, r.stderr
	finally:
		kill_pidfile(client)


# ── инвариант вывода: Usr/Pwd из cmdline клиентов не всплывают ──

def test_output_masks_creds(tmp_path):
	root = make_project(tmp_path, url="http://127.0.0.1:6003/mcp")
	raise_client(root)
	stranger_pidfile = tmp_path / "stranger.pid"
	falling = write_test(root, "test_fin_m.py", FALLING_MODULE)
	try:
		env = {"STRANGER_PID": str(stranger_pidfile),
		       "SOLO_IB": str(root / "build" / "ib")}
		# --tb=no: отчёт pytest не печатает исходник падающего теста с его
		# литералами — инвариант покрывает оба потока, как критерий Т1
		r = run_pytest(root, falling, extra_env=env,
		               pytest_args=("--tb=no",))
		assert r.returncode == 1, r.stdout[-300:]
		# cmdline клиентов несёт Usr=demo;Pwd=sekret (фейк) и
		# Usr=stranger;Pwd=strangerpw (чужой) — в выводе поставки их нет
		leaked = r.stdout + r.stderr
		assert "Pwd=" not in leaked, leaked[-400:]
		assert "Usr=" not in leaked, leaked[-400:]
		assert "sekret" not in leaked and "strangerpw" not in leaked, \
			leaked[-400:]
		assert "финализация сеанса" in r.stderr, r.stderr
	finally:
		if stranger_pidfile.exists():
			stranger = stranger_pidfile.read_text().strip()
			subprocess.run(["kill", "-9", stranger], capture_output=True)
		kill_pidfile(tmp_path / "client.pid")


# ── юниты реестра (in-process; импорты внутри — краснота на базе не
#    срубается ImportError'ом файла, а остаётся поведенческой) ──

def test_registry_skips_reused_pid(tmp_path, clean_registry):
	# pid переиспользован процессом, чей cmdline несёт ДРУГУЮ базу —
	# чужое не гасится (реализация, гасящая любой File=, провалит тест)
	from onec_db.plugin import _SESSION_CLIENTS, _finalize_clients
	other_base = tmp_path / "other" / "ib"
	other_base.mkdir(parents=True)
	proc = subprocess.Popen(
		["sh", "-c", "while :; do sleep 1; done", "onec-db-fake-client",
		 f"File={other_base};Usr=other;Pwd=otherpw"])
	try:
		_SESSION_CLIENTS.append((proc.pid, str(tmp_path / "expected" / "ib")))
		assert _finalize_clients() == []
		assert proc.poll() is None, \
			"погашен чужой клиент другой базы под тем же pid"
	finally:
		reap(proc)


def test_finalize_clears_registry(tmp_path, clean_registry):
	from onec_db.plugin import _SESSION_CLIENTS, _finalize_clients
	victim = sleeper()
	victim.kill()
	victim.wait()  # гарантированно мёртвый pid
	_SESSION_CLIENTS.append((victim.pid, "/nonexistent"))
	_finalize_clients()
	assert _SESSION_CLIENTS == [], "реестр не очищен после финализации"


def test_restore_without_pid_line_warns(tmp_path, capsys, clean_registry):
	# старт поднял клиента, но не назвал pid — финализация его не погасит:
	# громкое предупреждение, реестр пуст
	from onec_db.plugin import _SESSION_CLIENTS, _solo_base_restore
	mini = tmp_path / "start_1c_db.sh"
	mini.write_text(
		"#!/bin/sh\n"
		"sh -c 'while :; do sleep 1; done' onec-db-fake-client "
		">/dev/null 2>&1 &\n"
		'echo $! > "$1/raised.pid"\n'
		'echo "клиент поднят без контракта pid"\n', encoding="utf-8")
	mini.chmod(0o755)
	state = {"script": mini, "root": tmp_path, "instance": "",
	         "had_client": True, "file": str(tmp_path / "ib")}
	before = len(_SESSION_CLIENTS)
	try:
		_solo_base_restore(state)
		captured = capsys.readouterr()
		assert "не назвал pid" in captured.err, captured.err
		assert len(_SESSION_CLIENTS) == before, "немой старт попал в реестр"
	finally:
		raised = tmp_path / "raised.pid"
		if raised.exists():
			subprocess.run(["kill", "-9", raised.read_text().strip()],
			               capture_output=True)


def test_restore_failure_still_registers_client(tmp_path, clean_registry):
	# restore не прошёл (rc != 0), но pid напечатан контрактом ДО падения:
	# клиент мог подняться — сеанс не оставляет его без реестра, а ошибка
	# остаётся громкой (финализация в конце сеанса погасит поднятого)
	from onec_db.plugin import _SESSION_CLIENTS, _solo_base_restore
	mini = tmp_path / "start_1c_db.sh"
	mini.write_text(
		"#!/bin/sh\n"
		"sh -c 'while :; do sleep 1; done' onec-db-fake-client "
		">/dev/null 2>&1 &\n"
		'echo $! > "$1/raised.pid"\n'
		'echo "• клиент запущен (pid $(cat "$1/raised.pid"))"\n'
		'echo "фаза ожидания не дождалась" >&2\n'
		"exit 1\n", encoding="utf-8")
	mini.chmod(0o755)
	ib = tmp_path / "ib"
	ib.mkdir()
	state = {"script": mini, "root": tmp_path, "instance": "",
	         "had_client": True, "file": str(ib)}
	try:
		with pytest.raises(RuntimeError, match="не прошло"):
			_solo_base_restore(state)
		raised = int((tmp_path / "raised.pid").read_text())
		assert (raised, str(ib)) in _SESSION_CLIENTS, \
			"поднятый при неудавшемся restore клиент без реестра"
	finally:
		raised = tmp_path / "raised.pid"
		if raised.exists():
			subprocess.run(["kill", "-9", raised.read_text().strip()],
			               capture_output=True)
