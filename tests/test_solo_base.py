"""Соло-фикстура solo_base и маркер e2e_solo (юнит #56 Т2).

Критерии тикета процессами: соло-модуль гасит «клиента» перед модулем и
поднимает после (исход «тест упал ассертом» — тот же результат), прокси
переживает модуль, маркер автоповеска виден при сборе выборки, канал из
url разводит восстановление mono/``--instance`` (гашение инстанс-стенда —
по строке соединения записи), клиента не было — восстановление не звалось.

Клиент и прокси — настоящие спящие процессы; скрипт контура — фейк,
который гасит/поднимает настоящий процесс и логирует argv. Клиент фейка
несёт ``File=<база>;Usr=…;Pwd=…`` в cmdline — как поднимает настоящий
скрипт, поэтому гвард финализации сеанса (юнит #56 Т3) узнаёт его:
в конце сеанса sessionfinish гасит поднятого фикстурой, и «клиент
восстановлен» доказывается сменой pid-файла + мёртвым поднятым pid,
а не живостью после сеанса. pytest-сеансы — subprocess с PYTHONPATH
этого дерева и явной загрузкой плагина (``-p onec_db.plugin``):
dev-venv держит editable-установку другого каталога, ворктри-прогон
не должен её видеть. env сеансов герметичен по ONEC_DB_URL.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

from onec_db.plugin import (_channel_from_url, _instance_for_channel,
                            _solo_base_setup)

REPO = Path(__file__).resolve().parent.parent
SRC = str(REPO / "src")

FAKE_SCRIPT = """#!/bin/sh
# фейк start_1c_db.sh: лог argv; «клиент» — настоящий спящий процесс
# с File=<база>;Usr=…;Pwd=… в cmdline (как поднимает настоящий скрипт);
# FAKE_IB переопределяет базу — у инстанса она отлична от привязки дерева
LOG="{log}"
CLIENT="{pidfile}"
printf '%s\\n' "$*" >> "$LOG"
ROOT="$1"; shift
CMD="${{1:-}}"; [ $# -gt 0 ] && shift
IB="$(readlink -f "${{FAKE_IB:-$ROOT/build/ib}}")"
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
	# и subprocess.run ждёт смерти «клиента» вместо завершения
	sh -c 'while :; do sleep 1; done' onec-fake-client \\
		"File=$IB;Usr=demo;Pwd=demopw" >/dev/null 2>&1 &
	echo "$!" > "$CLIENT"
	echo "• клиент запущен (pid $(cat "$CLIENT"))"
fi
"""

SOLO_MODULE = """\
import os
from pathlib import Path


def _alive(pidfile):
	try:
		pid = int(Path(pidfile).read_text())
		st = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
	except OSError:
		return False
	return st.rsplit(")", 1)[-1].split()[0] != "Z"


def test_inside_solo(solo_base):
	assert not _alive(os.environ["SOLO_CLIENT_PID"])
	assert _alive(os.environ["SOLO_PROXY_PID"])


def test_marker_without_explicit_fixture(request):
	assert "e2e_solo" in [m.name for m in request.node.iter_markers()]
"""

# первый тест модуля БЕЗ явной фикстуры — автоповеска в fixturenames
# должна поднять её до первого теста (живость клиента проверяется в env)
SOLO_MODULE_PLAIN_FIRST = """\
import os
from pathlib import Path


def _alive(pidfile):
	try:
		pid = int(Path(pidfile).read_text())
		st = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
	except OSError:
		return False
	return st.rsplit(")", 1)[-1].split()[0] != "Z"


def test_first_plain():
	assert not _alive(os.environ["SOLO_CLIENT_PID"])


def test_second_explicit(solo_base):
	assert True
"""

FAILING_MODULE = """\
import os
from pathlib import Path


def _alive(pidfile):
	try:
		pid = int(Path(pidfile).read_text())
		st = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
	except OSError:
		return False
	return st.rsplit(")", 1)[-1].split()[0] != "Z"


def test_fails_mid_module(solo_base):
	assert not _alive(os.environ["SOLO_CLIENT_PID"])
	assert False  # падение по ассерту — восстановление всё равно идёт
"""


def alive_proc(pidfile: Path) -> bool:
	try:
		pid = int(pidfile.read_text())
	except Exception:
		return False
	return alive_pid(pid)


def alive_pid(pid: int) -> bool:
	try:
		st = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
	except OSError:
		return False
	return st.rsplit(")", 1)[-1].split()[0] != "Z"


def pidfile_pid(pidfile: Path):
	try:
		return int(pidfile.read_text())
	except (OSError, ValueError):
		return None


def sleeper() -> subprocess.Popen:
	return subprocess.Popen(["sh", "-c", "while :; do sleep 1; done"])


def package(tmp: Path) -> Path:
	"""Пакет контура ($DSH_1C_ROOT): проект скрипты не вендорит (канон DSH)."""
	package_scripts = tmp / "pkg" / "scripts"
	package_scripts.mkdir(parents=True, exist_ok=True)
	return package_scripts


def make_project(tmp: Path, url: str, instances: str = "") -> Path:
	"""Проект контура: привязка дерева, contour.json, фейк скрипта, инстансы."""
	root = tmp / "proj"
	(root / ".dsh" / "1c").mkdir(parents=True)
	(root / "build" / "ib").mkdir(parents=True)
	(root / "v8project.yaml").write_text("имя: demo\n", encoding="utf-8")
	(root / "v8project.local.yaml").write_text(
		"infobases:\n  origin:\n    connection: 'File=build/ib'\n",
		encoding="utf-8")
	(root / ".dsh" / "1c" / "contour.json").write_text(
		f'{{"1c_db": {{"url": "{url}"}}}}', encoding="utf-8")
	if instances:
		(root / ".dsh" / "1c" / "db-instances.yaml").write_text(
			instances, encoding="utf-8")
	script = package(tmp) / "start_1c_db.sh"
	script.write_text(FAKE_SCRIPT.format(log=tmp / "calls.log",
	                                     pidfile=tmp / "client.pid"),
	                  encoding="utf-8")
	script.chmod(0o755)
	return root.resolve()  # realpath: ожидания соединения строятся от него


def run_pytest(root: Path, *test_files: Path, extra_env: dict = None,
               pytest_args: tuple = ()):
	env = dict(os.environ, PYTHONPATH=SRC,
	           DSH_1C_ROOT=str(root.parent / "pkg"))
	env.pop("ONEC_DB_URL", None)  # герметичность: url задаёт contour.json
	# автозагрузка entry-points прочь: при установленном пакете (system/site)
	# entry-point «onec_db» и явный «-p onec_db.plugin» зарегистрируют один
	# модуль под двумя именами — pluggy падает «already registered»
	env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
	if extra_env:
		env.update(extra_env)
	return subprocess.run(
		[sys.executable, "-m", "pytest", "-p", "onec_db.plugin", "-q",
		 *pytest_args, *[str(f) for f in test_files]],
		capture_output=True, text=True, timeout=120, env=env, cwd=root)


def write_test(root: Path, name: str, body: str) -> Path:
	(root / "tests").mkdir(exist_ok=True)
	f = root / "tests" / name
	f.write_text(body, encoding="utf-8")
	return f


def raise_client(root: Path):
	# «клиент был до гашения»: старт фейком — настоящий спящий процесс
	subprocess.run(["bash", str(root.parent / "pkg" / "scripts"
	                            / "start_1c_db.sh"), str(root)],
	               capture_output=True, check=True)


def calls(log: Path) -> list[str]:
	return [ln.strip() for ln in log.read_text(encoding="utf-8").splitlines()
	        if ln.strip()]


def reap(proc: subprocess.Popen):
	proc.kill()
	proc.wait()


# ── критерии 1–2: гашение/восстановление, падший прогон, прокси переживает ──

def test_solo_module_guards_and_restores(tmp_path):
	root = make_project(tmp_path, url="http://127.0.0.1:6003/mcp")
	proxy = sleeper()  # прокси — вне интересов скрипта и фикстуры
	solo = write_test(root, "test_solo_a.py", SOLO_MODULE)
	try:
		raise_client(root)
		client = Path(tmp_path / "client.pid")
		proxy_pid = Path(tmp_path / "proxy.pid")
		proxy_pid.write_text(f"{proxy.pid}\n")
		pid_a = pidfile_pid(client)
		assert pid_a is not None
		env = {"SOLO_CLIENT_PID": str(client),
		       "SOLO_PROXY_PID": str(proxy_pid)}

		r1 = run_pytest(root, solo, extra_env=env)
		assert r1.returncode == 0, r1.stdout + r1.stderr
		# восстановление поднимало клиента (pid-файл сменился); в конце
		# сеанса поднятого гасит финализация плагина (Т3) — сеанс не
		# оставляет поднятых им клиентов
		pid_b = pidfile_pid(client)
		assert pid_b is not None and pid_b != pid_a, \
			f"restore не поднимал клиента (pid-файл: {pid_b})"
		assert not alive_pid(pid_b), \
			"поднятый фикстурой клиент пережил сеанс — финализация не сработала"
		assert alive_proc(proxy_pid), "прокси пережить соло-модуль не смог"

		# гашение — по строке соединения привязки дерева, без --instance;
		# восстановление mono
		log = calls(tmp_path / "calls.log")
		assert len(log) == 3, log  # raise_client + stop + restore
		expected_conn = f"File={root / 'build' / 'ib'}"
		assert log[1] == f"{root} --stop --base {expected_conn}", log[1]
		assert log[2] == str(root), log[2]  # mono: без --instance

		# исход «тест упал ассертом» — тот же результат: финализация
		# прошлого сеанса стенд опустошила, клиента поднимаем заново
		raise_client(root)
		pid_a2 = pidfile_pid(client)
		assert pid_a2 is not None and pid_a2 != pid_b
		failing = write_test(root, "test_solo_b.py", FAILING_MODULE)
		r2 = run_pytest(root, failing, extra_env=env)
		assert r2.returncode == 1 and "assert False" in r2.stdout, \
			f"rc={r2.returncode}, out={r2.stdout[-600:]!r}, err={r2.stderr[-200:]!r}"
		pid_c = pidfile_pid(client)
		assert pid_c is not None and pid_c != pid_a2, \
			"падший прогон не восстановил клиента"
		assert not alive_pid(pid_c), "поднятый пережил сеанс"
		assert alive_proc(proxy_pid), "прокси погиб на падшем прогоне"

		# второй pytest-сеанс на той же базе не зависит: клиент, поднятый
		# восстановлением, гасится снова («остановлено», не «не найдено»)
		raise_client(root)
		pid_a3 = pidfile_pid(client)
		assert pid_a3 is not None and pid_a3 != pid_c
		r3 = run_pytest(root, solo, extra_env=env)
		assert r3.returncode == 0, \
			f"rc={r3.returncode}, out={r3.stdout[-600:]!r}, err={r3.stderr[-200:]!r}"
		pid_d = pidfile_pid(client)
		assert pid_d is not None and pid_d != pid_a3
		assert not alive_pid(pid_d)
		assert alive_proc(proxy_pid)
		log = calls(tmp_path / "calls.log")
		# 3 × raise_client + (stop, restore) × 3 сеанса
		assert len(log) == 9, (log, r2.stdout[-400:], r3.stdout[-400:])
		assert "не найдено" not in "\n".join(log), log
	finally:
		reap(proxy)
		if (tmp_path / "client.pid").exists():
			pid = (tmp_path / "client.pid").read_text().strip()
			subprocess.run(["kill", pid], capture_output=True)


# ── границы тикета: клиента не было — восстановление ничего не поднимает ──

def test_no_client_means_no_restore(tmp_path):
	root = make_project(tmp_path, url="http://127.0.0.1:6003/mcp")
	solo = write_test(root, "test_solo_n.py",
	                  "def test_passes(solo_base):\n    pass\n")
	client = Path(tmp_path / "client.pid")
	r = run_pytest(root, solo)  # клиента до гашения не поднимали
	assert r.returncode == 0, r.stdout + r.stderr
	expected_conn = f"File={root / 'build' / 'ib'}"
	log = calls(tmp_path / "calls.log")
	assert log == [f"{root} --stop --base {expected_conn}"], log
	assert not client.exists(), "фейк-старт звался — восстановление сработало"


# ── критерий 3: маркер автоповеска виден при сборе выборки ──

def test_marker_visible_at_collection(tmp_path):
	root = make_project(tmp_path, url="http://127.0.0.1:6003/mcp")
	solo = write_test(root, "test_solo_m.py", SOLO_MODULE)
	# pytest 9, collect-only -q: сводка «tests/test_solo_m.py: 2»
	r_yes = run_pytest(root, solo, pytest_args=("--collect-only", "-q",
	                                            "-m", "e2e_solo"))
	assert r_yes.returncode == 0, r_yes.stdout + r_yes.stderr
	assert "test_solo_m.py: 2" in r_yes.stdout, r_yes.stdout
	r_no = run_pytest(root, solo, pytest_args=("--collect-only", "-q",
	                                           "-m", "not e2e_solo"))
	# rc 5 = «0 тестов отобрано» — весь модуль под маркером
	assert r_no.returncode == 5, \
		f"rc={r_no.returncode}, out={r_no.stdout[-300:]!r}"
	assert "test_solo_m.py" not in r_no.stdout, r_no.stdout


# автоповеска фикстуры: первый тест модуля без явного solo_base — гашение
# до него (фикстура дописана в fixturenames плагином)

def test_autofixture_reaches_first_plain_test(tmp_path):
	root = make_project(tmp_path, url="http://127.0.0.1:6003/mcp")
	solo = write_test(root, "test_solo_p.py", SOLO_MODULE_PLAIN_FIRST)
	try:
		raise_client(root)
		client = Path(tmp_path / "client.pid")
		pid_a = pidfile_pid(client)
		assert pid_a is not None
		r = run_pytest(root, solo,
		               extra_env={"SOLO_CLIENT_PID": str(client)})
		assert r.returncode == 0, r.stdout + r.stderr
		pid_b = pidfile_pid(client)
		assert pid_b is not None and pid_b != pid_a, \
			"restore не поднимал клиента"
		assert not alive_pid(pid_b), \
			"поднятый фикстурой клиент пережил сеанс — финализация не сработала"
		assert len(calls(tmp_path / "calls.log")) == 3
	finally:
		if (tmp_path / "client.pid").exists():
			pid = (tmp_path / "client.pid").read_text().strip()
			subprocess.run(["kill", pid], capture_output=True)


# ── критерий 4: канал из url — mono и --instance восстановления; гашение
# инстанс-стенда адресуется строкой соединения записи (не привязкой дерева) ──

def test_channel_resolves_instance_restore(tmp_path):
	root = make_project(
		tmp_path, url="http://127.0.0.1:6004/mcp?channel=solo1",
		instances="instances:\n"
		          "  solo1:\n    channel: solo1\n"
		          "    connection: File=build/ib/s1\n"
		          "    user: u\n    password: p\n")
	solo = write_test(root, "test_solo_d.py", SOLO_MODULE)
	raise_client(root)
	client = Path(tmp_path / "client.pid")
	pid_a = pidfile_pid(client)
	assert pid_a is not None
	proxy = sleeper()
	(tmp_path / "proxy.pid").write_text(f"{proxy.pid}\n")
	try:
		env = {"SOLO_CLIENT_PID": str(client),
		       "SOLO_PROXY_PID": str(tmp_path / "proxy.pid"),
		       # поднятый по --instance клиент несёт базу записи инстанса,
		       # не привязку дерева — как поднимает настоящий скрипт
		       "FAKE_IB": str(root / "build" / "ib" / "s1")}
		r = run_pytest(root, solo, extra_env=env)
		assert r.returncode == 0, r.stdout + r.stderr
		log = calls(tmp_path / "calls.log")
		assert len(log) == 3, log  # raise_client + stop + restore
		expected_conn = f"File={root / 'build' / 'ib' / 's1'}"
		# гашение инстанс-стенда — по connection записи (база инстанса
		# отлична от привязки дерева), --instance только в подъеме
		assert log[1] == f"{root} --stop --base {expected_conn}", log[1]
		assert log[2] == f"{root} --instance solo1", log[2]
		pid_b = pidfile_pid(client)
		assert pid_b is not None and pid_b != pid_a, \
			"restore не поднимал клиента инстанса"
		assert not alive_pid(pid_b), \
			"поднятый фикстурой клиент пережил сеанс — финализация не сработала"
		assert alive_proc(tmp_path / "proxy.pid"), "прокси пережить модуль не смог"
	finally:
		reap(proxy)
		if client.exists():
			subprocess.run(["kill", client.read_text().strip()],
			               capture_output=True)


def test_channel_without_instance_fails_loud(tmp_path):
	root = make_project(
		tmp_path, url="http://127.0.0.1:6005/mcp?channel=ghost",
		instances="instances:\n"
		          "  other:\n    connection: File=build/ib/o\n"
		          "    user: u\n    password: p\n")
	solo = write_test(root, "test_solo_e.py", SOLO_MODULE)
	raise_client(root)
	client = Path(tmp_path / "client.pid")
	try:
		r = run_pytest(root, solo)
		assert r.returncode != 0
		assert "нет инстанса с этим каналом" in r.stdout, r.stdout
		# отказ ДО гашения — клиент не тронут; реестр пуст, финализации
		# сеанса нечего гасить
		assert alive_proc(client)
		assert calls(tmp_path / "calls.log") == [str(root)]  # только raise_client
		assert "финализация" not in r.stderr, r.stderr
	finally:
		if client.exists():
			subprocess.run(["kill", client.read_text().strip()],
			               capture_output=True)


# ── громкие отказы фикстуры (in-process: резолв до subprocess) ──

def _project_min(tmp: Path, connection: str) -> Path:
	root = tmp / "proj"
	(root / ".dsh" / "1c").mkdir(parents=True)
	(root / "v8project.yaml").write_text("имя: demo\n", encoding="utf-8")
	(root / "v8project.local.yaml").write_text(
		"infobases:\n  origin:\n"
		f"    connection: '{connection}'\n", encoding="utf-8")
	return root.resolve()


def test_setup_fails_without_contour_root(tmp_path, monkeypatch):
	monkeypatch.chdir(tmp_path)
	with pytest.raises(RuntimeError, match="корень проекта контура не найден"):
		_solo_base_setup()


def test_setup_fails_without_script(tmp_path, monkeypatch):
	root = _project_min(tmp_path, "File=build/ib")
	monkeypatch.chdir(root)
	monkeypatch.delenv("DSH_1C_ROOT", raising=False)  # пакета нет — скрипта нет
	with pytest.raises(RuntimeError, match="скриптом контура"):
		_solo_base_setup()


def test_setup_fails_on_server_base(tmp_path, monkeypatch):
	root = _project_min(tmp_path, "Srvr=srv-01;Ref=demo_base")
	monkeypatch.chdir(root)
	(package(tmp_path) / "start_1c_db.sh").write_text("", encoding="utf-8")
	monkeypatch.setenv("DSH_1C_ROOT", str(tmp_path / "pkg"))
	with pytest.raises(RuntimeError, match="файловых баз"):
		_solo_base_setup()


def test_setup_fails_without_binding(tmp_path, monkeypatch):
	root = tmp_path / "proj"
	(root / ".dsh" / "1c").mkdir(parents=True)
	(root / "v8project.yaml").write_text("имя: demo\n", encoding="utf-8")
	monkeypatch.chdir(root)
	(package(tmp_path) / "start_1c_db.sh").write_text("", encoding="utf-8")
	monkeypatch.setenv("DSH_1C_ROOT", str(tmp_path / "pkg"))
	with pytest.raises(RuntimeError, match="привязка базы не найдена"):
		_solo_base_setup()


# ── юнит-тесты резолва канала (in-process, как test_plugin) ──

def test_channel_from_url_variants():
	assert _channel_from_url("http://127.0.0.1:6004/mcp?channel=inst2") == "inst2"
	assert _channel_from_url("http://127.0.0.1:6003/mcp") == ""
	assert _channel_from_url("http://127.0.0.1:6004/mcp?a=b&channel=inst3") == "inst3"
	with pytest.raises(RuntimeError, match="несколько channel"):
		_channel_from_url("http://127.0.0.1:6004/mcp?channel=a&channel=b")


def test_instance_for_channel_defaults_to_name(tmp_path):
	cfg = tmp_path / ".dsh" / "1c" / "db-instances.yaml"
	cfg.parent.mkdir(parents=True)
	cfg.write_text(
		"instances:\n"
		"  solo1:\n    connection: File=build/ib/s1\n"
		"    user: u\n    password: p\n"
		"  solo2:\n    channel: other2\n"
		"    connection: File=build/ib/s2\n"
		"    user: u\n    password: p\n", encoding="utf-8")
	# канал не задан — дефолт раннера: имя инстанса; connection возвращается
	assert _instance_for_channel(tmp_path,
	                             "http://127.0.0.1:6004/mcp?channel=solo1") == \
		("solo1", "File=build/ib/s1")
	assert _instance_for_channel(tmp_path,
	                             "http://127.0.0.1:6004/mcp?channel=other2") == \
		("solo2", "File=build/ib/s2")


def test_instance_for_channel_indents_and_comments(tmp_path):
	cfg = tmp_path / ".dsh" / "1c" / "db-instances.yaml"
	cfg.parent.mkdir(parents=True)
	# отступ 4 (раннер берёт name_indent из первой вложенной) + комментарии
	cfg.write_text(
		"# комментарий\n"
		"---\n"
		"instances:\n"
		"    solo1:\n"
		"        channel: 'quoted1' # инлайн\n"
		"        connection: File=build/ib/s1\n"
		"        user: u\n"
		"        password: p\n", encoding="utf-8")
	assert _instance_for_channel(tmp_path,
	                             "http://127.0.0.1:6004/mcp?channel=quoted1") == \
		("solo1", "File=build/ib/s1")


def test_instance_for_channel_ambiguous_fails_loud(tmp_path):
	cfg = tmp_path / ".dsh" / "1c" / "db-instances.yaml"
	cfg.parent.mkdir(parents=True)
	cfg.write_text(
		"instances:\n"
		"  one:\n    channel: same\n    connection: File=ib1\n"
		"  two:\n    channel: same\n    connection: File=ib2\n",
		encoding="utf-8")
	with pytest.raises(RuntimeError, match="нескольким инстансам"):
		_instance_for_channel(tmp_path, "http://127.0.0.1:6004/mcp?channel=same")
