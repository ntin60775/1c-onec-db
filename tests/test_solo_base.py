"""Соло-фикстура solo_base и маркер e2e_solo (юнит #56 Т2).

Критерии тикета процессами: соло-модуль гасит «клиента» перед модулем и
поднимает после (исход «тест упал ассертом» — тот же результат), прокси
переживает модуль, маркер автоповеска виден на всём модуле, канал из url
разводит восстановление mono/``--instance`` (гашение всегда по базе).

Клиент и прокси — настоящие спящие процессы; скрипт контура — фейк,
который гасит/поднимает настоящий процесс и логирует argv. pytest-сеансы
— subprocess с PYTHONPATH этого дерева и явной загрузкой плагина
(``-p onec_db.plugin``): dev-venv держит editable-установку другого
каталога, ворктри-прогон не должен её видеть.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

from onec_db.plugin import _channel_from_url, _instance_for_channel

REPO = Path(__file__).resolve().parent.parent
SRC = str(REPO / "src")

FAKE_SCRIPT = """#!/bin/sh
# фейк start_1c_db.sh: лог argv, «клиент» — настоящий спящий процесс
LOG="{log}"
CLIENT="{pidfile}"
printf '%s\\n' "$*" >> "$LOG"
ROOT="$1"; shift
CMD="${{1:-}}"; [ $# -gt 0 ] && shift
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
	sh -c 'while :; do sleep 1; done' >/dev/null 2>&1 &
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
	except Exception:
		return False
	try:
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
	try:
		st = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
	except OSError:
		return False
	return st.rsplit(")", 1)[-1].split()[0] != "Z"


def sleeper() -> subprocess.Popen:
	return subprocess.Popen(["sh", "-c", "while :; do sleep 1; done"])


def make_project(tmp: Path, url: str, instances: str = "") -> Path:
	"""Проект контура: привязка дерева, contour.json, фейк скрипта, инстансы."""
	root = tmp / "proj"
	(root / ".zcode" / "1c" / "scripts").mkdir(parents=True)
	(root / "build" / "ib").mkdir(parents=True)
	(root / "v8project.yaml").write_text("имя: demo\n", encoding="utf-8")
	(root / "v8project.local.yaml").write_text(
		"infobases:\n  origin:\n    connection: 'File=build/ib'\n",
		encoding="utf-8")
	(root / ".zcode" / "1c" / "contour.json").write_text(
		f'{{"1c_db": {{"url": "{url}"}}}}', encoding="utf-8")
	if instances:
		(root / ".zcode" / "1c" / "db-instances.yaml").write_text(
			instances, encoding="utf-8")
	script = root / ".zcode" / "1c" / "scripts" / "start_1c_db.sh"
	script.write_text(FAKE_SCRIPT.format(log=tmp / "calls.log",
	                                     pidfile=tmp / "client.pid"),
	                  encoding="utf-8")
	script.chmod(0o755)
	return root


def run_pytest(root: Path, *test_files: Path, extra_env: dict = None):
	env = dict(os.environ, PYTHONPATH=SRC)
	if extra_env:
		env.update(extra_env)
	return subprocess.run(
		[sys.executable, "-m", "pytest", "-p", "onec_db.plugin", "-q",
		 *[str(f) for f in test_files]],
		capture_output=True, text=True, timeout=120, env=env, cwd=root)


def write_test(root: Path, name: str, body: str) -> Path:
	(root / "tests").mkdir(exist_ok=True)
	f = root / "tests" / name
	f.write_text(body, encoding="utf-8")
	return f


def raise_client(root: Path):
	# «клиент был до гашения»: старт фейком — настоящий спящий процесс
	subprocess.run(["bash", str(root / ".zcode" / "1c" / "scripts"
	                            / "start_1c_db.sh"), str(root)],
	               capture_output=True, check=True)


def calls(log: Path) -> list[str]:
	return [ln.strip() for ln in log.read_text(encoding="utf-8").splitlines()
	        if ln.strip()]


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
		env = {"SOLO_CLIENT_PID": str(client),
		       "SOLO_PROXY_PID": str(proxy_pid)}

		r1 = run_pytest(root, solo, extra_env=env)
		assert r1.returncode == 0, r1.stdout + r1.stderr
		# после сеанса: клиент поднят обратно, прокси жив
		assert alive_proc(client), "клиент не восстановлен после соло-модуля"
		assert alive_proc(proxy_pid), "прокси пережить соло-модуль не смог"

		# гашение — по строке соединения, без --instance; восстановление mono
		log = calls(tmp_path / "calls.log")
		assert len(log) == 3, log  # raise_client + stop + restore
		expected_conn = f"File={root / 'build' / 'ib'}"
		assert log[1] == f"{root} --stop --base {expected_conn}", log[1]
		assert log[2] == str(root), log[2]  # mono: без --instance

		# исход «тест упал ассертом» — тот же результат: клиент поднят
		failing = write_test(root, "test_solo_b.py", FAILING_MODULE)
		r2 = run_pytest(root, failing, extra_env=env)
		assert r2.returncode == 1 and "assert False" in r2.stdout, \
			f"rc={r2.returncode}, out={r2.stdout[-600:]!r}, err={r2.stderr[-200:]!r}"
		assert alive_proc(client), "падший прогон не восстановил клиента"
		assert alive_proc(proxy_pid), "прокси погиб на падшем прогоне"

		# второй pytest-сеанс на той же базе не зависит: клиент, поднятый
		# восстановлением, гасится снова («остановлено: 1», не «не найдено»)
		r3 = run_pytest(root, solo, extra_env=env)
		assert r3.returncode == 0, \
			f"rc={r3.returncode}, out={r3.stdout[-600:]!r}, err={r3.stderr[-200:]!r}"
		assert alive_proc(client) and alive_proc(proxy_pid)
		log = calls(tmp_path / "calls.log")
		assert len(log) == 7, (log, r2.stdout[-400:], r3.stdout[-400:])
	finally:
		proxy.kill()
		if (tmp_path / "client.pid").exists():
			pid = int((tmp_path / "client.pid").read_text())
			subprocess.run(["kill", str(pid)], capture_output=True)


# ── критерий 3: маркер автоповеска — уже в SOLO_MODULE (оба теста модуля ──
# ── без литерала маркера assert'ят e2e_solo); здесь — сбор выборки        ──

def test_marker_visible_at_collection(tmp_path):
	root = make_project(tmp_path, url="http://127.0.0.1:6003/mcp")
	solo = write_test(root, "test_solo_c.py", SOLO_MODULE)
	raise_client(root)
	client = Path(tmp_path / "client.pid")
	proxy = sleeper()
	try:
		env = {"SOLO_CLIENT_PID": str(client),
		       "SOLO_PROXY_PID": str(tmp_path / "proxy.pid")}
		r = subprocess.run(
			[sys.executable, "-m", "pytest", "-p", "onec_db.plugin",
			 "--collect-only", "-q", str(solo)],
			capture_output=True, text=True, timeout=300,
			env=dict(os.environ, PYTHONPATH=SRC), cwd=root)
		assert r.returncode == 0, r.stdout + r.stderr
		# маркер в коллекции: 2 теста модуля в одном сеансе соло
		assert r.stdout.count("::") >= 2, r.stdout
		# фикстура гашение так и не сделала до тестов — сеанс collect-only
		# не запускает фикстуры: клиент жив
		assert alive_proc(client)
	finally:
		proxy.kill()
		if client.exists():
			subprocess.run(["kill", str(client.read_text().strip())],
			               capture_output=True)


# ── критерий 4: канал из url — mono и --instance восстановления ──

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
	proxy = sleeper()
	(tmp_path / "proxy.pid").write_text(f"{proxy.pid}\n")
	try:
		env = {"SOLO_CLIENT_PID": str(client),
		       "SOLO_PROXY_PID": str(tmp_path / "proxy.pid")}
		r = run_pytest(root, solo, extra_env=env)
		assert r.returncode == 0, r.stdout + r.stderr
		log = calls(tmp_path / "calls.log")
		assert len(log) == 3, log  # raise_client + stop + restore
		expected_conn = f"File={root / 'build' / 'ib'}"
		# гашение всегда по строке соединения — --instance только в подъеме
		assert log[1] == f"{root} --stop --base {expected_conn}", log[1]
		assert log[2] == f"{root} --instance solo1", log[2]
		assert alive_proc(client)
		assert alive_proc(tmp_path / "proxy.pid"), "прокси пережить модуль не смог"
	finally:
		proxy.kill()
		if client.exists():
			subprocess.run(["kill", str(client.read_text().strip())],
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
		# отказ ДО гашения — клиент не тронут
		assert alive_proc(client)
		assert calls(tmp_path / "calls.log") == [str(root)]  # только raise_client
	finally:
		if client.exists():
			subprocess.run(["kill", str(client.read_text().strip())],
			               capture_output=True)


# ── юнит-тесты резолва канала (in-process, как test_plugin) ──

def test_channel_from_url_variants():
	assert _channel_from_url("http://127.0.0.1:6004/mcp?channel=inst2") == "inst2"
	assert _channel_from_url("http://127.0.0.1:6003/mcp") == ""
	assert _channel_from_url("http://127.0.0.1:6004/mcp?a=b&channel=inst3") == "inst3"


def test_instance_for_channel_defaults_to_name(tmp_path):
	cfg = tmp_path / ".zcode" / "1c" / "db-instances.yaml"
	cfg.parent.mkdir(parents=True)
	cfg.write_text(
		"instances:\n"
		"  solo1:\n    connection: File=build/ib/s1\n"
		"    user: u\n    password: p\n"
		"  solo2:\n    channel: other2\n"
		"    connection: File=build/ib/s2\n"
		"    user: u\n    password: p\n", encoding="utf-8")
	# канал не задан — дефолт раннера: имя инстанса
	assert _instance_for_channel(tmp_path,
	                             "http://127.0.0.1:6004/mcp?channel=solo1") == "solo1"
	assert _instance_for_channel(tmp_path,
	                             "http://127.0.0.1:6004/mcp?channel=other2") == "solo2"


def test_instance_for_channel_ignores_comments_and_doc_marker(tmp_path):
	cfg = tmp_path / ".zcode" / "1c" / "db-instances.yaml"
	cfg.parent.mkdir(parents=True)
	cfg.write_text(
		"---\n"
		"# комментарий\n"
		"instances:\n"
		"  solo1:\n    channel: 'quoted1' # инлайн\n"
		"    connection: File=build/ib/s1\n"
		"    user: u\n    password: p\n", encoding="utf-8")
	assert _instance_for_channel(tmp_path,
	                             "http://127.0.0.1:6004/mcp?channel=quoted1") == "solo1"


def test_instance_for_channel_fails_loud(tmp_path):
	with pytest.raises(RuntimeError, match="db-instances.yaml"):
		_instance_for_channel(tmp_path, "http://127.0.0.1:6004/mcp?channel=x")
	cfg = tmp_path / ".zcode" / "1c" / "db-instances.yaml"
	cfg.parent.mkdir(parents=True)
	cfg.write_text(
		"instances:\n  other:\n    connection: File=ib\n"
		"    user: u\n    password: p\n", encoding="utf-8")
	with pytest.raises(RuntimeError, match="нет инстанса с этим каналом"):
		_instance_for_channel(tmp_path, "http://127.0.0.1:6004/mcp?channel=ghost")
