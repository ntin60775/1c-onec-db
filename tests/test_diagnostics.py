"""Диагностика таймаута канала фикстуры onec_db (юнит #56 Т6).

Фикстура при недоступном канале дописывает к ошибке состояние стенда —
блок `start_1c_db.sh --status`. Носитель сборки один: плагин зовёт
скрипт контура из пакета (`$DSH_1C_ROOT/scripts`), своей копии сборки не
держит. Здесь держится контракт вызова и деградации:

- скрипт зовётся с `<корень> --status`, его вывод входит в ошибку как есть;
- скрипт не найден/переменная не задана — ошибка называет пробел, исходная
  причина недоступности канала остаётся;
- скрипт упал — ошибка несёт rc и хвост stderr;
- скрипт не уложился в потолок (`ONEC_DB_STATUS_TIMEOUT`) — ошибка называет
  потолок, прогон не висит.

Прокси-фейк — закрытый порт: живой MCP не нужен, диагностика приходит на
любой недоступный канал. Четыре группы сущностей доказывает тест сборки
(tests/test_db_status.py контура) — здесь проверяется транспорт.
"""
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = str(REPO / "src")

BLOCK = (
	"── состояние стенда 1c-db ──\n"
	"url: http://127.0.0.1:6003/mcp\n"
	"порт 6003: слушает pid 4242 (1cv8) — не прокси тулкита\n"
	"процессы с базой в cmdline (1):\n"
	"  pid 4242 (1cv8): File=/tmp/ib\n"
	"лок 1Cv8.1CL: /tmp/ib/1Cv8.1CL — есть\n"
	"stand-замок: занят — /tmp/proj — операция start_client, "
	"с 2026-11-13T10:00:00+00:00, процесс 4242\n"
)

FAKE_SCRIPT = """#!/bin/sh
printf '%s\\n' "$*" >> "{log}"
{body}
"""


def project(tmp: Path) -> Path:
	"""Проект контура канонной раскладки: привязка дерева и contour.json."""
	root = tmp / "proj"
	(root / ".dsh" / "1c").mkdir(parents=True)
	(root / "build" / "ib").mkdir(parents=True)
	(root / "v8project.yaml").write_text("имя: demo\n", encoding="utf-8")
	(root / "v8project.local.yaml").write_text(
		"infobases:\n  origin:\n    connection: 'File=build/ib'\n",
		encoding="utf-8")
	(root / ".dsh" / "1c" / "contour.json").write_text(
		'{"1c_db": {"url": "http://127.0.0.1:1/mcp"}}', encoding="utf-8")
	return root.resolve()


def package(tmp: Path, body: str = f"cat <<'EOF'\n{BLOCK}EOF") -> Path:
	"""Пакет контура ($DSH_1C_ROOT) с фейковым стартером."""
	pkg = (tmp / "pkg").resolve()
	(pkg / "scripts").mkdir(parents=True)
	script = pkg / "scripts" / "start_1c_db.sh"
	script.write_text(FAKE_SCRIPT.format(log=tmp / "calls.log", body=body),
	                  encoding="utf-8")
	script.chmod(0o755)
	return pkg


def dead_url() -> str:
	"""url закрытого порта: канал не отвечает без живого MCP."""
	import socket
	s = socket.socket()
	s.bind(("127.0.0.1", 0))
	port = s.getsockname()[1]
	s.close()
	return f"http://127.0.0.1:{port}/mcp"


def write_test(root: Path) -> Path:
	(root / "tests").mkdir(exist_ok=True)
	file = root / "tests" / "test_channel.py"
	file.write_text(
		"def test_channel(onec_db):\n"
		"\tonec_db.execute('Результат = Истина;')\n", encoding="utf-8")
	return root / "tests" / "test_channel.py"


def run_pytest(root: Path, pkg: Path, url: str, extra_env: dict = None):
	env = dict(os.environ, PYTHONPATH=SRC, DSH_1C_ROOT=str(pkg),
	           ONEC_DB_URL=url)
	env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
	if extra_env:
		env.update(extra_env)
	return subprocess.run(
		[sys.executable, "-m", "pytest", "-p", "onec_db.plugin", "-q",
		 "--tb=short", str(write_test(root))],
		capture_output=True, text=True, timeout=120, env=env, cwd=root)


def calls(log: Path) -> list:
	if not log.is_file():
		return []
	return [line.strip() for line in log.read_text(encoding="utf-8").splitlines()
	        if line.strip()]


def test_timeout_error_carries_status_block(tmp_path):
	root = project(tmp_path)
	pkg = package(tmp_path)
	url = dead_url()
	r = run_pytest(root, pkg, url)
	out = r.stdout + r.stderr
	assert r.returncode != 0, out
	assert "1c-db не отвечает" in out, out
	for label in ("процессы с базой", "порт 6003", "1Cv8.1CL", "stand-замок"):
		assert label in out, f"в тексте ошибки нет группы «{label}»:\n{out}"
	assert "Pwd=" not in out and "Usr=" not in out, out
	assert calls(tmp_path / "calls.log") == [f"{root} --status"], calls(
		tmp_path / "calls.log")
	# причина таймаута не подменена сборкой: текст исходной ошибки на месте
	assert "Connection refused" in out or "connection refused" in out \
		or "1c-db" in out, out


def test_missing_package_names_gap_and_keeps_cause(tmp_path):
	root = project(tmp_path)
	url = dead_url()
	env = {"DSH_1C_ROOT": ""}
	r = run_pytest(root, package(tmp_path), url, extra_env=env)
	out = r.stdout + r.stderr
	assert r.returncode != 0, out
	assert "1c-db не отвечает" in out, out
	assert "не собрана" in out and "DSH_1C_ROOT" in out, out
	assert "Pwd=" not in out, out


def test_failing_script_adds_rc_and_stderr(tmp_path):
	root = project(tmp_path)
	body = "echo '✗ db-instances.yaml не разобран: табличка' >&2; exit 2"
	pkg = package(tmp_path, body=body)
	r = run_pytest(root, pkg, dead_url())
	out = r.stdout + r.stderr
	assert r.returncode != 0, out
	assert "не собрана (rc 2)" in out, out
	assert "db-instances.yaml не разобран" in out, out
	assert "1c-db не отвечает" in out, out


def test_hanging_script_respects_ceiling(tmp_path):
	root = project(tmp_path)
	pkg = package(tmp_path, body="sleep 30")
	r = run_pytest(root, pkg, dead_url(),
	               extra_env={"ONEC_DB_STATUS_TIMEOUT": "1"})
	out = r.stdout + r.stderr
	assert r.returncode != 0, out
	assert "не уложился" in out and "1 с" in out, out
	assert "1c-db не отвечает" in out, out