"""Проба принадлежности базы фикстуры onec_db (ловушка git-ворктри)."""
import pytest

from onec_db.plugin import (_assert_owns_base, _base_keys, _conn_keys,
                            _expected_connection, _find_root)
from onec_db.core import OnecDB
from test_core import FakeMCPHandler


def _project(tmp_path, connection="File=build/ib"):
	(tmp_path / "v8project.yaml").write_text("имя: demo\n", encoding="utf-8")
	(tmp_path / "v8project.local.yaml").write_text(
		"infobases:\n"
		"  origin:\n"
		f"    connection: '{connection}'\n",
		encoding="utf-8")
	return tmp_path


# ── парсеры ──

def test_conn_keys_strips_quotes_any_order():
	keys = _conn_keys('Srvr="srv-01";Ref="demo";Dbms="MSSQLServer"')
	assert keys == {"Srvr": "srv-01", "Ref": "demo", "Dbms": "MSSQLServer"}


def test_base_keys_resolves_relative_file(tmp_path):
	assert _base_keys('File="build/ib"', tmp_path) == \
		{"File": str(tmp_path / "build" / "ib")}
	assert _base_keys('File="/abs/base"', tmp_path) == {"File": "/abs/base"}


def test_base_keys_keeps_path_keys_only():
	assert _base_keys('Srvr="s";Ref="b";Dbms="MSSQLServer";Usr="u"', None) == \
		{"Srvr": "s", "Ref": "b"}


def test_expected_connection_prefers_local_over_main(tmp_path):
	(tmp_path / "v8project.yaml").write_text(
		"infobases:\n  origin:\n    connection: 'File=main'\n", encoding="utf-8")
	(tmp_path / "v8project.local.yaml").write_text(
		"infobases:\n  origin:\n    connection: 'File=local'\n", encoding="utf-8")
	assert _expected_connection(tmp_path) == "File=local"


def test_find_root_walks_up(tmp_path, monkeypatch):
	nested = tmp_path / "src" / "proj"
	nested.mkdir(parents=True)
	(tmp_path / "v8project.yaml").write_text("имя: demo\n", encoding="utf-8")
	monkeypatch.chdir(nested)
	assert _find_root() == tmp_path


# ── проба принадлежности ──

def test_probe_passes_on_own_base(tmp_path, fake_mcp, monkeypatch):
	root = _project(tmp_path)
	monkeypatch.chdir(root)
	FakeMCPHandler.conn_string = f'File="{root / "build" / "ib"}"'
	_assert_owns_base(OnecDB(fake_mcp), fake_mcp)


def test_probe_fails_on_foreign_base(tmp_path, fake_mcp, monkeypatch):
	root = _project(tmp_path)  # ворктри со своей привязкой
	monkeypatch.chdir(root)
	FakeMCPHandler.conn_string = 'File="/home/main/build/ib"'  # прокси основного дерева
	with pytest.raises(RuntimeError, match="ЧУЖУЮ базу"):
		_assert_owns_base(OnecDB(fake_mcp), "http://127.0.0.1:6003/mcp")


def test_probe_fails_without_local_binding(tmp_path, fake_mcp, monkeypatch):
	(tmp_path / "v8project.yaml").write_text("имя: demo\n", encoding="utf-8")
	monkeypatch.chdir(tmp_path)
	with pytest.raises(RuntimeError, match="привязка базы не найдена"):
		_assert_owns_base(OnecDB(fake_mcp), fake_mcp)


def test_probe_fails_without_contour_project(tmp_path, fake_mcp, monkeypatch):
	monkeypatch.chdir(tmp_path)
	with pytest.raises(RuntimeError, match="корень проекта контура не найден"):
		_assert_owns_base(OnecDB(fake_mcp), fake_mcp)


def test_probe_server_base_match_and_mismatch(tmp_path, fake_mcp, monkeypatch):
	root = _project(tmp_path, connection="Srvr=srv-01;Ref=demo_base")
	monkeypatch.chdir(root)
	FakeMCPHandler.conn_string = 'Srvr="srv-01";Ref="demo_base"'
	_assert_owns_base(OnecDB(fake_mcp), fake_mcp)
	FakeMCPHandler.conn_string = 'Srvr="srv-01";Ref="другая"'
	with pytest.raises(RuntimeError, match="ЧУЖУЮ базу"):
		_assert_owns_base(OnecDB(fake_mcp), fake_mcp)


def test_probe_reports_garbage_proxy_answer(tmp_path, fake_mcp, monkeypatch):
	root = _project(tmp_path)
	monkeypatch.chdir(root)
	FakeMCPHandler.conn_string = "коллекция вместо строки"
	with pytest.raises(RuntimeError, match="не отдал строку соединения"):
		_assert_owns_base(OnecDB(fake_mcp), fake_mcp)
