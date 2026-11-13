"""Проба принадлежности базы фикстуры onec_db (ловушка git-ворктри)."""
import pytest

# Приватные имена плагина импортируются внутри тестов (канон панели Т3):
# на базовом коммите новых имён нет, и файл обязан собираться — иначе
# краснеет весь набор, а не проверки переноса раскладки.
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
	assert _base_keys('File="build/ib"', tmp_path, resolve_relative=True) == \
		{"File": str(tmp_path / "build" / "ib")}
	assert _base_keys('File="/abs/base"', tmp_path, resolve_relative=True) == \
		{"File": "/abs/base"}


def test_base_keys_keeps_proxy_relative_answer_unresolved(tmp_path):
	# cwd клиента фикстуре неизвестен — относительный ответ прокси не резолвится
	assert _base_keys('File="build/ib"', tmp_path, resolve_relative=False) == \
		{"File": "build/ib"}


def test_base_keys_keeps_path_keys_only():
	assert _base_keys('Srvr="s";Ref="b";Dbms="MSSQLServer";Usr="u"', None,
	                  resolve_relative=True) == {"Srvr": "s", "Ref": "b"}


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


# ── раскладка проекта: канон `.dsh/1c` и пакет контура ──

def test_find_root_accepts_canon_layout(tmp_path, monkeypatch):
	root = tmp_path / "proj"
	(root / ".dsh" / "1c").mkdir(parents=True)
	nested = root / "tests" / "e2e"
	nested.mkdir(parents=True)
	monkeypatch.chdir(nested)
	assert _find_root() == root


def test_resolve_url_canon_layout_and_local_overlay(tmp_path, monkeypatch):
	from onec_db.plugin import _resolve_url

	monkeypatch.delenv("ONEC_DB_URL", raising=False)
	root = tmp_path / "proj"
	cfg = root / ".dsh" / "1c"
	cfg.mkdir(parents=True)
	(cfg / "contour.json").write_text(
		'{"1c_db": {"url": "http://127.0.0.1:6003/mcp"}}', encoding="utf-8")
	monkeypatch.chdir(root)
	assert _resolve_url() == "http://127.0.0.1:6003/mcp"
	# локальный оверлей порта применяется, пока желаемый url не менялся
	(cfg / "contour.local.json").write_text(
		'{"1c_db": {"desired_url": "http://127.0.0.1:6003/mcp",'
		' "url": "http://127.0.0.1:6004/mcp"}}', encoding="utf-8")
	assert _resolve_url() == "http://127.0.0.1:6004/mcp"
	# смена желаемого url в contour.json снимает дрейф
	(cfg / "contour.json").write_text(
		'{"1c_db": {"url": "http://127.0.0.1:6007/mcp"}}', encoding="utf-8")
	assert _resolve_url() == "http://127.0.0.1:6007/mcp"


def test_resolve_url_names_broken_layer(tmp_path, monkeypatch, capsys):
	from onec_db.plugin import _resolve_url

	monkeypatch.delenv("ONEC_DB_URL", raising=False)
	root = tmp_path / "proj"
	cfg = root / ".dsh" / "1c"
	cfg.mkdir(parents=True)
	(cfg / "contour.json").write_text(
		'{"1c_db": {"url": "http://127.0.0.1:6003/mcp"}}', encoding="utf-8")
	(cfg / "contour.local.json").write_text("{битый", encoding="utf-8")
	monkeypatch.chdir(root)
	assert _resolve_url() == "http://127.0.0.1:6003/mcp"
	err = capsys.readouterr().err
	assert "contour.local.json" in err and "не разобран" in err, err


def test_resolve_url_env_wins(tmp_path, monkeypatch):
	from onec_db.plugin import _resolve_url

	monkeypatch.setenv("ONEC_DB_URL", "http://127.0.0.1:7000/mcp")
	assert _resolve_url() == "http://127.0.0.1:7000/mcp"


def test_dead_zcode_layout_is_not_read(tmp_path, monkeypatch):
	# снятая раскладка ZCode (Т10 контура) не вход: иначе плагин тихо читал бы
	# contour.json мёртвого каталога и адресовал чужой стенд
	from onec_db.plugin import _resolve_url

	monkeypatch.delenv("ONEC_DB_URL", raising=False)
	root = tmp_path / "proj"
	cfg = root / ".zcode" / "1c"
	cfg.mkdir(parents=True)
	(cfg / "contour.json").write_text(
		'{"1c_db": {"url": "http://127.0.0.1:6999/mcp"}}', encoding="utf-8")
	monkeypatch.chdir(root)
	assert _find_root() is None
	assert _resolve_url() == "http://127.0.0.1:6003/mcp"


def test_contour_script_requires_package(tmp_path, monkeypatch):
	from onec_db.plugin import _contour_script

	monkeypatch.delenv("DSH_1C_ROOT", raising=False)
	with pytest.raises(RuntimeError, match="DSH_1C_ROOT"):
		_contour_script("start_1c_db.sh")
	monkeypatch.setenv("DSH_1C_ROOT", str(tmp_path))
	with pytest.raises(RuntimeError, match="поставь пакет контура"):
		_contour_script("start_1c_db.sh")
	script = tmp_path / "scripts" / "start_1c_db.sh"
	script.parent.mkdir()
	script.write_text("", encoding="utf-8")
	assert _contour_script("start_1c_db.sh") == script


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


def test_probe_fails_when_proxy_reports_relative(tmp_path, fake_mcp, monkeypatch):
	# регресс ложного прохода: одинаковые ОТНОСИТЕЛЬНЫЕ строки у дерева
	# («build/ib») и прокси — базы разных деревьев, совпадение строки ничего
	# не доказывает; к тому же ведёт на перезапуск стенда старым раннером
	root = _project(tmp_path)
	monkeypatch.chdir(root)
	FakeMCPHandler.conn_string = 'File="build/ib"'
	with pytest.raises(RuntimeError, match="относительный File="):
		_assert_owns_base(OnecDB(fake_mcp), fake_mcp)


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


def test_probe_does_not_print_credentials_from_binding(tmp_path, fake_mcp,
                                                       monkeypatch):
	# привязка дерева без File=/Srvr+Ref, но с учётками: текст ошибки их не несёт
	root = _project(tmp_path, connection='Usr="u";Pwd="sekret"')
	monkeypatch.chdir(root)
	with pytest.raises(RuntimeError) as err:
		_assert_owns_base(OnecDB(fake_mcp), fake_mcp)
	text = str(err.value)
	assert "sekret" not in text and "Pwd=" not in text and "Usr=" not in text
	assert "строка без File=/Srvr+Ref" in text


def test_probe_does_not_print_credentials_from_proxy_answer(tmp_path, fake_mcp,
                                                           monkeypatch):
	root = _project(tmp_path)  # привязка с базой и учётками
	monkeypatch.chdir(root)
	FakeMCPHandler.conn_string = 'Usr="u";Pwd="sekret"'  # ответ без базы
	with pytest.raises(RuntimeError) as err:
		_assert_owns_base(OnecDB(fake_mcp), fake_mcp)
	text = str(err.value)
	assert "sekret" not in text and "Pwd=" not in text and "Usr=" not in text
	assert "строка без File=/Srvr+Ref" in text


def test_probe_reports_garbage_proxy_answer(tmp_path, fake_mcp, monkeypatch):
	root = _project(tmp_path)
	monkeypatch.chdir(root)
	FakeMCPHandler.conn_string = "коллекция вместо строки"
	with pytest.raises(RuntimeError, match="не отдал строку соединения"):
		_assert_owns_base(OnecDB(fake_mcp), fake_mcp)
