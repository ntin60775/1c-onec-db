import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from onec_db import OnecDB, StubServer
from onec_db.core import OnecDB as CoreDB


# ── чистые функции ──

def test_bsl_str_escapes_double_quotes():
	assert CoreDB._bsl_str('ОАО "Ромашка"') == '"ОАО ""Ромашка"""'
	assert CoreDB._bsl_str("7700000000") == '"7700000000"'


def test_unwrap_toolkit_envelope():
	assert CoreDB._unwrap({"result": {"success": True, "data": "4"}}) == {"success": True, "data": "4"}
	assert CoreDB._unwrap({"success": True}) == {"success": True}


# ── парсер таблицы тулкита v1.10+ (execute_query текстом) ──

def test_parse_table_basic_types():
	table = ('[2]{"Наименование","ИНН"}:\n'
	         '  "[ORG-00001]",""\n'
	         '  "[ORG-00002]","7700000000"')
	assert CoreDB._parse_table(table) == [
		{"Наименование": "[ORG-00001]", "ИНН": ""},
		{"Наименование": "[ORG-00002]", "ИНН": "7700000000"},
	]


def test_parse_table_unquoted_numbers_and_nulls():
	table = '[2]{"Сумма","Комментарий"}:\n  42,null\n  10.5,"текст"'
	assert CoreDB._parse_table(table) == [
		{"Сумма": 42, "Комментарий": None},
		{"Сумма": 10.5, "Комментарий": "текст"},
	]


def test_parse_table_quotes_with_commas_and_newlines():
	# значение содержит запятую, удвоенные кавычки и перевод строки (ЖР)
	table = '[1]{"Дата","Комментарий"}:\n  "2026-11-02T21:33:47","Ошибка, да ""внутри""\nвторая строка"'
	assert CoreDB._parse_table(table) == [{
		"Дата": "2026-11-02T21:33:47",
		"Комментарий": 'Ошибка, да "внутри"\nвторая строка',
	}]


def test_parse_table_empty_and_crlf():
	assert CoreDB._parse_table('[0]{"Код"}:') == []
	table = '[1]{"Код","Имя"}:\r\n  "00-1","А"\r\n'
	assert CoreDB._parse_table(table) == [{"Код": "00-1", "Имя": "А"}]


def test_parse_table_not_a_table_returns_none():
	assert CoreDB._parse_table('внутренняя ошибка тулкита') is None
	assert CoreDB._parse_table('') is None


def test_parse_table_pads_short_rows():
	table = '[1]{"А","Б","В"}:\n  1,"два"'
	assert CoreDB._parse_table(table) == [{"А": 1, "Б": "два", "В": None}]


def test_create_object_rejects_non_identifier():
	db = OnecDB.__new__(OnecDB)  # без соединения
	with pytest.raises(ValueError):
		db.create_object("Контрагенты; УдалитьФайлы()", {})


def test_create_object_bsl_generation():
	db = OnecDB.__new__(OnecDB)
	captured = {}

	def fake_execute(code, context="server"):
		captured["code"] = code
		return "e74e4dae-be3a-11f1-9fbc-d85ed3523c22"

	db.execute = fake_execute
	obj = db.create_object("Контрагенты", {"Наименование": "МокТест", "ИНН": "7700000000", "Сумма": 5})
	assert obj["guid"] == "e74e4dae-be3a-11f1-9fbc-d85ed3523c22"
	assert obj["klass"] == "справочник"
	code = captured["code"]
	assert "Е2ЕОб = Справочники.Контрагенты.СоздатьЭлемент();" in code
	assert 'Е2ЕОб.Наименование = "Е2Е-МокТест";' in code
	assert "Новый(Тип(" not in code, "менеджерный путь обязателен"
	# документ: пост-режим и режим записи
	db.execute = fake_execute
	db.create_object("ПоступлениеТоваров", {"Номер": "001"}, post=True)
	assert "Документы.ПоступлениеТоваров.СоздатьДокумент();" in captured["code"]
	assert "РежимЗаписиДокумента.Проведение);" in captured["code"]


# ── фейковый MCP-сервер: полный handshake + tools/call ──

class FakeMCPHandler(BaseHTTPRequestHandler):
	def _reply(self, obj, status=200):
		payload = json.dumps(obj).encode("utf-8")
		self.send_response(status)
		self.send_header("Content-Type", "application/json")
		self.send_header("Content-Type-Extra", "x")
		self.send_header("Content-Length", str(len(payload)))
		self.end_headers()
		self.wfile.write(payload)

	def do_POST(self):
		length = int(self.headers.get("Content-Length", 0))
		body = json.loads(self.rfile.read(length))
		self.send_response(200)
		self.send_header("Content-Type", "application/json")
		self.send_header("Mcp-Session-Id", "sess-1")
		self.end_headers()
		if body.get("method") == "initialize":
			# сессия отдаётся заголовком, тело — initialize-ответ
			self.wfile.write(json.dumps({
				"jsonrpc": "2.0", "id": body["id"],
				"result": {"protocolVersion": "2025-03-26", "capabilities": {}}}).encode())
		elif body.get("method") == "tools/call":
			code = body["params"]["arguments"]["code"]
			if "ЗаписатьJSON" in code:
				# 1С-строка с JSON-текстом: сериализатор отдаёт JSON-литералом
				inner = json.dumps('{"sum": 42}')
			elif code == "Результат = 4;":
				# число 1С: сериализатор отдаёт строковым представлением «4»
				inner = "4"
			else:
				# коллекция: сериализатор отдаёт целиком как JSON
				inner = json.dumps({"echo": code})
			self.wfile.write(json.dumps({
				"jsonrpc": "2.0", "id": body["id"],
				"result": {"structuredContent": {"result": {
					"success": True, "data": inner}}}}).encode())
		elif body.get("method") == "notifications/initialized":
			self.wfile.write(b"")
		else:
			self.wfile.write(json.dumps({"jsonrpc": "2.0", "id": body.get("id", 0),
			                             "result": {}}).encode())

	def log_message(self, *a, **k):
		pass


@pytest.fixture()
def fake_mcp():
	httpd = ThreadingHTTPServer(("127.0.0.1", 0), FakeMCPHandler)
	threading.Thread(target=httpd.serve_forever, daemon=True).start()
	yield f"http://127.0.0.1:{httpd.server_address[1]}/mcp"
	httpd.shutdown()
	httpd.server_close()


def test_full_mcp_flow(fake_mcp):
	db = OnecDB(fake_mcp)
	out = db.execute('Результат = Новый Структура("Эхо", "…");')
	assert out == {"echo": 'Результат = Новый Структура("Эхо", "…");'}
	assert db._sid == "sess-1"


def test_numeric_string_unwraps_to_number(fake_mcp):
	db = OnecDB(fake_mcp)
	# «4» — строковое представление числа 1С → распаковывается в число
	assert db.execute("Результат = 4;") == 4


def test_execute_json(fake_mcp):
	db = OnecDB(fake_mcp)
	# execute распаковывает валидный JSON сам; execute_json принимает оба вида
	assert db.execute_json('Результат = ЗаписатьJSON(Запись, Объект);') == {"sum": 42}


# ── HTTP-заглушка ──

def test_stub_server_routes_and_calls():
	ss = StubServer()
	httpd = ss.start()
	try:
		import urllib.request
		ss.route("POST", "/api/bid", 200, '{"status": "ok"}')
		req = urllib.request.Request(ss.url + "/api/bid", data=b"x=1", method="POST")
		assert json.loads(urllib.request.urlopen(req).read()) == {"status": "ok"}
		# незарегистрированный маршрут — 404
		req = urllib.request.Request(ss.url + "/other")
		try:
			urllib.request.urlopen(req)
			raise AssertionError("ожидали 404")
		except urllib.error.HTTPError as e:
			assert e.code == 404
		assert ss.calls == [{"method": "POST", "path": "/api/bid"},
		                    {"method": "GET", "path": "/other"}]
	finally:
		httpd.shutdown()
		httpd.server_close()
