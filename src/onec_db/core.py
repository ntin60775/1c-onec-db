"""OnecDB — тонкий MCP-клиент 1c-db (stdlib only) и HTTP-заглушка внешних систем.

Контур 1c-zcode. Прямая зависимость — MCP-сервер 1c-db (прокси
1c-mcp-toolkit onec_mcp_toolkit_proxy). Прод защищён отдельно (mcp_gate):
фикстуры уровня логики предназначены только для тестовых деревьев.
"""
import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

__all__ = ["OnecDB", "StubServer"]


class OnecDB:
	"""Минимальный MCP-клиент (Streamable HTTP) к 1c-db: execute/query/фикстуры."""

	def __init__(self, url: str, timeout: int = 120):
		self.url = url
		self.timeout = timeout
		self._sid = None
		self._id = 0
		self._initialize()

	def _next_id(self) -> int:
		self._id += 1
		return self._id

	def _post(self, payload: dict, notify: bool = False):
		headers = {"Content-Type": "application/json",
		           "Accept": "application/json, text/event-stream"}
		if self._sid:
			headers["Mcp-Session-Id"] = self._sid
		req = urllib.request.Request(
			self.url, data=json.dumps(payload).encode("utf-8"),
			headers=headers, method="POST")
		try:
			with urllib.request.urlopen(req, timeout=self.timeout) as resp:
				sid = resp.headers.get("Mcp-Session-Id")
				if sid:
					self._sid = sid
				raw = resp.read().decode("utf-8")
				ctype = resp.headers.get("Content-Type", "")
		except urllib.error.HTTPError as e:
			raise RuntimeError(f"1c-db HTTP {e.code}: {e.read()[:300]}") from e
		if notify:
			return None
		if "text/event-stream" in ctype:
			for line in raw.splitlines():
				if line.startswith("data:"):
					candidate = line[5:].strip()
					if candidate:
						return json.loads(candidate)
			raise RuntimeError("1c-db вернул пустой SSE-поток")
		return json.loads(raw)

	def _initialize(self):
		resp = self._post({"jsonrpc": "2.0", "id": self._next_id(),
		                   "method": "initialize",
		                   "params": {"protocolVersion": "2025-03-26",
		                              "capabilities": {},
		                              "clientInfo": {"name": "onec-db-pytest", "version": "0.1"}}})
		if "error" in resp:
			raise RuntimeError(f"1c-db initialize: {resp['error']}")
		self._post({"jsonrpc": "2.0", "method": "notifications/initialized"}, notify=True)

	def _call(self, tool: str, args: dict):
		resp = self._post({"jsonrpc": "2.0", "id": self._next_id(),
		                   "method": "tools/call",
		                   "params": {"name": tool, "arguments": args}})
		if "error" in resp:
			raise RuntimeError(f"1c-db {tool}: {resp['error']}")
		result = resp.get("result", {})
		if result.get("isError"):
			text = "; ".join(c.get("text", "") for c in result.get("content", [])
			                 if isinstance(c, dict))
			raise RuntimeError(f"1c-db {tool}: {text[:500]}")
		if result.get("structuredContent") is not None:
			return result["structuredContent"]
		for c in result.get("content", []):
			if isinstance(c, dict) and c.get("type") == "text":
				try:
					return json.loads(c["text"])
				except json.JSONDecodeError:
					return c["text"]
		return result

	@staticmethod
	def _unwrap(data):
		"""Разворачивает обёртку тулкита {result: {success, data}}."""
		if isinstance(data, dict) and isinstance(data.get("result"), dict):
			data = data["result"]
		return data

	@staticmethod
	def _bsl_str(value) -> str:
		# строковый литерал 1С: двойные кавычки, экранирование удвоением
		return '"' + str(value).replace('"', '""') + '"'

	# ── публичное API ──

	def execute(self, code: str, context: str = "server"):
		"""Выполнить BSL на сервере; вернуть значение переменной `Результат`.

		Сериализатор тулкита отдаёт 1С-строку как JSON-литерал ('"e74e-…"') —
		разворачивается обратно; сложные значения передавай через ЗаписатьJSON
		и парси execute_json().
		"""
		data = self._unwrap(self._call(
			"execute_code", {"code": code, "execution_context": context}))
		if isinstance(data, dict) and data.get("success") is False:
			raise RuntimeError(f"BSL ошибка: {data.get('error', '?')[:500]}")
		payload = data.get("data") if isinstance(data, dict) else data
		if payload is None:
			raise RuntimeError("execute_code: код не установил переменную `Результат`")
		# сериализатор тулкита отдаёт значение строкой: 1С-строка — JSON-литералом
		# ('"e74e-…"'), коллекции — JSON ('[{…}]'), числа — строкой («4»);
		# разворачиваем валидный JSON-литерал, не-JSON — как есть
		if isinstance(payload, str):
			stripped = payload.strip()
			if stripped[:1] in ('"', "{", "[", "-", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "t", "f", "n"):
				try:
					payload = json.loads(payload)
				except (json.JSONDecodeError, ValueError):
					pass
		return payload

	def execute_json(self, code: str):
		"""BSL устанавливает `Результат` через ЗаписатьJSON; вернуть python-объект.

		принимает и строку-JSON, и уже распакованное execute'ом значение.
		"""
		payload = self.execute(code)
		if isinstance(payload, str):
			return json.loads(payload)
		return payload

	def query(self, text: str, limit: int = 100):
		"""Выполнить запрос; вернуть {"success", "data": [строки]}."""
		data = self._unwrap(self._call("execute_query", {"query": text, "limit": limit}))
		if isinstance(data, dict) and isinstance(data.get("data"), str):
			try:
				data = {**data, "data": json.loads(data["data"])}
			except json.JSONDecodeError:
				pass
		return data

	# ── тестовые данные (замена юнит-фикстур) ──

	def create_object(self, type_name: str, attrs: dict,
	                  post: bool = False, marker: str = "Е2Е-"):
		"""Создать справочник/документ с плоскими реквизитами; вернуть GUID ссылки.

		attrs: {ИмяРеквизита: значение(строка/число/bool)}; Наименование/Номер
		без маркера получают префикс `marker` (очистка по нему). post=True —
		провести документ. Только менеджерный путь
		(Справочники.X.СоздатьЭлемент()): Новый(Тип("СправочникОбъект.X"))
		в окружении Выполнить тулкита ломает установку реквизитов.
		"""
		import re
		if not re.fullmatch(r"[А-Яа-яЁё\w]+", type_name):
			raise ValueError(f"type_name должен быть идентификатором 1С: {type_name!r}")
		name = attrs.get("Наименование") or attrs.get("Номер") or ""
		body = dict(attrs)
		if name and not str(name).startswith(marker):
			key = "Наименование" if "Наименование" in body else "Номер"
			body[key] = marker + str(body[key])
		klass = "документ" if post or "Номер" in body else "справочник"
		manager = {"документ": "Документы", "справочник": "Справочники"}[klass]
		create = "СоздатьДокумент()" if klass == "документ" else "СоздатьЭлемент()"
		lines = [f"Е2ЕОб = {manager}.{type_name}.{create};"]
		for key, value in body.items():
			if isinstance(value, bool):
				expr = "Истина" if value else "Ложь"
			elif isinstance(value, (int, float)):
				expr = str(value)
			else:
				expr = self._bsl_str(value)
			lines.append(f"Е2ЕОб.{key} = {expr};")
		if klass == "документ":
			lines.append("Е2ЕОб.Записать(" + (
				"РежимЗаписиДокумента.Проведение);" if post else "РежимЗаписиДокумента.Запись);"))
		else:
			lines.append("Е2ЕОб.Записать();")
		lines.append("Результат = Е2ЕОб.Ссылка.УникальныйИдентификатор();")
		guid = self.execute("\n".join(lines))
		return {"type": type_name, "guid": str(guid), "klass": klass}

	def delete_object(self, type_name: str, guid: str, klass: str = "справочник"):
		import re
		if not re.fullmatch(r"[А-Яа-яЁё\w]+", type_name):
			raise ValueError(f"type_name должен быть идентификатором 1С: {type_name!r}")
		manager = {"документ": "Документы", "справочник": "Справочники"}[klass]
		self.execute(
			f"Е2ЕСсылка = {manager}.{type_name}.ПолучитьСсылку("
			f"Новый УникальныйИдентификатор({self._bsl_str(guid)}));\n"
			"Е2ЕОб = Е2ЕСсылка.ПолучитьОбъект();\n"
			"Если Е2ЕОб <> Неопределено Тогда Е2ЕОб.Удалить(); КонецЕсли;\n"
			"Результат = Истина;")

	def set_constant(self, name: str, value: str):
		"""Записать константу (канон мока интеграции: URL внешнего сервиса — из константы)."""
		self.execute(f"Константы.{name}.Установить({self._bsl_str(value)});\n"
		             "Результат = Истина;")


class StubServer:
	"""Локальная HTTP-заглушка внешней системы (мок интеграции).

	routes: {(method, path): (status, body_str)}. Запросы пишутся в .calls —
	тест может проверить, что конфигурация обратилась и с теми ли параметрами.
	Канон: конфигурация читает базовый URL из константы/настройки — тест
	ставит onec_db.set_constant(имя, stub_server.url).
	"""

	def __init__(self):
		self.calls = []
		self.routes = {}
		self._port = 0

	def route(self, method: str, path: str, status: int = 200, body: str = "{}"):
		self.routes[(method.upper(), path)] = (status, body)
		return self

	@property
	def url(self) -> str:
		return f"http://127.0.0.1:{self._port}"

	def handler_class(self):
		server = self

		class Handler(BaseHTTPRequestHandler):
			def _route(self):
				key = (self.command, self.path.split("?", 1)[0])
				server.calls.append({"method": self.command, "path": self.path})
				status, body = server.routes.get(
					key, (404, '{"error": "stub: нет маршрута"}'))
				payload = body.encode("utf-8")
				self.send_response(status)
				self.send_header("Content-Type", "application/json; charset=utf-8")
				self.send_header("Content-Length", str(len(payload)))
				self.end_headers()
				self.wfile.write(payload)

			do_GET = do_POST = do_PUT = _route
			log_message = lambda *a, **k: None  # noqa: E731

		return Handler

	def start(self):
		"""Поднять заглушку на свободном порту (фикстура делает это сама)."""
		httpd = ThreadingHTTPServer(("127.0.0.1", 0), self.handler_class())
		self._port = httpd.server_address[1]
		threading.Thread(target=httpd.serve_forever, daemon=True).start()
		return httpd
