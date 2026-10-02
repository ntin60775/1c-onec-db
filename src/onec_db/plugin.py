"""pytest-плагин: фикстуры onec_db и stub_server для тестов уровня логики 1С.

После установки пакета фикстуры доступны во всех тестах без conftest.
URL 1c-db: env ONEC_DB_URL → .zcode/1c/contour.json (1c_db.url) → дефолт
http://127.0.0.1:6003/mcp. Клиент 1c-db поднимает scripts/start_1c_db.sh
контура; прод защищён mcp_gate — фикстуры только для тестовых деревьев.
"""
import json
import os
import pathlib

import pytest

from .core import OnecDB, StubServer

__all__ = ["onec_db", "stub_server", "OnecDB", "StubServer"]


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


@pytest.fixture(scope="session")
def onec_db():
	try:
		client = OnecDB(_resolve_url())
		client.execute("Результат = Истина;")
	except Exception as e:  # noqa: BLE001 — внятный фейл вместо трейса внутри фикстуры
		raise RuntimeError(
			"1c-db не отвечает — подними тестовый клиент контура: "
			"bash .zcode/1c/scripts/start_1c_db.sh (прод-гейт execute_code блокирует)"
		) from e
	return client


@pytest.fixture()
def stub_server():
	server = StubServer()
	httpd = server.start()
	yield server
	httpd.shutdown()
	httpd.server_close()
