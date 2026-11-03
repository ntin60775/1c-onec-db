import threading
from http.server import ThreadingHTTPServer

import pytest

from test_core import FakeMCPHandler


@pytest.fixture()
def fake_mcp():
	httpd = ThreadingHTTPServer(("127.0.0.1", 0), FakeMCPHandler)
	threading.Thread(target=httpd.serve_forever, daemon=True).start()
	yield f"http://127.0.0.1:{httpd.server_address[1]}/mcp"
	httpd.shutdown()
	httpd.server_close()
