import asyncio
import json
from pathlib import Path

import pytest
import responses

from mcp import Client

from breachspider_mcp.api import API
from breachspider_mcp.server import build_server

FIXTURES = Path(__file__).parent / "fixtures"
BASE = "https://bs.test"
CORRELATE = f"{BASE}/api/v1/assets/correlate-cves"
CHECK = f"{BASE}/api/v1/assets/correlate-cves/check"
DEMO_TOKEN = f"{BASE}/api/v1/auth/demo-token"
TEST_KEY = "bs_live_TESTKEY0123456789abcdef"


def fixture(name):
    # correlate_mixed.json is a recorded response with asset "s" edited to coverage=partial and
    # needs_review=true, so the honesty paths are exercised.
    return json.loads((FIXTURES / name).read_text())


def error_body(code, message, detail=None, request_id="bs-req-test"):
    err = {"code": code, "message": message}
    if detail is not None:
        err["detail"] = detail
    return {"api": {"version": "1.0.0", "request_id": request_id}, "error": err}


def call(server, tool, args):
    async def go():
        async with Client(server) as c:
            return await c.call_tool(tool, args)
    r = asyncio.run(go())
    text = r.content[0].text if r.content else ""
    return r.is_error, (text if r.is_error else json.loads(text))


def list_tools(server):
    async def go():
        async with Client(server) as c:
            return (await c.list_tools()).tools
    return asyncio.run(go())


@pytest.fixture
def mocked():
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        yield rsps


@pytest.fixture
def keyed_server(mocked):
    return build_server(API(api_key=TEST_KEY, base_url=BASE))


@pytest.fixture
def demo_server(mocked):
    mocked.add(responses.POST, DEMO_TOKEN, json={"token": "bs_demo_TOKEN0123456789"}, status=200)
    return build_server(API(api_key="", base_url=BASE))
