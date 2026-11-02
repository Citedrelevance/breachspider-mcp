"""The hosted profile (mcp.breachspider.com): same tools and shaping as local, stricter input (plan 2.5, 2.6, D7)."""

import json

import pytest
import responses

from conftest import BASE, CORRELATE, TEST_KEY, call, fixture, list_tools

from breachspider_mcp.api import API
from breachspider_mcp.server import HOSTED_CAPS, build_server

WINDOWS = f"{BASE}/api/v2/assets/check-windows"


@pytest.fixture
def hosted(mocked):
    return build_server(API(api_key=TEST_KEY, base_url=BASE), hosted=True)


def _dev(i=1, **kw):
    d = {"vendor": "Moxa", "product": "EDS-518A", "version": "3.5", "asset_id": f"PLC-{i:02d}"}
    d.update(kw)
    return d


def test_same_tool_names_as_local(hosted, keyed_server):
    assert {t.name for t in list_tools(hosted)} == {t.name for t in list_tools(keyed_server)}


def test_hosted_output_equals_local_output(hosted, keyed_server, mocked):
    """Plan 3a confirmation 3: confidence, citations, warnings and needs_review are unchanged by the hosted profile."""
    mocked.add(responses.POST, CORRELATE, json=fixture("correlate_mixed.json"))
    assets = [{k: v for k, v in a.items() if k in ("vendor", "product", "version", "asset_id")}
              for a in json.loads(json.dumps(fixture("correlate_mixed.json")["data"]["results"]))
              if a.get("asset_id")][:3] or [_dev()]
    devs = [{"vendor": "Moxa", "product": "EDS-518A", "version": "3.5", "asset_id": a["asset_id"]} for a in assets]
    e1, local = call(keyed_server, "correlate_devices", {"assets": devs})
    e2, remote = call(hosted, "correlate_devices", {"assets": devs})
    assert not e1 and not e2
    assert local == remote


def test_unknown_field_is_a_schema_error_and_nothing_is_sent(hosted, mocked):
    err, text = call(hosted, "correlate_devices", {"assets": [_dev(hostname="plc1")]})
    assert err and not mocked.calls


@pytest.mark.parametrize("aid,reason", [("10.0.4.17", "IP address"), ("plc1.plant.example.com", "host name"),
                                        ("00:1a:2b:3c:4d:5e", "MAC address"), ("ops@example.com", "email address")])
def test_identifying_asset_id_refused_with_reason_not_value(hosted, mocked, aid, reason):
    err, text = call(hosted, "correlate_devices", {"assets": [_dev(1), _dev(2, asset_id=aid)]})
    assert err and not mocked.calls
    assert f"asset 2: asset_id looks like an {reason}" in text or f"asset 2: asset_id looks like a {reason}" in text
    assert aid not in text
    assert '"action": "fix_input"' in text


def test_identifying_refused_on_every_device_tool(hosted, mocked):
    bad = _dev(asset_id="10.0.0.1")
    for tool, args in [("check_changes", {"assets": [{**bad, "result_hash": "h"}]}),
                       ("get_fix_plan", {"asset": bad}),
                       ("submit_device_batch", {"assets": [bad]})]:
        err, text = call(hosted, tool, args)
        assert err and "IP address" in text, tool
    win = {"os_product": "Windows Server 2019 Standard", "edition_id": "ServerStandard", "os_build": "10.0.17763.6189",
           "architecture": "x64", "installation_type": "Server", "asset_id": "srv01.corp.example.com"}
    err, text = call(hosted, "check_windows_host", {"assets": [win]})
    assert err and "host name" in text
    assert not mocked.calls


def test_caps(hosted, mocked):
    tools = {t.name: t for t in list_tools(hosted)}
    assert tools["correlate_devices"].input_schema["properties"]["assets"]["maxItems"] == HOSTED_CAPS["devices"]
    assert tools["check_windows_host"].input_schema["properties"]["assets"]["maxItems"] == HOSTED_CAPS["windows_hosts"]
    assert tools["check_changes"].input_schema["properties"]["assets"]["maxItems"] == HOSTED_CAPS["check_changes"]
    assert "At most 5 hosts per call" in tools["check_windows_host"].description
    err, _ = call(hosted, "correlate_devices", {"assets": [_dev(i) for i in range(1, 27)]})
    assert err and not mocked.calls


def test_local_profile_unchanged(keyed_server):
    tools = {t.name: t for t in list_tools(keyed_server)}
    assert "maxItems" not in tools["correlate_devices"].input_schema["properties"]["assets"]
    assert "At most 25 hosts per call" in tools["check_windows_host"].description


def test_instructions_say_refused_not_stripped(hosted):
    ins = hosted.instructions if hasattr(hosted, "instructions") else hosted._mcp_server.instructions
    assert "refuses them" in ins and "stripped" not in ins


def test_hosted_needs_auth_not_demo():
    with pytest.raises(ValueError):
        build_server(API(api_key="", base_url=BASE), hosted=True)
