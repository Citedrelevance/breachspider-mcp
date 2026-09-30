"""Live test against production in demo mode (no key). Skip with BREACHSPIDER_SKIP_LIVE=1."""

import os

import pytest

from breachspider_mcp.api import API
from breachspider_mcp.server import build_server
from conftest import call

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(os.environ.get("BREACHSPIDER_SKIP_LIVE") == "1", reason="live tests disabled"),
]

EDS = {"vendor": "Moxa", "product": "EDS-518A", "version": "V3.5", "asset_id": "eds-1"}


@pytest.fixture(scope="module")
def server():
    return build_server(API(api_key=""))


def test_live_moxa_eds518a(server):
    err, out = call(server, "correlate_devices", {"assets": [EDS]})
    assert not err, out
    assert out["mode"] == "demo mode: public example access only"
    r = out["results"][0]
    assert r["resolution"]["status"] == "resolved" and r["resolution"]["product"] == "EDS-518A"
    assert r["total"] == 3 and len(r["findings"]) == 3 and r["has_more"] is False
    for f in r["findings"]:
        assert "3.11.2" in f["fix"]["action"]
        assert f["fix"]["document"] == "MPSA-241156"
        assert f["affected_range"]["source"]
    assert "3.11.2" in r["fix_plan"]["to_clear_all_fixable"]["fix"]
    first = r["findings"][0]
    assert any(g.get("source_document") == "MPSA-241156" and g.get("fixed_versions", {}).get("EDS-518A Series") == "3.11.2"
               for g in first["advisory_guidance"])
    server.live_hash = r["result_hash"]


def test_live_check_changes(server):
    h = getattr(server, "live_hash", None)
    if not h:
        pytest.skip("needs the correlate result")
    err, out = call(server, "check_changes", {"assets": [dict(EDS, result_hash=h)]})
    assert not err, out
    assert out["changed"] == [] and out["results"][0]["current_hash"] == h


def test_live_fix_plan(server):
    err, out = call(server, "get_fix_plan", {"asset": EDS})
    assert not err, out
    assert out["fix_groups"][0]["counts"]["total"] == 3
    assert "3.11.2" in out["fix_groups"][0]["fix"]


def test_live_lookup_cve(server):
    err, out = call(server, "lookup_cve", {"cve_id": "CVE-2024-9137"})
    assert not err, out
    assert out["cve_id"] == "CVE-2024-9137" and out["mode"] == "demo mode: public example access only"
