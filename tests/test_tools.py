"""Every tool against a mocked API (recorded responses)."""

import json

import pytest
import responses

from conftest import (CHECK, CORRELATE, TEST_KEY, BASE, call, fixture, list_tools)


def _sent(mocked, i=-1):
    return json.loads(mocked.calls[i].request.body)


# ------------------------------------------------------------ listing

def test_five_tools_listed_read_only(keyed_server):
    tools = {t.name: t for t in list_tools(keyed_server)}
    assert set(tools) == {"correlate_devices", "check_changes", "get_fix_plan", "lookup_cve", "check_windows_host"}
    for t in tools.values():
        assert t.annotations.read_only_hint is True
        assert t.annotations.destructive_hint is False
    props = tools["correlate_devices"].input_schema["properties"]
    assert {"assets", "confirmed_only", "known_exploited_only", "fix_available_only", "max_findings"} <= set(props)
    assert props["max_findings"]["default"] == 25


# ------------------------------------------------------------ correlate_devices

def test_correlate_devices_shape(keyed_server, mocked):
    mocked.add(responses.POST, CORRELATE, json=fixture("correlate_eds518a.json"))
    err, out = call(keyed_server, "correlate_devices",
                    {"assets": [{"vendor": "Moxa", "product": "EDS-518A", "version": "3.5", "asset_id": "a1"}]})
    assert not err
    assert "mode" not in out  # keyed, not demo
    r = out["results"][0]
    for k in ("resolution", "coverage", "warnings", "needs_review", "result_hash", "fix_plan", "findings",
              "total", "has_more", "assessment"):
        assert k in r
    assert r["total"] == 3 and r["has_more"] is False
    f = r["findings"][0]
    assert f["cve_id"] == "CVE-2024-9137" and f["priority_rank"] == 1
    for k in ("match_tier", "priority_reason", "severity", "known_exploited", "epss", "fix", "affected_range",
              "advisory_guidance"):
        assert k in f
    assert f["affected_range"]["source"]["document"] == "NVD CPE configuration"
    assert f["fix"]["document"] == "MPSA-241156"
    assert [x["priority_rank"] for x in r["findings"]] == sorted(x["priority_rank"] for x in r["findings"])
    # No unused bulk: capec, sage, scoring blocks are not passed through.
    blob = json.dumps(out)
    assert "capec" not in blob and "executive_summary" not in blob and "kev_flagged" not in blob


def test_correlate_devices_request_options(keyed_server, mocked):
    mocked.add(responses.POST, CORRELATE, json=fixture("correlate_eds518a.json"))
    call(keyed_server, "correlate_devices",
         {"assets": [{"vendor": "Moxa", "product": "EDS-518A", "version": "3.5"}],
          "known_exploited_only": True, "fix_available_only": True, "max_findings": 7})
    body = _sent(mocked)
    assert body["options"] == {"cve_page": 1, "cve_page_size": 7, "include_capec": False,
                               "known_exploited_only": True, "fix_available_only": True}
    assert body["assets"] == [{"vendor": "Moxa", "product": "EDS-518A", "version": "3.5", "asset_id": "asset-1"}]
    assert mocked.calls[-1].request.headers["Authorization"] == f"Bearer {TEST_KEY}"


def test_max_findings_bounds(keyed_server, mocked):
    err, msg = call(keyed_server, "correlate_devices",
                    {"assets": [{"vendor": "Moxa", "product": "EDS-518A"}], "max_findings": 500})
    assert err
    assert not mocked.calls


def test_descriptions_capped(keyed_server, mocked):
    body = fixture("correlate_eds518a.json")
    body["data"]["results"][0]["cves"][0]["advisory_guidance"][0]["details"] = "x " * 400
    mocked.add(responses.POST, CORRELATE, json=body)
    _, out = call(keyed_server, "correlate_devices", {"assets": [{"vendor": "Moxa", "product": "EDS-518A"}]})
    g = out["results"][0]["findings"][0]["advisory_guidance"][0]["details"]
    assert len(g) <= 300 and g.endswith("...")


def test_honest_assessments(keyed_server, mocked):
    mocked.add(responses.POST, CORRELATE, json=fixture("correlate_mixed.json"))
    _, out = call(keyed_server, "correlate_devices", {"assets": [
        {"vendor": "Siemens", "product": "SIMATIC S7-1500", "version": "2.0", "asset_id": "s"},
        {"vendor": "Acme", "product": "Nothing 9000", "version": "1", "asset_id": "x"},
        {"vendor": "Schneider Electric", "product": "Modicon M340", "asset_id": "p"}], "max_findings": 2})
    by = {r["asset_id"]: r for r in out["results"]}
    assert "Partial coverage" in by["s"]["assessment"] and "needs_review" in by["s"]["assessment"]
    assert by["s"]["needs_review"] is True and by["s"]["has_more"] is True and by["s"]["total"] == 11
    assert "not a clean result" in by["x"]["assessment"]
    assert by["x"]["findings"] == [] and "coverage" not in by["x"]
    for r in out["results"]:
        assert "clean" not in r["assessment"].replace("not a clean result", "")
    src = by["p"]["findings"][0]["affected_range"]["source"]
    assert src["document"] == "ICSA-25-114-01" and src["type"] == "government_advisory"


def test_empty_covered_result_is_not_called_clean(keyed_server, mocked):
    body = fixture("correlate_eds518a.json")
    r = body["data"]["results"][0]
    r["cves"] = []
    r["cves_page"] = {"page": 1, "page_size": 25, "total": 0, "total_unfiltered": 0, "has_more": False}
    mocked.add(responses.POST, CORRELATE, json=body)
    _, out = call(keyed_server, "correlate_devices", {"assets": [{"vendor": "Moxa", "product": "EDS-518A"}]})
    a = out["results"][0]["assessment"]
    assert "not proof" in a and "clean" not in a


# ------------------------------------------------------------ privacy

def test_identifying_fields_stripped_and_reported(keyed_server, mocked):
    mocked.add(responses.POST, CORRELATE, json=fixture("correlate_eds518a.json"))
    _, out = call(keyed_server, "correlate_devices", {"assets": [{
        "vendor": "Moxa", "product": "EDS-518A", "version": "3.5", "asset_id": "10.20.30.40",
        "hostname": "sw-core-1.plant.example.com", "ip": "10.20.30.40", "mac_address": "00:90:e8:12:34:56",
        "user": "jdoe", "site": "North Plant", "location": "Bay 4", "serial": "TBBHB1234567",
        "description": "core switch"}]})
    sent = mocked.calls[-1].request.body.decode()
    for secret in ("sw-core-1", "10.20.30.40", "00:90:e8", "jdoe", "North Plant", "Bay 4", "TBBHB", "core switch"):
        assert secret not in sent
    p = out["privacy"]
    assert set(p["dropped_identifying_fields"]) == {"hostname", "ip", "mac_address", "user", "site",
                                                    "location", "serial"}
    assert p["ignored_fields"] == ["description"]
    assert p["asset_ids_replaced"]["asset_ids"] == ["asset-1"]
    assert "10.20.30.40" not in json.dumps(out)


@pytest.mark.parametrize("asset_id", [
    "plant-a-sw01", "sw01", "PLC-LINE2", "hmi-north-3", "10.20.30.40", "fe80::1", "00:90:e8:12:34:56",
    "0090.e812.3456", "jdoe@example.com", "sw-core-1.plant.example.com", "x" * 200])
def test_non_neutral_asset_id_replaced(keyed_server, mocked, asset_id):
    mocked.add(responses.POST, CORRELATE, json=fixture("correlate_eds518a.json"))
    _, out = call(keyed_server, "correlate_devices", {"assets": [{
        "vendor": "Moxa", "product": "EDS-518A", "version": "3.5", "asset_id": asset_id}]})
    assert _sent(mocked)["assets"][0]["asset_id"] == "asset-1"
    assert out["privacy"]["asset_ids_replaced"]["asset_ids"] == ["asset-1"]
    assert asset_id not in mocked.calls[-1].request.body.decode()


@pytest.mark.parametrize("asset_id", [
    "asset-7", "asset_7", "Device-12", "dev12", "node 3", "42", "asset-7#2",
    "3f2b8c1e-1d2a-4b5c-9e8f-0a1b2c3d4e5f"])
def test_neutral_asset_id_kept(keyed_server, mocked, asset_id):
    mocked.add(responses.POST, CORRELATE, json=fixture("correlate_eds518a.json"))
    _, out = call(keyed_server, "correlate_devices", {"assets": [{
        "vendor": "Moxa", "product": "EDS-518A", "version": "3.5", "asset_id": asset_id}]})
    assert _sent(mocked)["assets"][0]["asset_id"] == asset_id
    assert "asset_ids_replaced" not in out.get("privacy", {})


# ------------------------------------------------------------ check_changes

def test_check_changes(keyed_server, mocked):
    mocked.add(responses.POST, CHECK, json=fixture("check.json"))
    err, out = call(keyed_server, "check_changes", {"assets": [
        {"asset_id": "a1", "vendor": "Moxa", "product": "EDS-518A", "version": "3.5", "result_hash": "sha256:aa",
         "hostname": "h1"},
        {"asset_id": "a2", "vendor": "Moxa", "product": "EDS-518A", "version": "3.5", "result_hash": "sha256:00"}]})
    assert not err
    assert out["changed"] == ["a2"] and out["unchanged_count"] == 1
    assert out["results"][1]["current_hash"].startswith("sha256:")
    sent = _sent(mocked)
    assert sent["assets"][0]["result_hash"] == "sha256:aa" and "hostname" not in sent["assets"][0]
    assert out["privacy"]["dropped_identifying_fields"] == ["hostname"]


def test_check_changes_needs_hash(keyed_server, mocked):
    err, msg = call(keyed_server, "check_changes", {"assets": [
        {"vendor": "Moxa", "product": "EDS-518A", "result_hash": " "}]})
    assert err and "result_hash" in msg
    assert not mocked.calls


# ------------------------------------------------------------ get_fix_plan

def test_get_fix_plan(keyed_server, mocked):
    mocked.add(responses.POST, CORRELATE, json=fixture("correlate_eds518a.json"))
    err, out = call(keyed_server, "get_fix_plan", {"asset": {"vendor": "Moxa", "product": "EDS-518A",
                                                             "version": "3.5"}})
    assert not err
    assert set(out) == {"asset_id", "resolution", "assessment", "needs_review", "fix_groups", "fix_plan"}
    assert out["fix_groups"][0]["cve_ids"] == ["CVE-2024-9137", "CVE-2024-7695", "CVE-2024-9404"]
    assert "3.11.2" in out["fix_plan"]["to_clear_all_fixable"]["fix"]
    assert _sent(mocked)["options"]["cve_page_size"] == 1


# ------------------------------------------------------------ lookup_cve

def test_lookup_cve(keyed_server, mocked):
    mocked.add(responses.GET, f"{BASE}/api/v1/cves/CVE-2024-9137", json=fixture("cve_2024_9137.json"))
    err, out = call(keyed_server, "lookup_cve", {"cve_id": " cve-2024-9137 "})
    assert not err
    assert out["cve_id"] == "CVE-2024-9137" and out["severity"] == "CRITICAL"
    assert out["known_exploited"] is False and out["cwes"] == ["CWE-306"]
    assert len(out["description"]) <= 300
    assert any("mpsa-241156" in a["url"] for a in out["vendor_advisories"])
    assert "sage" not in json.dumps(out)


def test_lookup_cve_fix_varies_by_product(keyed_server, mocked):
    rec = fixture("cve_2024_9137.json")
    rec["data"]["patch"].update(status="varies_by_product", note="Fixed versions differ by product. For the fix ...")
    mocked.add(responses.GET, f"{BASE}/api/v1/cves/CVE-2024-9137", json=rec)
    err, out = call(keyed_server, "lookup_cve", {"cve_id": "CVE-2024-9137"})
    assert not err
    assert out["fix"]["status"] == "varies_by_product"
    assert "correlate_devices" in out["fix"]["note"] and "/api/v1" not in out["fix"]["note"]


def test_lookup_cve_fix_single_product(keyed_server, mocked):
    rec = fixture("cve_2024_9137.json")
    rec["data"]["patch"].update(status="varies_by_product", note="Fixed in 11.36.46 for Commvault Web Server. ...",
                                fixed_in={"product": "Commvault Web Server", "version": "11.36.46"})
    mocked.add(responses.GET, f"{BASE}/api/v1/cves/CVE-2024-9137", json=rec)
    _, out = call(keyed_server, "lookup_cve", {"cve_id": "CVE-2024-9137"})
    assert out["fix"]["status"] == "varies_by_product"
    assert out["fix"]["note"] == ("Fixed in 11.36.46 for Commvault Web Server; use correlate_devices to confirm for "
                                  "your product.")


def test_lookup_cve_fix_unknown_has_no_note(keyed_server, mocked):
    rec = fixture("cve_2024_9137.json")
    rec["data"]["patch"].update(status="unknown", note=None)
    mocked.add(responses.GET, f"{BASE}/api/v1/cves/CVE-2024-9137", json=rec)
    _, out = call(keyed_server, "lookup_cve", {"cve_id": "CVE-2024-9137"})
    assert out["fix"]["status"] == "unknown" and "note" not in out["fix"]


def test_lookup_cve_rejects_non_ids(keyed_server, mocked):
    err, msg = call(keyed_server, "lookup_cve", {"cve_id": "../assets"})
    assert err and "not a CVE id" in msg
    assert not mocked.calls


# ------------------------------------------------------------ demo mode

def test_demo_mode_notice_and_token(demo_server, mocked):
    mocked.add(responses.POST, CORRELATE, json=fixture("correlate_eds518a.json"))
    _, out = call(demo_server, "correlate_devices", {"assets": [{"vendor": "Moxa", "product": "EDS-518A"}]})
    assert out["mode"] == "demo mode: public example access only"
    assert mocked.calls[0].request.url.endswith("/auth/demo-token")
    assert mocked.calls[-1].request.headers["Authorization"] == "Bearer bs_demo_TOKEN0123456789"


def test_demo_token_refreshed_once_on_401(demo_server, mocked):
    mocked.add(responses.POST, CORRELATE, json={"error": {"code": "UNAUTHORIZED", "message": "expired"}},
               status=401)
    mocked.add(responses.POST, CORRELATE, json=fixture("correlate_eds518a.json"))
    err, out = call(demo_server, "correlate_devices", {"assets": [{"vendor": "Moxa", "product": "EDS-518A"}]})
    assert not err and out["results"][0]["total"] == 3
    assert sum(c.request.url.endswith("/auth/demo-token") for c in mocked.calls) == 2


# ------------------------------------------------------------ check_windows_host

WINDOWS = f"{BASE}/api/v2/assets/check-windows"
WIN_HOST = {"os_product": "Windows Server 2019 Standard", "edition_id": "ServerStandard", "os_build": "10.0.17763.6189",
            "architecture": "x64", "installation_type": "Server", "installed_kbs": ["5041578"]}


def test_check_windows_host_description_says_stores_nothing(keyed_server):
    t = {t.name: t for t in list_tools(keyed_server)}["check_windows_host"]
    d = t.description
    assert "without storing anything" in d and "needs review" in d and "never call them clean" in d
    assert t.annotations.read_only_hint is True
    props = t.input_schema["properties"]
    assert props["assets"]["maxItems"] == 25


def test_check_windows_host_shape_and_request(keyed_server, mocked):
    mocked.add(responses.POST, WINDOWS, json=fixture("check_windows.json"))
    err, out = call(keyed_server, "check_windows_host", {"assets": [
        {**WIN_HOST, "asset_id": "asset-1"},
        {**WIN_HOST, "asset_id": "asset-2", "os_build": "10.0.22631"}], "max_findings": 3})
    assert not err
    sent = _sent(mocked)
    assert sent["options"] == {"include_cleared": False, "cve_page": 1, "cve_page_size": 3, "sort": "priority"}
    h = sent["windows_hosts"][0]
    assert h["installed_kbs"] == ["KB5041578"] and h["kb_source"] == "reported" and h["collected_at"].endswith("Z")
    assert out["stored"] is False and "Nothing about these hosts was stored" in out["note"]
    ok, unresolved = out["results"]
    assert ok["patch_resolved"] is True and ok["counts"]["needs_review"] == 3
    assert "need review" in ok["assessment"] and "confirmed open" in ok["assessment"]
    assert len(ok["findings"]) == 3 and ok["findings"][0]["known_exploited"] is True
    assert all(len(g.get("cve_ids", [])) <= 10 for g in ok["fix_groups"])
    assert unresolved["patch_resolved"] is False and "not a clean result" in unresolved["assessment"]


def test_check_windows_host_strips_identifying_fields(keyed_server, mocked):
    mocked.add(responses.POST, WINDOWS, json=fixture("check_windows.json"))
    _, out = call(keyed_server, "check_windows_host", {"assets": [{
        **WIN_HOST, "asset_id": "plant-a-sw01", "hostname": "srv-01.plant.example.com", "ip_address": "10.1.2.3",
        "user": "jdoe", "vendor": "Microsoft", "notes": "core server"}]})
    body = mocked.calls[-1].request.body.decode()
    for secret in ("plant-a-sw01", "srv-01", "10.1.2.3", "jdoe", "core server", "vendor"):
        assert secret not in body
    p = out["privacy"]
    assert set(p["dropped_identifying_fields"]) == {"hostname", "ip_address", "user"}
    assert set(p["ignored_fields"]) == {"notes", "vendor"}
    assert p["asset_ids_replaced"]["asset_ids"] == ["asset-1"]


def test_check_windows_host_refused_in_demo_mode_without_calling(demo_server, mocked):
    err, msg = call(demo_server, "check_windows_host", {"assets": [WIN_HOST]})
    assert err and "demo mode" in msg and "partner or customer API key" in msg
    assert not any("check-windows" in c.request.url for c in mocked.calls)


def test_check_windows_host_more_than_25_refused(keyed_server, mocked):
    err, msg = call(keyed_server, "check_windows_host", {"assets": [WIN_HOST] * 26})
    assert err
    assert len(mocked.calls) == 0
