"""search_products against a mocked catalog."""

import responses

from conftest import BASE, call

V = f"{BASE}/api/v1/catalog/vendors"
P = f"{BASE}/api/v1/catalog/products"


def test_search_products_shape_and_note(keyed_server, mocked):
    mocked.add(responses.GET, V, json={"data": [{"id": 1, "name": "Siemens", "slug": "siemens", "cve_product_count": 900},
                                                {"id": 2, "name": "Siemens Healthineers", "slug": "sh", "cve_product_count": 9},
                                                {"id": 3, "name": "A", "slug": "a", "cve_product_count": 1},
                                                {"id": 4, "name": "B", "slug": "b", "cve_product_count": 1}]})
    mocked.add(responses.GET, P, json={"data": [{"id": 10, "name": "SIMATIC S7-1200", "cve_count": 40}]})
    err, out = call(keyed_server, "search_products", {"vendor": "Siemens", "product": "S7-1200"})
    assert not err
    assert [v["vendor"] for v in out["vendors"]] == ["Siemens"]      # exact vendor match only (audit L6)
    assert out["vendors"][0]["products"] == [{"product": "SIMATIC S7-1200", "cve_count": 40}]
    assert "Only products with at least one CVE" in out["note"]
    assert "q=Siemens" in mocked.calls[0].request.url
    assert "vendor_id=1" in mocked.calls[1].request.url and "q=S7-1200" in mocked.calls[1].request.url
    assert len(mocked.calls) == 2


def test_search_products_no_vendor(keyed_server, mocked):
    mocked.add(responses.GET, V, json={"data": []})
    err, out = call(keyed_server, "search_products", {"vendor": "Nopecorp"})
    assert not err and out["vendors"] == [] and "cannot match the product" in out["note"]


def test_search_products_refused_in_demo(demo_server, mocked):
    err, text = call(demo_server, "search_products", {"vendor": "Siemens"})
    assert err and "use_different_key" in text
    assert not [c for c in mocked.calls if "/catalog/" in c.request.url]


def test_search_products_folds_firmware_entry(keyed_server, mocked):
    mocked.add(responses.GET, V, json={"data": [{"id": 5, "name": "Moxa", "slug": "moxa", "cve_product_count": 300}]})
    mocked.add(responses.GET, P, json={"data": [{"id": 20, "name": "EDS-518A", "cve_count": 10, "firmware_entry":
                                                 {"id": 21, "name": "EDS-518A Firmware", "cve_count": 12}},
                                                {"id": 22, "name": "EDS-510E", "cve_count": 4, "firmware_entry": None}]})
    err, out = call(keyed_server, "search_products", {"vendor": "Moxa", "product": "EDS"})
    assert not err
    assert out["vendors"][0]["products"] == [
        {"product": "EDS-518A", "cve_count": 10,
         "also_listed_as": {"product": "EDS-518A Firmware", "cve_count": 12}},
        {"product": "EDS-510E", "cve_count": 4}]
    assert "group_firmware=true" in mocked.calls[1].request.url


def test_exact_vendor_only(keyed_server, mocked):
    mocked.add(responses.GET, V, json={"data": [{"id": 7832, "name": "GE", "slug": "ge", "cve_product_count": 227},
                                                {"id": 847, "name": "Netgear", "slug": "netgear", "cve_product_count": 1100}]})
    mocked.add(responses.GET, P, json={"data": []})
    err, out = call(keyed_server, "search_products", {"vendor": "GE"})
    assert not err and [x["vendor"] for x in out["vendors"]] == ["GE"]


def test_similar_spelling_note(keyed_server, mocked):
    mocked.add(responses.GET, V, json={"data": [{"id": 110, "name": "Siemens", "slug": "siemens", "cve_product_count": 900}],
                                       "meta": {"similar_spelling": True}})
    mocked.add(responses.GET, P, json={"data": []})
    err, out = call(keyed_server, "search_products", {"vendor": "Seimens"})
    assert not err and out["vendors"][0]["vendor"] == "Siemens" and "closest spellings" in out["note"]
