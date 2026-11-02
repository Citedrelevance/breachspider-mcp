"""submit_device_batch and get_device_batch against a mocked API."""

import json

import responses

from conftest import BASE, TEST_KEY, call, error_body, fixture, list_tools

BATCH = f"{BASE}/api/v1/batches"
JID = "204be806-375f-4da9-a165-24da2fb0c45e"


def _one_result():
    return fixture("correlate_mixed.json")["data"]["results"][0]


def _status(status, done=2, total=2, **extra):
    d = {"job_id": JID, "status": status, "progress": {"done": done, "failed": 0, "total": total},
         "cancel_requested": False, "finished_at": None, "expires_at": "2026-12-02T00:00:00+00:00", "summary": None,
         "error_summary": None}
    d.update(extra)
    return {"data": d}


def test_batch_tools_listed_with_annotations(keyed_server):
    tools = {t.name: t for t in list_tools(keyed_server)}
    sub, get = tools["submit_device_batch"], tools["get_device_batch"]
    assert sub.annotations.read_only_hint is False and sub.annotations.destructive_hint is False
    assert sub.annotations.idempotent_hint is True
    assert get.annotations.read_only_hint is True
    assert sub.input_schema["properties"]["assets"]["maxItems"] == 5000
    assert get.input_schema["properties"]["page_size"]["maximum"] == 50


def test_submit_sends_body_and_idempotency_key(keyed_server, mocked):
    mocked.add(responses.POST, BATCH, status=202,
               json={"data": {"job_id": JID, "status": "queued", "created_at": "2026-11-02T10:00:00+00:00"}})
    err, out = call(keyed_server, "submit_device_batch", {"assets": [
        {"vendor": "Moxa", "product": "EDS-518A", "version": "3.5", "asset_id": "asset-1"},
        {"vendor": "Siemens", "product": "S7-1200", "version": "4.2", "hostname": "plc1.plant.example"}]})
    assert not err
    assert out["job_id"] == JID and out["status"] == "queued" and out["devices_queued"] == 2
    assert "hostname" in json.dumps(out["privacy"])
    req = mocked.calls[0].request
    body = json.loads(req.body)
    assert len(body["assets"]) == 2 and "hostname" not in body["assets"][1]
    assert body["options"]["cve_page_size"] == 10
    key = req.headers["Idempotency-Key"]
    assert key.startswith("mcp-") and 8 <= len(key) <= 80
    assert TEST_KEY not in json.dumps(out)


def test_submit_same_list_same_key_different_list_new_key(keyed_server, mocked):
    mocked.add(responses.POST, BATCH, status=202, json={"data": {"job_id": JID, "status": "queued"}})
    a = [{"vendor": "Moxa", "product": "EDS-518A", "version": "3.5"}]
    call(keyed_server, "submit_device_batch", {"assets": a})
    call(keyed_server, "submit_device_batch", {"assets": a})
    call(keyed_server, "submit_device_batch", {"assets": a, "max_findings": 5})
    keys = [c.request.headers["Idempotency-Key"] for c in mocked.calls]
    assert keys[0] == keys[1] != keys[2]


def test_submit_refused_in_demo_mode_without_calling(demo_server, mocked):
    err, text = call(demo_server, "submit_device_batch", {"assets": [{"vendor": "Moxa", "product": "EDS-518A"}]})
    assert err and "retryable" in text and "use_different_key" in text
    assert not [c for c in mocked.calls if "/batches" in c.request.url]


def test_submit_key_without_batches_gets_plain_message(keyed_server, mocked):
    mocked.add(responses.POST, BATCH, status=404, json=error_body("NOT_FOUND", "Not Found"))
    err, text = call(keyed_server, "submit_device_batch", {"assets": [{"vendor": "Moxa", "product": "EDS-518A"}]})
    assert err and "batch jobs are not enabled for this API key" in text and '"action": "contact_us"' in text
    assert "BREACHSPIDER_API_KEY" not in text


def test_submit_too_large_refused_by_schema(keyed_server, mocked):
    err, _ = call(keyed_server, "submit_device_batch",
                  {"assets": [{"vendor": "Moxa", "product": "EDS-518A"}] * 5001})
    assert err and not mocked.calls


def test_get_running_returns_progress_only(keyed_server, mocked):
    mocked.add(responses.GET, f"{BATCH}/{JID}", json=_status("running", done=1))
    err, out = call(keyed_server, "get_device_batch", {"job_id": JID})
    assert not err
    assert out["finished"] is False and out["progress"]["done"] == 1 and "results" not in out
    assert len(mocked.calls) == 1


def test_get_finished_shapes_results_and_pages(keyed_server, mocked):
    mocked.add(responses.GET, f"{BATCH}/{JID}", json=_status("partial", summary={"by_status": {"exact": 1}}))
    mocked.add(responses.GET, f"{BATCH}/{JID}/results", json={
        "data": {"items": [{"idx": 0, "state": "done", "result": _one_result()},
                           {"idx": 1, "state": "failed", "error_code": "INTERNAL"}]},
        "meta": {"next_cursor": 1, "limit": 2}})
    err, out = call(keyed_server, "get_device_batch", {"job_id": JID, "page_size": 2})
    assert not err
    assert out["finished"] is True and out["summary"] == {"by_status": {"exact": 1}}
    r = out["results"][0]
    assert r["idx"] == 0 and "assessment" in r and "result_hash" in r
    assert out["failed"] == [{"idx": 1, "error_code": "INTERNAL"}]
    assert out["next_cursor"] == 1 and "cursor=next_cursor" in out["next_step"]
    assert "cursor=-1" in mocked.calls[1].request.url and "limit=2" in mocked.calls[1].request.url


def test_get_passes_cursor(keyed_server, mocked):
    mocked.add(responses.GET, f"{BATCH}/{JID}", json=_status("succeeded"))
    mocked.add(responses.GET, f"{BATCH}/{JID}/results", json={"data": {"items": []}, "meta": {"next_cursor": None}})
    err, out = call(keyed_server, "get_device_batch", {"job_id": JID, "cursor": 19})
    assert not err and out["next_cursor"] is None and "next_step" not in out
    assert "cursor=19" in mocked.calls[1].request.url


def test_get_rejects_bad_job_id_without_calling(keyed_server, mocked):
    err, text = call(keyed_server, "get_device_batch", {"job_id": "../keys"})
    assert err and "fix_input" in text and not mocked.calls


def test_get_unknown_job_plain_message(keyed_server, mocked):
    mocked.add(responses.GET, f"{BATCH}/{JID}", status=404, json=error_body("NOT_FOUND", "Batch job not found."))
    err, text = call(keyed_server, "get_device_batch", {"job_id": JID})
    assert err and "no batch job with this job_id was found" in text and '"action": "fix_input"' in text
    assert "API key was refused" not in text


def test_submit_replay_status_normalized(keyed_server, mocked):
    mocked.add(responses.POST, BATCH, status=200, json={"data": {"job_id": JID, "status": "complete"}})
    err, out = call(keyed_server, "submit_device_batch", {"assets": [{"vendor": "Moxa", "product": "EDS-518A"}]})
    assert not err and out["status"] == "succeeded"
