"""Every API error the tools must explain, plus key safety and house style."""

import os
import re

import pytest
import requests
import responses

from breachspider_mcp.api import API
from breachspider_mcp.server import INSTRUCTIONS, build_server
from conftest import BASE, CHECK, CORRELATE, TEST_KEY, call, error_body, list_tools

ASSET = {"assets": [{"vendor": "Moxa", "product": "EDS-518A", "version": "3.5"}]}
CONTACT = "mailto:joshua@citedrelevance.com?subject=BreachSpider%20API%20scoping"


def _err(server, mocked, status, body, tool="correlate_devices", args=ASSET, url=CORRELATE, method=responses.POST,
         headers=None):
    mocked.add(method, url, json=body, status=status, headers=headers or {})
    err, msg = call(server, tool, args)
    assert err, msg
    assert TEST_KEY not in msg
    return msg


def _assert_trial_links(msg):
    assert "https://breachspider.com/developers" in msg
    assert "Talk to us" in msg


def test_trial_required(keyed_server, mocked):
    msg = _err(keyed_server, mocked, 403, error_body("TRIAL_REQUIRED", "Checking your own devices needs a free trial.",
                                                     {"code": "TRIAL_REQUIRED", "trial_url": "/developers"}))
    assert msg.count("TRIAL_REQUIRED") >= 1 and "free API trial" in msg
    _assert_trial_links(msg)


def test_trial_scope(keyed_server, mocked):
    msg = _err(keyed_server, mocked, 403, error_body("TRIAL_SCOPE", "Trial keys can call ...",
                                                     {"code": "TRIAL_SCOPE", "contact_url": CONTACT}),
               tool="lookup_cve", args={"cve_id": "CVE-2024-9137"}, url=f"{BASE}/api/v1/cves/CVE-2024-9137",
               method=responses.GET)
    assert "TRIAL_SCOPE" in msg and CONTACT in msg
    _assert_trial_links(msg)


def test_trial_batch_limit(keyed_server, mocked):
    assets = {"assets": [{"vendor": "Moxa", "product": f"EDS-{i}"} for i in range(26)]}
    msg = _err(keyed_server, mocked, 413,
               error_body("TRIAL_BATCH_LIMIT", "Trial requests may include at most 25 assets.",
                          {"code": "TRIAL_BATCH_LIMIT", "max": 25, "received": 26, "contact_url": CONTACT}),
               args=assets)
    assert "TRIAL_BATCH_LIMIT" in msg and "at most 25" in msg and "had 26" in msg and "batches of 25" in msg
    _assert_trial_links(msg)


def test_trial_limit_429_with_reset_time(keyed_server, mocked):
    detail = {"code": "TRIAL_ENDED", "error": "trial_ended", "reason": "limit", "contact_url": CONTACT,
              "used": 748.0, "limit": 750.0, "remaining": 2.0, "requested": 10.0,
              "trial_ends_at": "2026-10-14T18:00:00+00:00"}
    msg = _err(keyed_server, mocked, 429, error_body("TRIAL_ENDED", "This request needs 10 asset checks", detail))
    assert "TRIAL_ENDED" in msg and "limit reached" in msg and "nothing was processed" in msg
    assert "748 of 750" in msg and "needs 10" in msg and "2 left" in msg
    assert "2026-10-14T18:00:00+00:00" in msg and "does not reset" in msg
    assert "check_changes" in msg
    _assert_trial_links(msg)
    assert len(mocked.calls) == 1  # no retry loop on a trial limit


def test_trial_limit_429_all_used(keyed_server, mocked):
    detail = {"code": "TRIAL_ENDED", "reason": "limit", "used": 750.0, "limit": 750.0, "remaining": 0.0,
              "requested": 1.0, "trial_ends_at": "2026-10-14T18:00:00+00:00"}
    msg = _err(keyed_server, mocked, 429, error_body("TRIAL_ENDED", "used all", detail), tool="check_changes",
               args={"assets": [{"vendor": "Moxa", "product": "EDS-518A", "result_hash": "sha256:1"}]}, url=CHECK)
    assert "750 of 750" in msg and "0 left" in msg and "Send fewer" not in msg
    _assert_trial_links(msg)


@pytest.mark.parametrize("reason,extra,expect", [
    ("expired", {"ended_at": "2026-09-01T00:00:00+00:00"}, "2026-09-01T00:00:00+00:00"),
    ("ended", {}, "has ended"),
])
def test_trial_ended_403(keyed_server, mocked, reason, extra, expect):
    detail = {"code": "TRIAL_ENDED", "reason": reason, "contact_url": CONTACT, **extra}
    msg = _err(keyed_server, mocked, 403, error_body("TRIAL_ENDED", "Your trial has ended.", detail))
    assert "TRIAL_ENDED" in msg and expect in msg
    _assert_trial_links(msg)


def test_generic_rate_limit(keyed_server, mocked):
    msg = _err(keyed_server, mocked, 429, error_body("RATE_LIMITED", "Too many requests", {"retry_after": 7}),
               headers={"Retry-After": "7"})
    assert "Retry after 7 seconds" in msg


def test_bad_key_401(keyed_server, mocked):
    msg = _err(keyed_server, mocked, 401, error_body("UNAUTHORIZED", "Invalid API key"))
    assert "BREACHSPIDER_API_KEY" in msg


def test_cve_not_found(keyed_server, mocked):
    msg = _err(keyed_server, mocked, 404, error_body("NOT_FOUND", "CVE CVE-2099-0001 not found"),
               tool="lookup_cve", args={"cve_id": "CVE-2099-0001"}, url=f"{BASE}/api/v1/cves/CVE-2099-0001",
               method=responses.GET)
    assert "Not found" in msg


def test_non_trial_batch_too_large(keyed_server, mocked):
    msg = _err(keyed_server, mocked, 413, error_body("ERROR", "At most 200 assets per call.",
                                                     {"error": "batch_too_large", "max": 200}))
    assert "limit is 200" in msg


def test_server_error(keyed_server, mocked):
    msg = _err(keyed_server, mocked, 503, error_body("SERVICE_UNAVAILABLE", "down"))
    assert "server error (503)" in msg


def test_connection_error(keyed_server, mocked):
    mocked.add(responses.POST, CORRELATE, body=requests.ConnectionError("boom " + TEST_KEY))
    err, msg = call(keyed_server, "correlate_devices", ASSET)
    assert err and "Could not reach" in msg and TEST_KEY not in msg


def test_demo_forbidden_mentions_demo(demo_server, mocked):
    mocked.add(responses.POST, CORRELATE, json=error_body("FORBIDDEN", "nope"), status=403)
    err, msg = call(demo_server, "correlate_devices", ASSET)
    assert err and "demo mode: public example access only" in msg
    assert "free trial at https://breachspider.com/developers" in msg and "partner keys, talk to us" in msg


def test_key_never_echoed_even_if_server_does(keyed_server, mocked):
    msg = _err(keyed_server, mocked, 422, error_body("VALIDATION_ERROR", f"bad key {TEST_KEY} here"))
    assert TEST_KEY not in msg and "TESTKEY" not in msg


def test_key_read_from_env(monkeypatch, mocked):
    monkeypatch.setenv("BREACHSPIDER_API_KEY", TEST_KEY)
    api = API(base_url=BASE)
    assert not api.demo
    assert TEST_KEY not in repr(api.__dict__.get("_client"))


# ------------------------------------------------------------ house style

_BANNED = [("em or en dash", re.compile("[–—]")), ("spaced hyphen", re.compile(r"\s-\s")),
           ("exclamation", re.compile("!")), ("remediation", re.compile("remediation", re.I)),
           ("KEV", re.compile(r"\bKEV\b"))]


def _our_text(server):
    texts = [INSTRUCTIONS]
    for t in list_tools(server):
        texts.append(t.description or "")
        for p in (t.input_schema.get("properties") or {}).values():
            texts.append(p.get("description") or "")
        for d in (t.input_schema.get("$defs") or {}).values():
            texts.append(d.get("description") or "")
            texts += [p.get("description") or "" for p in d.get("properties", {}).values()]
    return texts


def test_house_style_descriptions(keyed_server):
    for text in _our_text(keyed_server):
        for name, rx in _BANNED:
            assert not rx.search(text), f"{name} in: {text}"


def test_house_style_module_strings():
    root = os.path.join(os.path.dirname(__file__), "..", "src", "breachspider_mcp")
    for fn in os.listdir(root):
        if not fn.endswith(".py"):
            continue
        src = open(os.path.join(root, fn)).read()
        # Only check string literals we write for users (double quoted lines), not code.
        for lit in re.findall(r'"((?:[^"\\\n]|\\.)*)"', src):
            for name, rx in _BANNED:
                if name == "KEV":
                    continue  # field names like kev_flagged are API keys we read, never shown
                if name == "remediation" and "remediation" in lit and " " not in lit:
                    continue
                assert not rx.search(lit), f"{name} in {fn}: {lit}"


def test_house_style_error_messages(keyed_server, mocked):
    cases = [
        (403, error_body("TRIAL_REQUIRED", "x", {"code": "TRIAL_REQUIRED"})),
        (403, error_body("TRIAL_SCOPE", "x", {"code": "TRIAL_SCOPE"})),
        (413, error_body("TRIAL_BATCH_LIMIT", "x", {"code": "TRIAL_BATCH_LIMIT", "max": 25, "received": 30})),
        (429, error_body("TRIAL_ENDED", "x", {"code": "TRIAL_ENDED", "reason": "limit", "used": 1, "limit": 750,
                                              "remaining": 749, "requested": 10, "trial_ends_at": "2026-10-14"})),
        (403, error_body("TRIAL_ENDED", "x", {"code": "TRIAL_ENDED", "reason": "expired"})),
        (401, error_body("UNAUTHORIZED", "x")),
        (429, error_body("RATE", "x")),
    ]
    for status, body in cases:
        mocked.replace(responses.POST, CORRELATE, json=body, status=status) if mocked.registered() else \
            mocked.add(responses.POST, CORRELATE, json=body, status=status)
        err, msg = call(keyed_server, "correlate_devices", ASSET)
        assert err
        for name, rx in _BANNED:
            assert not rx.search(msg), f"{name} in: {msg}"


# -- retry guidance (0.1.3): every failure starts with one sentence the agent acts on and ends with retry_guidance --

import json as _json


def _guided(code, message, retryable, action, after=None, detail=None, **extra):
    body = error_body(code, message, detail)
    body["error"].update({"retryable": retryable, "retry_after_seconds": after, "action": action, **extra})
    return body


def _text(msg):
    return msg.split(": ", 1)[1] if msg.startswith("Error executing tool ") else msg


def _guidance_line(msg):
    line = msg.rsplit("\nretry_guidance: ", 1)
    assert len(line) == 2, msg
    return _json.loads(line[1])


@pytest.mark.parametrize("status,body,sentence,guide", [
    (429, _guided("RATE_LIMITED", "Per-key limit.", True, "retry_later", 30, {"retry_after": 30}),
     "Retry after 30 seconds.", {"retryable": True, "retry_after_seconds": 30, "action": "retry_later"}),
    (503, _guided("ERROR", "Database unavailable", True, "retry_later", 30),
     "Retry after 30 seconds.", {"retryable": True, "action": "retry_later"}),
    (500, {"error": {"code": "INTERNAL_ERROR", "message": "x"}},          # no guidance: derived from the status
     "Retry after a few seconds.", {"retryable": True, "action": "retry_later"}),
    (429, _guided("PARTNER_LIMIT", "Needs 25 checks.", False, "wait_until_reset", reset_at="2026-11-01",
                  detail={"code": "PARTNER_LIMIT", "resets_at": "2026-11-01"}),
     "Do not retry this call before 2026-11-01;", {"retryable": False, "action": "wait_until_reset",
                                                   "reset_at": "2026-11-01"}),
    (403, _guided("TRIAL_ENDED", "Trial over.", False, "contact_us", detail={"code": "TRIAL_ENDED", "reason": "expired"}),
     "Do not retry this call; the trial has ended. Tell the user to start a new trial or ask for a partner key.",
     {"retryable": False, "action": "contact_us"}),
    (429, _guided("TRIAL_ENDED", "Used up.", False, "contact_us", detail={"code": "TRIAL_ENDED", "reason": "limit"}),
     "Do not retry this call; the trial's asset checks are used up", {"retryable": False, "action": "contact_us"}),
    (403, _guided("PARTNER_SCOPE", "This key can call ...", False, "contact_us", detail={"code": "PARTNER_SCOPE"}),
     "Do not retry this call; this key cannot use this endpoint.", {"retryable": False, "action": "contact_us"}),
    (413, _guided("BATCH_TOO_LARGE", "At most 25.", False, "reduce_batch", max=25,
                  detail={"code": "BATCH_TOO_LARGE", "max": 25, "received": 30}),
     "split the list into batches of at most 25", {"retryable": False, "action": "reduce_batch", "max": 25}),
    (422, _guided("VALIDATION_ERROR", "Request validation failed.", False, "fix_input"),
     "Do not retry this call unchanged; correct the input", {"retryable": False, "action": "fix_input"}),
    (401, _guided("AUTH_REQUIRED", "API key expired", False, "use_different_key"),
     "Do not retry this call; the API key was refused.", {"retryable": False, "action": "use_different_key"}),
    (403, _guided("TRIAL_REQUIRED", "Needs a trial.", False, "use_different_key", detail={"code": "TRIAL_REQUIRED"}),
     "checking your own devices needs a trial key", {"retryable": False, "action": "use_different_key"}),
])
def test_failure_starts_with_agent_sentence_and_ends_with_guidance(keyed_server, mocked, status, body, sentence, guide):
    msg = _text(_err(keyed_server, mocked, status, body))
    first = msg.split(". ", 1)[0] if msg.startswith("Retry") else msg.split(". ", 2)[:2]
    assert msg.startswith(("Retry after ", "Do not retry this call")), msg      # the sentence comes first
    assert sentence.rstrip(".") in ". ".join(first if isinstance(first, list) else [first]), msg
    g = _guidance_line(msg)
    assert set(("retryable", "retry_after_seconds", "action")) <= set(g)
    for k, v in guide.items():
        assert g[k] == v, (k, g)
    assert len(mocked.calls) == 1                       # the MCP server never retries on its own


def test_local_failures_carry_guidance(keyed_server, demo_server, mocked):
    err, msg = call(keyed_server, "lookup_cve", {"cve_id": "not-a-cve"})
    assert err and _text(msg).startswith("Do not retry this call unchanged")
    assert _guidance_line(msg) == {"retryable": False, "retry_after_seconds": None, "action": "fix_input"}
    err, msg = call(demo_server, "check_windows_host", {"assets": [{
        "os_product": "Windows Server 2019 Standard", "edition_id": "ServerStandard", "os_build": "10.0.17763.6189",
        "architecture": "x64"}]})
    assert err and _guidance_line(msg)["action"] == "use_different_key"


def test_descriptions_say_never_retry_when_not_retryable(keyed_server):
    for t in list_tools(keyed_server):
        assert "never retry when retryable is false" in t.description, t.name
    assert "Never retry when retryable is false" in INSTRUCTIONS
