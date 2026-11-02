"""BreachSpider MCP server (stdio, read only).

Four tools over the three endpoints a trial key can call:
    correlate_devices  POST /api/v1/assets/correlate-cves
    check_changes      POST /api/v1/assets/correlate-cves/check
    get_fix_plan       POST /api/v1/assets/correlate-cves (one asset, fix data only)
    lookup_cve         GET  /api/v1/cves/{cve_id}
and ones that need a partner or customer key:
    check_windows_host   POST /api/v2/assets/check-windows (stateless, stores nothing)
    submit_device_batch  POST /api/v1/batches (key with batch jobs enabled)
    get_device_batch     GET  /api/v1/batches/{id} and /results
    search_products      GET  /api/v1/catalog/vendors and /catalog/products (customer keys)
"""


import datetime as dt
import hashlib
import json as _json
import re
from typing import Annotated, Any, Dict, List, Literal, Optional

import anyio
from pydantic import BaseModel, ConfigDict, Field

try:  # mcp 2.x renamed FastMCP to MCPServer
    from mcp.server.mcpserver import MCPServer as _Server
    from mcp.server.mcpserver.exceptions import ToolError
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server  # type: ignore[no-redef]
    from mcp.server.fastmcp.exceptions import ToolError  # type: ignore[no-redef]

from mcp.types import ToolAnnotations

from . import __version__, shaping
from .api import API, BATCH_PATH, CHECK_PATH, CORRELATE_PATH, DEMO_NOTICE, DEVELOPERS_URL, CONTACT_URL, ToolFailure, agent_sentence, format_failure
from .safety import clean_assets, clean_windows_hosts, hosted_refusal, value_refusal

MAX_FINDINGS = 100
WINDOWS_PATH = "/api/v2/assets/check-windows"
MAX_WINDOWS_HOSTS = 25
MAX_BATCH_DEVICES = 5000
BATCH_PAGE_MAX = 50
CATALOG_VENDORS_PATH = "/api/v1/catalog/vendors"
CATALOG_PRODUCTS_PATH = "/api/v1/catalog/products"
_JOB_ID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_BATCH_FINAL = ("succeeded", "partial", "failed", "cancelled")
_BATCH_404 = {
    "contact_us": ("Do not retry this call; batch jobs are not enabled for this API key. Tell the user to ask "
                   "BreachSpider to enable them, or use correlate_devices for smaller lists.",
                   f"Batch jobs are enabled per partner or customer key. Talk to us: {CONTACT_URL}"),
    "fix_input": ("Do not retry this call unchanged; no batch job with this job_id was found for this key. Use the "
                  "job_id that submit_device_batch returned.",
                  "Jobs are visible only to the organization that submitted them and expire after 30 days."),
}
_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")

INSTRUCTIONS = """\
BreachSpider matches industrial and IT devices (vendor, product, firmware version) to the CVEs that affect that \
exact version, with the affected range, its source, the fix and the vendor advisory.

Rules for using these tools:
* Use correlate_devices for any specific device and firmware. Send vendor, product and version exactly as the \
inventory says. No CPE is needed.
* Report needs_review and partial coverage honestly. Never call an empty, unresolved or partial result clean; \
repeat the assessment field in your answer.
* When explaining a finding, cite the affected_range source and the vendor advisory.
* Use check_changes for repeat checks of devices you already have a result_hash for. It is much cheaper. Send \
the status_hash and status_facts you kept too: a status can change (a CVE becomes known-exploited, an end of support \
date is published, new firmware ships) while the findings stay the same.
* Use check_windows_host for Windows machines (OS product, edition, build, architecture, installed updates). \
It stores nothing. Report needs review and hosts that are not patch resolved honestly; never call them clean.
* When a tool call fails, read the retry_guidance at the end of the error. Never retry when retryable is false; \
follow action instead (fix_input, reduce_batch, use_different_key, contact_us, wait_until_reset). When retryable \
is true, wait retry_after_seconds before retrying.
* For long inventories (hundreds or thousands of devices) use submit_device_batch, then get_device_batch with the \
job_id until the job is finished, reading results page by page with next_cursor. It needs a key with batch jobs \
enabled. Each result has the same honesty rules as correlate_devices.
* Never send host names, IP or MAC addresses, serial numbers, user names or site names. Identifying fields are \
stripped before sending and reported in privacy.dropped_identifying_fields; an asset_id that looks identifying is \
replaced with asset-N; identifying text inside vendor, product, version or part_number refuses the call and nothing \
is sent.
"""

# The hosted server at mcp.breachspider.com (plan D7): every synchronous call must finish well under 30 s, so calls
# are capped per call; larger work goes to the batch tools.
HOSTED_CAPS = {"devices": 25, "windows_hosts": 5, "check_changes": 200}

HOSTED_RULE = ("* Never send host names, IP or MAC addresses, serial numbers, email addresses, user names or site "
               "names. This server refuses them, names the field and the reason, and sends nothing; send a neutral "
               "asset_id such as PLC-01 instead.\n"
               "* Per call: at most 25 devices for correlate_devices, 5 hosts for check_windows_host and 200 devices "
               "for check_changes. For more devices use submit_device_batch.\n")

_READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True)


class Device(BaseModel):
    """One device from an inventory. Only these five fields are sent; anything else is dropped."""

    model_config = ConfigDict(extra="allow")

    vendor: str = Field(description="Vendor exactly as the inventory says, for example 'Moxa'.")
    product: str = Field(description="Product or model exactly as the inventory says, for example 'EDS-518A'.")
    version: Optional[str] = Field(default=None, description="Firmware or software version as written, for example 'V3.5'.")
    part_number: Optional[str] = Field(default=None, description="Optional vendor part, order or model number when the inventory holds it separately from the product name, for example 'IR809G-LTE-VZ-K9' or '3623-072202'. Matched exactly for end-of-life and firmware answers.")
    asset_id: Optional[str] = Field(default=None, description="Optional id to map results back, for example your asset tag 'PLC-LINE-2' or 'asset-7'. An id that contains an IP, MAC or email address or is a host name with a domain is replaced with asset-N.")


class DeviceWithHash(Device):
    result_hash: str = Field(description="The result_hash returned by an earlier correlate_devices call for this device.")
    status_hash: Optional[str] = Field(default=None, description="Optional: the status_hash from the same earlier result. Then the answer also says whether the status changed (known-exploited, lifecycle, firmware currency).")
    status_facts: Optional[Dict[str, Any]] = Field(default=None, description="Optional: the status_facts from the same earlier result, unchanged. Then each status change is named in reasons.")


class WindowsHost(BaseModel):
    """One Windows host. Only the Windows host fields are sent; anything else is dropped."""

    model_config = ConfigDict(extra="allow")

    os_product: str = Field(description="Windows product name as reported, for example 'Windows Server 2019 Standard'.")
    edition_id: str = Field(description="EditionID, for example 'ServerStandard', 'ServerDatacenter', 'Enterprise' or 'Professional'.")
    os_build: str = Field(description="Full build including the revision number, for example '10.0.17763.6189'.")
    architecture: Literal["x64", "x86", "arm64"] = Field(description="x64, x86 or arm64.")
    installed_kbs: Optional[List[str]] = Field(default=None, description="Installed updates as KB numbers, for example ['KB5041578']. Leave out if unknown.")
    installation_type: Optional[Literal["Server", "Server Core", "Client"]] = Field(default=None, description="Required for server editions: Server or Server Core.")
    esu_enrolled: Optional[bool] = Field(default=None, description="True when the host is enrolled in Extended Security Updates.")
    display_version: Optional[str] = Field(default=None, description="Optional display version, for example '23H2'.")
    collected_at: Optional[str] = Field(default=None, description="When these facts were collected from the host, ISO 8601 UTC, for example '2026-09-25T14:02:00Z'. Leave out to use the time of this call.")
    asset_id: Optional[str] = Field(default=None, description="Optional id to map results back, for example your asset tag 'PLC-LINE-2' or 'asset-7'. An id that contains an IP, MAC or email address or is a host name with a domain is replaced with asset-N.")


def _raw(items) -> List[Dict[str, Any]]:
    out = []
    for a in items:
        if isinstance(a, BaseModel):
            d = a.model_dump(exclude_none=False)
            d.update(a.model_extra or {})
            out.append(d)
        else:
            out.append(dict(a))
    return out


def _envelope(api: API, body: Dict[str, Any], privacy: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if api.demo:
        out["mode"] = DEMO_NOTICE
    out.update(body)
    if privacy:
        out["privacy"] = privacy
    return out


async def _call(api: API, method: str, path: str, json: Optional[Dict[str, Any]] = None,
                params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    try:
        return await anyio.to_thread.run_sync(lambda: api.request(method, path, json=json, params=params, headers=headers))
    except ToolFailure as e:
        msg = e.message
        if api.demo and DEMO_NOTICE not in msg:
            msg = f"{msg} ({DEMO_NOTICE})"
        raise ToolError(format_failure(e.sentence, msg, e.guidance)) from None


def _fail(message: str, action: str, demo: bool = False, sentence: str = "") -> ToolError:
    """A failure found before calling the API: not retryable, with the same retry guidance as API errors."""
    g = {"retryable": False, "retry_after_seconds": None, "action": action}
    return ToolError(str(ToolFailure(message, g, sentence or agent_sentence(g, demo=demo))))


async def _batch_call(api: API, method: str, path: str, on_404: str, **kw: Any) -> Dict[str, Any]:
    """Batch routes answer 404 for keys without batch jobs and for unknown jobs; say which plainly.
    on_404 is contact_us (submit: batches are off for this key) or fix_input (status/results: wrong job_id)."""
    try:
        return await anyio.to_thread.run_sync(lambda: api.request(method, path, **kw))
    except ToolFailure as e:
        if e.message.startswith("Not found"):
            sentence, msg = _BATCH_404[on_404]
            raise _fail(msg, on_404, sentence=sentence) from None
        raise ToolError(format_failure(e.sentence, e.message, e.guidance)) from None


def _correlate_body(assets, *, page_size: int, confirmed_only=False, known_exploited_only=False,
                    fix_available_only=False) -> Dict[str, Any]:
    options: Dict[str, Any] = {"cve_page": 1, "cve_page_size": page_size, "include_capec": False}
    if confirmed_only:
        options["confirmed_only"] = True
    if known_exploited_only:
        options["known_exploited_only"] = True
    if fix_available_only:
        options["fix_available_only"] = True
    return {"assets": assets, "options": options}


class HostedDevice(Device):
    model_config = ConfigDict(extra="forbid")


class HostedDeviceWithHash(DeviceWithHash):
    model_config = ConfigDict(extra="forbid")


class HostedWindowsHost(WindowsHost):
    model_config = ConfigDict(extra="forbid")


def build_server(api: Optional[API] = None, *, hosted: bool = False,
                 server_kwargs: Optional[Dict[str, Any]] = None) -> Any:
    """The MCP server. hosted=True is the profile for mcp.breachspider.com: the same tools, names and shaping, but
    unknown fields are a schema error, identifying values are refused (not replaced), each call is capped
    (HOSTED_CAPS) and demo mode does not exist. server_kwargs go to the SDK server (token_verifier, auth)."""
    api = api or API()
    if hosted and api.demo:
        raise ValueError("the hosted profile needs an authenticated API (no demo mode)")
    instructions = INSTRUCTIONS
    if hosted:
        instructions = instructions.split("* Never send host names")[0] + HOSTED_RULE
    kw = dict(server_kwargs or {})
    mcp = _Server("breachspider", instructions=instructions, version=__version__, **kw) \
        if _Server.__name__ == "MCPServer" else _Server("breachspider", instructions=instructions, **kw)
    D = HostedDevice if hosted else Device
    DH = HostedDeviceWithHash if hosted else DeviceWithHash
    WH = HostedWindowsHost if hosted else WindowsHost
    cap_dev = HOSTED_CAPS["devices"] if hosted else None
    cap_win = HOSTED_CAPS["windows_hosts"] if hosted else MAX_WINDOWS_HOSTS
    cap_chk = HOSTED_CAPS["check_changes"] if hosted else None

    def guard(raw_items, privacy) -> None:
        """Both profiles: refuse identifying values inside the sent fields (audit C4). Hosted: also refuse identifying
        field names and asset_ids instead of stripping them."""
        msg = value_refusal(raw_items)
        if msg:
            raise _fail(msg, "fix_input")
        if hosted:
            msg = hosted_refusal(raw_items, privacy)
            if msg:
                raise _fail(msg, "fix_input")

    @mcp.tool(
        annotations=_READ_ONLY,
        structured_output=False,
        description=(
            "Find the CVEs that affect specific devices at their exact firmware or software version. Use this for "
            "any specific device and firmware. Send vendor, product and version exactly as the inventory says; no "
            "CPE is needed. Returns, per device: how it resolved, data coverage, an honest assessment, warnings, "
            "needs_review, result_hash (keep it for check_changes), the fix plan, and the top findings in priority "
            "order (known-exploited and confirmed first). Each finding gives the affected range with its source, the "
            "fix, advisory guidance and vendor advisories: cite the range source and the vendor advisory when "
            "explaining it. On client plans each device also gets lifecycle (vendor end of sale / end of support: "
            "quote its text and source_url; 'unknown' means the vendor publishes no date, never 'supported') and "
            "firmware (current or behind, latest version, security notes from the releases it misses). Zero CVEs "
            "on an unsupported device is not secure: future vulnerabilities will not be fixed. "
            "Report needs_review and partial coverage honestly and never call an empty, unresolved "
            "or partial result clean. Never send host names, IP or MAC addresses, user names or site names; such "
            "fields are stripped and listed under privacy."

            " If a call fails, the error starts with what to do and ends with retry_guidance (retryable, "
            "retry_after_seconds, action): never retry when retryable is false."
        ),
    )
    async def correlate_devices(
        assets: Annotated[List[D], Field(min_length=1, description="Devices to check: vendor, product, version and an optional neutral asset_id." + (f" At most {cap_dev} per call." if cap_dev else ""), json_schema_extra={"maxItems": cap_dev} if cap_dev else None)],
        confirmed_only: Annotated[bool, Field(description="Only CVEs confirmed for this version by a version range.")] = False,
        known_exploited_only: Annotated[bool, Field(description="Only known-exploited CVEs.")] = False,
        fix_available_only: Annotated[bool, Field(description="Only CVEs with a fix available.")] = False,
        max_findings: Annotated[int, Field(ge=1, le=MAX_FINDINGS, description="Findings returned per device, highest priority first.")] = 25,
    ) -> Dict[str, Any]:
        if cap_dev and len(assets) > cap_dev:
            # Audit M6 (2026-11-02): over the cap is a reduce_batch error with retry guidance, not a raw schema error.
            raise _fail(f"Too many devices: {len(assets)} sent, at most {cap_dev} per call. Split the list into calls "
                        f"of {cap_dev} or fewer, or use submit_device_batch for long inventories.", "reduce_batch")
        raw = _raw(assets)
        cleaned, privacy = clean_assets(raw)
        guard(raw, privacy)
        # Audit M7 (2026-11-02): one row without a vendor or product no longer fails the whole call: it gets its own
        # error and the other rows are checked.
        row_errors, sendable = [], []
        for c in cleaned:
            missing = [f for f in ("vendor", "product") if not (c.get(f) or "").strip()]
            if missing:
                row_errors.append({"asset_id": c.get("asset_id"), "error": f"{' and '.join(missing)} is empty; this "
                                   f"device was not checked. Send the vendor and product as the inventory names them."})
            else:
                sendable.append(c)
        if not sendable:
            raise _fail("No device could be checked: " + "; ".join(f"{e['asset_id']}: {e['error'].split(';')[0]}"
                                                                      for e in row_errors[:10]) + ".", "fix_input")
        filtered = bool(confirmed_only or known_exploited_only or fix_available_only)
        body = await _call(api, "POST", CORRELATE_PATH, _correlate_body(
            sendable, page_size=max_findings, confirmed_only=confirmed_only,
            known_exploited_only=known_exploited_only, fix_available_only=fix_available_only))
        data = body.get("data") or {}
        results = [shaping.asset_result(r, filtered) for r in data.get("results") or []]
        summary = data.get("summary") or {}
        out = {
            "assets_checked": summary.get("total", len(results)),
            "by_status": summary.get("by_status"),
            "results": results,
        }
        if row_errors:
            out["not_checked"] = row_errors
        lcs = shaping.lifecycle_summary(summary)
        if lcs:
            out["lifecycle_and_firmware"] = lcs
        return _envelope(api, out, privacy)

    @mcp.tool(
        annotations=_READ_ONLY,
        structured_output=False,
        description=(
            "Cheap repeat check. For devices you already checked with correlate_devices, send the same vendor, "
            "product and version plus the result_hash you kept. Returns which devices changed and their new hash; "
            "only changed devices need a fresh correlate_devices call. Also send the status_hash and status_facts "
            "you kept: then status_changed lists devices whose known-exploited flags, lifecycle or firmware currency "
            "changed with the same findings, and reasons names each change. Use this for repeat checks. Never send "
            "host names, IP or MAC addresses, user names or site names."

            " If a call fails, the error starts with what to do and ends with retry_guidance (retryable, "
            "retry_after_seconds, action): never retry when retryable is false."
        ),
    )
    async def check_changes(
        assets: Annotated[List[DH], Field(min_length=1, description="Devices with the result_hash from an earlier correlate_devices call." + (f" At most {cap_chk} per call." if cap_chk else ""), json_schema_extra={"maxItems": cap_chk} if cap_chk else None)],
    ) -> Dict[str, Any]:
        if cap_chk and len(assets) > cap_chk:
            raise _fail(f"Too many devices: {len(assets)} sent, at most {cap_chk} per call. Split the list into "
                        f"calls of {cap_chk} or fewer.", "reduce_batch")
        raw = _raw(assets)
        cleaned, privacy = clean_assets([{k: v for k, v in x.items() if k != "status_facts"} for x in raw],
                                        extra_fields=("result_hash", "status_hash"))
        guard(raw, privacy)
        missing = [a["asset_id"] for a in cleaned if not a.get("result_hash")]
        if missing:
            raise _fail("Every asset needs a result_hash from an earlier correlate_devices call. Missing for: "
                        + ", ".join(missing), "fix_input")
        # status_facts is the API's own object from the earlier result (no inventory values), passed through as is
        # next to its status_hash; the API checks it and ignores it unless it hashes to that status_hash.
        for a, src in zip(cleaned, raw):
            facts = src.get("status_facts") if isinstance(src, dict) else None
            if a.get("status_hash") and isinstance(facts, dict):
                a["status_facts"] = facts
        body = await _call(api, "POST", CHECK_PATH, {"assets": cleaned})
        rows = (body.get("data") or {}).get("results") or []
        results = []
        for r in rows:
            item = {"asset_id": r.get("asset_id"), "changed": bool(r.get("changed")),
                    "current_hash": r.get("current_hash"), "reason": r.get("reason")}
            if "status_changed" in r:
                item.update({"status_changed": bool(r.get("status_changed")),
                             "current_status_hash": r.get("current_status_hash"),
                             "current_status_facts": r.get("current_status_facts"),
                             "reasons": r.get("reasons") or []})
            results.append(item)
        changed = [r["asset_id"] for r in results if r["changed"]]
        status_changed = [r["asset_id"] for r in results if r.get("status_changed")]
        out = {
            "changed": changed,
            "unchanged_count": len(results) - len(changed),
            "results": results,
            "next_step": ("Call correlate_devices for the changed assets to see what is new."
                          if changed else "Nothing changed since the stored results."),
        }
        if any("status_changed" in r for r in results):
            out["status_changed"] = status_changed
            if status_changed and not changed:
                out["next_step"] = ("The findings are the same; the status changed for some devices (see reasons). "
                                    "Keep the new current_status_hash and current_status_facts.")
            elif not changed:
                out["next_step"] = "Nothing changed since the stored results: findings and status are the same."
        return _envelope(api, out, privacy)

    @mcp.tool(
        annotations=_READ_ONLY,
        structured_output=False,
        description=(
            "Fix plan for one device: fix groups (which update clears which CVEs) and the fix plan (the single step "
            "that clears the known-exploited CVEs, and the one that clears everything fixable). Send vendor, product "
            "and version exactly as the inventory says. Says so plainly when the device did not resolve or coverage "
            "is partial. Never send host names, IP or MAC addresses, user names or site names."

            " If a call fails, the error starts with what to do and ends with retry_guidance (retryable, "
            "retry_after_seconds, action): never retry when retryable is false."
        ),
    )
    async def get_fix_plan(
        asset: Annotated[D, Field(description="One device: vendor, product, version.")],
    ) -> Dict[str, Any]:
        raw = _raw([asset])
        cleaned, privacy = clean_assets(raw)
        guard(raw, privacy)
        body = await _call(api, "POST", CORRELATE_PATH, _correlate_body(cleaned, page_size=1))
        rows = (body.get("data") or {}).get("results") or []
        if not rows:
            raise _fail("The API returned no result for this device.", "contact_us")
        r = rows[0]
        res = r.get("resolution") or {}
        total = (r.get("cves_page") or {}).get("total", len(r.get("cves") or []))
        return _envelope(api, {
            "asset_id": r.get("asset_id"),
            "resolution": shaping.resolution(res),
            "assessment": shaping.assessment(res.get("status"), res.get("coverage"), total,
                                             bool(r.get("needs_review")), False),
            "needs_review": bool(r.get("needs_review")),
            "fix_groups": shaping.fix_groups(r.get("fix_groups") or []),
            "fix_plan": shaping.fix_plan(r.get("fix_plan")),
        }, privacy)

    @mcp.tool(
        annotations=_READ_ONLY,
        structured_output=False,
        description=(
            "Look up one CVE by id (for example CVE-2024-9137) and return BreachSpider's record, trimmed: severity, "
            "CVSS, known-exploited status, EPSS, fix status, vendor and CISA ICS advisories and links. It is not "
            "device specific; to know whether a device is affected, use correlate_devices."

            " If a call fails, the error starts with what to do and ends with retry_guidance (retryable, "
            "retry_after_seconds, action): never retry when retryable is false."
        ),
    )
    async def lookup_cve(
        cve_id: Annotated[str, Field(description="A CVE id such as CVE-2024-9137.")],
    ) -> Dict[str, Any]:
        cid = (cve_id or "").strip().upper()
        if not _CVE_ID.match(cid):
            raise _fail(f"'{cap_id(cve_id)}' is not a CVE id. Use the form CVE-2024-9137.", "fix_input")
        body = await _call(api, "GET", f"/api/v1/cves/{cid}")
        data = body.get("data") if isinstance(body.get("data"), dict) else body
        return _envelope(api, shaping.cve_record(data), {})

    @mcp.tool(
        annotations=_READ_ONLY,
        structured_output=False,
        description=(
            "Check Windows hosts against Microsoft's own patch data, without storing anything: nothing about the "
            "hosts is saved by BreachSpider. Send per host the OS product, edition_id, the full os_build (with the "
            "revision number), the architecture and, if known, the installed updates as KB numbers. Returns per host "
            "an honest assessment, counts of CVEs confirmed open, cleared and needs review, the top open and needs "
            "review findings in priority order (known-exploited first) with the fixed build, KB and Microsoft "
            "source, the fix groups (which update clears which CVEs) and a result_hash. Report needs review and "
            "hosts that are not patch resolved honestly: never call them clean, and repeat the assessment. Needs a "
            f"partner or customer API key; trial keys and demo mode cannot use it. At most {cap_win} hosts per call. Never "
            "send host names, IP or MAC addresses, user names or site names; such fields are stripped and listed "
            "under privacy."

            " If a call fails, the error starts with what to do and ends with retry_guidance (retryable, "
            "retry_after_seconds, action): never retry when retryable is false."
        ),
    )
    async def check_windows_host(
        assets: Annotated[List[WH], Field(min_length=1, description=f"Windows hosts to check, at most {cap_win}.", json_schema_extra={"maxItems": cap_win})],
        max_findings: Annotated[int, Field(ge=1, le=MAX_FINDINGS, description="Open and needs review findings returned per host, highest priority first.")] = 25,
    ) -> Dict[str, Any]:
        if api.demo:
            raise _fail(f"check_windows_host is not available in {DEMO_NOTICE}, and trial keys cannot use it "
                        f"either. It needs a partner or customer API key in BREACHSPIDER_API_KEY. Talk to us: "
                        f"{CONTACT_URL} (developer page: {DEVELOPERS_URL}).", "use_different_key", demo=True)
        if cap_win and len(assets) > cap_win:
            raise _fail(f"Too many hosts: {len(assets)} sent, at most {cap_win} per call. Split the list into "
                        f"calls of {cap_win} or fewer.", "reduce_batch")
        raw = _raw(assets)
        cleaned, privacy = clean_windows_hosts(raw)
        guard(raw, privacy)
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        for h in cleaned:
            h.setdefault("collected_at", now)       # the caller's collection time when given; the API validates it
            if h.get("installed_kbs") is not None:
                h["kb_source"] = "reported"
        body = await _call(api, "POST", WINDOWS_PATH, {
            "windows_hosts": cleaned,
            "options": {"include_cleared": False, "cve_page": 1, "cve_page_size": max_findings, "sort": "priority"}})
        data = body.get("data") or {}
        rejected = [{"asset_id": r.get("asset_id"),
                     "errors": [shaping.cap(e.get("message")) for e in r.get("errors") or []]}
                    for r in data.get("rejected") or []]
        return _envelope(api, {
            "stored": False,
            "note": "Nothing about these hosts was stored. Findings list open and needs review CVEs only; cleared "
                    "CVEs are counted, not listed.",
            "results": [shaping.windows_host_result(h) for h in data.get("assets") or []],
            **({"rejected": rejected} if rejected else {}),
        }, privacy)

    @mcp.tool(
        annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True),
        structured_output=False,
        description=(
            "Queue a batch job that checks a long device list (up to 5,000 devices) for the CVEs affecting each exact "
            "version. Returns at once with a job_id; then call get_device_batch with it until the job is finished and "
            "read the results page by page. Each result is the same as a correlate_devices result. Use this instead "
            "of correlate_devices for hundreds or thousands of devices. The job uses the key's quota for every device "
            "when it is queued (devices left unprocessed after a cancel are refunded). Sending the exact same list "
            "and max_findings again within 24 hours returns the original job instead of a new one, so a retry never "
            "charges twice. Needs a partner or customer key with batch jobs enabled; trial keys and demo mode cannot "
            "use it. Never send host names, IP or MAC addresses, user names or site names; such fields are stripped "
            "and listed under privacy."

            " If a call fails, the error starts with what to do and ends with retry_guidance (retryable, "
            "retry_after_seconds, action): never retry when retryable is false."
        ),
    )
    async def submit_device_batch(
        assets: Annotated[List[D], Field(min_length=1, max_length=MAX_BATCH_DEVICES, description="Devices to check, at most 5,000: vendor, product, version and an optional neutral asset_id.")],
        max_findings: Annotated[int, Field(ge=1, le=MAX_FINDINGS, description="Findings kept per device, highest priority first.")] = 10,
    ) -> Dict[str, Any]:
        if api.demo:
            raise _fail(f"submit_device_batch is not available in {DEMO_NOTICE}, and trial keys cannot use it "
                        f"either. It needs a partner or customer API key with batch jobs enabled in "
                        f"BREACHSPIDER_API_KEY. Talk to us: {CONTACT_URL} (developer page: {DEVELOPERS_URL}).",
                        "use_different_key", demo=True)
        raw = _raw(assets)
        cleaned, privacy = clean_assets(raw)
        guard(raw, privacy)
        body = _correlate_body(cleaned, page_size=max_findings)
        # Same list, same options -> same key -> the API returns the original job (24 h): retries never double charge.
        idem = "mcp-" + hashlib.sha256(_json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()[:48]
        resp = await _batch_call(api, "POST", BATCH_PATH, "contact_us", json=body, headers={"Idempotency-Key": idem})
        data = resp.get("data") or {}
        return _envelope(api, {
            "job_id": data.get("job_id"),
            "status": {"complete": "succeeded"}.get(data.get("status"), data.get("status")),  # replay sends the raw status
            "devices_queued": len(cleaned),
            "created_at": data.get("created_at"),
            "next_step": "Call get_device_batch with this job_id. A job of a few hundred devices usually finishes "
                         "within a minute; wait about 10 seconds between status checks.",
        }, privacy)

    @mcp.tool(
        annotations=_READ_ONLY,
        structured_output=False,
        description=(
            "Status and results of a batch job from submit_device_batch. While the job is queued or running it "
            "returns progress (done, failed, total); once finished it returns the summary and one page of results "
            "in submission order. Each result has the same fields and honesty rules as correlate_devices: report "
            "needs_review and partial coverage honestly and never call an empty, unresolved or partial result clean. "
            "When next_cursor is not null, call again with cursor=next_cursor for the next page. Devices that "
            "failed are listed with an error_code. Results are kept 30 days."

            " If a call fails, the error starts with what to do and ends with retry_guidance (retryable, "
            "retry_after_seconds, action): never retry when retryable is false."
        ),
    )
    async def get_device_batch(
        job_id: Annotated[str, Field(description="The job_id returned by submit_device_batch.")],
        cursor: Annotated[Optional[int], Field(ge=-1, description="The next_cursor from the previous page; leave out for the first page.")] = None,
        page_size: Annotated[int, Field(ge=1, le=BATCH_PAGE_MAX, description="Devices per page, at most 50.")] = 20,
    ) -> Dict[str, Any]:
        if api.demo:
            raise _fail(f"get_device_batch is not available in {DEMO_NOTICE}. It needs a partner or customer API "
                        f"key with batch jobs enabled. Talk to us: {CONTACT_URL}", "use_different_key", demo=True)
        jid = (job_id or "").strip()
        if not _JOB_ID.match(jid):
            raise _fail("job_id must be the job_id returned by submit_device_batch (a UUID).", "fix_input")
        st = (await _batch_call(api, "GET", f"{BATCH_PATH}/{jid}", "fix_input")).get("data") or {}
        status = st.get("status")
        out: Dict[str, Any] = {
            "job_id": jid,
            "status": status,
            "progress": st.get("progress"),
            "finished": status in _BATCH_FINAL,
        }
        if status not in _BATCH_FINAL:
            out["next_step"] = "Not finished yet. Wait about 10 seconds and call get_device_batch again."
            if st.get("cancel_requested"):
                out["cancel_requested"] = True
            return _envelope(api, out, {})
        out["finished_at"] = st.get("finished_at")
        out["expires_at"] = st.get("expires_at")
        if st.get("summary"):
            out["summary"] = st.get("summary")
        if st.get("error_summary"):
            out["error_summary"] = st.get("error_summary")
        page = await _batch_call(api, "GET", f"{BATCH_PATH}/{jid}/results", "fix_input",
                                 params={"cursor": -1 if cursor is None else cursor, "limit": page_size})
        results, failed = [], []
        for item in (page.get("data") or {}).get("items") or []:
            if item.get("state") == "done" and isinstance(item.get("result"), dict):
                r = shaping.asset_result(item["result"], False)
                r["idx"] = item.get("idx")
                results.append(r)
            else:
                failed.append({"idx": item.get("idx"), "error_code": shaping.cap(item.get("error_code"), 60)})
        out["results"] = results
        if failed:
            out["failed"] = failed
        nxt = (page.get("meta") or {}).get("next_cursor")
        out["next_cursor"] = nxt
        if nxt is not None:
            out["next_step"] = "More results: call get_device_batch again with cursor=next_cursor."
        if status == "cancelled":
            out["note"] = "The job was cancelled: only the devices processed before the cancel have results."
        return _envelope(api, out, {})

    @mcp.tool(
        annotations=_READ_ONLY,
        structured_output=False,
        description=(
            "Find how BreachSpider's catalog names a vendor and its products, for example to check the spelling of "
            "a product before correlate_devices. Send the vendor as written and, optionally, part of the product "
            "name. Returns up to 3 matching vendors, each with up to 15 matching products and their CVE counts. "
            "Only products with at least one CVE are listed: a product that is not listed may still exist, and "
            "this is never an answer about whether a device is affected. For that, use correlate_devices with the "
            "inventory's own vendor, product and version; it resolves names itself. Needs a customer API key; "
            "trial and partner keys cannot use it."

            " If a call fails, the error starts with what to do and ends with retry_guidance (retryable, "
            "retry_after_seconds, action): never retry when retryable is false."
        ),
    )
    async def search_products(
        vendor: Annotated[str, Field(min_length=1, max_length=100, description="Vendor as written, for example 'Siemens' or 'Schneider'.")],
        product: Annotated[Optional[str], Field(max_length=100, description="Optional part of the product name, for example 'S7-1200'.")] = None,
    ) -> Dict[str, Any]:
        if api.demo:
            raise _fail(f"search_products is not available in {DEMO_NOTICE}. It needs a customer API key. Talk to "
                        f"us: {CONTACT_URL}", "use_different_key", demo=True)
        v = vendor.strip()
        p = (product or "").strip()
        vbody = await _call(api, "GET", CATALOG_VENDORS_PATH, params={"q": v})
        vendors = (vbody.get("data") or [])[:3]
        out_vendors = []
        for row in vendors:
            # group_firmware (finding 7): NVD's separate "X Firmware" entry is folded under "X" so it does not use up
            # a result slot. Needs API 2026-11 or later.
            pbody = await _call(api, "GET", CATALOG_PRODUCTS_PATH,
                                params={"vendor_id": row.get("id"), "q": p, "group_firmware": "true"})
            out_vendors.append({
                "vendor": shaping.cap(row.get("name"), 100),
                "products_with_cves": row.get("cve_product_count"),
                "products": [shaping.catalog_product(x) for x in (pbody.get("data") or [])[:15]],
            })
        note = ("Only products with at least one CVE are listed. A missing product is not a sign the device has no "
                "CVEs; check the device itself with correlate_devices.")
        if not out_vendors:
            note = ("No vendor in the catalog matches that name. Check the spelling, or run correlate_devices with the "
                    "inventory's own names: it reports PRODUCT_UNRESOLVED when it cannot match.")
        return _envelope(api, {"query": {"vendor": shaping.cap(v, 100), "product": shaping.cap(p, 100) or None},
                               "vendors": out_vendors, "note": note}, {})

    return mcp


def cap_id(v: Any) -> str:
    return shaping.cap(v, 40) or ""


def main() -> None:
    build_server().run("stdio")


if __name__ == "__main__":
    main()
