"""BreachSpider MCP server (stdio, read only).

Four tools over the three endpoints a trial key can call:
    correlate_devices  POST /api/v1/assets/correlate-cves
    check_changes      POST /api/v1/assets/correlate-cves/check
    get_fix_plan       POST /api/v1/assets/correlate-cves (one asset, fix data only)
    lookup_cve         GET  /api/v1/cves/{cve_id}
and one that needs a partner or customer key (stateless, stores nothing):
    check_windows_host POST /api/v2/assets/check-windows
"""

from __future__ import annotations

import datetime as dt
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
from .api import API, CHECK_PATH, CORRELATE_PATH, DEMO_NOTICE, DEVELOPERS_URL, CONTACT_URL, ToolFailure, agent_sentence, format_failure
from .safety import clean_assets, clean_windows_hosts

MAX_FINDINGS = 100
WINDOWS_PATH = "/api/v2/assets/check-windows"
MAX_WINDOWS_HOSTS = 25
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
* Use check_changes for repeat checks of devices you already have a result_hash for. It is much cheaper.
* Use check_windows_host for Windows machines (OS product, edition, build, architecture, installed updates). \
It stores nothing. Report needs review and hosts that are not patch resolved honestly; never call them clean.
* When a tool call fails, read the retry_guidance at the end of the error. Never retry when retryable is false; \
follow action instead (fix_input, reduce_batch, use_different_key, contact_us, wait_until_reset). When retryable \
is true, wait retry_after_seconds before retrying.
* Never send host names, IP or MAC addresses, user names or site names. Identifying fields are stripped \
before sending and reported in privacy.dropped_identifying_fields.
"""

_READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True)


class Device(BaseModel):
    """One device from an inventory. Only these four fields are sent; anything else is dropped."""

    model_config = ConfigDict(extra="allow")

    vendor: str = Field(description="Vendor exactly as the inventory says, for example 'Moxa'.")
    product: str = Field(description="Product or model exactly as the inventory says, for example 'EDS-518A'.")
    version: Optional[str] = Field(default=None, description="Firmware or software version as written, for example 'V3.5'.")
    asset_id: Optional[str] = Field(default=None, description="Optional id to map results back, for example your asset tag 'PLC-LINE-2' or 'asset-7'. An id that contains an IP, MAC or email address or is a host name with a domain is replaced with asset-N.")


class DeviceWithHash(Device):
    result_hash: str = Field(description="The result_hash returned by an earlier correlate_devices call for this device.")


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


async def _call(api: API, method: str, path: str, json: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    try:
        return await anyio.to_thread.run_sync(lambda: api.request(method, path, json=json))
    except ToolFailure as e:
        msg = e.message
        if api.demo and DEMO_NOTICE not in msg:
            msg = f"{msg} ({DEMO_NOTICE})"
        raise ToolError(format_failure(e.sentence, msg, e.guidance)) from None


def _fail(message: str, action: str, demo: bool = False) -> ToolError:
    """A failure found before calling the API: not retryable, with the same retry guidance as API errors."""
    g = {"retryable": False, "retry_after_seconds": None, "action": action}
    return ToolError(str(ToolFailure(message, g, agent_sentence(g, demo=demo))))


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


def build_server(api: Optional[API] = None) -> Any:
    api = api or API()
    mcp = _Server("breachspider", instructions=INSTRUCTIONS, version=__version__) \
        if _Server.__name__ == "MCPServer" else _Server("breachspider", instructions=INSTRUCTIONS)

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
            "explaining it. Report needs_review and partial coverage honestly and never call an empty, unresolved "
            "or partial result clean. Never send host names, IP or MAC addresses, user names or site names; such "
            "fields are stripped and listed under privacy."

            " If a call fails, the error starts with what to do and ends with retry_guidance (retryable, "
            "retry_after_seconds, action): never retry when retryable is false."
        ),
    )
    async def correlate_devices(
        assets: Annotated[List[Device], Field(min_length=1, description="Devices to check: vendor, product, version and an optional neutral asset_id.")],
        confirmed_only: Annotated[bool, Field(description="Only CVEs confirmed for this version by a version range.")] = False,
        known_exploited_only: Annotated[bool, Field(description="Only known-exploited CVEs.")] = False,
        fix_available_only: Annotated[bool, Field(description="Only CVEs with a fix available.")] = False,
        max_findings: Annotated[int, Field(ge=1, le=MAX_FINDINGS, description="Findings returned per device, highest priority first.")] = 25,
    ) -> Dict[str, Any]:
        cleaned, privacy = clean_assets(_raw(assets))
        filtered = bool(confirmed_only or known_exploited_only or fix_available_only)
        body = await _call(api, "POST", CORRELATE_PATH, _correlate_body(
            cleaned, page_size=max_findings, confirmed_only=confirmed_only,
            known_exploited_only=known_exploited_only, fix_available_only=fix_available_only))
        data = body.get("data") or {}
        results = [shaping.asset_result(r, filtered) for r in data.get("results") or []]
        summary = data.get("summary") or {}
        return _envelope(api, {
            "assets_checked": summary.get("total", len(results)),
            "by_status": summary.get("by_status"),
            "results": results,
        }, privacy)

    @mcp.tool(
        annotations=_READ_ONLY,
        structured_output=False,
        description=(
            "Cheap repeat check. For devices you already checked with correlate_devices, send the same vendor, "
            "product and version plus the result_hash you kept. Returns which devices changed and their new hash; "
            "only changed devices need a fresh correlate_devices call. Use this for repeat checks. Never send host "
            "names, IP or MAC addresses, user names or site names."

            " If a call fails, the error starts with what to do and ends with retry_guidance (retryable, "
            "retry_after_seconds, action): never retry when retryable is false."
        ),
    )
    async def check_changes(
        assets: Annotated[List[DeviceWithHash], Field(min_length=1, description="Devices with the result_hash from an earlier correlate_devices call.")],
    ) -> Dict[str, Any]:
        cleaned, privacy = clean_assets(_raw(assets), extra_fields=("result_hash",))
        missing = [a["asset_id"] for a in cleaned if not a.get("result_hash")]
        if missing:
            raise _fail("Every asset needs a result_hash from an earlier correlate_devices call. Missing for: "
                        + ", ".join(missing), "fix_input")
        body = await _call(api, "POST", CHECK_PATH, {"assets": cleaned})
        rows = (body.get("data") or {}).get("results") or []
        results = [{"asset_id": r.get("asset_id"), "changed": bool(r.get("changed")),
                    "current_hash": r.get("current_hash"), "reason": r.get("reason")} for r in rows]
        changed = [r["asset_id"] for r in results if r["changed"]]
        return _envelope(api, {
            "changed": changed,
            "unchanged_count": len(results) - len(changed),
            "results": results,
            "next_step": ("Call correlate_devices for the changed assets to see what is new."
                          if changed else "Nothing changed since the stored results."),
        }, privacy)

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
        asset: Annotated[Device, Field(description="One device: vendor, product, version.")],
    ) -> Dict[str, Any]:
        cleaned, privacy = clean_assets(_raw([asset]))
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
            "partner or customer API key; trial keys and demo mode cannot use it. At most 25 hosts per call. Never "
            "send host names, IP or MAC addresses, user names or site names; such fields are stripped and listed "
            "under privacy."

            " If a call fails, the error starts with what to do and ends with retry_guidance (retryable, "
            "retry_after_seconds, action): never retry when retryable is false."
        ),
    )
    async def check_windows_host(
        assets: Annotated[List[WindowsHost], Field(min_length=1, max_length=MAX_WINDOWS_HOSTS, description="Windows hosts to check, at most 25.")],
        max_findings: Annotated[int, Field(ge=1, le=MAX_FINDINGS, description="Open and needs review findings returned per host, highest priority first.")] = 25,
    ) -> Dict[str, Any]:
        if api.demo:
            raise _fail(f"check_windows_host is not available in {DEMO_NOTICE}, and trial keys cannot use it "
                        f"either. It needs a partner or customer API key in BREACHSPIDER_API_KEY. Talk to us: "
                        f"{CONTACT_URL} (developer page: {DEVELOPERS_URL}).", "use_different_key", demo=True)
        cleaned, privacy = clean_windows_hosts(_raw(assets))
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

    return mcp


def cap_id(v: Any) -> str:
    return shaping.cap(v, 40) or ""


def main() -> None:
    build_server().run("stdio")


if __name__ == "__main__":
    main()
