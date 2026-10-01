"""BreachSpider MCP server (stdio, read only).

Four tools over the three endpoints a trial key can call:
    correlate_devices  POST /api/v1/assets/correlate-cves
    check_changes      POST /api/v1/assets/correlate-cves/check
    get_fix_plan       POST /api/v1/assets/correlate-cves (one asset, fix data only)
    lookup_cve         GET  /api/v1/cves/{cve_id}
"""

from __future__ import annotations

import re
from typing import Annotated, Any, Dict, List, Optional

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
from .api import API, CHECK_PATH, CORRELATE_PATH, DEMO_NOTICE, ToolFailure
from .safety import clean_assets

MAX_FINDINGS = 100
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
    asset_id: Optional[str] = Field(default=None, description="Optional neutral id to map results back, for example 'asset-7' or '42'. Any other id, such as a host name or address, is replaced with asset-N.")


class DeviceWithHash(Device):
    result_hash: str = Field(description="The result_hash returned by an earlier correlate_devices call for this device.")


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
        msg = str(e)
        if api.demo and DEMO_NOTICE not in msg:
            msg = f"{msg} ({DEMO_NOTICE})"
        raise ToolError(msg) from None


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
        ),
    )
    async def check_changes(
        assets: Annotated[List[DeviceWithHash], Field(min_length=1, description="Devices with the result_hash from an earlier correlate_devices call.")],
    ) -> Dict[str, Any]:
        cleaned, privacy = clean_assets(_raw(assets), extra_fields=("result_hash",))
        missing = [a["asset_id"] for a in cleaned if not a.get("result_hash")]
        if missing:
            raise ToolError("Every asset needs a result_hash from an earlier correlate_devices call. Missing for: "
                            + ", ".join(missing))
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
        ),
    )
    async def get_fix_plan(
        asset: Annotated[Device, Field(description="One device: vendor, product, version.")],
    ) -> Dict[str, Any]:
        cleaned, privacy = clean_assets(_raw([asset]))
        body = await _call(api, "POST", CORRELATE_PATH, _correlate_body(cleaned, page_size=1))
        rows = (body.get("data") or {}).get("results") or []
        if not rows:
            raise ToolError("The API returned no result for this device.")
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
        ),
    )
    async def lookup_cve(
        cve_id: Annotated[str, Field(description="A CVE id such as CVE-2024-9137.")],
    ) -> Dict[str, Any]:
        cid = (cve_id or "").strip().upper()
        if not _CVE_ID.match(cid):
            raise ToolError(f"'{cap_id(cve_id)}' is not a CVE id. Use the form CVE-2024-9137.")
        body = await _call(api, "GET", f"/api/v1/cves/{cid}")
        data = body.get("data") if isinstance(body.get("data"), dict) else body
        return _envelope(api, shaping.cve_record(data), {})

    return mcp


def cap_id(v: Any) -> str:
    return shaping.cap(v, 40) or ""


def main() -> None:
    build_server().run("stdio")


if __name__ == "__main__":
    main()
