"""Trim API responses to what an agent needs, in house style.

House style for all text this module writes: no dashes, no exclamation marks, "known-exploited" rather than the
short catalog name, and never the word the style guide rules out (we say "fix"). Text quoted from vendor
advisories is passed through as the vendor wrote it, capped in length.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

MAX_TEXT = 300
MAX_GUIDANCE = 3
MAX_ADVISORIES = 3
MAX_CANDIDATES = 3


def cap(text: Any, limit: int = MAX_TEXT) -> Optional[str]:
    if text is None:
        return None
    s = " ".join(str(text).split())
    if len(s) <= limit:
        return s
    return s[: limit - 3].rstrip() + "..."


def _drop_empty(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v not in (None, [], {}, "")}


# ---------------------------------------------------------------- findings

def _range_text(r: Dict[str, Any]) -> Optional[str]:
    if not r:
        return None
    start, end = r.get("version_start"), r.get("version_end")
    if not r.get("is_range"):
        v = r.get("cpe_version")
        if v in (None, "*", "-", ""):
            return "all versions (no version bound published)"
        return f"exactly {v}"
    lo = f"{start} ({'inclusive' if r.get('version_start_inclusive') else 'exclusive'})" if start else None
    hi = f"{end} ({'inclusive' if r.get('version_end_inclusive') else 'exclusive'})" if end else None
    if lo and hi:
        return f"from {lo} up to {hi}"
    if hi:
        return f"up to {hi}"
    if lo:
        return f"from {lo} onward"
    return "all versions (no version bound published)"


def _range_source(src: Any) -> Dict[str, Any]:
    if isinstance(src, dict) and src.get("document"):
        return _drop_empty({"type": src.get("type"), "document": src.get("document"), "url": src.get("url")})
    # Rows with no per row provenance come from the NVD CPE configuration for the CVE.
    return {"type": "nvd", "document": "NVD CPE configuration"}


def affected_range(r: Dict[str, Any]) -> Dict[str, Any]:
    return _drop_empty({"versions": _range_text(r or {}), "source": _range_source((r or {}).get("source"))})


def _guidance(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out, seen = [], set()
    for g in items or []:
        key = (g.get("category"), g.get("url") or g.get("source_url"))
        if key in seen:
            continue
        seen.add(key)
        if len(out) == MAX_GUIDANCE:
            break
        out.append(_drop_empty({
            "category": g.get("category"),
            "details": cap(g.get("details")),
            "fixed_versions": g.get("fixed_versions"),
            "source_document": g.get("source_document"),
            "url": g.get("url") or g.get("source_url"),
        }))
    return out


def _vendor_advisories(refs: Dict[str, Any]) -> List[str]:
    return [a.get("url") for a in (refs or {}).get("vendor_advisories") or [] if a.get("url")][:MAX_ADVISORIES]


def _cisa(refs: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [_drop_empty({"advisory_id": a.get("advisory_id"), "url": a.get("url")})
            for a in (refs or {}).get("cisa_ics_advisories") or []][:MAX_ADVISORIES]


def _epss(scoring: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    e = (scoring or {}).get("epss") or {}
    if e.get("score") is None:
        return None
    return _drop_empty({"score": e.get("score"), "percentile": e.get("percentile")})


def finding(c: Dict[str, Any]) -> Dict[str, Any]:
    scoring = c.get("scoring") or {}
    cvss = scoring.get("cvss") or {}
    expl = c.get("exploitation") or {}
    fix = c.get("fix") or {}
    refs = c.get("references") or {}
    return _drop_empty({
        "cve_id": c.get("cve_id"),
        "priority_rank": c.get("priority_rank"),
        "priority_reason": c.get("priority_reason"),
        "match_tier": c.get("match_tier"),
        "severity": cvss.get("severity"),
        "cvss": cvss.get("score"),
        "known_exploited": bool(expl.get("kev_flagged")),
        "known_exploited_since": expl.get("kev_added_at"),
        "exploit_available": bool(expl.get("has_public_exploit") or expl.get("poc_available")) or None,
        "epss": _epss(scoring),
        "fix": _drop_empty({
            "available": bool(fix.get("available")),
            "action": fix.get("action"),
            "source": fix.get("source"),
            "document": fix.get("document"),
            "derived_from_range": True if fix.get("derived") else None,
        }),
        "affected_range": affected_range(c.get("affected_range") or {}),
        "advisory_guidance": _guidance(c.get("advisory_guidance") or []),
        "vendor_advisories": _vendor_advisories(refs),
        "cisa_ics_advisories": _cisa(refs),
    })


# ---------------------------------------------------------------- per asset

def resolution(res: Dict[str, Any]) -> Dict[str, Any]:
    return _drop_empty({
        "status": res.get("status"),
        "vendor": (res.get("vendor") or {}).get("name"),
        "product": (res.get("product") or {}).get("name"),
        "confidence": res.get("confidence"),
        "confidence_band": res.get("confidence_band"),
    })


def _candidates(cands: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for c in (cands or [])[:MAX_CANDIDATES]:
        vendor = c.get("vendor")
        product = c.get("product")
        out.append(_drop_empty({
            "vendor": vendor.get("name") if isinstance(vendor, dict) else vendor,
            "product": product.get("name") if isinstance(product, dict) else (product or c.get("name")),
            "confidence": c.get("confidence"),
        }))
    return out


def assessment(status: Optional[str], coverage: Optional[str], total: Optional[int], needs_review: bool,
               filtered: bool) -> str:
    """One honest sentence about what the result does and does not show. Never calls a result clean."""
    if status == "unresolved":
        msg = ("Not assessed: the device could not be matched to a catalog product, so no CVEs were checked. "
               "This is not a clean result. Check the vendor and product spelling against the inventory.")
    elif status == "ambiguous":
        msg = ("Ambiguous match: several catalog products fit. The findings may be incomplete or belong to a "
               "different model. Confirm the product before relying on them.")
    elif coverage == "no_cpe_data":
        msg = ("The product was found but BreachSpider has no affected version data for it, so an empty list "
               "does not mean the device is free of CVEs.")
    elif coverage == "partial":
        msg = ("Partial coverage: some affected version data for this product is missing, so the findings may "
               "be incomplete. Do not treat missing CVEs as absent.")
    elif total == 0 and filtered:
        msg = "No CVEs matched the filters. Other CVEs may still apply; rerun without filters to see them."
    elif total == 0:
        msg = ("No CVEs matched this version in BreachSpider's published data. That is not proof the device "
               "is free of vulnerabilities, only that none are known for this product and version.")
    else:
        msg = f"{total} CVE{'' if total == 1 else 's'} matched."
    if needs_review:
        msg += " Flagged needs_review: confirm the match before acting on it."
    return msg


def fix_groups(groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [_drop_empty({
        "rank": g.get("group_rank"),
        "fix": g.get("fix"),
        "fix_type": g.get("fix_type"),
        "source": g.get("source"),
        "derived_from_range": True if g.get("derived") else None,
        "cve_ids": g.get("cve_ids"),
        "counts": g.get("counts"),
        "highest_score": g.get("highest_score"),
    }) for g in groups or []]


def fix_plan(plan: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    plan = plan or {}

    def step(s):
        if not s:
            return None
        return _drop_empty({"fix": s.get("fix"), "source": s.get("source"),
                            "derived_from_range": True if s.get("derived") else None,
                            "clears": s.get("clears"), "note": cap(s.get("note"))})

    return {
        "to_clear_known_exploited": step(plan.get("to_clear_known_exploited")),
        "to_clear_all_fixable": step(plan.get("to_clear_all_fixable")),
    }


def asset_result(r: Dict[str, Any], filtered: bool) -> Dict[str, Any]:
    res = r.get("resolution") or {}
    page = r.get("cves_page") or {}
    cves = r.get("cves") or []
    total = page.get("total", len(cves))
    status, coverage = res.get("status"), res.get("coverage")
    needs_review = bool(r.get("needs_review"))
    out = {
        "asset_id": r.get("asset_id"),
        "resolution": resolution(res),
        "coverage": coverage,
        "assessment": assessment(status, coverage, total, needs_review, filtered),
        "needs_review": needs_review,
        "warnings": [cap(w.get("message") or w.get("code"), 200) for w in r.get("warnings") or []],
        "result_hash": r.get("result_hash"),
        "total": total,
        "has_more": bool(page.get("has_more")),
        "fix_plan": fix_plan(r.get("fix_plan")),
        "findings": [finding(c) for c in cves],
    }
    if filtered and page.get("total_unfiltered") is not None:
        out["total_unfiltered"] = page.get("total_unfiltered")
    if status == "ambiguous":
        out["candidates"] = _candidates(r.get("candidates") or [])
    if coverage is None:
        out.pop("coverage")
    return out


# ---------------------------------------------------------------- CVE record

def cve_record(d: Dict[str, Any]) -> Dict[str, Any]:
    scoring = d.get("scoring") or {}
    cvss = scoring.get("cvss") or {}
    expl = d.get("exploitation") or {}
    patch = d.get("patch") or {}
    refs = d.get("references") or {}
    affected = d.get("affected") or {}
    temporal = d.get("temporal") or {}
    cls = d.get("classification") or {}
    return _drop_empty({
        "cve_id": d.get("cve_id"),
        "description": cap(d.get("description") or d.get("title")),
        "severity": cvss.get("severity"),
        "cvss": _drop_empty({"score": cvss.get("score"), "vector": cvss.get("vector"),
                             "version": cvss.get("version")}),
        "known_exploited": bool(expl.get("kev_flagged")),
        "known_exploited_since": expl.get("kev_added_at"),
        "exploit_available": bool(expl.get("has_public_exploit") or expl.get("poc_available")),
        "epss": _epss(scoring),
        "vendors": (affected.get("vendors") or [])[:5],
        "products": (affected.get("products") or [])[:5],
        "cwes": [f"CWE-{c.get('id')}" for c in cls.get("cwes") or [] if c.get("id") is not None],
        "fix": _drop_empty({"status": patch.get("status"), "available": patch.get("patch_available"),
                            "version": patch.get("patch_version"), "url": patch.get("patch_url"),
                            "notes": cap(patch.get("patch_notes"))}),
        "published": temporal.get("published_at"),
        "modified": temporal.get("modified_at"),
        "vendor_advisories": [_drop_empty({"url": a.get("url"), "title": cap(a.get("title"), 120),
                                           "source": a.get("source")})
                              for a in refs.get("vendor_advisories") or []][:MAX_ADVISORIES],
        "cisa_ics_advisories": _cisa(refs),
        "links": _drop_empty({"breachspider": refs.get("breachspider_url"), "nvd": refs.get("nvd_url"),
                              "cve_org": refs.get("cve_org_url")}),
        "note": "Device specific findings (affected range for a given version, fix plan) come from correlate_devices.",
    })
