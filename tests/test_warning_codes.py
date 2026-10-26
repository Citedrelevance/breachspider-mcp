"""Warning codes: the new code is known, unknown codes pass through, messages win."""
from breachspider_mcp.shaping import asset_result
from breachspider_mcp.warning_codes import WARNING_CODES, warning_text


def _r(warnings):
    return {"asset_id": "a", "resolution": {"status": "resolved", "coverage": "covered"}, "cves": [],
            "cves_page": {"total": 0, "has_more": False}, "fix_groups": [], "warnings": warnings}


def test_known_codes():
    assert "NO_VERSION_SUPPLIED" in WARNING_CODES and "PART_NUMBER_RESOLVED" in WARNING_CODES


def test_message_wins_then_known_text_then_code():
    assert warning_text({"code": "NO_VERSION_SUPPLIED", "message": "API text"}) == "API text"
    assert warning_text({"code": "PRODUCT_WIDE_MATCH"}) == WARNING_CODES["PRODUCT_WIDE_MATCH"]
    assert warning_text({"code": "SOME_FUTURE_CODE"}) == "SOME_FUTURE_CODE"


def test_asset_result_with_unknown_and_new_codes():
    out = asset_result(_r([{"code": "SOME_FUTURE_CODE"}, {"code": "PRODUCT_WIDE_MATCH", "message": "m"}]),
                       filtered=False)
    assert out["warnings"] == ["SOME_FUTURE_CODE", "m"]


def test_version_not_used_for_resolution_known():
    assert "R3.02.10" in warning_text({"code": "VERSION_NOT_USED_FOR_RESOLUTION"})
