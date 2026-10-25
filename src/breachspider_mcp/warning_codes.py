"""Warning codes correlate-cves can return, with a one-line meaning (the codes documented in the API
field reference). Used only as a fallback when a warning arrives without a message; unknown
codes are passed through as the bare code, never an error."""

WARNING_CODES = {
    'NO_VERSION_SUPPLIED': 'No version was sent; every CVE is PRODUCT_WIDE.',
    'VERSION_FROM_FIRMWARE': 'No version; firmware_version was used for matching.',
    'PRODUCT_WIDE_MATCH': 'At least one CVE applies with no version bound.',
    'NO_CPE_DATA': 'No CVE data behind the resolved product; result undetermined.',
    'NO_MATCHING_RANGE': 'The product has affected-range data but none contains this version (structured sources only).',
    'PRODUCT_UNRESOLVED': 'The product could not be identified, so no correlation ran; undetermined, not clean.',
    'MODEL_NOT_SPECIFIED': 'Resolved to a model family; send a specific model for a complete result.',
    'NEEDS_REVIEW': 'Below min_confidence, or no data: do not read as clean.',
    'FIRMWARE_UNPARSEABLE': 'The version is not comparable; treated as absent.',
    'VERSION_SUFFIX_APPROXIMATE': 'Version has letters or brackets; ordering approximate.',
    'VERSION_SUFFIX_IGNORED': 'A space-separated suffix was dropped.',
    'AMBIGUOUS_RESOLUTION': 'Several close candidates; see candidates[].',
    'GENERIC_FAMILY_NAME': 'The product is a generic family name; candidates are offered.',
    'CANONICAL_SELECTED': 'Close candidates were variants of the exact-name product; that product was chosen.',
    'VENDOR_ALIAS_APPLIED': 'Vendor spelling mapped to its canonical name.',
    'VENDOR_RESOLVED_PRODUCT_NOT_FOUND': 'Vendor recognised, product not found.',
    'SKU_MAP_APPLIED': 'A curated model or order-code pattern was used.',
    'SKU_MAP_DISAMBIGUATED': 'A curated model or order-code pattern chose between candidates.',
    'SERIES_SUFFIX_DISAMBIGUATED': 'A catalog-number series suffix picked the product.',
    'LEADING_TOKEN_RESOLVED': "Resolved via the model's leading identifier.",
    'PART_NUMBER_RESOLVED': 'The product text did not resolve; the submitted part_number identified the product.',
    'BARE_NUMBER_MODEL': 'The model is only a short number; candidates are offered, nothing is resolved.',
    'WINDOWS_DISAMBIGUATED': 'Windows release chosen from the name or build.',
    'OS_BUILD_RELEASE_UNCERTAIN': 'Windows release mapping from the build is not fully certain.',
    'WINDOWS_RELEASE_TOKEN_NOT_COMPARED': 'A Windows release label was sent where ranges are OS builds; not compared.',
    'WINDOWS_RELEASE_PARTIAL': 'Only part of the Windows release could be compared.',
}


def warning_text(w: dict) -> str:
    """The API's own message; else the known meaning of the code; else the code itself."""
    code = str(w.get("code") or "")
    return str(w.get("message") or WARNING_CODES.get(code) or code)
