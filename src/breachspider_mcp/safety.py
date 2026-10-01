"""Keep identifying data out of API requests.

Only vendor, product, version, asset_id (and result_hash for check_changes) ever leave this machine; for
check_windows_host only the Windows host fields in WINDOWS_FIELDS do. Any other
field an agent passes along is dropped, and the fields that look identifying are named in the output so the
user can see what was held back. An asset_id is sent only when it is clearly neutral (asset-7, device_12, 42 or a
UUID); anything else, such as a host name like plant-a-sw01, an IP or MAC address or an email, is replaced with a
neutral one, because the API echoes it back and logs request shapes.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Tuple

SENT_FIELDS = ("asset_id", "vendor", "product", "version")

# Tokens that mark a field name as identifying. Matched per word, so "description" never matches "ip".
_IDENTIFYING_TOKENS = frozenset({
    "host", "hostname", "hostnames", "fqdn", "dns", "domain", "computer", "computername",
    "ip", "ips", "ipv4", "ipv6", "ipaddr", "ipaddress", "addr", "address",
    "mac", "macaddr", "macaddress",
    "user", "users", "username", "userid", "login", "owner", "email", "contact",
    "site", "sitename", "plant", "facility", "building", "location", "loc", "room", "rack", "zone", "area",
    "serial", "serialno", "serialnumber", "sn",
})

# An asset_id is sent only if it is clearly neutral: an optional generic prefix and a number, or a UUID, with the
# "#n" suffix this module adds to repeated ids. Short host names such as "plant-a-sw01" have no dot, so no
# pattern can tell them apart from other free text; an allowlist is the only safe test.
_NEUTRAL_ID = re.compile(
    r"(?:(?:asset|device|dev|item|node|row|id|a|d)[-_ ]?)?\d{1,9}"
    r"|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.I)


def _tokens(key: str) -> List[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(key))
    return [t for t in re.split(r"[^a-z0-9]+", spaced.lower()) if t]


def is_identifying_field(key: str) -> bool:
    toks = _tokens(key)
    return any(t in _IDENTIFYING_TOKENS for t in toks) or "".join(toks) in _IDENTIFYING_TOKENS


def is_neutral_id(value: str) -> bool:
    """True when an asset_id carries no host name, address, email or other free text."""
    base = re.sub(r"#\d+$", "", str(value).strip())
    return bool(_NEUTRAL_ID.fullmatch(base))


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def clean_assets(assets: Iterable[Any], extra_fields: Tuple[str, ...] = ()) -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
    """Return (assets safe to send, a privacy report).

    The report lists identifying field names that were dropped, other fields that were ignored, and asset
    ids that were replaced. Values are never echoed in the report.
    """
    allowed = SENT_FIELDS + tuple(extra_fields)
    cleaned: List[Dict[str, str]] = []
    dropped: set = set()
    ignored: set = set()
    replaced_ids: List[str] = []

    for i, raw in enumerate(assets, start=1):
        item = raw if isinstance(raw, dict) else dict(raw)
        out: Dict[str, str] = {}
        for key, value in item.items():
            if key in allowed:
                if value is not None and _text(value) != "":
                    out[key] = _text(value)
            elif is_identifying_field(key):
                dropped.add(key)
            else:
                ignored.add(key)

        default_id = f"asset-{i}"
        aid = out.get("asset_id")
        if not aid:
            out["asset_id"] = default_id
        elif not is_neutral_id(aid):
            replaced_ids.append(default_id)
            out["asset_id"] = default_id
        cleaned.append(out)

    # Keep asset ids unique so results map back one to one.
    seen: Dict[str, int] = {}
    for a in cleaned:
        n = seen.get(a["asset_id"], 0)
        seen[a["asset_id"]] = n + 1
        if n:
            a["asset_id"] = f"{a['asset_id']}#{n + 1}"

    report: Dict[str, Any] = {}
    if dropped:
        report["dropped_identifying_fields"] = sorted(dropped)
    if ignored:
        report["ignored_fields"] = sorted(ignored)
    if replaced_ids:
        report["asset_ids_replaced"] = {
            "asset_ids": replaced_ids,
            "reason": "the submitted asset_id was not a neutral id such as asset-7 and could be a host name, address or email, so a neutral id was sent",
        }
    return cleaned, report


# check_windows_host: the Windows host contract fields that are sent. Everything else is dropped as above.
WINDOWS_FIELDS = ("asset_id", "os_product", "edition_id", "os_build", "architecture", "installation_type",
                  "display_version", "installed_kbs", "esu_enrolled")


def clean_windows_hosts(hosts: Iterable[Any]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """clean_assets for Windows hosts: the same dropping, reporting and asset_id replacement, but only
    WINDOWS_FIELDS are sent, installed_kbs stays a list of KB strings and esu_enrolled a yes/no."""
    raws = [h if isinstance(h, dict) else dict(h) for h in hosts]
    kbs = [r.get("installed_kbs") for r in raws]
    esu = [r.get("esu_enrolled") for r in raws]
    stripped = [{k: v for k, v in r.items() if k not in ("installed_kbs", "esu_enrolled")} for r in raws]
    cleaned, report = clean_assets(stripped, extra_fields=WINDOWS_FIELDS)
    extra_ignored = set()
    for c, k, e in zip(cleaned, kbs, esu):
        for f in SENT_FIELDS:                  # vendor / product / version are not Windows host fields
            if f != "asset_id" and c.pop(f, None) is not None:
                extra_ignored.add(f)
        if k is not None:
            items = k if isinstance(k, (list, tuple)) else str(k).replace(",", ";").split(";")
            c["installed_kbs"] = [str(x).strip().upper() if str(x).strip().upper().startswith("KB")
                                  else "KB" + str(x).strip() for x in items if str(x).strip()]
        if e is not None:
            c["esu_enrolled"] = "yes" if (e is True or str(e).strip().lower() in ("yes", "true")) else "no"
    if extra_ignored:
        report["ignored_fields"] = sorted(set(report.get("ignored_fields", [])) | extra_ignored)
    return cleaned, report
