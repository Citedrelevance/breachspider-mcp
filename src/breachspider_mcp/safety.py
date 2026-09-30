"""Keep identifying data out of API requests.

Only vendor, product, version, asset_id (and result_hash for check_changes) ever leave this machine. Any other
field an agent passes along is dropped, and the fields that look identifying are named in the output so the
user can see what was held back. An asset_id that looks like a hostname, IP or MAC address is replaced with a
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

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b", re.I)
_MAC = re.compile(r"\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b|\b[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\b", re.I)
_FQDN = re.compile(r"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\.[a-z]{2,}\b", re.I)
_EMAIL = re.compile(r"[^@\s]+@[^@\s]+")


def _tokens(key: str) -> List[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(key))
    return [t for t in re.split(r"[^a-z0-9]+", spaced.lower()) if t]


def is_identifying_field(key: str) -> bool:
    toks = _tokens(key)
    return any(t in _IDENTIFYING_TOKENS for t in toks) or "".join(toks) in _IDENTIFYING_TOKENS


def looks_identifying(value: str) -> bool:
    """True when a free-text value looks like an IP, MAC, email or fully qualified host name."""
    v = str(value)
    return bool(_IPV4.search(v) or _MAC.search(v) or _EMAIL.search(v) or _FQDN.search(v)
                or (":" in v and _IPV6.search(v) and not _looks_like_version(v)))


def _looks_like_version(v: str) -> bool:
    return bool(re.fullmatch(r"[vV]?\d+(?:[.:]\d+)*", v.strip()))


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
        elif looks_identifying(aid) or len(aid) > 128:
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
            "reason": "the submitted asset_id looked like a host name, address or email, so a neutral id was sent",
        }
    return cleaned, report
