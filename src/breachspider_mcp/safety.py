"""Keep identifying data out of API requests.

Only vendor, product, version, asset_id (and result_hash for check_changes) ever leave this machine; for
check_windows_host only the Windows host fields in WINDOWS_FIELDS do. Any other
field an agent passes along is dropped, and the fields that look identifying are named in the output so the
user can see what was held back. An asset_id that contains an IP, MAC or email address, or is a domain or fully
qualified host name, is replaced with a neutral one, because the API echoes it back. Tag-shaped ids such as
PLC-LINE-2 or plant-a-sw01 are kept: they map results back to the customer's own equipment, and they cannot be told
apart from short host names.
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

# asset_id values replaced before sending: the same shapes the API refuses (IP, MAC, domain name), plus email and any
# value that contains an IP, MAC, email or multi-label host name. Tag-shaped ids are kept (2026-10-01).
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b", re.I)
_MAC = re.compile(r"\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b|\b[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\b", re.I)
_FQDN_IN = re.compile(r"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\.[a-z]{2,}\b", re.I)
_DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.I)     # the API's domain rule
_EMAIL = re.compile(r"[^@\s]+@[^@\s]+")
MAX_ASSET_ID = 128


def _tokens(key: str) -> List[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(key))
    return [t for t in re.split(r"[^a-z0-9]+", spaced.lower()) if t]


def is_identifying_field(key: str) -> bool:
    toks = _tokens(key)
    return any(t in _IDENTIFYING_TOKENS for t in toks) or "".join(toks) in _IDENTIFYING_TOKENS


def looks_identifying(value: str) -> bool:
    """True when an asset_id contains an IP, MAC or email address, or is a domain or fully qualified host name."""
    v = str(value).strip()
    return bool(len(v) > MAX_ASSET_ID or _IPV4.search(v) or _MAC.search(v) or _EMAIL.search(v)
                or _FQDN_IN.search(v) or _DOMAIN.match(v)
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
        elif looks_identifying(aid):
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
            "reason": "the submitted asset_id contained an IP, MAC or email address or a host name, so a neutral id was sent",
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
