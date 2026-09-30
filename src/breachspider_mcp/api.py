"""BreachSpider API access for the MCP tools.

Calls go through the official ``breachspider`` Python SDK. The key is read from BREACHSPIDER_API_KEY and lives
only inside the SDK client, which never renders it. With no key the server mints a public demo token.
"""

from __future__ import annotations

import os
import re
import threading
from typing import Any, Callable, Dict, Optional

import breachspider
from breachspider import exceptions as bs_exc

DEFAULT_BASE_URL = "https://breachspider.com"
DEVELOPERS_URL = "https://breachspider.com/developers"
CONTACT_URL = "mailto:joshua@citedrelevance.com?subject=BreachSpider%20API%20scoping"
DEMO_NOTICE = "demo mode: public example access only"

CORRELATE_PATH = "/api/v1/assets/correlate-cves"
CHECK_PATH = "/api/v1/assets/correlate-cves/check"


class ToolFailure(Exception):
    """A clear, user facing error message. Never carries the key."""


class API:
    """Lazily builds one SDK client and reuses it. Thread safe (tools run in worker threads)."""

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None,
                 client_factory: Optional[Callable[..., Any]] = None) -> None:
        key = api_key if api_key is not None else os.environ.get("BREACHSPIDER_API_KEY", "")
        self._key = key.strip() or None
        self.base_url = (base_url or os.environ.get("BREACHSPIDER_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
        self._factory = client_factory
        self._client = None
        self._lock = threading.Lock()

    @property
    def demo(self) -> bool:
        return self._key is None

    # max_retries=0: a trial limit 429 is not transient, and a stdio tool call should not sit in backoff.
    def _build(self):
        if self._factory is not None:
            return self._factory(self._key, self.base_url)
        if self._key:
            return breachspider.Client(self._key, base_url=self.base_url, max_retries=0)
        return breachspider.Client.demo(base_url=self.base_url, max_retries=0)

    def _get(self, fresh: bool = False):
        with self._lock:
            if self._client is None or fresh:
                try:
                    self._client = self._build()
                except bs_exc.BreachSpiderError as e:
                    raise ToolFailure(self._message(e)) from None
            return self._client

    def request(self, method: str, path: str, json: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        client = self._get()
        try:
            return client.request(method, path, json=json)
        except bs_exc.AuthenticationError as e:
            if self.demo:  # demo tokens last 24h; mint a new one once
                try:
                    return self._get(fresh=True).request(method, path, json=json)
                except bs_exc.BreachSpiderError as e2:
                    raise ToolFailure(self._message(e2)) from None
            raise ToolFailure(self._message(e)) from None
        except bs_exc.BreachSpiderError as e:
            raise ToolFailure(self._message(e)) from None

    def _redact(self, text: str) -> str:
        if self._key and self._key in text:
            text = text.replace(self._key, "***")
        return re.sub(r"bs_(live|demo)_[A-Za-z0-9_\-]{6,}", "bs_\\1_***", text)

    def _message(self, e: Exception) -> str:
        return self._redact(error_message(e, demo=self.demo))


def _trial_links(detail: Dict[str, Any]) -> str:
    contact = detail.get("contact_url") or CONTACT_URL
    return f"Start or manage a trial at {DEVELOPERS_URL}. Talk to us: {contact}"


def error_message(e: Exception, demo: bool = False) -> str:
    """Turn an SDK exception into one clear sentence or two, in house style."""
    if isinstance(e, bs_exc.APIConnectionError):
        return "Could not reach the BreachSpider API. Check the network connection and try again."
    if not isinstance(e, bs_exc.APIError):
        return "The BreachSpider API request failed."

    code = (e.code or "").upper()
    detail = e.detail if isinstance(e.detail, dict) else {}
    status = e.status_code
    server_msg = (e.message or "").strip()
    rid = f" (request id {e.request_id})" if e.request_id else ""

    if code == "TRIAL_REQUIRED":
        return ("TRIAL_REQUIRED: checking your own devices needs a free API trial. "
                "Create a trial key and set it as BREACHSPIDER_API_KEY. " + _trial_links(detail))
    if code == "TRIAL_SCOPE":
        return ("TRIAL_SCOPE: trial keys can check devices (correlate_devices, check_changes, get_fix_plan) "
                "and look up single CVEs only. Wider access is scoped individually. " + _trial_links(detail))
    if code == "TRIAL_BATCH_LIMIT":
        mx = detail.get("max", 25)
        got = detail.get("received")
        got_txt = f" This request had {got}." if got is not None else ""
        return (f"TRIAL_BATCH_LIMIT: trial requests can include at most {mx} assets.{got_txt} "
                f"Split the list into batches of {mx} or fewer and call again. " + _trial_links(detail))
    if code == "TRIAL_ENDED":
        reason = detail.get("reason")
        if status == 429 or reason == "limit":
            used, limit = detail.get("used"), detail.get("limit")
            remaining, requested = detail.get("remaining"), detail.get("requested")
            ends = detail.get("trial_ends_at")
            parts = ["TRIAL_ENDED (limit reached): nothing was processed."]
            if used is not None and limit is not None:
                parts.append(f"The trial has used {_n(used)} of {_n(limit)} asset checks"
                             + (f" and this request needs {_n(requested)}" if requested is not None else "")
                             + (f", with {_n(remaining)} left." if remaining is not None else "."))
            if remaining:
                parts.append("Send fewer assets, or use check_changes for repeat checks, which costs a tenth as much.")
            if ends:
                parts.append(f"The allowance does not reset during the trial. The trial ends at {ends}.")
            if getattr(e, "retry_after", None):
                parts.append(f"Retry after {int(e.retry_after)} seconds.")
            parts.append(_trial_links(detail))
            return " ".join(parts)
        ended_at = detail.get("ended_at")
        when = f" It ended at {ended_at}." if ended_at else ""
        return (f"TRIAL_ENDED: this BreachSpider API trial has ended.{when} " + _trial_links(detail))

    if status == 401:
        if demo:
            return "The demo token was refused. Try again in a moment; the server mints a new one on each start."
        return ("The API key was refused (401). Check BREACHSPIDER_API_KEY; the key may be revoked or mistyped. "
                f"Keys are managed at {DEVELOPERS_URL}.")
    if status == 403:
        if demo:
            return (f"This is not available in {DEMO_NOTICE}. Set BREACHSPIDER_API_KEY to a trial key "
                    f"from {DEVELOPERS_URL}.")
        return f"Not allowed for this key (403): {server_msg}{rid}"
    if status == 404:
        return f"Not found: {server_msg}{rid}"
    if status == 413:
        mx = detail.get("max")
        return (f"Too many assets in one call" + (f" (the limit is {mx})" if mx else "")
                + ". Split the list and call again.")
    if status == 422:
        return f"The API rejected the request: {server_msg}{rid}"
    if status == 429:
        wait = getattr(e, "retry_after", None)
        return ("Rate limited by the API (429)." + (f" Retry after {int(wait)} seconds." if wait else
                " Wait a few seconds and retry."))
    if status >= 500:
        return f"The BreachSpider API had a server error ({status}). Try again shortly.{rid}"
    return f"The API returned an error ({status}): {server_msg}{rid}"


def _n(v: Any) -> str:
    try:
        f = float(v)
        return str(int(f)) if f.is_integer() else f"{f:g}"
    except (TypeError, ValueError):
        return str(v)
