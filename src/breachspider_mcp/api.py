"""BreachSpider API access for the MCP tools.

Calls go through the official ``breachspider`` Python SDK. The key is read from BREACHSPIDER_API_KEY and lives
only inside the SDK client, which never renders it. With no key the server mints a public demo token.
"""

from __future__ import annotations

import json
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
    """A clear, user facing error message plus the API's retry guidance. Never carries the key.

    str() is the full text the agent sees: one plain sentence telling it what to do, the explanation, and a
    retry_guidance line with retryable, retry_after_seconds and action (plus reset_at and max where they exist).
    """

    def __init__(self, message: str, guidance: Optional[Dict[str, Any]] = None, sentence: str = "") -> None:
        self.message = message
        self.guidance = guidance or {"retryable": False, "retry_after_seconds": None, "action": None}
        self.sentence = sentence or agent_sentence(self.guidance)
        super().__init__(format_failure(self.sentence, message, self.guidance))


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
                    raise self._failure(e) from None
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
                    raise self._failure(e2) from None
            raise self._failure(e) from None
        except bs_exc.BreachSpiderError as e:
            raise self._failure(e) from None

    def _redact(self, text: str) -> str:
        if self._key and self._key in text:
            text = text.replace(self._key, "***")
        return re.sub(r"bs_(live|demo)_[A-Za-z0-9_\-]{6,}", "bs_\\1_***", text)

    def _message(self, e: Exception) -> str:
        return self._redact(error_message(e, demo=self.demo))

    def _failure(self, e: Exception) -> ToolFailure:
        g = guidance_of(e)
        return ToolFailure(self._message(e), g, self._redact(agent_sentence(g, e, demo=self.demo)))


def guidance_of(e: Exception) -> Dict[str, Any]:
    """retryable / retry_after_seconds / action from an SDK exception (0.3.2 carries them on every exception),
    plus reset_at and max where the API sent them."""
    g = {"retryable": bool(getattr(e, "retryable", False)),
         "retry_after_seconds": getattr(e, "retry_after_seconds", None),
         "action": getattr(e, "action", None)}
    if getattr(e, "reset_at", None):
        g["reset_at"] = e.reset_at
    detail = getattr(e, "detail", None)
    if isinstance(detail, dict) and detail.get("max") is not None:
        g["max"] = detail["max"]
    return g


def agent_sentence(g: Dict[str, Any], e: Optional[Exception] = None, demo: bool = False) -> str:
    """One plain sentence the agent will act on: retry after a wait, or do not retry and what to tell the user."""
    action = g.get("action")
    code = (getattr(e, "code", None) or "").upper()
    detail = getattr(e, "detail", None)
    detail = detail if isinstance(detail, dict) else {}
    if g.get("retryable"):
        after = g.get("retry_after_seconds")
        return f"Retry after {after} seconds." if after else "Retry after a few seconds."
    if action == "wait_until_reset":
        reset = g.get("reset_at")
        return ("Do not retry this call" + (f" before {reset}" if reset else " until the limit resets")
                + "; this key's monthly asset checks are used up. Tell the user, or ask us for a higher limit.")
    if action == "reduce_batch":
        mx = g.get("max")
        return ("Do not retry this call unchanged; split the list into batches of "
                + (f"at most {mx}" if mx else "fewer items") + " and call again.")
    if action == "contact_us":
        if code == "TRIAL_ENDED" and detail.get("reason") == "limit":
            return ("Do not retry this call; the trial's asset checks are used up and do not reset. "
                    "Tell the user to ask for a partner key.")
        if code == "TRIAL_ENDED":
            return ("Do not retry this call; the trial has ended. "
                    "Tell the user to start a new trial or ask for a partner key.")
        if code in ("PARTNER_SCOPE", "TRIAL_SCOPE"):
            return ("Do not retry this call; this key cannot use this endpoint. "
                    "Tell the user to ask BreachSpider for a key with wider access.")
        return "Do not retry this call. Tell the user to contact BreachSpider."
    if action == "use_different_key":
        if demo:
            return ("Do not retry this call; demo mode cannot do this. "
                    "Tell the user to start a free trial and set BREACHSPIDER_API_KEY to the trial key.")
        if code == "TRIAL_REQUIRED":
            return ("Do not retry this call; checking your own devices needs a trial key. "
                    "Tell the user to start a free trial and set BREACHSPIDER_API_KEY to the trial key.")
        return "Do not retry this call; the API key was refused. Tell the user to check BREACHSPIDER_API_KEY."
    if action == "fix_input":
        return "Do not retry this call unchanged; correct the input as described and call again."
    return "Do not retry this call unchanged."


def format_failure(sentence: str, message: str, g: Dict[str, Any]) -> str:
    return f"{sentence} {message}\nretry_guidance: {json.dumps(g)}"


def _trial_links(detail: Dict[str, Any]) -> str:
    contact = detail.get("contact_url") or CONTACT_URL
    return f"Start or manage a trial at {DEVELOPERS_URL}. Talk to us: {contact}"


def error_message(e: Exception, demo: bool = False) -> str:
    """Turn an SDK exception into one clear sentence or two, in house style."""
    if isinstance(e, bs_exc.APIConnectionError):
        return "Could not reach the BreachSpider API. Check the network connection."
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
            return (f"This is not available in {DEMO_NOTICE}. For your own devices, start a free trial at "
                    f"{DEVELOPERS_URL} and set BREACHSPIDER_API_KEY to the trial key. For partner keys, "
                    f"talk to us: {CONTACT_URL}")
        return f"Not allowed for this key (403): {server_msg}{rid}"
    if status == 404:
        return f"Not found: {server_msg}{rid}"
    if status == 413:
        mx = detail.get("max")
        return (f"Too many assets in one call" + (f" (the limit is {mx})" if mx else "")
                + ". Split the list and call again.")
    if status == 422:
        return f"The API rejected the request: {server_msg}{rid}"
    if status == 429:                           # the agent sentence in front says when to retry
        return f"Rate limited by the API (429).{rid}"
    if status >= 500:
        return f"The BreachSpider API had a server error ({status}).{rid}"
    return f"The API returned an error ({status}): {server_msg}{rid}"


def _n(v: Any) -> str:
    try:
        f = float(v)
        return str(int(f)) if f.is_integer() else f"{f:g}"
    except (TypeError, ValueError):
        return str(v)
