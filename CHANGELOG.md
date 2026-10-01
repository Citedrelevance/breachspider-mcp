# Changelog

All notable changes to the BreachSpider MCP server. This project follows [Semantic Versioning](https://semver.org/).

## 0.1.4 (2026-10-01)

Includes everything below from 0.1.3, which was a TestPyPI-only build and was not released to PyPI.

### Fixed
- `check_windows_host` in demo mode: the refusal now tells the agent that demo mode cannot do this and to start a
  free trial, instead of saying the API key was refused.

## 0.1.3 (TestPyPI only)

### Added
- **Retry guidance on every failed tool call.** The error starts with one plain sentence the agent acts on (for
  example "Retry after 30 seconds." or "Do not retry this call; the trial has ended. Tell the user to start a new
  trial or ask for a partner key.") and ends with a `retry_guidance` line carrying the API's `retryable`,
  `retry_after_seconds` and `action` (plus `reset_at` and `max` where they exist). Failures found before calling
  the API (a malformed CVE id, a missing result_hash, Windows in demo mode) carry the same fields. The instructions
  and every tool description say never to retry when `retryable` is false. Requires `breachspider>=0.3.2`.

### Changed
- Rate limit and server error messages no longer repeat when to retry; the leading sentence says it. The trial
  limit message no longer suggests retrying.

### Fixed
- `check_windows_host` now sends the `collected_at` you give for a host (when the facts were collected, ISO 8601 UTC)
  instead of ignoring it and always sending the time of the call. Without it, the time of the call is still used.

## 0.1.2 (2026-10-01)

### Added
- `check_windows_host`: check Windows hosts (OS product, edition, build, architecture, installed updates) against
  Microsoft's own patch data through `POST /api/v2/assets/check-windows`, which stores nothing about the hosts.
  Returns an honest assessment per host (a host that is not patch resolved is never called clean, and needs review
  is reported), counts, the top open and needs review CVEs with fixed build, KB and Microsoft source, fix groups and
  a `result_hash`. Only the Windows host fields are sent; identifying fields are stripped and reported. Needs a
  partner or customer key; in demo mode it explains that without calling the API. At most 25 hosts per call.

### Fixed
- `asset_id` replacement now matches the API: an id that contains an IP, MAC or email address, or is a domain name
  (for example `plant.local`) or a fully qualified host name, is replaced with `asset-N`. Tag-shaped ids such as
  `PLC-LINE-2` or `plant-a-sw01` are kept, so results map back to your own equipment.

### Changed
- In demo mode, the message for a call that needs a key now points to both the free trial at
  breachspider.com/developers and partner keys through "Talk to us".
- README: every tool's arguments, pipx install steps per OS with `pipx ensurepath`, uvx as a separate option,
  the Claude Code command reads the key from `$BREACHSPIDER_API_KEY`, and a warning that `claude mcp get` prints it.

## 0.1.1 (2026-10-01)

### Changed
- `lookup_cve` reports a CVE's fix status as `varies_by_product` when the vendor's advisory states fixed versions
  per product, instead of `unknown`. `fix.note` then says to use `correlate_devices` for the exact fix for a device.
  When the advisory lists a fix for only one product, the note names it, for example "Fixed in 11.36.46 for
  Commvault Web Server; use correlate_devices to confirm for your product."
- `lookup_cve` passes through the API's `patch.note` in `fix.note`.

## 0.1.0 (2026-09-30)

First release: `correlate_devices`, `check_changes`, `get_fix_plan` and `lookup_cve` over the BreachSpider device API,
with demo mode when no key is set.
