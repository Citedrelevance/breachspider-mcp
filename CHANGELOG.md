# Changelog

All notable changes to the BreachSpider MCP server. This project follows [Semantic Versioning](https://semver.org/).

## 0.1.2 (unreleased)

### Fixed
- An `asset_id` is now sent only when it is clearly neutral (`asset-7`, `device_12`, `42` or a UUID). Short host
  names such as `plant-a-sw01` used to pass through unchanged; they are now replaced with `asset-N` like other
  identifying ids.

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
