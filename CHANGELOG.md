# Changelog

All notable changes to the BreachSpider MCP server. This project follows [Semantic Versioning](https://semver.org/).

## 0.1.1 (unreleased)

### Changed
- `lookup_cve` reports a CVE's fix status as `varies_by_product` when the vendor's advisory states fixed versions
  per product, instead of `unknown`. `fix.note` then says to use `correlate_devices` for the exact fix for a device.
  When the advisory lists a fix for only one product, the note names it, for example "Fixed in 11.36.46 for
  Commvault Web Server; use correlate_devices to confirm for your product."
- `lookup_cve` passes through the API's `patch.note` in `fix.note`.

## 0.1.0 (2026-09-30)

First release: `correlate_devices`, `check_changes`, `get_fix_plan` and `lookup_cve` over the BreachSpider device API,
with demo mode when no key is set.
