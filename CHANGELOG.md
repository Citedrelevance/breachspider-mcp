# Changelog

All notable changes to the BreachSpider MCP server. This project follows [Semantic Versioning](https://semver.org/).

## 0.3.1 (2026-11-12)

### Fixed
- `check_changes` and `correlate_devices` wait up to 90 s for the API (the SDK default 30 s failed check_changes calls
  of about 68 or more devices). A timeout now returns `retry_guidance` with `action: reduce_batch` and `max: 50`, and
  the agent is told to split the list into batches of at most 50 instead of retrying it unchanged.
- The tool description and server instructions state the real cost: about 0.2 s per distinct device, so 200 distinct
  devices take about 40 s.

### Changed
- Requires `breachspider>=0.5.1`.

## 0.3.0 (2026-11-08)

### Added
- `build_server(hosted=True, server_kwargs=...)`: the profile for the hosted server at mcp.breachspider.com. Same
  tools, names and result shaping; unknown fields are a schema error; identifying values (an asset_id that looks
  like an IP, MAC or email address or a host name) are refused with the field and the reason, never the value, and
  nothing is sent; per-call caps of 25 devices, 5 Windows hosts and 200 change checks; no demo mode.
- `search_products`: how the catalog names a vendor and its products (top 3 vendors, up to 15 products each, CVE
  counts), with a note that only products with CVEs are listed. Customer keys only.
- `safety.hosted_refusal` and `safety.identifying_reason`.

- Warning codes `FAMILY_ONLY_MATCH` (a bare family name matched over many models: answered, confidence below HIGH,
  needs review) and `PRODUCT_LINE_ADDED` (the vendor's product-line name was added to resolve, e.g. SIMATIC).
- `correlate_devices`: `findings_note` when the findings are cut short ("showing 25 of 60 ...").
- Warning code `LIKELY_NOT_AFFECTED`; `correlate_devices` names those CVEs in `likely_not_affected` (they sort last and
  are often past max_findings).
- `search_products`: an "X Firmware" catalog entry is shown under "X" as `also_listed_as`, so the pair uses one of
  the 15 places. Needs the BreachSpider API from November 2026 (`group_firmware`).

### Changed
- The check_windows_host description states the per-call cap of the profile in use.
- `lookup_cve`: when fixed versions vary by product and one product's fix is named, the note says fixes for other
  affected products, if any, are in the vendor advisories.

## 0.2.0 (2026-11-02)

### Added
- `submit_device_batch`: queue up to 5,000 devices as one batch job (`POST /api/v1/batches`) and get a `job_id` at
  once. Identifying fields are stripped as in `correlate_devices`. The Idempotency-Key is derived from the cleaned
  body, so sending the same list again within 24 hours returns the original job and never charges twice.
- `get_device_batch`: job status and progress; once finished, the summary and one page of results (same shape and
  honesty rules as `correlate_devices`) with `next_cursor` for the next page. Failed devices are listed with their
  `error_code`.
- Both need a partner or customer key with batch jobs enabled; demo mode refuses them without calling the API, and
  a key without batch jobs gets a plain message instead of "Not found".

### Changed
- Requires `breachspider>=0.4.0` (request headers).

## 0.1.9 (2026-10-27)

### Added
- `correlate_devices` returns `status_hash` and `status_facts` per device: the known-exploited flags of the matched
  CVEs, lifecycle and firmware currency, and their hash.
- `check_changes` accepts the stored `status_hash` and `status_facts` per device. The answer then lists
  `status_changed` and, per device, `reasons` (for example a CVE newly known-exploited, an end of support date
  published, a new firmware release) with `current_status_hash` and `current_status_facts`. A status can change while
  the findings stay the same. Without `status_hash` the answer is as before.

## 0.1.8 (2026-10-26)

### Added
- Known warning code `VERSION_NOT_USED_FOR_RESOLUTION`: a version was sent but has no numeric form the resolver can use
  (for example `R3.02.10`); it is still used for CVE matching. Replaces `NO_VERSION_SUPPLIED` in that case.

## 0.1.7 (2026-10-24)

### Added
- `correlate_devices`, `check_changes` and `get_fix_plan` accept an optional `part_number` per device (the vendor part,
  order or model number when the inventory holds it apart from the product name). The API matches it exactly for
  lifecycle and firmware answers and uses it to identify the product only when the product text does not resolve.
- Known warning codes (as documented in the API field reference): used as the text when a warning arrives without
  a message. Unknown codes are passed through as the code, never an error.

## 0.1.6 (2026-10-22)

### Added
- `correlate_devices`: a lifecycle answer of "Not publicly available" (`reason: not_publicly_available`) or
  "under review" now carries `pages_checked` (up to 5 vendor pages that were read) and `checked_on`, and its
  `source_url` is the first page checked, so the agent can cite where the vendor publishes no date.

## 0.1.5 (2026-10-20)

### Added
- `correlate_devices`, on client plans: each device carries `lifecycle` (the vendor's end of sale / end of support,
  in the API's own wording, with `source_url`, the vendor's term, replacement and, for aggregator answers, `listed_by`)
  and `firmware` (current / behind, latest version and date, releases behind, up to 5 security notes from the
  releases it misses). Findings carry `unsupported_when_assigned` when the CVE record has that tag, attributed to
  its assigner. The call adds `lifecycle_and_firmware` (counts, unsupported devices, firmware ranking, notices).
- Trial and demo keys are unchanged: the API sends no such blocks, and the tool adds no empty keys.

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
