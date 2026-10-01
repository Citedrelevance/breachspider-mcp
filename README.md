# BreachSpider MCP server

A local, read only [MCP](https://modelcontextprotocol.io) server that lets AI agents (Claude Code, Claude Desktop,
Cursor and any other MCP client) check industrial and IT devices against the
[BreachSpider](https://breachspider.com/developers) device API.

Give it a vendor, product and firmware version exactly as your inventory says. It returns the CVEs that affect
that version, the affected range and where it comes from, the fix, the vendor advisory and a fix plan. No CPE
strings needed.

## Tools

| Tool | Arguments | What it does |
| --- | --- | --- |
| `correlate_devices` | `assets` (list of `vendor`, `product`, `version`, optional `asset_id`); optional `confirmed_only`, `known_exploited_only`, `fix_available_only`, `max_findings` | CVEs for each device at its exact version, in priority order, with the fix plan, coverage, warnings, `needs_review` and a `result_hash` |
| `check_changes` | `assets` (as above, each with its stored `result_hash`) | Cheap repeat check: get back which devices changed |
| `get_fix_plan` | `asset` (one `vendor`, `product`, `version`) | Fix groups and fix plan for one device |
| `lookup_cve` | `cve_id` (for example `CVE-2024-9137`) | BreachSpider's record for one CVE, trimmed |

All four are read only. They use the three endpoints a trial key can call:
`POST /api/v1/assets/correlate-cves`, `POST /api/v1/assets/correlate-cves/check` and `GET /api/v1/cves/{id}`.

## Install

Requires Python 3.10 or newer. Install with [pipx](https://pipx.pypa.io), which puts a `breachspider-mcp` command
on your path.

1. Install pipx and add its folder to your path:

   ```bash
   # macOS
   brew install pipx
   pipx ensurepath

   # Debian / Ubuntu
   sudo apt install pipx
   pipx ensurepath

   # Windows (PowerShell)
   py -m pip install --user pipx
   py -m pipx ensurepath
   ```

2. Open a new terminal so the path change applies, then install:

   ```bash
   pipx install breachspider-mcp
   ```

### Option: run with uvx instead

To run it without installing, install [uv](https://docs.astral.sh/uv/getting-started/installation/) first, then use
`uvx breachspider-mcp` wherever this README uses `breachspider-mcp`.

## API key

Set `BREACHSPIDER_API_KEY` to your key. Get a free 14 day trial key at
[breachspider.com/developers](https://breachspider.com/developers).

With no key the server runs in **demo mode: public example access only**, using a short lived public demo token.
Every result says so. For your own devices, start a free trial at
[breachspider.com/developers](https://breachspider.com/developers); for partner keys, use "Talk to us" on the same
page.

The key is only read from the environment. It is never logged or returned in tool output.

## Setup

### Claude Code

With the key in your shell's `BREACHSPIDER_API_KEY` variable:

```bash
claude mcp add breachspider -e BREACHSPIDER_API_KEY="$BREACHSPIDER_API_KEY" -- breachspider-mcp
```

If you use uv instead of pipx, end the command with `-- uvx breachspider-mcp`.

Add `--scope user` to make it available in every project. Leave out `-e ...` for demo mode.

Claude Code stores the key in its MCP config, and `claude mcp get breachspider` prints it in plain text. Don't run
that command while sharing your screen or recording, and don't paste its output anywhere.

### Claude Desktop

Edit `claude_desktop_config.json` (Settings, Developer, Edit Config) and restart Claude Desktop:

```json
{
  "mcpServers": {
    "breachspider": {
      "command": "/full/path/to/breachspider-mcp",
      "env": { "BREACHSPIDER_API_KEY": "bs_live_your_key" }
    }
  }
}
```

Use the full path from `which breachspider-mcp`; Claude Desktop does not read your shell path.

### Cursor

Add the same block to `~/.cursor/mcp.json` (all projects) or `.cursor/mcp.json` (one project):

```json
{
  "mcpServers": {
    "breachspider": {
      "command": "/full/path/to/breachspider-mcp",
      "env": { "BREACHSPIDER_API_KEY": "bs_live_your_key" }
    }
  }
}
```

## Example question

> We have a Moxa EDS-518A switch on firmware V3.5. Which CVEs affect it, are any known-exploited, and what
> version fixes them? Cite the sources.

The agent calls `correlate_devices` and answers with three CVEs, all fixed by security patch 3.11.2, citing
Moxa advisory MPSA-241156.

## Privacy

Only `vendor`, `product`, `version` and an optional `asset_id` (plus `result_hash` for `check_changes`) are sent.
Any other field is dropped before the request. Fields that look identifying (host name, IP or MAC address, user,
site, location, serial number and similar) are listed in the output under `privacy.dropped_identifying_fields`.
An `asset_id` is sent only when it is clearly neutral: a generic prefix and a number (`asset-7`, `device_12`, `42`)
or a UUID. Anything else, including short host names such as `plant-a-sw01`, IP or MAC addresses and emails, is
replaced with a neutral id such as `asset-1`.

## Honest results

Each device gets an `assessment` sentence. An unresolved device, partial coverage, a product with no version data
or an empty list is never reported as clean, and `needs_review` is always passed through. Agents are told to
repeat this in their answer.

## Trial limits and errors

API errors come back as plain messages, including `TRIAL_REQUIRED`, `TRIAL_SCOPE`, `TRIAL_BATCH_LIMIT`
(25 devices per call on a trial), the trial limit (750 device checks; the message gives usage and when the trial
ends) and `TRIAL_ENDED`, each with a link to the developer page and a way to talk to us. `check_changes` costs a
tenth of a device check, so use it for repeat checks.

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest                          # unit tests (mocked) plus live demo mode tests
BREACHSPIDER_SKIP_LIVE=1 .venv/bin/python -m pytest # offline only
npx @modelcontextprotocol/inspector --cli .venv/bin/breachspider-mcp --method tools/list
```

`BREACHSPIDER_BASE_URL` points the server at another deployment (default `https://breachspider.com`).

## License

MIT, same as the BreachSpider Python SDK. See [LICENSE](LICENSE).
