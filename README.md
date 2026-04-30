# krisp-meetings-fetcher

CLI tool that exports [Krisp](https://krisp.ai/) meeting summaries to Markdown files. Uses the official Krisp MCP endpoint with OAuth2 + PKCE authorization.

## What it does

- Authorizes via browser (OAuth2 Authorization Code + PKCE), tokens are saved locally and auto-refreshed on expiry
- Fetches meetings with filtering by date range, keyword, or ID
- Saves each meeting as a Markdown file with action items, key points, summary, and participants
- Files are named `YYYY-MM-DD meeting-title.md`

## Requirements

- Python 3.10+
- Krisp account with Meeting Notes access

## Installation

```bash
pip install requests
```

## First run

```bash
python krisp_client.py --login
```

A browser window will open for authorization. After approval, tokens are saved to `.krisp_token.json` (gitignored).

## Usage

```bash
# Last 10 meetings
python krisp_client.py

# Up to 50 meetings
python krisp_client.py --limit 50

# Meetings after a date
python krisp_client.py --after 2026-04-01

# Meetings before a date
python krisp_client.py --before 2026-05-01

# Date range
python krisp_client.py --after 2026-04-01 --before 2026-05-01

# Full-text search
python krisp_client.py --search "product review"

# Single meeting by ID (32-char hex)
python krisp_client.py --id <meeting-id>

# Save to a custom directory
python krisp_client.py --output-dir ~/notes/meetings

# Print Markdown to terminal without saving
python krisp_client.py --dry-run

# Dump raw API JSON
python krisp_client.py --json
```

## Output format

Each meeting is saved as `YYYY-MM-DD meeting-title.md`:

```markdown
# Product Review

**Date:** 1 Apr 2026, 3:00 PM
**Source:** Krisp Meeting Notes
**Link:** https://krisp.ai/...

## Action Items

- [ ] **@alice** — Prepare Q2 roadmap _(due 2026-04-08)_
- [ ] **@bob** — Send updated pricing doc

## Key Points

- Launched new feature ahead of schedule
- Need to align on pricing strategy

## Summary

...

## Participants

- Alice
- Bob
```

## Debugging

```bash
# Enable verbose SSE and MCP logs
KRISP_DEBUG=1 python krisp_client.py

# Print raw document for a meeting ID
python krisp_client.py --debug-doc <meeting-id>
```

## Security

Tokens are stored in `.krisp_token.json` with `600` permissions (owner-only). Do not commit this file.