#!/usr/bin/env python3
"""
Krisp REST client — fetches meeting summaries via the Krisp MCP endpoint.

First run:  python krisp_client.py --login
            Opens your browser for OAuth2 authorization, saves token to
            .krisp_token.json (gitignored).

Subsequent runs use the saved token and auto-refresh when expired.

Install deps:
    pip install requests

Usage
-----
    python krisp_client.py --login              # authorize (first time)
    python krisp_client.py                      # last 10 meetings
    python krisp_client.py --limit 50           # up to 50 meetings
    python krisp_client.py --after 2026-04-01   # meetings after date
    python krisp_client.py --before 2026-05-01  # meetings before date
    python krisp_client.py --id <32-char-hex>   # single meeting
    python krisp_client.py --search "keyword"   # full-text search
    python krisp_client.py --dry-run            # print markdown, don't save
    python krisp_client.py --json               # dump raw API JSON
    python krisp_client.py --output-dir ~/notes # save files to ~/notes
"""

import argparse
import base64
import hashlib
import http.server
import json
import os
import re
import secrets
import sys
import threading
import time
import urllib.parse
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

import requests

# ── OAuth2 + MCP constants ───────────────────────────────────────────────────

_WELL_KNOWN_RESOURCE  = "https://mcp.krisp.ai/.well-known/oauth-protected-resource"
_WELL_KNOWN_SERVER    = "https://mcp.krisp.ai/.well-known/oauth-authorization-server"
_REGISTRATION_URL     = "https://mcp.krisp.ai/.well-known/oauth-registration"
_AUTH_URL             = "https://api.krisp.ai/platform/v1/oauth2/authorize"
_TOKEN_URL            = "https://api.krisp.ai/platform/v1/oauth2/token"
_MCP_URL              = "https://mcp.krisp.ai/mcp"

_SCOPES = " ".join([
    "user::me::read",
    "user::meetings::list",
    "user::meetings:metadata::read",
    "user::meetings:notes::read",
    "user::meetings:transcripts::read",
    "user::activities::list",
])

_REDIRECT_HOST = "127.0.0.1"
_REDIRECT_PORT = 9999
_REDIRECT_URI  = f"http://{_REDIRECT_HOST}:{_REDIRECT_PORT}/callback"
_TOKEN_FILE    = Path(__file__).parent / ".krisp_token.json"

_CLIENT_NAME = "krisp-cli"

# ── PKCE helpers ─────────────────────────────────────────────────────────────

def _pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    digest   = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


# ── Local callback server ────────────────────────────────────────────────────

class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    result: dict = {}

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        _CallbackHandler.result = params
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(
            b"<html><body style='font-family:sans-serif;padding:2em'>"
            b"<h2>Krisp authorized &#10003;</h2>"
            b"<p>You can close this tab and return to the terminal.</p>"
            b"</body></html>"
        )

    def log_message(self, *_):
        pass  # silence request logs


def _wait_for_callback(timeout: int = 120) -> dict:
    server = http.server.HTTPServer((_REDIRECT_HOST, _REDIRECT_PORT), _CallbackHandler)
    server.timeout = 1
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        server.handle_request()
        if _CallbackHandler.result:
            server.server_close()
            return _CallbackHandler.result
    server.server_close()
    raise TimeoutError("OAuth callback not received within timeout")


# ── Token persistence ────────────────────────────────────────────────────────

def _load_token() -> dict:
    if _TOKEN_FILE.exists():
        return json.loads(_TOKEN_FILE.read_text())
    return {}


def _save_token(data: dict):
    _TOKEN_FILE.write_text(json.dumps(data, indent=2))
    _TOKEN_FILE.chmod(0o600)


# ── OAuth2 client registration (RFC 7591) ────────────────────────────────────

def _register_client() -> tuple[str, str]:
    resp = requests.post(_REGISTRATION_URL, json={
        "client_name": _CLIENT_NAME,
        "redirect_uris": [_REDIRECT_URI],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_basic",
        "scope": _SCOPES,
    }, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    return data["client_id"], data["client_secret"]


# ── OAuth2 token exchange ────────────────────────────────────────────────────

def _exchange_code(client_id: str, client_secret: str,
                   code: str, verifier: str) -> dict:
    resp = requests.post(_TOKEN_URL, data={
        "grant_type":    "authorization_code",
        "code":          code,
        "redirect_uri":  _REDIRECT_URI,
        "code_verifier": verifier,
    }, auth=(client_id, client_secret), timeout=15)
    resp.raise_for_status()
    return resp.json()


def _refresh_token(client_id: str, client_secret: str, refresh: str) -> dict:
    resp = requests.post(_TOKEN_URL, data={
        "grant_type":    "refresh_token",
        "refresh_token": refresh,
    }, auth=(client_id, client_secret), timeout=15)
    resp.raise_for_status()
    return resp.json()


# ── Main auth flow ───────────────────────────────────────────────────────────

def login() -> dict:
    """Full Authorization Code + PKCE flow. Returns saved token data."""
    print("Registering OAuth2 client with Krisp...")
    client_id, client_secret = _register_client()
    print(f"  client_id: {client_id}")

    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(16)

    params = urllib.parse.urlencode({
        "response_type":         "code",
        "client_id":             client_id,
        "redirect_uri":          _REDIRECT_URI,
        "scope":                 _SCOPES,
        "state":                 state,
        "code_challenge":        challenge,
        "code_challenge_method": "S256",
    })
    url = f"{_AUTH_URL}?{params}"

    print(f"\nOpening browser for authorization...")
    print(f"  If it doesn't open, visit:\n  {url}\n")
    webbrowser.open(url)

    print("Waiting for callback on http://127.0.0.1:9999/callback ...")
    callback = _wait_for_callback(timeout=120)

    if callback.get("state") != state:
        raise ValueError("OAuth state mismatch — possible CSRF attack")
    if "error" in callback:
        raise RuntimeError(f"Authorization error: {callback['error']}: {callback.get('error_description','')}")

    code = callback["code"]
    print("Code received. Exchanging for tokens...")
    tokens = _exchange_code(client_id, client_secret, code, verifier)

    saved = {
        "client_id":     client_id,
        "client_secret": client_secret,
        "access_token":  tokens["access_token"],
        "refresh_token": tokens.get("refresh_token"),
        "expires_at":    time.time() + tokens.get("expires_in", 3600) - 60,
        "scope":         tokens.get("scope", _SCOPES),
    }
    _save_token(saved)
    print(f"Tokens saved to {_TOKEN_FILE}\n")
    return saved


def get_access_token() -> str:
    """Return a valid access token, refreshing if expired."""
    data = _load_token()
    if not data:
        sys.exit(
            "Not logged in. Run:  python krisp_client.py --login"
        )

    if time.time() < data.get("expires_at", 0):
        return data["access_token"]

    # Token expired — try refresh
    refresh = data.get("refresh_token")
    if not refresh:
        sys.exit("Refresh token missing. Run:  python krisp_client.py --login")

    print("Access token expired, refreshing...", flush=True)
    tokens = _refresh_token(data["client_id"], data["client_secret"], refresh)
    data.update({
        "access_token":  tokens["access_token"],
        "refresh_token": tokens.get("refresh_token", refresh),
        "expires_at":    time.time() + tokens.get("expires_in", 3600) - 60,
    })
    _save_token(data)
    return data["access_token"]


# ── MCP transport ────────────────────────────────────────────────────────────

_rpc_id = 0
_session_id: str | None = None  # Mcp-Session-Id from initialize

def _next_id() -> int:
    global _rpc_id
    _rpc_id += 1
    return _rpc_id


def _read_sse_stream(resp: requests.Response, target_id: int) -> dict:
    """
    Buffer raw SSE bytes, split on double-newline (event boundary),
    then assemble multi-line data: fields and parse JSON.
    """
    buf = ""
    for chunk in resp.iter_content(chunk_size=4096):
        if isinstance(chunk, bytes):
            chunk = chunk.decode("utf-8", errors="replace")
        buf += chunk
        # SSE events are separated by an empty line (\n\n or \r\n\r\n)
        while "\n\n" in buf:
            event_raw, buf = buf.split("\n\n", 1)
            # collect data: lines (the value may wrap across lines without prefix)
            data_parts = []
            in_data = False
            for line in event_raw.split("\n"):
                if line.startswith("data:"):
                    data_parts.append(line[5:].lstrip(" "))
                    in_data = True
                elif in_data and not any(line.startswith(p) for p in ("event:", "id:", "retry:", ":")):
                    # bare continuation line — part of the same data value
                    data_parts.append(line)
                else:
                    in_data = False

            if not data_parts:
                continue
            raw = "".join(data_parts)
            if not raw or raw == "[DONE]":
                continue
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if _DEBUG:
                print(f"[SSE] parsed id={msg.get('id')} target={target_id} keys={list(msg.keys())}")
            if msg.get("id") == target_id:
                resp.close()
                return msg
    return {}


def _post(session: requests.Session, method: str, params: dict) -> dict:
    global _session_id

    rpc_id  = _next_id()
    payload = {"jsonrpc": "2.0", "id": rpc_id, "method": method, "params": params}

    headers = {"Accept": "application/json, text/event-stream"}
    if _session_id:
        headers["Mcp-Session-Id"] = _session_id

    resp = session.post(_MCP_URL, json=payload, headers=headers, timeout=30, stream=True)
    resp.raise_for_status()

    if method == "initialize" and "Mcp-Session-Id" in resp.headers:
        _session_id = resp.headers["Mcp-Session-Id"]

    ct = resp.headers.get("Content-Type", "")
    if "text/event-stream" in ct:
        msg = _read_sse_stream(resp, rpc_id)
    else:
        msg = resp.json()

    if not msg:
        return {}
    if "error" in msg:
        raise RuntimeError(
            f"MCP error [{msg['error']['code']}]: {msg['error']['message']}"
        )
    return msg.get("result", {})


def _init(session: requests.Session):
    _post(session, "initialize", {
        "protocolVersion": "2024-11-05",
        "clientInfo": {"name": _CLIENT_NAME, "version": "1.0.0"},
        "capabilities": {},
    })
    # notifications/initialized is a one-way message (no response expected)
    session.post(
        _MCP_URL,
        json={"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        headers={
            "Accept": "application/json, text/event-stream",
            **({"Mcp-Session-Id": _session_id} if _session_id else {}),
        },
        timeout=10,
    )


_DEBUG = os.environ.get("KRISP_DEBUG") == "1"


def _call_tool(session: requests.Session, tool: str, arguments: dict) -> dict | list:
    result  = _post(session, "tools/call", {"name": tool, "arguments": arguments})
    if _DEBUG:
        print(f"\n[DEBUG] raw result keys for {tool}: {list(result.keys())}\n")
    # Prefer structuredContent (machine-readable), fall back to text content
    structured = result.get("structuredContent")
    if structured:
        if _DEBUG:
            print(f"[DEBUG] using structuredContent, keys: {list(structured.keys())}\n")
        return structured
    content = result.get("content", [])
    text    = "".join(c["text"] for c in content if c.get("type") == "text")
    return json.loads(text) if text else {}


# ── Krisp API wrappers ───────────────────────────────────────────────────────

_FIELDS = [
    "name", "date", "url", "attendees", "speakers",
    "key_points", "action_items", "detailed_summary",
]


def search_meetings(session, *, search=None, after=None, before=None,
                    limit=10, offset=0) -> dict:
    args: dict = {"limit": limit, "offset": offset, "fields": _FIELDS}
    if search:
        args["search"] = search
    if after:
        args["after"] = after
    if before:
        args["before"] = before
    return _call_tool(session, "search_meetings", args)


def get_meeting_by_id(session, meeting_id: str) -> dict:
    return _call_tool(session, "search_meetings", {
        "id":     meeting_id.replace("-", ""),
        "fields": _FIELDS,
    })


def _docs_entries(result: dict | list) -> list[dict]:
    """Normalise get_multiple_documents result → list of {id, document} dicts."""
    if isinstance(result, list):
        return result
    if isinstance(result, dict):
        return result.get("results") or result.get("documents") or []
    return []


def get_full_document(session, meeting_id: str) -> str | None:
    clean = meeting_id.replace("-", "").lower()
    result = _call_tool(session, "get_multiple_documents", {"ids": [clean]})
    entries = _docs_entries(result)
    if entries:
        return entries[0].get("document")
    return None


def _parse_section_bullets(doc: str, heading: str) -> list[str]:
    """Extract bullet lines from a markdown section (any heading level)."""
    lines = doc.splitlines()
    inside = False
    bullets = []
    for line in lines:
        if re.match(rf"^#+\s+{re.escape(heading)}\s*$", line, re.IGNORECASE):
            inside = True
            continue
        if inside:
            if re.match(r"^#+\s+", line):
                break
            m = re.match(r"^[-*]\s+(.*)", line)
            if m:
                bullets.append(m.group(1).strip())
    return bullets


def enrich_key_points(session, meetings: list[dict]) -> None:
    """Fetch full documents in batches and inject key_points into each meeting."""
    to_enrich = [
        m for m in meetings
        if not (m.get("key_points") or (m.get("meeting_notes") or {}).get("key_points"))
    ]
    if not to_enrich:
        return

    batch_size = 10
    id_to_meeting = {m["meeting_id"].replace("-", "").lower(): m for m in to_enrich}
    ids = list(id_to_meeting.keys())

    for i in range(0, len(ids), batch_size):
        batch = ids[i : i + batch_size]
        result = _call_tool(session, "get_multiple_documents", {"ids": batch})
        entries = _docs_entries(result)
        if _DEBUG:
            print(f"[enrich] got {len(entries)} entries for batch {batch}")
        for entry in entries:
            doc = entry.get("document") or ""
            mid = entry.get("id", "")
            if _DEBUG:
                # show first heading lines to understand document structure
                headings = [l for l in doc.splitlines() if l.startswith("#")][:6]
                print(f"[enrich] id={mid} doc_len={len(doc)} headings={headings}")
            if not doc or mid not in id_to_meeting:
                if _DEBUG and mid not in id_to_meeting:
                    print(f"[enrich] id={mid!r} not in id_to_meeting keys={list(id_to_meeting.keys())}")
                continue
            kp = _parse_section_bullets(doc, "Key Points")
            if _DEBUG:
                print(f"[enrich] key_points found: {len(kp)}")
            if kp:
                id_to_meeting[mid]["key_points"] = kp


# ── Markdown rendering ───────────────────────────────────────────────────────

_OUTPUT_DIR = Path(__file__).parent


def _slug(title: str) -> str:
    return re.sub(r"[^\w-]", "-", title.lower().strip()).strip("-")[:60]


def _fmt_human(iso: str) -> str:
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.strftime("%-d %b %Y, %-I:%M %p")
    except Exception:
        return iso


def _fmt_prefix(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).strftime("%Y-%m-%d")
    except Exception:
        return iso[:10]


def _render_markdown(meeting: dict) -> str:
    title  = meeting.get("name", "Untitled Meeting")
    date   = meeting.get("date", "")
    url    = meeting.get("url", "")
    notes  = meeting.get("meeting_notes") or {}

    lines = [
        f"# {title}", "",
        f"**Дата:** {_fmt_human(date)}",
        "**Источник:** Krisp Meeting Notes",
    ]
    if url:
        lines.append(f"**Ссылка:** {url}")
    lines.append("")

    # action_items: top-level or inside meeting_notes
    items = meeting.get("action_items") or (meeting.get("meeting_notes") or {}).get("action_items") or []
    if items:
        lines += ["## Action Items", ""]
        for item in items:
            assignee = item.get("assignee") or item.get("owner") or "Unknown"
            text     = item.get("text") or item.get("title") or item.get("description") or ""
            ts       = item.get("timestamp") or item.get("time") or ""
            due      = item.get("due_date") or ""
            parts    = ([f"_{ts}_"] if ts else []) + ([f"due {due}"] if due else [])
            suffix   = f" _({', '.join(parts)})_" if parts else ""
            lines.append(f"- [ ] **@{assignee}** — {text}{suffix}")
        lines.append("")

    # key_points: top-level or inside meeting_notes
    points = meeting.get("key_points") or (meeting.get("meeting_notes") or {}).get("key_points") or []
    if points:
        lines += ["## Key Points", ""]
        for p in points:
            if isinstance(p, dict):
                text   = p.get("text") or p.get("content") or str(p)
                ts     = p.get("timestamp") or p.get("time") or ""
                suffix = f" _({ts})_" if ts else ""
                lines.append(f"- {text}{suffix}")
            else:
                lines.append(f"- {p}")
        lines.append("")

    detailed = notes.get("detailed_summary") or meeting.get("detailed_summary") or ""
    if detailed:
        lines += ["## Summary", "", detailed, ""]

    participants = sorted(set(meeting.get("attendees") or []) | set(meeting.get("speakers") or []))
    if participants:
        lines += ["## Participants", ""]
        for p in participants:
            lines.append(f"- {p}")
        lines.append("")

    return "\n".join(lines)


def save_markdown(meeting: dict, dry_run: bool = False,
                  output_dir: Path | None = None) -> Path:
    prefix   = _fmt_prefix(meeting.get("date", "0000-00-00"))
    name     = _slug(meeting.get("name", "untitled"))
    out      = output_dir if output_dir is not None else _OUTPUT_DIR
    filename = out / f"{prefix}-{name}.md"
    content  = _render_markdown(meeting)

    if dry_run:
        print(f"\n{'='*60}\n# Would write: {filename}\n{'='*60}")
        print(content)
        return filename

    out.mkdir(parents=True, exist_ok=True)
    filename.write_text(content, encoding="utf-8")
    return filename


# ── CLI ──────────────────────────────────────────────────────────────────────

def build_session() -> requests.Session:
    token = get_access_token()
    s = requests.Session()
    s.headers["Authorization"] = f"Bearer {token}"
    return s


def main():
    parser = argparse.ArgumentParser(description="Fetch Krisp meeting summaries")
    parser.add_argument("--login",  action="store_true", help="Authorize via browser (first-time setup)")
    parser.add_argument("--id",     dest="meeting_id",   help="Fetch single meeting by 32-char hex ID")
    parser.add_argument("--search", help="Full-text search query")
    parser.add_argument("--after",  help="ISO date, e.g. 2026-04-01")
    parser.add_argument("--before", help="ISO date, e.g. 2026-05-01")
    parser.add_argument("--limit",  type=int, default=10, help="Max meetings (1-50, default 10)")
    parser.add_argument("--output-dir", dest="output_dir", metavar="DIR",
                        help="Directory to save markdown files (default: script directory)")
    parser.add_argument("--dry-run",   action="store_true", help="Print markdown, don't write files")
    parser.add_argument("--json",      dest="as_json", action="store_true", help="Dump raw JSON response")
    parser.add_argument("--debug-doc", dest="debug_doc", help="Print raw document text for a meeting ID and exit")
    args = parser.parse_args()

    if args.login:
        login()
        print("Login successful. You can now run without --login.")
        return

    session = build_session()

    if args.debug_doc:
        _init(session)
        clean = args.debug_doc.replace("-", "").lower()
        result = _call_tool(session, "get_multiple_documents", {"ids": [clean]})
        print(repr(result))  # raw repr to see exact structure
        if isinstance(result, list) and result:
            doc = result[0].get("document") or ""
            print("\n--- RAW DOCUMENT ---")
            print(doc[:3000])  # first 3000 chars
        return

    print("Connecting to Krisp MCP...", flush=True)
    _init(session)
    print("Connected.", flush=True)

    if args.meeting_id:
        data     = get_meeting_by_id(session, args.meeting_id)
        meetings = data.get("meetings") or ([data] if data else [])
    else:
        data     = search_meetings(
            session,
            search=args.search,
            after=args.after,
            before=args.before,
            limit=min(args.limit, 50),
        )
        meetings = data.get("meetings") or []

    if not meetings:
        print("No meetings found.")
        return

    if args.as_json:
        print(json.dumps(meetings, ensure_ascii=False, indent=2))
        return

    print(f"Found {len(meetings)} meeting(s). Fetching key points...", flush=True)
    enrich_key_points(session, meetings)

    output_dir = Path(args.output_dir).expanduser().resolve() if args.output_dir else None

    for m in meetings:
        path = save_markdown(m, dry_run=args.dry_run, output_dir=output_dir)
        if not args.dry_run:
            print(f"  Saved: {path}")

    if not args.dry_run:
        out = output_dir if output_dir is not None else _OUTPUT_DIR
        print(f"\nDone. Files written to {out}/")


if __name__ == "__main__":
    main()
