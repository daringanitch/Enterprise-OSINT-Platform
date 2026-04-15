# Sherlock Username Search Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `sherlock_username_search` tool to the existing `social-media-enhanced` MCP server that scans 400+ social sites and returns claimed accounts for a given username.

**Architecture:** Extend `mcp-servers/social-media-enhanced/app.py` with a new tool branch in the `/execute` handler. Sherlock's blocking scan runs in a `ThreadPoolExecutor` to keep Flask responsive. The `sherlock-project` pip package is imported directly (no subprocess).

**Tech Stack:** Flask, `sherlock-project` (pip), `concurrent.futures.ThreadPoolExecutor`, pytest

---

## File Map

| Action | File |
|--------|------|
| Modify | `mcp-servers/social-media-enhanced/app.py` |
| Modify | `mcp-servers/social-media-enhanced/requirements.txt` |
| Modify | `mcp-servers/tests/test_social_media_enhanced.py` |

---

### Task 1: Add `sherlock-project` to requirements

**Files:**
- Modify: `mcp-servers/social-media-enhanced/requirements.txt`

- [ ] **Step 1: Add the dependency**

Open `mcp-servers/social-media-enhanced/requirements.txt`. Add one line so it reads:

```
Flask==3.0.0
requests==2.31.0
python-dotenv==1.0.0
sherlock-project>=0.14.0
```

- [ ] **Step 2: Verify install (in the server's venv or a fresh one)**

```bash
cd mcp-servers/social-media-enhanced
pip install sherlock-project>=0.14.0
python -c "from sherlock_project.sherlock import sherlock; print('ok')"
```

Expected output: `ok`

- [ ] **Step 3: Commit**

```bash
git add mcp-servers/social-media-enhanced/requirements.txt
git commit -m "feat(social-mcp): add sherlock-project dependency"
```

---

### Task 2: Write failing tests for the new tool

**Files:**
- Modify: `mcp-servers/tests/test_social_media_enhanced.py`

- [ ] **Step 1: Add the failing tests**

Append the following class to `mcp-servers/tests/test_social_media_enhanced.py`:

```python
# ---------------------------------------------------------------------------
# Sherlock username search tool
# ---------------------------------------------------------------------------
class TestSherlockUsernameTool:
    """Tests for sherlock_username_search — Sherlock is mocked so no network calls."""

    def _post(self, client, tool, parameters):
        payload = {"tool": tool, "parameters": parameters}
        return client.post(
            "/execute",
            data=json.dumps(payload),
            content_type="application/json",
        )

    def test_missing_username_returns_400(self, client):
        resp = self._post(client, "sherlock_username_search", {})
        assert resp.status_code == 400

    def test_sherlock_tool_listed_in_tools_endpoint(self, client):
        tools = _json(client.get("/tools")).get("tools", {})
        assert "sherlock_username_search" in tools, (
            "sherlock_username_search not found in /tools"
        )

    def test_sherlock_tool_has_description(self, client):
        tools = _json(client.get("/tools")).get("tools", {})
        defn = tools.get("sherlock_username_search", {})
        assert "description" in defn

    def test_sherlock_returns_claimed_accounts(self, client, monkeypatch):
        """Mock run_sherlock so no real scan is made; verify response shape."""
        import social_media_enhanced_app as srv

        monkeypatch.setattr(
            srv,
            "run_sherlock",
            lambda username: [
                {"site": "GitHub", "url": "https://github.com/testuser"},
                {"site": "Twitter", "url": "https://twitter.com/testuser"},
            ],
        )

        resp = self._post(client, "sherlock_username_search", {"username": "testuser"})
        assert resp.status_code == 200
        data = _json(resp)
        result = data.get("result", {})
        assert result.get("username") == "testuser"
        assert result.get("found_count") == 2
        assert len(result.get("accounts", [])) == 2
        assert result["accounts"][0]["site"] == "GitHub"
        assert result["accounts"][0]["url"] == "https://github.com/testuser"

    def test_sherlock_returns_zero_accounts_when_none_found(self, client, monkeypatch):
        import social_media_enhanced_app as srv

        monkeypatch.setattr(srv, "run_sherlock", lambda username: [])

        resp = self._post(client, "sherlock_username_search", {"username": "nobody123xyz"})
        assert resp.status_code == 200
        result = _json(resp).get("result", {})
        assert result.get("found_count") == 0
        assert result.get("accounts") == []

    def test_sherlock_response_has_scan_duration(self, client, monkeypatch):
        import social_media_enhanced_app as srv

        monkeypatch.setattr(srv, "run_sherlock", lambda username: [])

        resp = self._post(client, "sherlock_username_search", {"username": "testuser"})
        assert resp.status_code == 200
        result = _json(resp).get("result", {})
        assert "scan_duration_seconds" in result

    def test_sherlock_response_has_timestamp(self, client, monkeypatch):
        import social_media_enhanced_app as srv

        monkeypatch.setattr(srv, "run_sherlock", lambda username: [])

        resp = self._post(client, "sherlock_username_search", {"username": "testuser"})
        assert resp.status_code == 200
        result = _json(resp).get("result", {})
        assert "timestamp" in result
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd Enterprise-OSINT-Platform
pytest mcp-servers/tests/test_social_media_enhanced.py::TestSherlockUsernameTool -v
```

Expected: All 6 tests FAIL (AttributeError or 400/404 responses — `run_sherlock` and the tool branch don't exist yet).

- [ ] **Step 3: Commit the failing tests**

```bash
git add mcp-servers/tests/test_social_media_enhanced.py
git commit -m "test(social-mcp): add failing tests for sherlock_username_search"
```

---

### Task 3: Implement `run_sherlock` and wire up the tool

**Files:**
- Modify: `mcp-servers/social-media-enhanced/app.py`

- [ ] **Step 1: Add imports and executor at the top of `app.py`**

After the existing imports (after `import base64`), add:

```python
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

# Sherlock is optional — server starts even if not installed
try:
    from sherlock_project.sherlock import sherlock as _sherlock_run
    from sherlock_project.sites import SitesInformation
    from sherlock_project.result import QueryStatus
    from sherlock_project.notify import QueryNotify
    SHERLOCK_AVAILABLE = True
except ImportError:
    SHERLOCK_AVAILABLE = False

_executor = ThreadPoolExecutor(max_workers=4)
```

- [ ] **Step 2: Add `run_sherlock` helper function**

After the `search_social_media_mentions` function (before the Flask route definitions), add:

```python
def run_sherlock(username: str) -> list[dict]:
    """
    Run a Sherlock username scan and return only claimed accounts.

    Executes synchronously — call via _executor.submit() to avoid
    blocking the Flask worker thread.

    Returns a list of {"site": str, "url": str} dicts.
    """
    if not SHERLOCK_AVAILABLE:
        raise RuntimeError("sherlock-project is not installed")

    sites_info = SitesInformation()
    query_notify = QueryNotify()  # base class — silent, no output

    results = _sherlock_run(
        username,
        sites_info.sites,
        query_notify,
        timeout=60,
    )

    return [
        {"site": site_name, "url": data["url_user"]}
        for site_name, data in results.items()
        if data["status"].status == QueryStatus.CLAIMED
    ]
```

- [ ] **Step 3: Add `sherlock_username_search` branch in `/execute` handler**

In `execute_tool()`, find the line:

```python
        else:
            return jsonify({'error': f'Unknown tool: {tool}'}), 400
```

Insert the new branch **before** that `else`:

```python
        elif tool == 'sherlock_username_search':
            username = parameters.get('username')
            if not username:
                return jsonify({'error': 'username parameter required'}), 400

            if not SHERLOCK_AVAILABLE:
                return jsonify({'error': 'sherlock not available'}), 500

            scan_start = datetime.utcnow()
            try:
                future = _executor.submit(run_sherlock, username)
                accounts = future.result(timeout=120)
            except FuturesTimeoutError:
                return jsonify({'error': 'scan timed out'}), 504

            scan_duration = (datetime.utcnow() - scan_start).total_seconds()

            result = {
                'username': username,
                'found_count': len(accounts),
                'accounts': accounts,
                'scan_duration_seconds': round(scan_duration, 2),
                'timestamp': datetime.utcnow().isoformat(),
            }
```

- [ ] **Step 4: Add `sherlock_username_search` to the `/tools` endpoint**

In `list_tools()`, find the closing `}` of the `'tools'` dict (after `social_media_search`'s entry). Add:

```python
            'sherlock_username_search': {
                'description': 'Search 400+ social media sites for a username and return claimed accounts',
                'parameters': {
                    'username': {'type': 'string', 'description': 'Username to search for', 'required': True}
                },
                'intelligence_type': 'REAL',
                'requires_api_key': False,
                'example': {'username': 'john_doe'}
            },
```

- [ ] **Step 5: Commit the implementation**

```bash
git add mcp-servers/social-media-enhanced/app.py
git commit -m "feat(social-mcp): add sherlock_username_search tool"
```

---

### Task 4: Run all tests and verify

- [ ] **Step 1: Run the full social media test suite**

```bash
cd Enterprise-OSINT-Platform
pytest mcp-servers/tests/test_social_media_enhanced.py -v
```

Expected: All tests PASS (including the pre-existing ones and the 6 new Sherlock tests).

- [ ] **Step 2: Confirm the tools endpoint lists the new tool**

```bash
python -c "
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location('app', 'mcp-servers/social-media-enhanced/app.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
with mod.app.test_client() as c:
    import json
    tools = json.loads(c.get('/tools').data)['tools']
    print(list(tools.keys()))
"
```

Expected output includes: `'sherlock_username_search'`

- [ ] **Step 3: Final commit**

```bash
git add -A
git commit -m "feat(social-mcp): sherlock username search - complete implementation"
```
