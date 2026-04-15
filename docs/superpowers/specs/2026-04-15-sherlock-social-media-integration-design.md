# Sherlock Username Search — Design Spec
**Date:** 2026-04-15
**Status:** Approved

## Overview

Extend the existing `social-media-enhanced` MCP server (port 8010) with a new tool `sherlock_username_search` that performs username enumeration across 400+ social media sites using the Sherlock library. Returns only claimed accounts.

## Architecture

- **No new services, ports, or containers.** Sherlock is added as a tool inside `mcp-servers/social-media-enhanced/app.py`.
- Sherlock's blocking scan runs in a `ThreadPoolExecutor` to keep Flask responsive.
- `sherlock-project` pip package is added to `requirements.txt`.
- Tool dispatch follows the existing `POST /execute` pattern.

## Tool Interface

### Request
```json
{
  "tool": "sherlock_username_search",
  "parameters": {
    "username": "john_doe"
  }
}
```

### Response
```json
{
  "username": "john_doe",
  "found_count": 12,
  "accounts": [
    {"site": "GitHub", "url": "https://github.com/john_doe"},
    {"site": "Twitter", "url": "https://twitter.com/john_doe"}
  ],
  "scan_duration_seconds": 42.3,
  "timestamp": "2026-04-15T10:00:00Z"
}
```

### Error Responses
| Condition | Status | Body |
|-----------|--------|------|
| Missing `username` | 400 | `{"error": "username parameter required"}` |
| Sherlock import fails | 500 | `{"error": "sherlock not available"}` |
| Scan exceeds 120s | 504 | `{"error": "scan timed out"}` |

## Implementation Details

### Helper function
```python
from sherlock_project.sherlock import sherlock
from sherlock_project.sites import SitesInformation
from sherlock_project.result import QueryStatus

def run_sherlock(username: str) -> list[dict]:
    sites = SitesInformation()
    results = sherlock(username, sites, ...)
    return [
        {"site": name, "url": data["url_user"]}
        for name, data in results.items()
        if data["status"].status == QueryStatus.CLAIMED
    ]
```

### Thread execution
```python
from concurrent.futures import ThreadPoolExecutor, TimeoutError

executor = ThreadPoolExecutor(max_workers=4)

# Inside /execute handler:
future = executor.submit(run_sherlock, username)
accounts = future.result(timeout=120)
```

### Dependency
```
sherlock-project>=0.14.0
```

## Files Changed
- `mcp-servers/social-media-enhanced/app.py` — add `run_sherlock()` helper, `ThreadPoolExecutor`, and tool dispatch branch
- `mcp-servers/social-media-enhanced/requirements.txt` — add `sherlock-project>=0.14.0`

## Out of Scope
- Caching (always fresh scan)
- Username variant enumeration (future work)
- Graph intelligence integration (future work)
- New MCP server / new port
