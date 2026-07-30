"""
Tests for the social intelligence blueprint (POST /api/social/username-search).

The endpoint proxies the social-media-enhanced MCP `sherlock_username_search`
tool, so the MCP call itself (`_call_sherlock`) is mocked here.
"""

from unittest.mock import AsyncMock, patch

ENDPOINT = "/api/social/username-search"


class TestUsernameSearch:
    def test_requires_auth(self, client):
        """Unauthenticated requests are rejected."""
        response = client.post(ENDPOINT, json={"username": "john_doe"})
        assert response.status_code == 401

    def test_missing_username_returns_400(self, client, auth_headers):
        """A body without a username is a client error."""
        response = client.post(ENDPOINT, json={}, headers=auth_headers)
        assert response.status_code == 400
        assert "error" in response.get_json()

    def test_blank_username_returns_400(self, client, auth_headers):
        """A whitespace-only username is treated as empty."""
        response = client.post(ENDPOINT, json={"username": "   "}, headers=auth_headers)
        assert response.status_code == 400

    @patch("blueprints.social._call_sherlock", new_callable=AsyncMock)
    def test_returns_normalized_accounts(self, mock_call, client, auth_headers):
        """Successful scans are normalized to {username, count, accounts, duration}."""
        mock_call.return_value = {
            "username": "john_doe",
            "found_count": 2,
            "accounts": [
                {"site": "GitHub", "url": "https://github.com/john_doe"},
                {"site": "Reddit", "url": "https://reddit.com/user/john_doe"},
            ],
            "scan_duration_seconds": 12.3,
        }

        response = client.post(ENDPOINT, json={"username": "  john_doe  "}, headers=auth_headers)

        assert response.status_code == 200
        data = response.get_json()
        assert data["username"] == "john_doe"
        assert data["count"] == 2
        assert len(data["accounts"]) == 2
        assert data["accounts"][0]["site"] == "GitHub"
        assert data["scan_duration_seconds"] == 12.3
        # username is trimmed before being passed to the MCP
        mock_call.assert_awaited_once_with("john_doe")

    @patch("blueprints.social._call_sherlock", new_callable=AsyncMock)
    def test_count_falls_back_to_len_accounts(self, mock_call, client, auth_headers):
        """If the MCP omits found_count, count is derived from accounts."""
        mock_call.return_value = {
            "accounts": [{"site": "GitHub", "url": "https://github.com/x"}],
        }
        response = client.post(ENDPOINT, json={"username": "x"}, headers=auth_headers)
        assert response.status_code == 200
        assert response.get_json()["count"] == 1

    @patch("blueprints.social._call_sherlock", new_callable=AsyncMock)
    def test_mcp_error_returns_502(self, mock_call, client, auth_headers):
        """MCP/network failures surface as a 502 with an error message."""
        mock_call.side_effect = RuntimeError("sherlock not available")
        response = client.post(ENDPOINT, json={"username": "x"}, headers=auth_headers)
        assert response.status_code == 502
        assert "error" in response.get_json()
