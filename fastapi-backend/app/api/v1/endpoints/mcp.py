"""
MCP server status and control endpoints
"""
from typing import Dict, Any
from fastapi import APIRouter, HTTPException
import httpx

from app.services.mcp_client import MCPClient
# from app.core.deps import get_current_user  # Not needed for demo

router = APIRouter()


@router.get("/servers/status")
async def get_mcp_servers_status() -> Dict[str, Any]:
    """Get status of all MCP servers"""
    async with MCPClient() as mcp_client:
        try:
            status = await mcp_client.get_all_servers_status()
            return {
                "success": True,
                "servers": status,
                "total_servers": len(status),
                "healthy_servers": sum(1 for s in status.values() if s.get("healthy", False))
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to get MCP status: {str(e)}")


@router.get("/servers/{server_name}/status")
async def get_mcp_server_status(server_name: str) -> Dict[str, Any]:
    """Get status of a specific MCP server"""
    async with MCPClient() as mcp_client:
        if server_name not in mcp_client.MCP_SERVERS:
            raise HTTPException(status_code=404, detail=f"Unknown MCP server: {server_name}")
        
        try:
            info = await mcp_client._get_server_info(server_name)
            return {
                "success": True,
                "server": server_name,
                "info": info
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to get server status: {str(e)}")


@router.post("/execute")
async def execute_mcp_tool(request: Dict[str, Any]) -> Dict[str, Any]:
    """Execute a tool on an MCP server"""
    server_name = request.get("server")
    tool_name = request.get("tool")
    parameters = request.get("parameters", {})
    
    if not server_name or not tool_name:
        raise HTTPException(status_code=400, detail="server and tool are required")
    
    async with MCPClient() as mcp_client:
        result = await mcp_client.call_tool(server_name, tool_name, parameters)
        
        if not result.get("success", True) and "error" in result:
            raise HTTPException(status_code=400, detail=result["error"])
        
        return result


# Demo endpoints (no auth required)
@router.get("/demo/servers/status")
async def get_mcp_servers_status_demo() -> Dict[str, Any]:
    """Get status of all MCP servers (demo - no auth)"""
    return await get_mcp_servers_status()


@router.post("/demo/execute")
async def execute_mcp_tool_demo(request: Dict[str, Any]) -> Dict[str, Any]:
    """Execute a tool on an MCP server (demo - no auth)"""
    return await execute_mcp_tool(request)