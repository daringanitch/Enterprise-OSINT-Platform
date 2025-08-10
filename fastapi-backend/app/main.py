"""
FastAPI main application with async support
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
import structlog
import time
from typing import Any

from app.core.config import settings
from app.api.v1.api import api_router
from app.db.session import engine
from app.db.base import Base
from app.core.logging import setup_logging
from app.utils.exceptions import setup_exception_handlers
from app.core.metrics import metrics_middleware, metrics_endpoint

# Setup structured logging
setup_logging()
logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle"""
    # Startup
    logger.info("Starting Enterprise OSINT Platform", version=settings.VERSION)
    
    # Create database tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # Initialize services
    # await init_redis()
    # await init_celery()
    
    yield
    
    # Shutdown
    logger.info("Shutting down Enterprise OSINT Platform")
    await engine.dispose()


# Create FastAPI app
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=f"{settings.API_V1_STR}/redoc",
    lifespan=lifespan
)

# Setup middlewares
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(GZipMiddleware, minimum_size=1000)

if not settings.DEBUG:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["*"]  # Configure appropriately for production
    )

# Add metrics middleware
app.middleware("http")(metrics_middleware)

# Add request ID and logging middleware
@app.middleware("http")
async def add_request_id(request: Request, call_next):
    """Add request ID to all requests"""
    request_id = request.headers.get("X-Request-ID", str(time.time()))
    
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    
    logger.info(
        "Request completed",
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        process_time=round(process_time, 3),
        request_id=request_id
    )
    
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time"] = str(process_time)
    return response

# Setup exception handlers
setup_exception_handlers(app)

# Include API router
app.include_router(api_router, prefix=settings.API_V1_STR)

# Setup Prometheus metrics endpoint
app.add_route("/metrics", metrics_endpoint, methods=["GET"])

# Health check endpoints
@app.get("/health")
async def health() -> dict[str, Any]:
    """Basic health check"""
    return {
        "status": "healthy",
        "version": settings.VERSION,
        "timestamp": time.time()
    }


@app.get("/health/ready")
async def health_ready() -> dict[str, Any]:
    """Readiness probe - check essential dependencies"""
    checks = {
        "database": False,
        "mcp_servers": False
    }
    
    # Check database
    try:
        from sqlalchemy import text
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
            checks["database"] = True
    except Exception as e:
        logger.error("Database health check failed", error=str(e))
    
    # Check MCP servers (at least one should be healthy)
    try:
        from app.services.mcp_client import MCPClient
        async with MCPClient() as mcp_client:
            server_status = await mcp_client.get_all_servers_status()
            healthy_servers = sum(1 for s in server_status.values() if s.get("healthy", False))
            checks["mcp_servers"] = healthy_servers > 0
    except Exception as e:
        logger.error("MCP health check failed", error=str(e))
    
    # For demo purposes, we only require database to be ready
    # MCP servers are nice-to-have but not blocking
    essential_ready = checks["database"]
    all_healthy = all(checks.values())
    
    return JSONResponse(
        status_code=200 if essential_ready else 503,
        content={
            "status": "ready" if essential_ready else "not ready",
            "checks": checks,
            "all_services_healthy": all_healthy,
            "timestamp": time.time()
        }
    )


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Enterprise OSINT Platform API",
        "version": settings.VERSION,
        "docs": f"{settings.API_V1_STR}/docs"
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        workers=1 if settings.DEBUG else settings.WORKERS,
        log_config=None,  # Use structlog
        access_log=False,  # Handled by middleware
    )