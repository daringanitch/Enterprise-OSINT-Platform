# ⚠️ ARCHIVED — Do Not Use

This directory (`fastapi-backend/`) is an **archived FastAPI rewrite** of the OSINT Platform backend.
It is kept for historical reference only and is **not maintained**.

## Canonical Backend

All active development happens in:

```
Enterprise-OSINT-Platform/simple-backend/
```

`simple-backend/` is a Flask REST API with:
- JWT authentication
- PostgreSQL + Redis integration
- 220+ automated tests
- Blueprint-based modular routing
- Startup security validation

## Why This Was Archived

This directory contains an experimental FastAPI port that explored async-first architecture
(Alembic migrations, Celery task queue, Gunicorn/uvicorn deployment). While technically
interesting, the port was not completed and is missing key platform features:

- Investigation orchestration (7-stage workflow)
- MCP server client integration
- Graph intelligence module
- Compliance framework (GDPR/CCPA)
- Demo mode and demo data provider
- Full test suite

The Dockerfiles, Alembic migrations, and performance monitor here are **not used** by
any active CI pipeline or Kubernetes manifest.

## What To Do

- **New features** → `simple-backend/`
- **Bug fixes** → `simple-backend/`
- **Reference only** → you are here

Do **not** add this directory to any Docker build, Kubernetes manifest, or CI pipeline.
If you need async capabilities, add them inside `simple-backend/` rather than resurrecting this port.
