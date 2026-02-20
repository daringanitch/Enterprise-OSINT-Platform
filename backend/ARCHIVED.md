# ⚠️ ARCHIVED — Do Not Use

This directory (`backend/`) is an **archived, early-stage implementation** of the OSINT Platform backend.
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

This directory contains an earlier Flask prototype that pre-dates the current architecture.
It lacks the full investigation workflow, MCP server integration, graph intelligence module,
compliance framework, and the test coverage now present in `simple-backend/`.

## What To Do

- **New features** → `simple-backend/`
- **Bug fixes** → `simple-backend/`
- **Reference only** → you are here

Do **not** add this directory to any Docker build, Kubernetes manifest, or CI pipeline.
