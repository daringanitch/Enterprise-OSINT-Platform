# Scripts Directory

Organized scripts for the Enterprise OSINT Platform.

## Directory Structure

```
scripts/
├── deploy/       # Deployment and build scripts
├── dev/          # Development and testing scripts
├── maintenance/  # Database and system maintenance
└── legacy/       # Deprecated scripts (kept for reference)
```

## deploy/

Scripts for building and deploying the platform.

| Script | Purpose |
|--------|---------|
| `build-images.sh` | Build Docker images for all services |
| `build-enhanced-mcp.sh` | Build enhanced MCP server images |
| `deploy-demo-production-mode.sh` | Full Kubernetes deployment |
| `ensure-port-forwards.sh` | Set up kubectl port forwarding |
| `ensure-all-ports.sh` | Verify all port forwards are active |
| `setup-local-dns.sh` | Configure local DNS for development |
| `update-frontend.sh` | Rebuild and deploy frontend |

## dev/

Scripts for development and testing.

| Script | Purpose |
|--------|---------|
| `test-endpoints.sh` | Test all API endpoints |
| `test-auth-endpoints.py` | Test authentication flows |
| `test-auth-simple.sh` | Simple auth verification |
| `test-enhanced-intelligence.py` | Test MCP intelligence gathering |
| `test_debug.sh` | Debug helper script |

## maintenance/

Scripts for system maintenance and troubleshooting.

| Script | Purpose |
|--------|---------|
| `validate-config.py` | Validate platform configuration |
| `fix-database-schema.py` | Repair database schema issues |
| `fix-hardcoded-values.py` | Update hardcoded configuration |
| `process-stuck-investigations.py` | Clear stuck investigations |
| `sync-memory-database.py` | Sync in-memory and persistent data |

## legacy/

Deprecated scripts kept for historical reference. **Do not use in production.**

## Usage

Most users should use the main `start.sh` script in the root directory:

```bash
# From repository root
./start.sh demo    # Start demo mode
./start.sh local   # Start local development
./start.sh k8s     # Deploy to Kubernetes
```

For advanced operations, run scripts from this directory:

```bash
# Build all Docker images
./scripts/deploy/build-images.sh

# Test API endpoints
./scripts/dev/test-endpoints.sh

# Validate configuration
python scripts/maintenance/validate-config.py
```
