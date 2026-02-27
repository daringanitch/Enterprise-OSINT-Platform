#!/bin/bash
# ============================================================================
# Enterprise OSINT Platform - One-Command Setup
# ============================================================================
# Usage:
#   ./start.sh              # Interactive mode - choose deployment type
#   ./start.sh demo         # Docker Compose demo (no API keys needed)
#   ./start.sh local        # Docker Compose with optional API keys
#   ./start.sh k8s          # Kubernetes deployment
#   ./start.sh stop         # Stop all running services
#   ./start.sh restart      # Restart currently active services
#   ./start.sh status       # Check service status
#   ./start.sh logs [svc]   # View logs (optional: backend|worker|frontend)
#   ./start.sh help         # Show this help
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# Compose files
COMPOSE_FILE="docker-compose.yml"
DEMO_COMPOSE_FILE="docker-compose.demo.yml"
K8S_NAMESPACE="osint-platform"
MODE_FILE=".osint-mode"          # tracks last-started mode (demo|local)

# ── helpers ─────────────────────────────────────────────────────────────────
print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║        Enterprise OSINT Platform - Quick Start               ║"
    echo "║        Open Source Intelligence Investigation System         ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; }

# Return the compose file for whatever mode is currently running,
# or the local compose file as a default.
active_compose() {
    if [ -f "$MODE_FILE" ]; then
        local saved_mode
        saved_mode=$(cat "$MODE_FILE")
        case "$saved_mode" in
            demo)  echo "$DEMO_COMPOSE_FILE" ;;
            local) echo "$COMPOSE_FILE" ;;
            *)     echo "$COMPOSE_FILE" ;;
        esac
    else
        echo "$COMPOSE_FILE"
    fi
}

# ── prerequisites ────────────────────────────────────────────────────────────
check_prerequisites() {
    info "Checking prerequisites..."

    local missing=()

    if ! command -v docker &> /dev/null; then
        missing+=("docker")
    else
        if ! docker info &> /dev/null; then
            error "Docker is installed but not running. Please start Docker Desktop."
            exit 1
        fi
    fi

    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null 2>&1; then
        missing+=("docker-compose")
    fi

    if [ ${#missing[@]} -ne 0 ]; then
        error "Missing required tools: ${missing[*]}"
        echo ""
        echo "Please install the missing tools:"
        echo "  Docker:         https://docs.docker.com/get-docker/"
        echo "  Docker Compose: https://docs.docker.com/compose/install/"
        exit 1
    fi

    success "All prerequisites met"
}

check_k8s_prerequisites() {
    info "Checking Kubernetes prerequisites..."

    if ! command -v kubectl &> /dev/null; then
        error "kubectl not found. Please install kubectl first."
        echo "  Install: https://kubernetes.io/docs/tasks/tools/"
        exit 1
    fi

    if ! kubectl cluster-info &> /dev/null 2>&1; then
        error "Cannot connect to Kubernetes cluster."
        echo "  Options:"
        echo "    - Docker Desktop with Kubernetes enabled"
        echo "    - Minikube: minikube start"
        echo "    - Kind: kind create cluster"
        exit 1
    fi

    success "Kubernetes prerequisites met"
}

# ── stop any currently running stacks ───────────────────────────────────────
stop_existing() {
    # Stop demo stack if running
    if docker compose -f "$DEMO_COMPOSE_FILE" ps 2>/dev/null | grep -q "Up\|running"; then
        info "Stopping existing demo stack..."
        docker compose -f "$DEMO_COMPOSE_FILE" down --remove-orphans 2>/dev/null || true
    fi
    # Stop local stack if running
    if docker compose -f "$COMPOSE_FILE" ps 2>/dev/null | grep -q "Up\|running"; then
        info "Stopping existing local stack..."
        docker compose -f "$COMPOSE_FILE" down --remove-orphans 2>/dev/null || true
    fi
    # Ensure no leftover named containers from either stack remain
    for c in osint-backend osint-frontend osint-worker osint-postgresql osint-redis osint-vault; do
        if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${c}$"; then
            docker rm -f "$c" 2>/dev/null || true
        fi
    done
}

# ── demo mode ────────────────────────────────────────────────────────────────
start_demo() {
    info "Starting Enterprise OSINT Platform in DEMO mode..."
    echo ""
    echo -e "${YELLOW}Demo mode:${NC}"
    echo "  • No external API keys required"
    echo "  • Pre-loaded sample investigations"
    echo "  • Synthetic threat intelligence data"
    echo "  • Full UI and reporting functionality"
    echo ""

    if [ ! -f "$DEMO_COMPOSE_FILE" ]; then
        error "Demo compose file not found: $DEMO_COMPOSE_FILE"
        exit 1
    fi

    stop_existing

    docker compose -f "$DEMO_COMPOSE_FILE" up -d --build --remove-orphans

    echo "demo" > "$MODE_FILE"
    wait_for_services "demo"
    print_access_info "demo"
}

# ── local development mode ───────────────────────────────────────────────────
start_local() {
    info "Starting Enterprise OSINT Platform in LOCAL mode..."
    echo ""

    if [ -f ".env" ]; then
        info "Found .env file - API keys will be loaded"
    else
        warning "No .env file found. Running without external API integrations."
        echo ""
        echo "  To enable external APIs create a .env file with:"
        echo "    OPENAI_API_KEY=your-key"
        echo "    VIRUSTOTAL_API_KEY=your-key"
        echo "    SHODAN_API_KEY=your-key"
        echo ""
    fi

    stop_existing

    docker compose -f "$COMPOSE_FILE" up -d --build --remove-orphans

    echo "local" > "$MODE_FILE"
    wait_for_services "local"
    print_access_info "local"
}

# ── kubernetes mode ──────────────────────────────────────────────────────────
start_k8s() {
    check_k8s_prerequisites

    info "Starting Enterprise OSINT Platform on Kubernetes..."
    echo ""

    kubectl create namespace "$K8S_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

    info "Deploying core services..."
    kubectl apply -f k8s/mode-config-configmap.yaml -n "$K8S_NAMESPACE" 2>/dev/null || true
    kubectl apply -f k8s/postgresql-deployment.yaml  -n "$K8S_NAMESPACE"
    kubectl apply -f k8s/simple-backend-deployment.yaml  -n "$K8S_NAMESPACE"
    kubectl apply -f k8s/simple-frontend-deployment.yaml -n "$K8S_NAMESPACE"

    info "Waiting for pods to be ready..."
    kubectl wait --for=condition=ready pod -l app=osint-backend  -n "$K8S_NAMESPACE" --timeout=120s || true
    kubectl wait --for=condition=ready pod -l app=osint-frontend -n "$K8S_NAMESPACE" --timeout=60s  || true

    info "Setting up port forwarding..."
    kubectl port-forward -n "$K8S_NAMESPACE" svc/osint-simple-frontend 8080:80   &>/dev/null &
    kubectl port-forward -n "$K8S_NAMESPACE" svc/osint-backend         5001:5001 &>/dev/null &

    sleep 3
    print_access_info "k8s"
}

# ── wait for services ────────────────────────────────────────────────────────
wait_for_services() {
    local mode=${1:-local}
    info "Waiting for services to be ready..."

    local max_attempts=40
    local attempt=1
    local backend_ready=false

    while [ $attempt -le $max_attempts ]; do
        if curl -sf http://localhost:5001/health > /dev/null 2>&1; then
            backend_ready=true
            break
        fi
        echo -n "."
        sleep 3
        ((attempt++))
    done
    echo ""

    if $backend_ready; then
        success "Backend is ready"
    else
        warning "Backend health check timed out. Check logs: ./start.sh logs backend"
    fi

    # Check worker (local mode only — demo mode has no worker service)
    if [ "$mode" = "local" ]; then
        local worker_up=false
        if docker compose -f "$COMPOSE_FILE" ps worker 2>/dev/null | grep -q "Up\|running"; then
            worker_up=true
        fi
        if $worker_up; then
            success "Worker is running"
        else
            warning "Worker container not yet running — check: ./start.sh logs worker"
        fi
    fi
}

# ── print access info ────────────────────────────────────────────────────────
print_access_info() {
    local mode=$1

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              Platform is Ready!                              ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BOLD}Access the platform:${NC}"
    echo -e "  Frontend:  ${CYAN}http://localhost:8080${NC}"
    echo -e "  API:       ${CYAN}http://localhost:5001${NC}"
    echo -e "  Health:    ${CYAN}http://localhost:5001/health${NC}"
    echo ""
    echo -e "${BOLD}Default credentials:${NC}"
    echo -e "  Username:  ${YELLOW}admin${NC}"
    echo -e "  Password:  ${YELLOW}admin123${NC}"
    echo ""

    case "$mode" in
        demo)
            echo -e "${BOLD}Demo mode:${NC}"
            echo "  • 5 pre-loaded sample investigations (no real OSINT data)"
            echo "  • Simulated threat intelligence"
            echo "  • No external API costs"
            echo ""
            ;;
        local)
            echo -e "${BOLD}Local mode services:${NC}"
            echo "  • Backend  (gunicorn, 1 worker + 4 threads)"
            echo "  • Worker   (RQ background job processor)"
            echo "  • Redis    (job queue + caching)"
            echo "  • Postgres (audit + investigation storage)"
            echo "  • Vault    (secrets management)"
            echo ""
            ;;
    esac

    echo -e "${BOLD}Quick commands:${NC}"
    echo "  ./start.sh status         - Check all service health"
    echo "  ./start.sh logs           - Stream all logs"
    echo "  ./start.sh logs backend   - Stream backend logs only"
    echo "  ./start.sh logs worker    - Stream worker logs only"
    echo "  ./start.sh restart        - Restart current stack"
    echo "  ./start.sh stop           - Stop everything"
    echo ""
}

# ── stop ─────────────────────────────────────────────────────────────────────
stop_services() {
    info "Stopping Enterprise OSINT Platform..."

    # Stop both compose stacks (safe to call even if not running)
    if [ -f "$DEMO_COMPOSE_FILE" ]; then
        docker compose -f "$DEMO_COMPOSE_FILE" down --remove-orphans 2>/dev/null || true
    fi
    docker compose -f "$COMPOSE_FILE" down --remove-orphans 2>/dev/null || true

    # Stop any K8s port forwards
    pkill -f "kubectl port-forward.*osint" 2>/dev/null || true

    # Remove mode tracking file
    rm -f "$MODE_FILE"

    success "All services stopped"
}

# ── restart ───────────────────────────────────────────────────────────────────
restart_services() {
    if [ ! -f "$MODE_FILE" ]; then
        error "No active mode found. Run './start.sh demo' or './start.sh local' first."
        exit 1
    fi

    local current_mode
    current_mode=$(cat "$MODE_FILE")
    info "Restarting in ${current_mode} mode..."

    case "$current_mode" in
        demo)  start_demo  ;;
        local) start_local ;;
        *)
            error "Unknown mode '$current_mode' in $MODE_FILE"
            exit 1
            ;;
    esac
}

# ── status ────────────────────────────────────────────────────────────────────
check_status() {
    echo ""
    echo -e "${BOLD}═══════════════════════════ Service Status ═══════════════════════════${NC}"

    local found_compose=false

    # Demo stack
    if [ -f "$DEMO_COMPOSE_FILE" ] && docker compose -f "$DEMO_COMPOSE_FILE" ps 2>/dev/null | grep -q "osint"; then
        echo ""
        echo -e "${CYAN}Docker Compose (demo mode):${NC}"
        docker compose -f "$DEMO_COMPOSE_FILE" ps
        found_compose=true
    fi

    # Local stack
    if docker compose -f "$COMPOSE_FILE" ps 2>/dev/null | grep -q "osint"; then
        echo ""
        echo -e "${CYAN}Docker Compose (local mode):${NC}"
        docker compose -f "$COMPOSE_FILE" ps
        found_compose=true
    fi

    if ! $found_compose; then
        warning "No Docker Compose services are currently running."
    fi

    # Kubernetes
    if kubectl get namespace "$K8S_NAMESPACE" &>/dev/null 2>&1; then
        echo ""
        echo -e "${CYAN}Kubernetes ($K8S_NAMESPACE):${NC}"
        kubectl get pods -n "$K8S_NAMESPACE"
    fi

    # Endpoint health
    echo ""
    echo -e "${CYAN}Endpoint Health:${NC}"
    if curl -sf http://localhost:5001/health > /dev/null 2>&1; then
        echo -e "  Backend:  ${GREEN}● HEALTHY${NC}  http://localhost:5001"
    else
        echo -e "  Backend:  ${RED}○ UNAVAILABLE${NC}"
    fi

    if curl -sf http://localhost:8080 > /dev/null 2>&1; then
        echo -e "  Frontend: ${GREEN}● HEALTHY${NC}  http://localhost:8080"
    else
        echo -e "  Frontend: ${RED}○ UNAVAILABLE${NC}"
    fi

    # Worker (local mode only)
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^osint-worker$"; then
        local worker_status
        worker_status=$(docker inspect --format='{{.State.Status}}' osint-worker 2>/dev/null || echo "unknown")
        if [ "$worker_status" = "running" ]; then
            echo -e "  Worker:   ${GREEN}● RUNNING${NC}   (RQ job processor)"
        else
            echo -e "  Worker:   ${YELLOW}⚠ ${worker_status^^}${NC}"
        fi
    fi

    echo ""
}

# ── logs ──────────────────────────────────────────────────────────────────────
view_logs() {
    local service="${2:-}"
    local compose_file
    compose_file=$(active_compose)

    if docker compose -f "$compose_file" ps 2>/dev/null | grep -q "osint"; then
        if [ -n "$service" ]; then
            docker compose -f "$compose_file" logs -f --tail=100 "$service"
        else
            docker compose -f "$compose_file" logs -f --tail=50
        fi
    elif kubectl get namespace "$K8S_NAMESPACE" &>/dev/null 2>&1; then
        local k8s_label="${service:-osint-backend}"
        kubectl logs -f -l "app=${k8s_label}" -n "$K8S_NAMESPACE"
    else
        error "No running services found. Start the platform first."
        exit 1
    fi
}

# ── interactive ───────────────────────────────────────────────────────────────
interactive_mode() {
    print_banner

    echo -e "${BOLD}Choose deployment mode:${NC}"
    echo ""
    echo "  1) ${GREEN}Demo Mode${NC}  — recommended for first-time users"
    echo "     No API keys needed · pre-loaded investigations · Docker Compose"
    echo ""
    echo "  2) ${BLUE}Local Dev${NC}  — full platform with optional API keys"
    echo "     Real OSINT data (if keys provided) · includes background worker"
    echo ""
    echo "  3) ${CYAN}Kubernetes${NC} — production-like deployment"
    echo "     Requires a running K8s cluster"
    echo ""

    read -rp "Enter choice [1-3]: " choice

    case $choice in
        1) start_demo  ;;
        2) start_local ;;
        3) start_k8s   ;;
        *) error "Invalid choice"; exit 1 ;;
    esac
}

# ── main ──────────────────────────────────────────────────────────────────────
main() {
    # Always run from the directory containing this script
    cd "$(dirname "$0")"

    case "${1:-}" in
        demo)
            print_banner
            check_prerequisites
            start_demo
            ;;
        local)
            print_banner
            check_prerequisites
            start_local
            ;;
        k8s|kubernetes)
            print_banner
            start_k8s
            ;;
        stop)
            stop_services
            ;;
        restart)
            print_banner
            check_prerequisites
            restart_services
            ;;
        status)
            check_status
            ;;
        logs)
            view_logs "$@"
            ;;
        help|--help|-h)
            print_banner
            echo -e "${BOLD}Usage:${NC} ./start.sh [command] [service]"
            echo ""
            echo -e "${BOLD}Commands:${NC}"
            echo "  (none)    Interactive mode — choose demo/local/k8s"
            echo "  demo      Start in demo mode (no API keys required)"
            echo "  local     Start local dev stack (optional .env API keys)"
            echo "  k8s       Deploy to Kubernetes"
            echo "  restart   Restart the currently running stack"
            echo "  stop      Stop all running services"
            echo "  status    Show health of all services"
            echo "  logs      Stream all logs"
            echo "  logs backend  Stream backend logs only"
            echo "  logs worker   Stream worker logs only"
            echo "  logs frontend Stream frontend logs only"
            echo "  help      Show this message"
            echo ""
            echo -e "${BOLD}Examples:${NC}"
            echo "  ./start.sh demo           # Quick demo with sample data"
            echo "  ./start.sh local          # Local dev with .env keys"
            echo "  ./start.sh logs worker    # Watch RQ worker output"
            echo "  ./start.sh restart        # Rebuild + restart current mode"
            echo "  ./start.sh stop           # Tear everything down"
            ;;
        "")
            check_prerequisites
            interactive_mode
            ;;
        *)
            error "Unknown command: $1"
            echo "Run './start.sh help' for usage information"
            exit 1
            ;;
    esac
}

main "$@"
