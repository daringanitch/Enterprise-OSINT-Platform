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
#   ./start.sh status       # Check service status
#   ./start.sh logs         # View logs
# ============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Configuration
COMPOSE_FILE="docker-compose.yml"
DEMO_COMPOSE_FILE="docker-compose.demo.yml"
K8S_NAMESPACE="osint-platform"

# Print banner
print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║        Enterprise OSINT Platform - Quick Start               ║"
    echo "║        Open Source Intelligence Investigation System         ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Print status message
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check prerequisites
check_prerequisites() {
    info "Checking prerequisites..."

    local missing=()

    # Check Docker
    if ! command -v docker &> /dev/null; then
        missing+=("docker")
    else
        # Check if Docker daemon is running
        if ! docker info &> /dev/null; then
            error "Docker is installed but not running. Please start Docker Desktop."
            exit 1
        fi
    fi

    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        missing+=("docker-compose")
    fi

    if [ ${#missing[@]} -ne 0 ]; then
        error "Missing required tools: ${missing[*]}"
        echo ""
        echo "Please install the missing tools:"
        echo "  - Docker: https://docs.docker.com/get-docker/"
        echo "  - Docker Compose: https://docs.docker.com/compose/install/"
        exit 1
    fi

    success "All prerequisites met"
}

# Check Kubernetes prerequisites
check_k8s_prerequisites() {
    info "Checking Kubernetes prerequisites..."

    if ! command -v kubectl &> /dev/null; then
        error "kubectl not found. Please install kubectl first."
        echo "  Install: https://kubernetes.io/docs/tasks/tools/"
        exit 1
    fi

    # Check if kubectl can connect to a cluster
    if ! kubectl cluster-info &> /dev/null; then
        error "Cannot connect to Kubernetes cluster."
        echo "  Please ensure you have a running Kubernetes cluster."
        echo "  Options:"
        echo "    - Docker Desktop with Kubernetes enabled"
        echo "    - Minikube: minikube start"
        echo "    - Kind: kind create cluster"
        exit 1
    fi

    success "Kubernetes prerequisites met"
}

# Start demo mode with Docker Compose
start_demo() {
    info "Starting Enterprise OSINT Platform in DEMO mode..."
    echo ""
    echo -e "${YELLOW}Demo mode features:${NC}"
    echo "  - Pre-loaded sample investigations"
    echo "  - No external API keys required"
    echo "  - Synthetic threat intelligence data"
    echo "  - Full UI functionality"
    echo ""

    # Use demo compose file if it exists, otherwise use main with demo env
    if [ -f "$DEMO_COMPOSE_FILE" ]; then
        docker compose -f "$DEMO_COMPOSE_FILE" up -d --build
    else
        PLATFORM_MODE=demo docker compose -f "$COMPOSE_FILE" up -d --build
    fi

    wait_for_services
    print_access_info "demo"
}

# Start local development mode
start_local() {
    info "Starting Enterprise OSINT Platform in LOCAL mode..."
    echo ""

    # Check for .env file
    if [ -f ".env" ]; then
        info "Found .env file - loading API keys"
    else
        warning "No .env file found. Running without external API integrations."
        echo ""
        echo "To enable external APIs, create a .env file with:"
        echo "  OPENAI_API_KEY=your-key"
        echo "  VIRUSTOTAL_API_KEY=your-key"
        echo "  SHODAN_API_KEY=your-key"
        echo ""
    fi

    docker compose -f "$COMPOSE_FILE" up -d --build

    wait_for_services
    print_access_info "local"
}

# Start with Kubernetes
start_k8s() {
    check_k8s_prerequisites

    info "Starting Enterprise OSINT Platform on Kubernetes..."
    echo ""

    # Create namespace
    kubectl create namespace "$K8S_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

    # Apply core manifests
    info "Deploying core services..."
    kubectl apply -f k8s/mode-config-configmap.yaml -n "$K8S_NAMESPACE" 2>/dev/null || true
    kubectl apply -f k8s/postgresql-deployment.yaml -n "$K8S_NAMESPACE"
    kubectl apply -f k8s/simple-backend-deployment.yaml -n "$K8S_NAMESPACE"
    kubectl apply -f k8s/simple-frontend-deployment.yaml -n "$K8S_NAMESPACE"

    # Wait for deployments
    info "Waiting for pods to be ready..."
    kubectl wait --for=condition=ready pod -l app=osint-backend -n "$K8S_NAMESPACE" --timeout=120s || true
    kubectl wait --for=condition=ready pod -l app=osint-frontend -n "$K8S_NAMESPACE" --timeout=60s || true

    # Start port forwarding in background
    info "Setting up port forwarding..."
    kubectl port-forward -n "$K8S_NAMESPACE" svc/osint-simple-frontend 8080:80 &>/dev/null &
    kubectl port-forward -n "$K8S_NAMESPACE" svc/osint-backend 5000:5000 &>/dev/null &

    sleep 3
    print_access_info "k8s"
}

# Wait for services to be healthy
wait_for_services() {
    info "Waiting for services to be ready..."

    local max_attempts=30
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        if curl -s http://localhost:5000/health > /dev/null 2>&1; then
            success "Backend is ready"
            break
        fi
        echo -n "."
        sleep 2
        ((attempt++))
    done

    if [ $attempt -gt $max_attempts ]; then
        warning "Backend may not be fully ready yet. Check logs with: ./start.sh logs"
    fi

    echo ""
}

# Print access information
print_access_info() {
    local mode=$1

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              Platform is Ready!                              ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BOLD}Access the platform:${NC}"
    echo -e "  Frontend:  ${CYAN}http://localhost:8080${NC}"
    echo -e "  API:       ${CYAN}http://localhost:5000${NC}"
    echo -e "  API Docs:  ${CYAN}http://localhost:5000/health${NC}"
    echo ""
    echo -e "${BOLD}Default credentials:${NC}"
    echo -e "  Username:  ${YELLOW}admin${NC}"
    echo -e "  Password:  ${YELLOW}admin123${NC}"
    echo ""

    if [ "$mode" == "demo" ]; then
        echo -e "${BOLD}Demo mode features:${NC}"
        echo "  - 5 pre-loaded sample investigations"
        echo "  - Simulated threat intelligence"
        echo "  - Full report generation"
        echo "  - No external API costs"
        echo ""
    fi

    echo -e "${BOLD}Quick commands:${NC}"
    echo "  ./start.sh status  - Check service status"
    echo "  ./start.sh logs    - View logs"
    echo "  ./start.sh stop    - Stop all services"
    echo ""
}

# Stop all services
stop_services() {
    info "Stopping Enterprise OSINT Platform..."

    # Stop Docker Compose
    if docker compose ps 2>/dev/null | grep -q "osint"; then
        docker compose down
        success "Docker Compose services stopped"
    fi

    # Stop port forwarding for K8s
    pkill -f "kubectl port-forward.*osint" 2>/dev/null || true

    success "All services stopped"
}

# Check status
check_status() {
    echo ""
    echo -e "${BOLD}Service Status:${NC}"
    echo ""

    # Check Docker Compose services
    if docker compose ps 2>/dev/null | grep -q "osint"; then
        echo -e "${CYAN}Docker Compose Services:${NC}"
        docker compose ps
        echo ""
    fi

    # Check Kubernetes
    if kubectl get namespace "$K8S_NAMESPACE" &>/dev/null; then
        echo -e "${CYAN}Kubernetes Pods:${NC}"
        kubectl get pods -n "$K8S_NAMESPACE"
        echo ""
    fi

    # Check connectivity
    echo -e "${CYAN}Service Health:${NC}"
    if curl -s http://localhost:5000/health > /dev/null 2>&1; then
        echo -e "  Backend:  ${GREEN}HEALTHY${NC}"
    else
        echo -e "  Backend:  ${RED}UNAVAILABLE${NC}"
    fi

    if curl -s http://localhost:8080 > /dev/null 2>&1; then
        echo -e "  Frontend: ${GREEN}HEALTHY${NC}"
    else
        echo -e "  Frontend: ${RED}UNAVAILABLE${NC}"
    fi
    echo ""
}

# View logs
view_logs() {
    local service=${2:-""}

    if docker compose ps 2>/dev/null | grep -q "osint"; then
        if [ -n "$service" ]; then
            docker compose logs -f "$service"
        else
            docker compose logs -f
        fi
    elif kubectl get namespace "$K8S_NAMESPACE" &>/dev/null; then
        if [ -n "$service" ]; then
            kubectl logs -f -l app="$service" -n "$K8S_NAMESPACE"
        else
            kubectl logs -f -l app=osint-backend -n "$K8S_NAMESPACE"
        fi
    else
        error "No running services found"
    fi
}

# Interactive mode
interactive_mode() {
    print_banner

    echo -e "${BOLD}Choose deployment mode:${NC}"
    echo ""
    echo "  1) ${GREEN}Demo Mode${NC} (Recommended for first-time users)"
    echo "     - No external API keys required"
    echo "     - Pre-loaded sample investigations"
    echo "     - Uses Docker Compose"
    echo ""
    echo "  2) ${BLUE}Local Development${NC}"
    echo "     - Optional API key integration"
    echo "     - Real external data (if API keys provided)"
    echo "     - Uses Docker Compose"
    echo ""
    echo "  3) ${CYAN}Kubernetes${NC}"
    echo "     - Production-like deployment"
    echo "     - Requires running K8s cluster"
    echo ""

    read -p "Enter choice [1-3]: " choice

    case $choice in
        1) start_demo ;;
        2) start_local ;;
        3) start_k8s ;;
        *) error "Invalid choice"; exit 1 ;;
    esac
}

# Main script
main() {
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
        status)
            check_status
            ;;
        logs)
            view_logs "$@"
            ;;
        help|--help|-h)
            print_banner
            echo "Usage: ./start.sh [command]"
            echo ""
            echo "Commands:"
            echo "  demo      Start in demo mode (no API keys needed)"
            echo "  local     Start with Docker Compose (optional API keys)"
            echo "  k8s       Deploy to Kubernetes"
            echo "  stop      Stop all services"
            echo "  status    Check service status"
            echo "  logs      View service logs"
            echo "  help      Show this help message"
            echo ""
            echo "Examples:"
            echo "  ./start.sh demo     # Quick demo with sample data"
            echo "  ./start.sh local    # Local dev with .env API keys"
            echo "  ./start.sh k8s      # Deploy to Kubernetes"
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
