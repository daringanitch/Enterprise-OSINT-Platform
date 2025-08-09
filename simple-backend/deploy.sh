#!/bin/bash

# Enterprise OSINT Platform Deployment Script
# Deploys Flask+React application with all features

set -e

echo "🚀 Enterprise OSINT Platform Deployment"
echo "========================================"

# Configuration
IMAGE_NAME="enterprise-osint-flask"
IMAGE_TAG="latest"
CONTAINER_NAME="osint-backend"
FRONTEND_CONTAINER="osint-frontend"
PORT="5000"
FRONTEND_PORT="8080"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        error "Docker is not running. Please start Docker daemon."
        exit 1
    fi
    
    log "Prerequisites check completed ✓"
}

# Stop existing containers
stop_existing() {
    log "Stopping existing containers..."
    
    if docker ps -q --filter "name=$CONTAINER_NAME" | grep -q .; then
        info "Stopping backend container: $CONTAINER_NAME"
        docker stop $CONTAINER_NAME
        docker rm $CONTAINER_NAME
    fi
    
    if docker ps -q --filter "name=$FRONTEND_CONTAINER" | grep -q .; then
        info "Stopping frontend container: $FRONTEND_CONTAINER"
        docker stop $FRONTEND_CONTAINER
        docker rm $FRONTEND_CONTAINER
    fi
    
    log "Existing containers stopped ✓"
}

# Build backend image
build_backend() {
    log "Building backend Docker image..."
    
    if ! docker build -t $IMAGE_NAME:$IMAGE_TAG .; then
        error "Failed to build backend Docker image"
        exit 1
    fi
    
    log "Backend image built successfully ✓"
}

# Build frontend
build_frontend() {
    log "Building frontend..."
    
    cd ../simple-frontend
    
    # Create simple Dockerfile for frontend if it doesn't exist
    if [ ! -f "Dockerfile" ]; then
        info "Creating frontend Dockerfile..."
        cat > Dockerfile << EOF
FROM nginx:alpine

# Copy static files
COPY index.html /usr/share/nginx/html/
COPY style.css /usr/share/nginx/html/
COPY script.js /usr/share/nginx/html/

# Copy nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
EOF
    fi
    
    # Create nginx configuration
    if [ ! -f "nginx.conf" ]; then
        info "Creating nginx configuration..."
        cat > nginx.conf << EOF
server {
    listen 80;
    server_name localhost;
    root /usr/share/nginx/html;
    index index.html;

    # Serve static files
    location / {
        try_files \$uri \$uri/ /index.html;
    }

    # Proxy API requests to backend
    location /api/ {
        proxy_pass http://host.docker.internal:5000/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # CORS headers
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS' always;
        add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization' always;
        
        if (\$request_method = 'OPTIONS') {
            add_header 'Access-Control-Allow-Origin' '*';
            add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS';
            add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization';
            add_header 'Access-Control-Max-Age' 1728000;
            add_header 'Content-Type' 'text/plain; charset=utf-8';
            add_header 'Content-Length' 0;
            return 204;
        }
    }
}
EOF
    fi
    
    # Build frontend image
    if ! docker build -t osint-frontend:latest .; then
        error "Failed to build frontend Docker image"
        cd ../simple-backend
        exit 1
    fi
    
    cd ../simple-backend
    log "Frontend image built successfully ✓"
}

# Create network
create_network() {
    log "Creating Docker network..."
    
    if ! docker network ls | grep -q "osint-network"; then
        docker network create osint-network
        info "Created network: osint-network"
    else
        info "Network osint-network already exists"
    fi
    
    log "Network setup completed ✓"
}

# Deploy backend
deploy_backend() {
    log "Deploying backend container..."
    
    docker run -d \
        --name $CONTAINER_NAME \
        --network osint-network \
        -p $PORT:5000 \
        -e FLASK_ENV=production \
        -e OPENAI_API_KEY="${OPENAI_API_KEY:-}" \
        -e REDIS_URL="${REDIS_URL:-redis://localhost:6379}" \
        --restart unless-stopped \
        $IMAGE_NAME:$IMAGE_TAG
    
    log "Backend container deployed ✓"
}

# Deploy frontend
deploy_frontend() {
    log "Deploying frontend container..."
    
    docker run -d \
        --name $FRONTEND_CONTAINER \
        --network osint-network \
        -p $FRONTEND_PORT:80 \
        --restart unless-stopped \
        osint-frontend:latest
    
    log "Frontend container deployed ✓"
}

# Health check
health_check() {
    log "Performing health checks..."
    
    info "Waiting for backend to be ready..."
    sleep 10
    
    for i in {1..30}; do
        if curl -f http://localhost:$PORT/health &> /dev/null; then
            log "Backend health check passed ✓"
            break
        fi
        
        if [ $i -eq 30 ]; then
            error "Backend health check failed after 30 attempts"
            show_logs
            exit 1
        fi
        
        info "Attempt $i/30: Backend not ready yet, waiting..."
        sleep 2
    done
    
    info "Checking frontend..."
    if curl -f http://localhost:$FRONTEND_PORT &> /dev/null; then
        log "Frontend health check passed ✓"
    else
        warn "Frontend health check failed, but continuing..."
    fi
}

# Show logs
show_logs() {
    echo
    info "Recent backend logs:"
    docker logs --tail 20 $CONTAINER_NAME || true
    
    echo
    info "Recent frontend logs:"
    docker logs --tail 20 $FRONTEND_CONTAINER || true
}

# Show deployment info
show_deployment_info() {
    echo
    log "🎉 Deployment completed successfully!"
    echo
    echo "📱 Application URLs:"
    echo "   Frontend: http://localhost:$FRONTEND_PORT"
    echo "   Backend API: http://localhost:$PORT"
    echo "   API Documentation: http://localhost:$PORT/health"
    echo
    echo "🔧 Management Commands:"
    echo "   View backend logs:  docker logs -f $CONTAINER_NAME"
    echo "   View frontend logs: docker logs -f $FRONTEND_CONTAINER"
    echo "   Stop backend:       docker stop $CONTAINER_NAME"
    echo "   Stop frontend:      docker stop $FRONTEND_CONTAINER"
    echo "   Restart backend:    docker restart $CONTAINER_NAME"
    echo "   Restart frontend:   docker restart $FRONTEND_CONTAINER"
    echo
    echo "🚀 Enterprise OSINT Features:"
    echo "   ✓ Real-time world clocks (LA, NY, London, Tokyo)"
    echo "   ✓ 7-stage OSINT investigation workflow"
    echo "   ✓ MCP client intelligence gathering"
    echo "   ✓ GDPR/CCPA compliance framework"
    echo "   ✓ Investigation activity reporting"
    echo "   ✓ PDF report generation"
    echo "   ✓ Multi-format export (JSON, CSV, HTML)"
    echo "   ✓ Docker containerization"
    echo
    echo "🔐 Environment Variables:"
    echo "   OPENAI_API_KEY: ${OPENAI_API_KEY:+Set}${OPENAI_API_KEY:-Not set}"
    echo "   REDIS_URL: ${REDIS_URL:-Default (redis://localhost:6379)}"
    echo
}

# Cleanup function
cleanup() {
    if [ $? -ne 0 ]; then
        error "Deployment failed. Cleaning up..."
        docker stop $CONTAINER_NAME $FRONTEND_CONTAINER 2>/dev/null || true
        docker rm $CONTAINER_NAME $FRONTEND_CONTAINER 2>/dev/null || true
    fi
}

# Main execution
main() {
    trap cleanup EXIT
    
    echo
    info "Starting Enterprise OSINT Platform deployment..."
    echo
    
    check_prerequisites
    stop_existing
    create_network
    build_backend
    build_frontend
    deploy_backend
    deploy_frontend
    health_check
    show_deployment_info
    
    log "Deployment completed successfully! 🚀"
}

# Handle command line arguments
case "${1:-deploy}" in
    "deploy")
        main
        ;;
    "stop")
        log "Stopping all containers..."
        docker stop $CONTAINER_NAME $FRONTEND_CONTAINER 2>/dev/null || true
        docker rm $CONTAINER_NAME $FRONTEND_CONTAINER 2>/dev/null || true
        log "Containers stopped ✓"
        ;;
    "logs")
        show_logs
        ;;
    "status")
        echo
        info "Container Status:"
        docker ps --filter "name=$CONTAINER_NAME" --filter "name=$FRONTEND_CONTAINER"
        echo
        info "Health Status:"
        curl -f http://localhost:$PORT/health 2>/dev/null && echo "Backend: Healthy" || echo "Backend: Unhealthy"
        curl -f http://localhost:$FRONTEND_PORT 2>/dev/null && echo "Frontend: Healthy" || echo "Frontend: Unhealthy"
        ;;
    "restart")
        log "Restarting containers..."
        docker restart $CONTAINER_NAME $FRONTEND_CONTAINER
        log "Containers restarted ✓"
        ;;
    *)
        echo "Usage: $0 {deploy|stop|logs|status|restart}"
        echo
        echo "Commands:"
        echo "  deploy   - Deploy the full application (default)"
        echo "  stop     - Stop and remove all containers"
        echo "  logs     - Show recent logs from all containers"
        echo "  status   - Show container and health status"
        echo "  restart  - Restart all containers"
        exit 1
        ;;
esac