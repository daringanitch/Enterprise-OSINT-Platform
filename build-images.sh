#!/bin/bash

# Enterprise OSINT Platform - Docker Image Build Script
# Builds all Docker images with consistent versioning

set -e  # Exit on any error

# Configuration
VERSION="${VERSION:-v1.0.0-auth}"
REGISTRY="${REGISTRY:-osint-platform}"

echo "🔨 Building Enterprise OSINT Platform Docker Images"
echo "📦 Version: $VERSION"
echo "📋 Registry: $REGISTRY"
echo ""

# Function to build and tag image
build_image() {
    local name=$1
    local dockerfile_path=$2
    local context_path=$3
    
    echo "🏗️  Building $name..."
    docker build -f "$dockerfile_path" -t "$REGISTRY/$name:$VERSION" "$context_path"
    echo "✅ Built $REGISTRY/$name:$VERSION"
    echo ""
}

# Build all images
build_image "fastapi-backend" "fastapi-backend/Dockerfile" "fastapi-backend/"
build_image "simple-backend" "simple-backend/Dockerfile" "simple-backend/"
build_image "simple-frontend" "simple-frontend/Dockerfile" "simple-frontend/"
build_image "mcp-infrastructure" "mcp-servers/infrastructure/Dockerfile" "mcp-servers/infrastructure/"
build_image "mcp-social-media" "mcp-servers/social-media/Dockerfile" "mcp-servers/social-media/"
build_image "mcp-threat-intel" "mcp-servers/threat-intel/Dockerfile" "mcp-servers/threat-intel/"

# Also tag with 'latest' for convenience
echo "🏷️  Tagging images with 'latest' tag..."
for image in fastapi-backend simple-backend simple-frontend mcp-infrastructure mcp-social-media mcp-threat-intel; do
    docker tag "$REGISTRY/$image:$VERSION" "$REGISTRY/$image:latest"
    echo "   Tagged $REGISTRY/$image:latest"
done

echo ""
echo "🎉 All images built successfully!"
echo "📋 Images built:"
docker images | grep "$REGISTRY" | grep -E "($VERSION|latest)"

echo ""
echo "🚀 Next Steps:"
echo "1. Deploy to Kubernetes: kubectl apply -f k8s/"
echo "2. Or use Helm: helm install osint-platform ./helm/osint-platform/"
echo "3. Check status: kubectl get pods -n osint-platform" 