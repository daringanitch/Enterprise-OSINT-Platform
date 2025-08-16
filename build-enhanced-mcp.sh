#!/bin/bash

# Build script for enhanced MCP servers

echo "Building Enhanced MCP Servers..."

# Set Docker registry (use local for now)
REGISTRY="localhost:5000"
TAG="latest"

# Build Infrastructure Advanced
echo "Building Infrastructure Advanced MCP Server..."
docker build -t mcp-infrastructure-advanced:$TAG ./mcp-servers/infrastructure-advanced/
docker tag mcp-infrastructure-advanced:$TAG $REGISTRY/mcp-infrastructure-advanced:$TAG

# Build Threat Aggregator
echo "Building Threat Aggregator MCP Server..."
docker build -t mcp-threat-aggregator:$TAG ./mcp-servers/threat-aggregator/
docker tag mcp-threat-aggregator:$TAG $REGISTRY/mcp-threat-aggregator:$TAG

# Build AI Analyzer
echo "Building AI Analyzer MCP Server..."
docker build -t mcp-ai-analyzer:$TAG ./mcp-servers/ai-analyzer/
docker tag mcp-ai-analyzer:$TAG $REGISTRY/mcp-ai-analyzer:$TAG

echo "Build complete!"

# Optional: Push to registry
read -p "Push images to registry? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
    echo "Pushing images..."
    docker push $REGISTRY/mcp-infrastructure-advanced:$TAG
    docker push $REGISTRY/mcp-threat-aggregator:$TAG
    docker push $REGISTRY/mcp-ai-analyzer:$TAG
    echo "Push complete!"
fi