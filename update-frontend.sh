#!/bin/bash
# Script to update the simple frontend with latest changes

echo "Updating simple frontend..."

# Copy the updated index.html to the simple-frontend directory
cp /Users/daringanitch/workspace/enterprise-osint-flask/simple-frontend/index.html /Users/daringanitch/workspace/enterprise-osint-flask/simple-frontend/

# Build new Docker image
echo "Building new Docker image..."
cd /Users/daringanitch/workspace/enterprise-osint-flask/simple-frontend
docker build -t osint-platform/simple-frontend:local .

# Delete the old pod to force a new one with the updated image
echo "Restarting frontend pod..."
kubectl delete pod -n osint-platform -l app=osint-simple-frontend

echo "Done! Frontend should reload with latest changes."