#!/bin/bash

# Enterprise OSINT Platform Setup Script
# This script helps set up the development environment

echo "🚀 Enterprise OSINT Platform Setup"
echo "=================================="

# Check prerequisites
check_prerequisite() {
    if ! command -v $1 &> /dev/null; then
        echo "❌ $1 is not installed. Please install it first."
        return 1
    else
        echo "✅ $1 is installed"
        return 0
    fi
}

echo ""
echo "📋 Checking prerequisites..."
PREREQ_MET=true

check_prerequisite "python3" || PREREQ_MET=false
check_prerequisite "docker" || PREREQ_MET=false
check_prerequisite "docker-compose" || PREREQ_MET=false
check_prerequisite "git" || PREREQ_MET=false

if [ "$PREREQ_MET" = false ]; then
    echo ""
    echo "❌ Please install missing prerequisites before continuing."
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
REQUIRED_VERSION="3.8"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" = "$REQUIRED_VERSION" ]; then 
    echo "✅ Python $PYTHON_VERSION meets minimum requirement ($REQUIRED_VERSION+)"
else
    echo "❌ Python $PYTHON_VERSION is below minimum requirement ($REQUIRED_VERSION+)"
    exit 1
fi

# Create environment file if it doesn't exist
if [ ! -f ".env" ]; then
    echo ""
    echo "📝 Creating .env file from template..."
    cp .env.template .env
    echo "⚠️  Please edit .env file and add your API keys!"
else
    echo "✅ .env file already exists"
fi

# Set up Python virtual environment
echo ""
echo "🐍 Setting up Python virtual environment..."
cd simple-backend

if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✅ Virtual environment created"
else
    echo "✅ Virtual environment already exists"
fi

# Activate virtual environment and install dependencies
echo "📦 Installing Python dependencies..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Create necessary directories
echo ""
echo "📁 Creating necessary directories..."
mkdir -p ../logs
mkdir -p ../data
mkdir -p ../reports

# Initialize database (if running locally)
echo ""
read -p "Do you want to initialize the PostgreSQL database? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🗄️  Initializing PostgreSQL database..."
    docker-compose up -d postgresql
    
    echo "⏳ Waiting for PostgreSQL to be ready..."
    sleep 10
    
    # Test database connection
    docker exec osint-postgresql psql -U postgres -d osint_audit -c "SELECT version();" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "✅ PostgreSQL is ready and initialized"
    else
        echo "❌ Failed to connect to PostgreSQL"
    fi
fi

# Initialize Vault (if running locally)
echo ""
read -p "Do you want to initialize HashiCorp Vault? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🔐 Initializing HashiCorp Vault..."
    docker-compose up -d vault
    
    echo "⏳ Waiting for Vault to be ready..."
    sleep 5
    
    echo "✅ Vault is running in dev mode with token: dev-only-token"
    echo "⚠️  For production, properly initialize and unseal Vault!"
fi

# Display next steps
echo ""
echo "✅ Setup complete!"
echo ""
echo "📋 Next steps:"
echo "1. Edit .env file and add your API keys"
echo "2. Run 'docker-compose up' to start all services"
echo "3. Access the application:"
echo "   - Frontend: http://localhost:8080"
echo "   - Backend API: http://localhost:5001"
echo "   - Vault UI: http://localhost:8200"
echo "   - PostgreSQL: localhost:5432"
echo ""
echo "🚀 To start the application:"
echo "   docker-compose up"
echo ""
echo "🧪 To run in development mode:"
echo "   cd simple-backend"
echo "   source venv/bin/activate"
echo "   python app.py"
echo ""
echo "📚 Documentation:"
echo "   - Platform Overview: PLATFORM_OVERVIEW.md"
echo "   - Technical Architecture: TECHNICAL_ARCHITECTURE.md"