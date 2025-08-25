#!/bin/bash

# Supabase Authentication Backend Deployment Script
# This script sets up and runs the authentication backend

set -e

echo "🚀 Supabase Authentication Backend Deployment"
echo "=============================================="

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

# Check if pip is installed
if ! command -v pip &> /dev/null; then
    echo "❌ pip is required but not installed."
    exit 1
fi

echo "✅ Python and pip are available"

# Install dependencies
echo "📦 Installing dependencies..."
pip install -r requirements.txt

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "⚠️  .env file not found. Creating from template..."
    cp .env.example .env
    echo "📝 Please edit .env with your configuration before running the application"
    echo "   Required: SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY"
    echo "   Required: JWT_SECRET_KEY, EMAIL_* configuration"
    exit 1
fi

echo "✅ .env file found"

# Validate that the application can start
echo "🔍 Validating application..."
if PYTHONPATH=. python -c "import src.api.main; print('✅ Application validation successful')" 2>/dev/null; then
    echo "✅ Application is ready to run"
else
    echo "❌ Application validation failed. Check your .env configuration."
    exit 1
fi

# Check if port is specified
PORT=${PORT:-8000}

# Check if host is specified
HOST=${HOST:-0.0.0.0}

echo "🌐 Starting server on http://${HOST}:${PORT}"
echo "📚 API Documentation will be available at http://${HOST}:${PORT}/docs"
echo "📋 OpenAPI specification at http://${HOST}:${PORT}/openapi.json"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Start the application
PYTHONPATH=. uvicorn src.api.main:app --host $HOST --port $PORT --reload
