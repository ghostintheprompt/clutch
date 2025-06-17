#!/bin/bash

# Cellular Security Monitoring System - Quick Start
# This script sets up and launches the complete system

echo "🛡️  Cellular Security Monitoring System - Quick Start"
echo "======================================================="

# Check if we're in the right directory
if [ ! -f "cellular_remote_server.py" ]; then
    echo "❌ Error: Please run this script from the project directory"
    echo "   Expected files: cellular_remote_server.py, cellular_security.py"
    exit 1
fi

echo "✅ Project directory verified"

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
echo "🐍 Python version: $PYTHON_VERSION"

# Setup virtual environment and install dependencies
echo "📦 Setting up virtual environment and dependencies..."
if [ ! -d "cellular_env" ]; then
    echo "   Creating virtual environment..."
    python3 -m venv cellular_env
fi

echo "   Activating virtual environment..."
source cellular_env/bin/activate

echo "   Installing dependencies..."
if ! pip install -r requirements.txt > /dev/null 2>&1; then
    echo "❌ Failed to install dependencies"
    echo "   Please run: source cellular_env/bin/activate && pip install -r requirements.txt"
    exit 1
fi
echo "✅ Dependencies installed"

# Check for iOS app
if [ -d "iOS-App/NetworkSecurityMonitor" ]; then
    echo "📱 iOS app found: iOS-App/NetworkSecurityMonitor"
else
    echo "⚠️  iOS app not found - remote monitoring will be limited"
fi

# Create necessary directories
mkdir -p logs
echo "📁 Log directory created"

# Start the system
echo ""
echo "🚀 Starting Cellular Security Monitoring System..."
echo "------------------------------------------------------"

# Option 1: Start remote server only
echo "Choose startup mode:"
echo "1) Remote Server Only (for iOS app connection)"
echo "2) Local Monitoring Only (macOS/Linux cellular monitoring)"
echo "3) Complete System (Remote server + iOS integration test)"
echo ""
read -p "Enter choice (1-3): " choice

case $choice in
    1)
        echo "🌐 Starting remote monitoring server..."
        echo "   Server will run on ws://localhost:8766"
        echo "   Use this URL in the iOS app settings"
        echo ""
        python cellular_remote_server.py
        ;;
    2)
        echo "💻 Starting local cellular monitoring..."
        echo "   Monitoring macOS/Linux cellular interfaces"
        echo ""
        python cellular_security.py
        ;;
    3)
        echo "🔄 Starting complete system test..."
        echo "   Remote server + iOS integration testing"
        echo ""
        python test_ios_remote_integration.py
        ;;
    *)
        echo "❌ Invalid choice. Starting remote server (default)..."
        python cellular_remote_server.py
        ;;
esac

echo ""
echo "🏁 System stopped. Check logs for details:"
echo "   - cellular_remote_monitoring.log (server activity)"
echo "   - System logs in terminal output"
