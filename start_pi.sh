#!/bin/bash

# Memory-optimized startup script for Raspberry Pi Zero 2W

echo "Starting Pi Cryptolink Server..."

# Check available memory
echo "Available memory:"
free -h

# Set environment variables for low memory usage
export PYTHONUNBUFFERED=1
export WEB_HOST=0.0.0.0
export WEB_PORT=5000
export TCP_HOST=0.0.0.0
export TCP_PORT=5001

# Reduce Python memory usage
export PYTHONHASHSEED=0
export PYTHONDONTWRITEBYTECODE=1

echo "Starting server with optimized settings..."
python3 -O server.py

