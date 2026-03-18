#!/bin/bash
# FenrisHub - Development Server Startup Script for macOS/Linux

echo ""
echo "===================================="
echo "FenrisHub - Development Server"
echo "===================================="
echo ""

# Activate virtual environment
source venv/bin/activate

# Run the development server
python manage.py runserver
