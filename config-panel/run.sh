#!/bin/bash

# Function to install dependencies
install_dependencies() {
    pip install -r requirements.txt
}

# Check if dependencies need to be installed
if [ ! -f requirements.txt ]; then
    echo "requirements.txt not found, skipping installation."
else
    install_dependencies
fi

# Run the FastAPI server
PORT=${1:-8000}  # Default to port 8000 if no port is specified
uvicorn main:app --host 0.0.0.0 --port $PORT --reload
