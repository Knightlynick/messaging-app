#!/bin/bash
# =====================================================================
# Messaging-App Server Setup Script for Linux
# This script installs required dependencies using the system package manager
# and configures the CMake build.
# =====================================================================

echo "Installing required dependencies..."
sudo apt-get update
sudo apt-get install -y build-essential cmake libboost-all-dev libfmt-dev

# Create a build directory if it does not exist.
if [ ! -d "build" ]; then
    mkdir build
fi

# Change to build directory.
cd build

# Run CMake configuration.
echo "Configuring the project with CMake..."
cmake ..

if [ $? -ne 0 ]; then
    echo "CMake configuration failed."
    exit 1
fi

echo "Setup complete!"
echo "To build the project, run: cd build && cmake --build ."