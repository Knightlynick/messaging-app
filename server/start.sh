#!/bin/bash
# filepath: /home/ball/messaging-app/server/start.sh
#
# This script builds the backend server then starts it.
# It performs the following steps:
#   1. Determines the script's directory.
#   2. Creates a build directory if it doesn’t exist.
#   3. Changes to the build directory.
#   4. Runs CMake configuration if needed (checks for CMakeCache.txt).
#   5. Builds the project.
#   6. Changes to the executable directory and runs the server.
#
# Usage:
#   ./start.sh

# Determine the directory where this script is located.
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo "[INFO] Server script directory: $SCRIPT_DIR"

# Ensure the build directory exists.
BUILD_DIR="$SCRIPT_DIR/build"
if [ ! -d "$BUILD_DIR" ]; then
    echo "[INFO] Build directory not found. Creating build directory at $BUILD_DIR"
    mkdir -p "$BUILD_DIR"
fi

# Change to the build directory.
cd "$BUILD_DIR" || { echo "[ERROR] Failed to change directory to $BUILD_DIR"; exit 1; }

# If there is no CMakeCache.txt, assume we need to configure the project.
if [ ! -f "CMakeCache.txt" ]; then
    echo "[INFO] CMakeCache.txt not found. Configuring project with CMake..."
    cmake .. || { echo "[ERROR] CMake configuration failed."; exit 1; }
fi

# Build the server backend.
echo "[INFO] Building the backend server..."
cmake --build . || { echo "[ERROR] Build failed."; exit 1; }

# Change to the directory containing the built executable.
# In this setup, the executable is assumed to be in the build/src subdirectory.
cd "$BUILD_DIR/src" || { echo "[ERROR] Failed to change directory to $BUILD_DIR/src"; exit 1; }

# Run the MessagingApp server.
echo "[INFO] Starting MessagingApp server..."
./MessagingApp || { echo "[ERROR] Failed to start the server."; exit 1; }