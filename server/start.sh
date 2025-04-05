#!/bin/bash
# Start the messaging server with the correct parameters
cd "$(dirname "$0")/build/src"
./MessagingApp 0.0.0.0 12345