# Messaging-App

This is a simple guide to set up and run the Messaging-App project on a Linux environment.

## Setup Instructions

### Frontend
1. Navigate to the `client` folder:
   ```bash
   cd client
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Start the frontend:
   ```bash
   npm start
   ```

### Backend
1. Navigate to the `server` folder:
   ```bash
   cd server
   ```
2. Setup Backend:
   ```bash
   ./setup.sh
   ```
   This set up the backend, install any dependencies onto the pc, as well as get the build folder set up.  Make changes inside the src folder inside of server, not build

3. Build and Run backend
    cd server
    ./start.sh

    This will start the backend on a local ip, on the port 12345