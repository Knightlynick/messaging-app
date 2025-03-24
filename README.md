# Messaging-App

This is how to install and swt everything up for our Messaging-App project, implemented in C++ with Boost.Asio, and react in javascript. It uses CMake for building and [vcpkg](https://github.com/microsoft/vcpkg) for dependency management for the backend, and node for frontend building and dependency management.  Below are instuctions for how to set up both.

## Prerequisites

Before setting up the project, ensure that you have the following installed:
- **Git:** [Download Git](https://git-scm.com/downloads)
- **CMake:** [Download CMake](https://cmake.org/download/)
- **Visual Studio 2019/2022 or Build Tools for Visual Studio:** Ensure you have the "Desktop development with C++" workload 
installed.
-**Microsoft Powershell** Ensure its added and part of the path variable: C:\Windows\System32\WindowsPowerShell\v1.0
    - If not follow these instructions
        windows + x 
        system
        advanced system settings
        environment variables
        Click the path variable
        Edit
        Add the path C:\Windows\System32\WindowsPowerShell\v1.0
        Click ok out
        Restart visual studio

## Setup Instructions

Follow these steps to set up the project on your machine:

1. **Clone the Repository:**

   git clone https://your.repo.url/messaging-app.git

2. **Set up the Backend**

   cd messaging-app/server
   setup.bat
   You can begin writing code
  
3. **Set up the Frontend**

   cd messaging-app/client
   npm install
   You can begin writing code

## Running Instructions

1. **FRONTEND**

    cd messaging-app/client
    npm start
    
This starts up the frontend

2. **BACKEND**

    cd messaging-app/server/build
    cmake --build .
    cd messaging-app/server/build/src/debug/
    .\MessagingApp.exe

This starts up the backend