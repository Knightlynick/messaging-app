@echo off
REM =====================================================================
REM Messaging-App Server Setup Script
REM This script installs vcpkg (if not already installed), installs
REM required packages via vcpkg (using the manifest), and configures
REM the CMake build.
REM =====================================================================

REM Set the path for vcpkg relative to the project root.
set VCPKG_DIR=%~dp0vcpkg

REM Check if vcpkg folder exists; if not, clone it.
if not exist "%VCPKG_DIR%\bootstrap-vcpkg.bat" (
    echo Cloning vcpkg...
    git clone https://github.com/microsoft/vcpkg.git "%VCPKG_DIR%"
    if errorlevel 1 (
        echo Failed to clone vcpkg. Make sure Git is installed.
        pause
        exit /b 1
    )
)

REM Bootstrap vcpkg.
echo Bootstrapping vcpkg...
pushd "%VCPKG_DIR%"
bootstrap-vcpkg.bat
if errorlevel 1 (
    echo vcpkg bootstrap failed.
    popd
    pause
    exit /b 1
)
popd

REM Install dependencies using the manifest.
echo Installing dependencies with vcpkg...
"%VCPKG_DIR%\vcpkg.exe" install
if errorlevel 1 (
    echo vcpkg install failed.
    pause
    exit /b 1
)

REM Create a build directory if it does not exist.
if not exist "build" (
    mkdir build
)

REM Change to build directory.
cd build

REM Run CMake configuration.
echo Configuring the project with CMake...
cmake .. -DCMAKE_TOOLCHAIN_FILE=%~dp0vcpkg\scripts\buildsystems\vcpkg.cmake
if errorlevel 1 (
    echo CMake configuration failed.
    pause
    exit /b 1
)

echo Setup complete!
echo To build the project, run: cmake --build .
pause