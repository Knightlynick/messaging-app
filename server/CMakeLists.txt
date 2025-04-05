cmake_minimum_required(VERSION 3.15)
project(MessagingApp)

# Use C++17 standard.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(Boost REQUIRED COMPONENTS system thread)
find_package(fmt REQUIRED)

# Add the source directory.
add_subdirectory(src)

# (Optionally) set up output directories, compiler flags, etc.
