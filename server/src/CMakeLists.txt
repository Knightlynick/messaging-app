# src/CMakeLists.txt
add_executable(MessagingApp main.cpp)

# Find Boost packages via system libraries
find_package(Boost REQUIRED COMPONENTS system thread)
find_package(fmt REQUIRED)

# Include and link libraries
target_include_directories(MessagingApp PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(MessagingApp PRIVATE Boost::system Boost::thread fmt::fmt)

# Set installation path
install(TARGETS MessagingApp RUNTIME DESTINATION bin)
