# src/CMakeLists.txt
add_executable(MessagingApp main.cpp)

# Find Boost packages via system libraries
find_package(Boost REQUIRED COMPONENTS system thread)
find_package(fmt REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

# Include and link libraries
target_include_directories(MessagingApp PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(MessagingApp PRIVATE Boost::system Boost::thread fmt::fmt OpenSSL::Crypto SQLite::SQLite3)

# Set installation path
install(TARGETS MessagingApp RUNTIME DESTINATION bin)
