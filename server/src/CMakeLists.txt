# src/CMakeLists.txt
add_executable(MessagingApp main.cpp)

# Find Boost packages via vcpkg.
find_package(Boost REQUIRED COMPONENTS system thread)
if(Boost_FOUND)
    target_include_directories(MessagingApp PRIVATE ${Boost_INCLUDE_DIRS})
    target_link_libraries(MessagingApp PRIVATE ${Boost_LIBRARIES})
endif()
