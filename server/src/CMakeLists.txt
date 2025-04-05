add_executable(MessagingApp
    main.cpp
    authentication.cpp
    chat.cpp
    http_session.cpp
)

find_package(Boost REQUIRED COMPONENTS system thread)
find_package(fmt REQUIRED)

target_include_directories(MessagingApp PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(MessagingApp PRIVATE 
    Boost::system 
    Boost::thread 
    fmt::fmt
    sqlite3
    ssl
    crypto
)

install(TARGETS MessagingApp RUNTIME DESTINATION bin)
