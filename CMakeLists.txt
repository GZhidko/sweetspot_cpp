cmake_minimum_required(VERSION 3.10)
project(sweetspot_cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


# исходники основной программы
file(GLOB SRC
    main.cpp
    parsers/*.cpp
    filters/*.cpp
    nat/*.cpp
    common/*.cpp
)

add_executable(PacketProcessor ${SRC})
target_include_directories(PacketProcessor PRIVATE include common parsers filters nat chain)



# ---------- TESTS ----------
enable_testing()

# фан-аут тест
file(GLOB TEST_SRC
    tests/test_fanout.cpp
    parsers/*.cpp
    filters/*.cpp
    nat/*.cpp
    common/*.cpp
)

add_executable(test_fanout ${TEST_SRC})

target_include_directories(test_fanout PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/parsers
    ${CMAKE_SOURCE_DIR}/filters
    ${CMAKE_SOURCE_DIR}/nat
    ${CMAKE_SOURCE_DIR}/chain
)
add_test(NAME FanoutTest COMMAND test_fanout)

