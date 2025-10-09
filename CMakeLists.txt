cmake_minimum_required(VERSION 3.10)
project(sweetspot_cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)


# исходники основной программы
file(GLOB SRC
    main.cpp
    committer/*.cpp
    parsers/*.cpp
    filters/*.cpp
    nat/*.cpp
    common/*.cpp
    af_packet_io/*.cpp
    sessions/*.cpp
    uam/*.cpp
    acct/*.cpp
    shape/*.cpp
)

add_executable(PacketProcessor ${SRC})
target_include_directories(PacketProcessor PRIVATE
     ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/committer
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/parsers
    ${CMAKE_SOURCE_DIR}/filters
    ${CMAKE_SOURCE_DIR}/nat
    ${CMAKE_SOURCE_DIR}/chain
    ${CMAKE_SOURCE_DIR}/af_packet_io
    ${CMAKE_SOURCE_DIR}/sessions
    ${CMAKE_SOURCE_DIR}/uam
    ${CMAKE_SOURCE_DIR}/acct

)


# af_packet runner (uses raw socket + NAT pipeline)
file(GLOB AF_PACKET_RUNNER_SRC
    apps/af_packet_runner.cpp
    committer/*.cpp
    parsers/*.cpp
    filters/*.cpp
    nat/*.cpp
    common/*.cpp
    af_packet_io/*.cpp
    sessions/*.cpp
    uam/*.cpp
    acct/*.cpp
    shape/*.cpp
)

add_executable(af_packet_runner ${AF_PACKET_RUNNER_SRC})
target_include_directories(af_packet_runner PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/committer
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/parsers
    ${CMAKE_SOURCE_DIR}/filters
    ${CMAKE_SOURCE_DIR}/nat
    ${CMAKE_SOURCE_DIR}/chain
    ${CMAKE_SOURCE_DIR}/af_packet_io
    ${CMAKE_SOURCE_DIR}/sessions
    ${CMAKE_SOURCE_DIR}/uam
    ${CMAKE_SOURCE_DIR}/acct
)
target_link_libraries(af_packet_runner PRIVATE Threads::Threads)



file(GLOB SWEETSPOT_DAEMON_SRC
    apps/sweetspot_daemon.cpp
    committer/*.cpp
    parsers/*.cpp
    filters/*.cpp
    nat/*.cpp
    common/*.cpp
    af_packet_io/*.cpp
    sessions/*.cpp
    uam/*.cpp
    acct/*.cpp
    shape/*.cpp
)

add_executable(sweetspot_daemon ${SWEETSPOT_DAEMON_SRC})
target_include_directories(sweetspot_daemon PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/committer
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/parsers
    ${CMAKE_SOURCE_DIR}/filters
    ${CMAKE_SOURCE_DIR}/nat
    ${CMAKE_SOURCE_DIR}/chain
    ${CMAKE_SOURCE_DIR}/af_packet_io
    ${CMAKE_SOURCE_DIR}/sessions
    ${CMAKE_SOURCE_DIR}/uam
    ${CMAKE_SOURCE_DIR}/acct
)
target_link_libraries(sweetspot_daemon PRIVATE Threads::Threads)


# ---------- TESTS ----------
enable_testing()

# фан-аут тест
file(GLOB TEST_SRC
    tests/test_fanout.cpp
    committer/*.cpp
    parsers/*.cpp
    filters/*.cpp
    nat/*.cpp
    common/*.cpp
    af_packet_io/*.cpp
    sessions/*.cpp
    uam/*.cpp
    acct/*.cpp
    shape/*.cpp
)

add_executable(test_fanout ${TEST_SRC})

target_include_directories(test_fanout PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/committer
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/parsers
    ${CMAKE_SOURCE_DIR}/filters
    ${CMAKE_SOURCE_DIR}/nat
    ${CMAKE_SOURCE_DIR}/chain
    ${CMAKE_SOURCE_DIR}/af_packet_io
    ${CMAKE_SOURCE_DIR}/sessions
    ${CMAKE_SOURCE_DIR}/uam
    ${CMAKE_SOURCE_DIR}/acct
)
add_test(NAME FanoutTest COMMAND test_fanout)

add_executable(test_checksum
    tests/test_checksum.cpp
    common/checksum.cpp
)
target_include_directories(test_checksum PRIVATE
    ${CMAKE_SOURCE_DIR}/af_packet_io
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/common
)
add_test(NAME ChecksumTest COMMAND test_checksum)


file(GLOB TEST_NAT_SRC
    tests/test_nat.cpp
    committer/*.cpp
    parsers/*.cpp
    filters/*.cpp
    nat/*.cpp
    common/*.cpp
    af_packet_io/*.cpp
    sessions/*.cpp
    uam/*.cpp
    acct/*.cpp
    shape/*.cpp
)

add_executable(test_nat ${TEST_NAT_SRC})
target_include_directories(test_nat PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/committer
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/parsers
    ${CMAKE_SOURCE_DIR}/filters
    ${CMAKE_SOURCE_DIR}/nat
    ${CMAKE_SOURCE_DIR}/chain
    ${CMAKE_SOURCE_DIR}/af_packet_io
    ${CMAKE_SOURCE_DIR}/sessions
    ${CMAKE_SOURCE_DIR}/uam
    ${CMAKE_SOURCE_DIR}/acct
)

target_link_libraries(test_nat PRIVATE Threads::Threads)

add_test(NAME NatTest COMMAND test_nat)

file(GLOB TEST_FILTERS_SRC
    tests/test_filters.cpp
    committer/*.cpp
    parsers/*.cpp
    filters/*.cpp
    nat/*.cpp
    common/*.cpp
    af_packet_io/*.cpp
    sessions/*.cpp
    uam/*.cpp
    acct/*.cpp
    shape/*.cpp
)

add_executable(test_filters ${TEST_FILTERS_SRC})

target_include_directories(test_filters PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/committer
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/parsers
    ${CMAKE_SOURCE_DIR}/filters
    ${CMAKE_SOURCE_DIR}/nat
    ${CMAKE_SOURCE_DIR}/chain
    ${CMAKE_SOURCE_DIR}/af_packet_io
    ${CMAKE_SOURCE_DIR}/sessions
    ${CMAKE_SOURCE_DIR}/uam
    ${CMAKE_SOURCE_DIR}/acct
)

target_link_libraries(test_filters PRIVATE Threads::Threads)

add_test(NAME FiltersTest COMMAND test_filters)

file(GLOB TEST_SESSIONS_SRC
    tests/test_sessions.cpp
    committer/*.cpp
    parsers/*.cpp
    filters/*.cpp
    nat/*.cpp
    common/*.cpp
    af_packet_io/*.cpp
    sessions/*.cpp
    uam/*.cpp
    acct/*.cpp
    shape/*.cpp
)

add_executable(test_sessions ${TEST_SESSIONS_SRC})

target_include_directories(test_sessions PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/committer
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/parsers
    ${CMAKE_SOURCE_DIR}/filters
    ${CMAKE_SOURCE_DIR}/nat
    ${CMAKE_SOURCE_DIR}/chain
    ${CMAKE_SOURCE_DIR}/af_packet_io
    ${CMAKE_SOURCE_DIR}/sessions
    ${CMAKE_SOURCE_DIR}/uam
    ${CMAKE_SOURCE_DIR}/acct
)

target_link_libraries(test_sessions PRIVATE Threads::Threads)

add_test(NAME SessionsTest COMMAND test_sessions)

file(GLOB TEST_UAM_SRC
    tests/test_uam.cpp
    committer/*.cpp
    parsers/*.cpp
    filters/*.cpp
    nat/*.cpp
    common/*.cpp
    af_packet_io/*.cpp
    sessions/*.cpp
    uam/*.cpp
    acct/*.cpp
    shape/*.cpp
)

add_executable(test_uam ${TEST_UAM_SRC})

target_include_directories(test_uam PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/committer
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/parsers
    ${CMAKE_SOURCE_DIR}/filters
    ${CMAKE_SOURCE_DIR}/nat
    ${CMAKE_SOURCE_DIR}/chain
    ${CMAKE_SOURCE_DIR}/af_packet_io
    ${CMAKE_SOURCE_DIR}/sessions
    ${CMAKE_SOURCE_DIR}/uam
    ${CMAKE_SOURCE_DIR}/acct
)

target_link_libraries(test_uam PRIVATE Threads::Threads)

add_test(NAME UamTest COMMAND test_uam)

file(GLOB TEST_ACCT_SRC
    tests/test_acct.cpp
    committer/*.cpp
    parsers/*.cpp
    filters/*.cpp
    nat/*.cpp
    common/*.cpp
    af_packet_io/*.cpp
    sessions/*.cpp
    uam/*.cpp
    acct/*.cpp
    shape/*.cpp
)

add_executable(test_acct ${TEST_ACCT_SRC})

target_include_directories(test_acct PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/committer
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/parsers
    ${CMAKE_SOURCE_DIR}/filters
    ${CMAKE_SOURCE_DIR}/nat
    ${CMAKE_SOURCE_DIR}/chain
    ${CMAKE_SOURCE_DIR}/af_packet_io
    ${CMAKE_SOURCE_DIR}/sessions
    ${CMAKE_SOURCE_DIR}/uam
    ${CMAKE_SOURCE_DIR}/acct
)

target_link_libraries(test_acct PRIVATE Threads::Threads)

add_test(NAME AcctTest COMMAND test_acct)
