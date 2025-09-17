cmake_minimum_required(VERSION 3.10)
project(PacketProcessor LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Пути к заголовкам
include_directories(
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/chain
    ${PROJECT_SOURCE_DIR}/filters
    ${PROJECT_SOURCE_DIR}/nat
    ${PROJECT_SOURCE_DIR}/parsers
    ${PROJECT_SOURCE_DIR}/common 
)

# Собираем все .cpp кроме build/
file(GLOB_RECURSE SOURCES
    ${PROJECT_SOURCE_DIR}/chain/*.cpp
    ${PROJECT_SOURCE_DIR}/filters/*.cpp
    ${PROJECT_SOURCE_DIR}/nat/*.cpp
    ${PROJECT_SOURCE_DIR}/parsers/*.cpp
    ${PROJECT_SOURCE_DIR}/main.cpp
)

add_executable(PacketProcessor ${SOURCES})

# Генерируем compile_commands.json для clangd/YouCompleteMe
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

