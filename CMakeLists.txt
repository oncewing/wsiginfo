INCLUDE(CMakeForceCompiler)

SET(CMAKE_SYSTEM_NAME Linux)
SET(CMAKE_SYSTEM_VERSION 1)

PROJECT(wsiginfo)
cmake_minimum_required(VERSION 2.8.0)

#<SDKPATH> is sdk installed path.

find_package(Threads REQUIRED)

add_executable(wsiginfo src/signal_info.c)
target_link_libraries(wsiginfo ${CMAKE_THREAD_LIBS_INIT})

add_compile_options (-g0 -Wall)

SET(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
SET(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
SET(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
