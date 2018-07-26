cmake_minimum_required(VERSION 3.6.2)
project(lp C CXX)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

add_compile_options(-Wall -Wextra -Wpedantic -Wno-psabi -g)
add_definitions(-DSPDLOG_ENABLE_SYSLOG=1)

set(SPDLOG_BUILD_TESTING OFF CACHE BOOL "Disable spdlog tests")
set(UDEVPP_BUILD_EXAMPLES OFF CACHE BOOL "Disable udevpp examples")

add_subdirectory(external/wpa_ctrl_cmake)

add_library(wpa_ctrlpp src/network.cpp)
set_property(TARGET wpa_ctrlpp PROPERTY CXX_STANDARD 17)
target_include_directories(wpa_ctrlpp PRIVATE include)
target_compile_options(wpa_ctrlpp PUBLIC -Wall -Wextra -Wpedantic)

target_link_libraries(wpa_ctrlpp PRIVATE wpa_ctrl)
target_link_libraries(wpa_ctrlpp PRIVATE stdc++fs)
