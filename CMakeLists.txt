# The environment variable PCAPDIR allows to specficy where to find 
# libpcap in non standard location.

cmake_minimum_required (VERSION 2.8)
project (kdd99extractor CXX C)

# Distributed CMake Find modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")

# libpcap / WinPcap
find_package(PCAP)
include_directories(BEFORE ${PCAP_INCLUDE_DIR})

set(LIBS ${PCAP_LIBRARIES})

message(STATUS "ENV{PCAPDIR}=$ENV{PCAPDIR}")
message(STATUS "PCAP_FOUND=${PCAP_FOUND}")
message(STATUS "PCAP_LIBRARIES=${PCAP_LIBRARIES}")
message(STATUS "PCAP_INCLUDE_DIR=${PCAP_INCLUDE_DIR}")

add_subdirectory(src)
