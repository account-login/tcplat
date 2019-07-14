cmake_minimum_required(VERSION 2.8)
project(asynclog)

set(CMAKE_CXX_STANDARD 98)

add_definitions(-Wall -Wextra -g)
add_definitions(-O2)

# tcplat
add_executable(tcplat
    src/main.cpp
    src/analyzer.cpp
    src/percentile.cpp
    src/log.cpp
)
set(CMAKE_EXE_LINKER_FLAGS "-static")
target_link_libraries(tcplat
    Pcap++ Packet++ Common++
    pcap
    -static -static-libgcc -static-libstdc++
)
