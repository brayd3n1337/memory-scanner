cmake_minimum_required(VERSION 3.28)
project(memory_scanner)

set(CMAKE_CXX_STANDARD 17)

# Explicitly set the Windows SDK version if needed
if(NOT DEFINED CMAKE_SYSTEM_VERSION)
    set(CMAKE_SYSTEM_VERSION 10.0)  # Adjust this to match your installed SDK version if necessary
endif()

# Set the target architecture
if(WIN32)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        # 64 bits
        add_definitions(-D_WIN64)
        set(CMAKE_GENERATOR_PLATFORM x64)
    elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
        # 32 bits
        add_definitions(-D_WIN32)
        set(CMAKE_GENERATOR_PLATFORM x86)
    endif()
endif()

add_executable(memory_scanner main.cpp)
