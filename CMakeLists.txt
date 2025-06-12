cmake_minimum_required(VERSION 3.16)
project(VacModuleDumper LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)

add_library(VacModuleDumper SHARED
    dllmain.cpp
    module_utils.cpp
    icekey.cpp
)

target_include_directories(VacModuleDumper PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/MinHook/include
)

if(MSVC)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        target_link_libraries(VacModuleDumper PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/MinHook/lib/libMinHook.x64.lib
        )
    else()
        target_link_libraries(VacModuleDumper PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/MinHook/lib/libMinHook.x86.lib
        )
    endif()
endif()
