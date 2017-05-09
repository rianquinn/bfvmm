# cmake -DCMAKE_TOOLCHAIN_FILE=~/bfprefix/cmake/CMakeToolchain_VMM.txt ..

cmake_minimum_required(VERSION 3.6)
project(bfvmm C CXX)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    if(NOT WIN32 STREQUAL "1")
        set(CMAKE_INSTALL_PREFIX "$ENV{HOME}/bfprefix" CACHE PATH "default install path" FORCE)
    else()
        set(CMAKE_INSTALL_PREFIX "$ENV{HOMEPATH}/bfprefix" CACHE PATH "default install path" FORCE)
    endif()
endif()

include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Project.txt")

# ------------------------------------------------------------------------------
# Subdirectories
# ------------------------------------------------------------------------------

add_subdirectory(src)

if(ENABLE_UNITTESTING AND NOT CMAKE_TOOLCHAIN_FILE)
    add_subdirectory(tests)
endif()

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(DIRECTORY include/debug_ring DESTINATION include)
install(DIRECTORY include/exit_handler DESTINATION include)
install(DIRECTORY include/intrinsics DESTINATION include)
install(DIRECTORY include/memory_manager DESTINATION include)
install(DIRECTORY include/serial DESTINATION include)
install(DIRECTORY include/vcpu DESTINATION include)
install(DIRECTORY include/vmcs DESTINATION include)
install(DIRECTORY include/vmxon DESTINATION include)
install(FILES include/user_data.h DESTINATION include)
install(FILES include/vcpuid.h DESTINATION include)
