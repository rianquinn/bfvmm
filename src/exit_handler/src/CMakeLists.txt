# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

if(NOT CMAKE_TOOLCHAIN_FILE)
    include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeFlags_Native_GCC.txt")
endif()

include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt")

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    exit_handler_intel_x64.cpp
    exit_handler_intel_x64_entry.cpp
    exit_handler_intel_x64_support.asm
    exit_handler_intel_x64_unittests.cpp
    exit_handler_intel_x64_unittests_containers.cpp
    exit_handler_intel_x64_unittests_io.cpp
)

add_library(bfvmm_exit_handler ${SOURCES})

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    install(TARGETS bfvmm_exit_handler DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
endif()
