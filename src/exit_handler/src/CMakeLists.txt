# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

if(NOT CMAKE_TOOLCHAIN_FILE)
    include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeFlags_Native_GCC.txt")
endif()

include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt")

# ------------------------------------------------------------------------------
# Exports
# ------------------------------------------------------------------------------

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCOMPILING_EXIT_HANDLER")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DCOMPILING_EXIT_HANDLER")

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    exit_handler_intel_x64.cpp
    exit_handler_intel_x64_entry.cpp
    exit_handler_intel_x64_unittests.cpp
    exit_handler_intel_x64_unittests_containers.cpp
    exit_handler_intel_x64_unittests_io.cpp
)

if(NOT CMAKE_TOOLCHAIN_FILE)
    list(APPEND SOURCES exit_handler_intel_x64_support_mock.cpp)
else()
    list(APPEND SOURCES exit_handler_intel_x64_support.asm)
endif()

add_library(exit_handler OBJECT ${SOURCES})
add_library(bfvmm_exit_handler SHARED $<TARGET_OBJECTS:exit_handler>)
add_library(bfvmm_exit_handler_static STATIC $<TARGET_OBJECTS:exit_handler>)

target_link_libraries(bfvmm_exit_handler bfvmm_intrinsics)
target_link_libraries(bfvmm_exit_handler bfvmm_memory_manager)
target_link_libraries(bfvmm_exit_handler bfvmm_vmcs)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    install(TARGETS bfvmm_exit_handler DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
    install(TARGETS bfvmm_exit_handler_static DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
endif()
