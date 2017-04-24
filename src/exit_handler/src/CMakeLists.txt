# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt")

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    exit_handler_intel_x64.cpp
    exit_handler_intel_x64_entry.cpp
    exit_handler_intel_x64_unittests_containers.cpp
    exit_handler_intel_x64_unittests.cpp
    exit_handler_intel_x64_unittests_io.cpp
)

if(NOT CMAKE_TOOLCHAIN_FILE)
    list(APPEND SOURCES exit_handler_intel_x64_support_mock.cpp)
else()
    list(APPEND SOURCES exit_handler_intel_x64_support.asm)
endif()

add_library(bfvmm_exit_handler SHARED ${SOURCES})
add_library(bfvmm_exit_handler_static STATIC ${SOURCES})

set_target_properties(bfvmm_exit_handler PROPERTIES DEFINE_SYMBOL SHARED_EXIT_HANDLER)
set_target_properties(bfvmm_exit_handler_static PROPERTIES COMPILE_FLAGS -DBUILD_STATIC)

target_link_libraries(bfvmm_exit_handler bfvmm_vmcs)
target_link_libraries(bfvmm_exit_handler bfvmm_memory_manager)
target_link_libraries(bfvmm_exit_handler bfvmm_intrinsics)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    install(TARGETS bfvmm_exit_handler DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
    install(TARGETS bfvmm_exit_handler_static DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
endif()
