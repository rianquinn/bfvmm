# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt")

# ------------------------------------------------------------------------------
# Exports
# ------------------------------------------------------------------------------

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCOMPILING_VMCS")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DCOMPILING_VMCS")

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    vmcs_intel_x64.cpp
    vmcs_intel_x64_host_vm_state.cpp
    vmcs_intel_x64_vmm_state.cpp
)

if(NOT CMAKE_TOOLCHAIN_FILE)
    list(APPEND SOURCES vmcs_intel_x64_launch_mock.cpp)
    list(APPEND SOURCES vmcs_intel_x64_promote_mock.cpp)
    list(APPEND SOURCES vmcs_intel_x64_resume_mock.cpp)
else()
    list(APPEND SOURCES vmcs_intel_x64_launch.asm)
    list(APPEND SOURCES vmcs_intel_x64_promote.asm)
    list(APPEND SOURCES vmcs_intel_x64_resume.asm)
endif()

add_library(vmcs OBJECT ${SOURCES})
add_library(bfvmm_vmcs SHARED $<TARGET_OBJECTS:vmcs>)
add_library(bfvmm_vmcs_static STATIC $<TARGET_OBJECTS:vmcs>)

target_link_libraries(bfvmm_vmcs bfvmm_intrinsics)
target_link_libraries(bfvmm_vmcs bfvmm_memory_manager)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    install(TARGETS bfvmm_vmcs DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
    install(TARGETS bfvmm_vmcs_static DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
endif()
