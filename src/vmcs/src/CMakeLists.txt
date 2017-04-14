# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt")

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

add_library(bfvmm_vmcs SHARED ${SOURCES})
add_library(bfvmm_vmcs_static STATIC ${SOURCES})

set_target_properties(bfvmm_vmcs PROPERTIES DEFINE_SYMBOL SHARED_VMCS)
set_target_properties(bfvmm_vmcs_static PROPERTIES COMPILE_FLAGS -DBUILD_STATIC)

target_link_libraries(bfvmm_vmcs bfvmm_memory_manager)
target_link_libraries(bfvmm_vmcs bfvmm_intrinsics)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    install(TARGETS bfvmm_vmcs DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
    install(TARGETS bfvmm_vmcs_static DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
endif()
