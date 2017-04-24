# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt")

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    vcpu.cpp
    vcpu_intel_x64.cpp
    vcpu_manager.cpp
    vcpu_factory.cpp
)

add_library(bfvmm_vcpu SHARED ${SOURCES})
add_library(bfvmm_vcpu_static STATIC ${SOURCES})

set_target_properties(bfvmm_vcpu PROPERTIES DEFINE_SYMBOL SHARED_VCPU)
set_target_properties(bfvmm_vcpu_static PROPERTIES COMPILE_FLAGS -DBUILD_STATIC)

target_link_libraries(bfvmm_vcpu bfvmm_vmxon)
target_link_libraries(bfvmm_vcpu bfvmm_exit_handler)
target_link_libraries(bfvmm_vcpu bfvmm_vmcs)
target_link_libraries(bfvmm_vcpu bfvmm_memory_manager)
target_link_libraries(bfvmm_vcpu bfvmm_debug_ring)
target_link_libraries(bfvmm_vcpu bfvmm_intrinsics)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    install(TARGETS bfvmm_vcpu DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
    install(TARGETS bfvmm_vcpu_static DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
endif()
