# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt")

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    vcpu_manager.cpp
)

add_library(bfvmm_vcpu_manager SHARED ${SOURCES})
add_library(bfvmm_vcpu_manager_static STATIC ${SOURCES})

target_compile_definitions(bfvmm_vcpu_manager PRIVATE SHARED_VCPU)
target_compile_definitions(bfvmm_vcpu_manager_static PUBLIC STATIC_VCPU)
target_compile_definitions(bfvmm_vcpu_manager_static PUBLIC STATIC_VMXON)
target_compile_definitions(bfvmm_vcpu_manager_static PUBLIC STATIC_EXIT_HANDLER)
target_compile_definitions(bfvmm_vcpu_manager_static PUBLIC STATIC_VMCS)
target_compile_definitions(bfvmm_vcpu_manager_static PUBLIC STATIC_MEMORY_MANAGER)
target_compile_definitions(bfvmm_vcpu_manager_static PUBLIC STATIC_DEBUG_RING)
target_compile_definitions(bfvmm_vcpu_manager_static PUBLIC STATIC_INTRINSICS)

target_link_libraries(bfvmm_vcpu_manager bfvmm_vcpu)
target_link_libraries(bfvmm_vcpu_manager bfvmm_vcpu_factory)
target_link_libraries(bfvmm_vcpu_manager bfvmm_vmxon)
target_link_libraries(bfvmm_vcpu_manager bfvmm_exit_handler)
target_link_libraries(bfvmm_vcpu_manager bfvmm_vmcs)
target_link_libraries(bfvmm_vcpu_manager bfvmm_memory_manager)
target_link_libraries(bfvmm_vcpu_manager bfvmm_debug_ring)
target_link_libraries(bfvmm_vcpu_manager bfvmm_intrinsics)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    install(TARGETS bfvmm_vcpu_manager DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
    install(TARGETS bfvmm_vcpu_manager_static DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
endif()
