# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt")

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    main.cpp
)

add_executable(bfvmm_main ${SOURCES})

target_link_libraries(bfvmm_main bfvmm_debug_ring)
target_link_libraries(bfvmm_main bfvmm_serial)
target_link_libraries(bfvmm_main bfvmm_intrinsics)
target_link_libraries(bfvmm_main bfvmm_memory_manager)
target_link_libraries(bfvmm_main bfvmm_vmxon)
target_link_libraries(bfvmm_main bfvmm_vmcs)
target_link_libraries(bfvmm_main bfvmm_exit_handler)
target_link_libraries(bfvmm_main bfvmm_vcpu)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    install(TARGETS bfvmm_main DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
endif()
