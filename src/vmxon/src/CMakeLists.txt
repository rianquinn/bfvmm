# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    vmxon_intel_x64.cpp
)

add_library(bfvmm_vmxon SHARED ${SOURCES})
add_library(bfvmm_vmxon_static STATIC ${SOURCES})

target_compile_definitions(bfvmm_vmxon PRIVATE SHARED_VMXON)
target_compile_definitions(bfvmm_vmxon_static PUBLIC STATIC_VMXON)
target_compile_definitions(bfvmm_vmxon_static PUBLIC STATIC_MEMORY_MANAGER)
target_compile_definitions(bfvmm_vmxon_static PUBLIC STATIC_INTRINSICS)

target_link_libraries(bfvmm_vmxon bfvmm_memory_manager)
target_link_libraries(bfvmm_vmxon bfvmm_intrinsics)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    install(TARGETS bfvmm_vmxon DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
    install(TARGETS bfvmm_vmxon_static DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
else()
    install(TARGETS bfvmm_vmxon DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
    install(TARGETS bfvmm_vmxon_static DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
endif()
