# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt")

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    vmxon_intel_x64.cpp
)

add_library(bfvmm_vmxon SHARED ${SOURCES})
add_library(bfvmm_vmxon_static STATIC ${SOURCES})

set_target_properties(bfvmm_vmxon PROPERTIES DEFINE_SYMBOL SHARED_VMXON)
set_target_properties(bfvmm_vmxon_static PROPERTIES COMPILE_FLAGS -DBUILD_STATIC)

target_link_libraries(bfvmm_vmxon bfvmm_memory_manager)
target_link_libraries(bfvmm_vmxon bfvmm_intrinsics)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    install(TARGETS bfvmm_vmxon DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
    install(TARGETS bfvmm_vmxon_static DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
endif()
