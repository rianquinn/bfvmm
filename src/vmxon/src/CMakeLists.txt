# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt")

# ------------------------------------------------------------------------------
# Exports
# ------------------------------------------------------------------------------

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCOMPILING_VMXON")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DCOMPILING_VMXON")

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    vmxon_intel_x64.cpp
)

add_library(vmxon OBJECT ${SOURCES})
add_library(bfvmm_vmxon SHARED $<TARGET_OBJECTS:vmxon>)
add_library(bfvmm_vmxon_static STATIC $<TARGET_OBJECTS:vmxon>)

target_link_libraries(bfvmm_vmxon bfvmm_intrinsics)
target_link_libraries(bfvmm_vmxon bfvmm_memory_manager)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    install(TARGETS bfvmm_vmxon DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
    install(TARGETS bfvmm_vmxon_static DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
endif()
