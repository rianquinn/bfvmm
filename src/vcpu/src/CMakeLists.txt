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

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCOMPILING_VCPU")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DCOMPILING_VCPU")

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    vcpu.cpp
    vcpu_intel_x64.cpp
    vcpu_manager.cpp
    vcpu_factory.cpp
)

add_library(vcpu OBJECT ${SOURCES})
add_library(bfvmm_vcpu SHARED $<TARGET_OBJECTS:vcpu>)
add_library(bfvmm_vcpu_static STATIC $<TARGET_OBJECTS:vcpu>)

target_link_libraries(bfvmm_vcpu bfvmm_debug_ring)
target_link_libraries(bfvmm_vcpu bfvmm_intrinsics)
target_link_libraries(bfvmm_vcpu bfvmm_memory_manager)
target_link_libraries(bfvmm_vcpu bfvmm_vmxon)
target_link_libraries(bfvmm_vcpu bfvmm_vmcs)
target_link_libraries(bfvmm_vcpu bfvmm_exit_handler)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    install(TARGETS bfvmm_vcpu DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
    install(TARGETS bfvmm_vcpu_static DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
endif()
