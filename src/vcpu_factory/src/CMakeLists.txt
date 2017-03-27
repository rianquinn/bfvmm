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
    vcpu_factory_intel_x64.cpp
)

add_library(vcpu_factory OBJECT ${SOURCES})
add_library(bfvmm_vcpu_factory SHARED $<TARGET_OBJECTS:vcpu_factory>)
add_library(bfvmm_vcpu_factory_static STATIC $<TARGET_OBJECTS:vcpu_factory>)

target_link_libraries(bfvmm_vcpu_factory bfvmm_debug_ring)
target_link_libraries(bfvmm_vcpu_factory bfvmm_intrinsics)
target_link_libraries(bfvmm_vcpu_factory bfvmm_memory_manager)
target_link_libraries(bfvmm_vcpu_factory bfvmm_vmxon)
target_link_libraries(bfvmm_vcpu_factory bfvmm_vmcs)
target_link_libraries(bfvmm_vcpu_factory bfvmm_exit_handler)
target_link_libraries(bfvmm_vcpu_factory bfvmm_vcpu)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    install(TARGETS bfvmm_vcpu_factory DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
    install(TARGETS bfvmm_vcpu_factory_static DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
endif()
