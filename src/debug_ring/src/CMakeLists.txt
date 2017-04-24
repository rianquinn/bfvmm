# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt")

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    debug_ring.cpp
)

add_library(bfvmm_debug_ring SHARED ${SOURCES})
add_library(bfvmm_debug_ring_static STATIC ${SOURCES})

target_compile_definitions(bfvmm_debug_ring PRIVATE SHARED_DEBUG_RING)
target_compile_definitions(bfvmm_debug_ring_static PUBLIC STATIC_DEBUG_RING)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    install(TARGETS bfvmm_debug_ring DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
    install(TARGETS bfvmm_debug_ring_static DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
endif()
