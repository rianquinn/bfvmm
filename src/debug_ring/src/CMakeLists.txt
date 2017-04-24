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

set_target_properties(bfvmm_debug_ring PROPERTIES DEFINE_SYMBOL SHARED_DEBUG_RING)
set_target_properties(bfvmm_debug_ring_static PROPERTIES COMPILE_FLAGS -DBUILD_STATIC)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    install(TARGETS bfvmm_debug_ring DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
    install(TARGETS bfvmm_debug_ring_static DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
endif()
