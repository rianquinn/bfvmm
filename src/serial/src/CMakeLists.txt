# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt")

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    serial_port_intel_x64.cpp
)

add_library(bfvmm_serial SHARED ${SOURCES})
add_library(bfvmm_serial_static STATIC ${SOURCES})

set_target_properties(bfvmm_serial PROPERTIES DEFINE_SYMBOL SHARED_SERIAL)
set_target_properties(bfvmm_serial_static PROPERTIES COMPILE_FLAGS -DBUILD_STATIC)

target_link_libraries(bfvmm_serial bfvmm_intrinsics)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    install(TARGETS bfvmm_serial DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
    install(TARGETS bfvmm_serial_static DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
endif()
