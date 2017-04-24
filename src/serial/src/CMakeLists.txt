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

target_compile_definitions(bfvmm_serial PRIVATE SHARED_SERIAL)
target_compile_definitions(bfvmm_serial_static PUBLIC STATIC_SERIAL)
target_compile_definitions(bfvmm_serial_static PUBLIC STATIC_INTRINSICS)

target_link_libraries(bfvmm_serial bfvmm_intrinsics)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    install(TARGETS bfvmm_serial DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
    install(TARGETS bfvmm_serial_static DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
endif()
