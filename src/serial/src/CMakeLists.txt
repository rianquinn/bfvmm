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

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCOMPILING_SERIAL")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DCOMPILING_SERIAL")

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    serial_port_intel_x64.cpp
)

add_library(serial OBJECT ${SOURCES})
add_library(bfvmm_serial SHARED $<TARGET_OBJECTS:serial>)
add_library(bfvmm_serial_static STATIC $<TARGET_OBJECTS:serial>)

target_link_libraries(bfvmm_serial bfvmm_intrinsics)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    install(TARGETS bfvmm_serial DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
    install(TARGETS bfvmm_serial_static DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
endif()
