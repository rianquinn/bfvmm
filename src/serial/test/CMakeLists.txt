# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt")
include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeOption_Testing.txt")

# ------------------------------------------------------------------------------
# Static Linking
# ------------------------------------------------------------------------------

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DSTATIC_INTRINSICS")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DSTATIC_SERIAL")

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

macro(do_test str source)
    add_executable(test_${str} test_${str}.cpp ${source})
    target_link_libraries(test_${str} bfvmm_catch_static)
    target_link_libraries(test_${str} bfvmm_intrinsics_static)
    add_test(test_${str} test_${str})
endmacro(do_test)

list(APPEND SERIAL_SOURCE
    ../src/serial_port_intel_x64.cpp
)

do_test(serial_port_intel_x64 ${SERIAL_SOURCE})
