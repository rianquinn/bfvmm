# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

macro(do_test str)
    add_executable(test_${str} test_${str}.cpp)
    target_compile_definitions(test_${str} PRIVATE STATIC_SERIAL)
    target_compile_definitions(test_${str} PRIVATE STATIC_INTRINSICS)
    target_link_libraries(test_${str} bfvmm_serial_static)
    target_link_libraries(test_${str} bfvmm_intrinsics_static)
    target_link_libraries(test_${str} bfvmm_catch_static)
    add_test(test_${str} test_${str})
endmacro(do_test)

do_test(serial_port_intel_x64)
