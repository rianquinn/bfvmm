# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt")
include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeOption_Testing.txt")

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------


macro(do_test str source)
    add_executable(test_${str} test_${str}.cpp ${source})
    target_compile_definitions(test_${str} PRIVATE STATIC_DEBUG_RING)
    target_link_libraries(test_${str} bfvmm_catch_static)
    add_test(test_${str} test_${str})
endmacro(do_test)

list(APPEND DEBUG_RING_SOURCE
    ../src/debug_ring.cpp
)

do_test(debug_ring ${DEBUG_RING_SOURCE})
