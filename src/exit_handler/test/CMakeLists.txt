# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt")
include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeOption_Testing.txt")

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DBUILD_STATIC -DEXIT_HANDLER_TEST")

macro(do_test str source)
    add_executable(test_${str} test_${str}.cpp ${source})
    target_link_libraries(test_${str} bfvmm_catch_static)
    target_link_libraries(test_${str} bfvmm_vmcs_static)
    target_link_libraries(test_${str} bfvmm_memory_manager_static)
    target_link_libraries(test_${str} bfvmm_intrinsics_static)
    add_test(test_${str} test_${str})
endmacro(do_test)

list(APPEND EXIT_HANDLER_SOURCE
    ../src/exit_handler_intel_x64.cpp
    ../src/exit_handler_intel_x64_entry.cpp
    ../src/exit_handler_intel_x64_support_mock.cpp
    ../src/exit_handler_intel_x64_unittests_containers.cpp
    ../src/exit_handler_intel_x64_unittests.cpp
    ../src/exit_handler_intel_x64_unittests_io.cpp
)

do_test(exit_handler_intel_x64 "${EXIT_HANDLER_SOURCE}")
do_test(exit_handler_intel_x64_entry "${EXIT_HANDLER_SOURCE}")
