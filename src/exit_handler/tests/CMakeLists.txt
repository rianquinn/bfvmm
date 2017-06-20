# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

macro(do_test str)
    add_executable(test_${str} test_${str}.cpp)
    target_compile_definitions(test_${str} PRIVATE STATIC_EXIT_HANDLER)
    target_compile_definitions(test_${str} PRIVATE EXIT_HANDLER_TEST)
    target_link_libraries(test_${str} bfvmm_exit_handler_static)
    target_link_libraries(test_${str} bfvmm_vmcs_static)
    target_link_libraries(test_${str} bfvmm_memory_manager_static)
    target_link_libraries(test_${str} bfvmm_intrinsics_static)
    target_link_libraries(test_${str} bfvmm_catch_static)
    add_test(test_${str} test_${str})
endmacro(do_test)

do_test(exit_handler_intel_x64)
do_test(exit_handler_intel_x64_entry)
