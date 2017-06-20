# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

macro(do_test str)
    add_executable(test_${str} test_${str}.cpp)
    add_test(test_${str} test_${str})
endmacro(do_test)

do_test(map_ptr_x64)
do_test(mem_attr_x64)
do_test(mem_pool)
do_test(memory_manager_x64)
do_test(page_table_entry_x64)
do_test(page_table_x64)
do_test(pat_x64)
do_test(root_page_table_x64)
