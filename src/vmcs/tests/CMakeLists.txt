# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt")
include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeOption_Testing.txt")

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

macro(do_test str)
    add_executable(test_${str} test_${str}.cpp )
    add_test(test_${str} test_${str})
endmacro(do_test)

do_test(vmcs_intel_x64)
do_test(vmcs_intel_x64_host_vm_state)
do_test(vmcs_intel_x64_state)
do_test(vmcs_intel_x64_vmm_state)
