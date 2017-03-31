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

do_test(cache_x64)
do_test(cpuid_x64)
do_test(crs_intel_x64)
do_test(debug_x64)
do_test(gdt_x64)
do_test(idt_x64)
do_test(msrs_intel_x64)
do_test(msrs_x64)
do_test(pdpte_x64)
do_test(pm_x64)
do_test(portio_x64)
do_test(rdtsc_x64)
do_test(rflags_x64)
do_test(srs_x64)
do_test(tlb_x64)
# do_test(vmcs_intel_x64)
do_test(vmcs_intel_x64_check_controls)
do_test(vmcs_intel_x64_check_guest)
do_test(vmcs_intel_x64_check_host)
do_test(vmcs_intel_x64_debug)
do_test(vmcs_intel_x64_helpers)
do_test(vmx_intel_x64)
