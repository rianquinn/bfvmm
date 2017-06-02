#-------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt")

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

macro(do_test str source)
    add_executable(test_${str} test_${str}.cpp ${source})
    target_compile_definitions(test_${str} PRIVATE STATIC_INTRINSICS)
    target_link_libraries(test_${str} bfvmm_catch_static)
    add_test(test_${str} test_${str})
endmacro(do_test)

list(APPEND INTRINSICS_SOURCE
  ../src/cache_x64_mock.cpp
  ../src/cpuid_x64_mock.cpp
  ../src/crs_intel_x64_mock.cpp
  ../src/debug_x64_mock.cpp
  ../src/gdt_x64_mock.cpp
  ../src/idt_x64_mock.cpp
  ../src/msrs_x64_mock.cpp
  ../src/pm_x64_mock.cpp
  ../src/portio_x64_mock.cpp
  ../src/rdtsc_x64_mock.cpp
  ../src/rflags_x64_mock.cpp
  ../src/srs_x64_mock.cpp
  ../src/thread_context_x64_mock.cpp
  ../src/tlb_x64_mock.cpp
  ../src/vmx_intel_x64_mock.cpp
)

do_test(cache_x64 "${INTRINSICS_SOURCE}")
do_test(cpuid_x64 "${INTRINSICS_SOURCE}")
do_test(crs_intel_x64 "${INTRINSICS_SOURCE}")
do_test(debug_x64 "${INTRINSICS_SOURCE}")
do_test(gdt_x64 "${INTRINSICS_SOURCE}")
do_test(idt_x64 "${INTRINSICS_SOURCE}")
do_test(msrs_intel_x64 "${INTRINSICS_SOURCE}")
do_test(msrs_x64 "${INTRINSICS_SOURCE}")
do_test(pdpte_x64 "${INTRINSICS_SOURCE}")
do_test(pm_x64 "${INTRINSICS_SOURCE}")
do_test(portio_x64 "${INTRINSICS_SOURCE}")
do_test(rdtsc_x64 "${INTRINSICS_SOURCE}")
do_test(rflags_x64 "${INTRINSICS_SOURCE}")
do_test(srs_x64 "${INTRINSICS_SOURCE}")
do_test(tlb_x64 "${INTRINSICS_SOURCE}")
# do_test(vmcs_intel_x64 "${INTRINSICS_SOURCE}")
do_test(vmcs_intel_x64_check_controls "${INTRINSICS_SOURCE}")
do_test(vmcs_intel_x64_check_guest "${INTRINSICS_SOURCE}")
do_test(vmcs_intel_x64_check_host "${INTRINSICS_SOURCE}")
do_test(vmcs_intel_x64_debug "${INTRINSICS_SOURCE}")
do_test(vmcs_intel_x64_helpers "${INTRINSICS_SOURCE}")
do_test(vmx_intel_x64 "${INTRINSICS_SOURCE}")
