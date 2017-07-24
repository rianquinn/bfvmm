# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

if(NOT CMAKE_TOOLCHAIN_FILE)

    list(APPEND SOURCES
        cache_x64_mock.cpp
        cpuid_x64_mock.cpp
        crs_intel_x64_mock.cpp
        debug_x64_mock.cpp
        gdt_x64_mock.cpp
        idt_x64_mock.cpp
        msrs_x64_mock.cpp
        pm_x64_mock.cpp
        portio_x64_mock.cpp
        rdtsc_x64_mock.cpp
        rflags_x64_mock.cpp
        srs_x64_mock.cpp
        thread_context_x64_mock.cpp
        tlb_x64_mock.cpp
        vmx_intel_x64_mock.cpp
    )

else()

    list(APPEND SOURCES
        cache_x64.asm
        cpuid_x64.asm
        crs_intel_x64.asm
        debug_x64.asm
        gdt_x64.asm
        idt_x64.asm
        msrs_x64.asm
        pm_x64.asm
        portio_x64.asm
        rdtsc_x64.asm
        rflags_x64.asm
        srs_x64.asm
        thread_context_x64.asm
        tlb_x64.asm
        vmx_intel_x64.asm
    )

endif()

list(APPEND SOURCES
    isr_x64.cpp
)

add_library(bfvmm_intrinsics SHARED ${SOURCES})
add_library(bfvmm_intrinsics_static STATIC ${SOURCES})

target_compile_definitions(bfvmm_intrinsics PRIVATE SHARED_INTRINSICS)
target_compile_definitions(bfvmm_intrinsics_static PUBLIC STATIC_INTRINSICS)

set_target_properties(bfvmm_intrinsics PROPERTIES LINKER_LANGUAGE C)
set_target_properties(bfvmm_intrinsics_static PROPERTIES LINKER_LANGUAGE C)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    install(TARGETS bfvmm_intrinsics DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
    install(TARGETS bfvmm_intrinsics_static DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
else()
    install(TARGETS bfvmm_intrinsics DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
    install(TARGETS bfvmm_intrinsics_static DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
endif()
