# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Custom Flags
# ------------------------------------------------------------------------------

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie")

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

if(NOT EXISTS ${CMAKE_BINARY_DIR}/null.cpp)
    file(WRITE
        ${CMAKE_BINARY_DIR}/null.cpp ""
    )
endif()

list(APPEND SOURCES
    main.cpp
)

add_library(bfvmm_main_static STATIC ${SOURCES})
add_executable(bfvmm ${CMAKE_BINARY_DIR}/null.cpp)

target_link_libraries(bfvmm bfvmm_vcpu)
target_link_libraries(bfvmm bfvmm_vcpu_factory)
target_link_libraries(bfvmm bfvmm_vcpu_manager)
target_link_libraries(bfvmm bfvmm_debug_ring)
target_link_libraries(bfvmm bfvmm_exit_handler)
target_link_libraries(bfvmm bfvmm_vmcs)
target_link_libraries(bfvmm bfvmm_vmxon)
target_link_libraries(bfvmm bfvmm_serial)
target_link_libraries(bfvmm bfvmm_memory_manager)
target_link_libraries(bfvmm bfvmm_intrinsics)
target_link_libraries(bfvmm -Wl,--whole-archive bfvmm_main_static -Wl,--no-whole-archive)

if(CMAKE_TOOLCHAIN_FILE)
    target_link_libraries(bfvmm bfvmm_support)
endif()

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    install(TARGETS bfvmm DESTINATION ${BAREFLANK_SYSROOT_PATH}/bin)
    install(TARGETS bfvmm_main_static DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
else()
    install(TARGETS bfvmm DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)
    install(TARGETS bfvmm_main_static DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
endif()
