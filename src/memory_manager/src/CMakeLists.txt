# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    map_ptr_x64.cpp
    memory_manager_x64.cpp
    page_table_entry_x64.cpp
    page_table_x64.cpp
    root_page_table_x64.cpp
)

add_library(bfvmm_memory_manager SHARED ${SOURCES})
add_library(bfvmm_memory_manager_static STATIC ${SOURCES})

target_compile_definitions(bfvmm_memory_manager PRIVATE SHARED_MEMORY_MANAGER)
target_compile_definitions(bfvmm_memory_manager_static PUBLIC STATIC_MEMORY_MANAGER)
target_compile_definitions(bfvmm_memory_manager_static PUBLIC STATIC_INTRINSICS)

target_link_libraries(bfvmm_memory_manager bfvmm_intrinsics)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    install(TARGETS bfvmm_memory_manager DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
    install(TARGETS bfvmm_memory_manager_static DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
else()
    install(TARGETS bfvmm_memory_manager DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
    install(TARGETS bfvmm_memory_manager_static DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
endif()
