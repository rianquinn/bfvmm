# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt")

# ------------------------------------------------------------------------------
# Exports
# ------------------------------------------------------------------------------

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCOMPILING_MEMORY_MANAGER")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DCOMPILING_MEMORY_MANAGER")

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

add_library(memory_manager OBJECT ${SOURCES})
add_library(bfvmm_memory_manager SHARED $<TARGET_OBJECTS:memory_manager>)
add_library(bfvmm_memory_manager_static STATIC $<TARGET_OBJECTS:memory_manager>)

target_link_libraries(bfvmm_memory_manager bfvmm_intrinsics)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    install(TARGETS bfvmm_memory_manager DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
    install(TARGETS bfvmm_memory_manager_static DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
endif()
