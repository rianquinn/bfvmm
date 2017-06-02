# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt")

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    unistd.cpp
)

add_library(bfvmm_support SHARED ${SOURCES})
add_library(bfvmm_support_static STATIC ${SOURCES})

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    install(TARGETS bfvmm_support DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
    install(TARGETS bfvmm_support_static DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
else()
    install(TARGETS bfvmm_support DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
    install(TARGETS bfvmm_support_static DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
endif()
