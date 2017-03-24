add_subdirectory(src)

if(NOT CMAKE_TOOLCHAIN_FILE)
    add_subdirectory(test)
endif()
