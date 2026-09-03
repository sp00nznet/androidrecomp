cmake_minimum_required(VERSION 3.20)
project(androidrecomp CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
  add_compile_options(/W4)
  # windows.h defines min/max macros that collide with <algorithm>, and the
  # shim forwarders deliberately reimplement strcpy/strcat & friends.
  add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
else()
  add_compile_options(-Wall -Wextra)
endif()

# The reusable half: loader, Bionic/Android shims, host window. A port links
# this and supplies only its own title-specific bridge.
add_library(androidrecomp STATIC
  runtime/elf_image.cpp
  runtime/shim.cpp
  runtime/shim_pthread.cpp
  runtime/shim_posix.cpp
  runtime/shim_gl.cpp
  runtime/shim_file.cpp
  runtime/shim_sys.cpp
  runtime/window.cpp
)
target_include_directories(androidrecomp PUBLIC runtime)

if(UNIX AND NOT APPLE)
  target_link_libraries(androidrecomp PUBLIC dl)
endif()
if(WIN32)
  target_link_libraries(androidrecomp PUBLIC ws2_32)
endif()

# zlib satisfies a dozen imports directly -- Bionic ships stock zlib, so every
# signature matches. On Windows point CMake at vcpkg:
#   -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
find_package(ZLIB QUIET)
if(ZLIB_FOUND)
  target_link_libraries(androidrecomp PUBLIC ZLIB::ZLIB)
  target_compile_definitions(androidrecomp PUBLIC ARC_HAVE_ZLIB)
  message(STATUS "androidrecomp: zlib found")
else()
  message(STATUS "androidrecomp: no zlib -- those imports stay on the work list")
endif()

# SDL2 supplies the window, the GL context and the event loop. Without it the
# library still loads and reports, it just cannot open a window -- and GL
# imports stay outstanding, since they bind through the live GL driver.
find_package(SDL2 CONFIG QUIET)
if(SDL2_FOUND)
  target_link_libraries(androidrecomp PUBLIC
    $<TARGET_NAME_IF_EXISTS:SDL2::SDL2>
    $<TARGET_NAME_IF_EXISTS:SDL2::SDL2main>)
  target_compile_definitions(androidrecomp PUBLIC ARC_HAVE_SDL2)
  message(STATUS "androidrecomp: SDL2 found -- window enabled")
else()
  message(STATUS "androidrecomp: no SDL2 -- headless, no window")
endif()

# Standalone triage tool. Ports usually build their own host instead, linking
# the library above and passing their own contract.
if(PROJECT_IS_TOP_LEVEL OR NOT DEFINED PROJECT_IS_TOP_LEVEL)
  add_executable(arc_host tools/arc_host.cpp)
  target_link_libraries(arc_host PRIVATE androidrecomp)
endif()
