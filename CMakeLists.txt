cmake_minimum_required(VERSION 3.20)
project(androidrecomp C CXX)

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
  runtime/shim_asset.cpp
  runtime/shim_file.cpp
  runtime/shim_sys.cpp
  runtime/shim_zlib.cpp
  runtime/shim_varargs.cpp
  runtime/window.cpp
  runtime/jni_env.cpp
  runtime/arm64_runtime.c
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

# The lifted program, when one has been generated. Building it here rather than
# from the verification driver means the dependency discovery above -- zlib,
# SDL2, the platform libraries -- is done once and reused, instead of being
# guessed at a second time.
#
#   python tools/lifter.py libengine.so --out generated
#   cmake -S . -B build-lifted -DARC_LIFTED_DIR=generated
#   cmake --build build-lifted
set(ARC_LIFTED_DIR "" CACHE PATH "directory of generated lifted C")
# One store per guest function call, in exchange for knowing which functions
# ran when something faults. Worth it while a port is being brought up.
option(ARC_FRAMES "record which lifted functions were entered" ON)
if(ARC_FRAMES)
  add_compile_definitions(ARC_FRAMES)
endif()
if(ARC_LIFTED_DIR)
  file(TO_CMAKE_PATH "${ARC_LIFTED_DIR}" ARC_LIFTED_DIR)
  file(GLOB ARC_LIFTED_SOURCES "${ARC_LIFTED_DIR}/*.c")
  list(LENGTH ARC_LIFTED_SOURCES ARC_LIFTED_COUNT)
  if(ARC_LIFTED_COUNT EQUAL 0)
    message(FATAL_ERROR "no generated C in ${ARC_LIFTED_DIR}")
  endif()
  message(STATUS "androidrecomp: lifted program, ${ARC_LIFTED_COUNT} units")
  # The lifter emits arc_dispatch; the runtime's fallback must stand down.
  target_compile_definitions(androidrecomp PUBLIC ARC_LIFTED)
  add_library(lifted SHARED ${ARC_LIFTED_SOURCES}
                            tools/lift_harness.cpp)
  target_include_directories(lifted PRIVATE runtime "${ARC_LIFTED_DIR}")
  target_link_libraries(lifted PRIVATE androidrecomp)
  set_target_properties(lifted PROPERTIES C_STANDARD 11)
  if(MSVC)
    # Optimising 430 MB of generated C buys nothing while it is being checked
    # for correctness, and costs a great deal of build time.
    target_compile_options(lifted PRIVATE /Od /MP)
  else()
    target_compile_options(lifted PRIVATE -O0)
  endif()

  # The boot attempt: runs the lifted program's static constructors, then an
  # entry point. Links the lifted code directly rather than through the shared
  # library, so a fault lands in this process with a usable stack.
  add_executable(arc_boot tools/arc_boot.cpp ${ARC_LIFTED_SOURCES})
  target_include_directories(arc_boot PRIVATE runtime "${ARC_LIFTED_DIR}")
  target_link_libraries(arc_boot PRIVATE androidrecomp)
  if(MSVC)
    target_compile_options(arc_boot PRIVATE /Od /MP)
  else()
    target_compile_options(arc_boot PRIVATE -O0)
  endif()
endif()
