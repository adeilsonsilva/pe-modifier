cmake_minimum_required(VERSION 3.12 FATAL_ERROR)
project(pe_injector)

if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/build/install CACHE PATH "Default install directory" FORCE)
endif ()

if (MSVC)
  # Default CMAKE_PREFIX_PATH is empty and CMAKE_SYSTEM_PREFIX_PATH is
  # set to a list of Program Files directories, which is a problem because
  # pe-parser-library (by default) installs itself to `%SystemDrive%\usr`
  # directory on Windows its not found by CMake when performing its search.
  list(APPEND CMAKE_PREFIX_PATH /usr/lib/cmake)

  list(APPEND PEADDRCONV_CXXFLAGS /W4 /WX /analyze)

  if (CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    list(APPEND PEADDRCONV_CXXFLAGS /Zi)
  endif ()

else ()
  set(CMAKE_CXX_STANDARD 17)
  set(CMAKE_CXX_EXTENSIONS OFF)

  list(APPEND PEADDRCONV_CXXFLAGS
    -pedantic -Wall -Wextra -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization
    -Wformat=2 -Winit-self -Wlong-long -Wmissing-declarations -Wmissing-include-dirs -Wcomment
    -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-conversion
    -Wsign-promo -Wstrict-overflow=5 -Wswitch-default -Wundef -Werror -Wunused -Wuninitialized
    -Wno-missing-declarations
  )

  if (CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    list(APPEND PEADDRCONV_CXXFLAGS -gdwarf-2 -g3)
  endif ()
endif ()

# we add the files in the include directory to be included
# while compiling all the source code
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/dependencies/pe-parse/build/include)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(pe-parse REQUIRED)
find_package(Python COMPONENTS Interpreter Development REQUIRED)
find_package(pybind11 REQUIRED)

add_library(_section src/Section.cpp)
add_library(_injector src/Injector.cpp)
pybind11_add_module(${PROJECT_NAME}_py pybind11.cpp)

add_executable(${PROJECT_NAME} main.cpp)

target_link_libraries(_injector _section)
target_link_libraries(${PROJECT_NAME} _injector)
target_link_libraries(${PROJECT_NAME} pe-parse::pe-parser-library)
target_compile_options(${PROJECT_NAME} PRIVATE ${PEADDRCONV_CXXFLAGS})

# https://github.com/pybind/pybind11/issues/387
target_link_libraries(${PROJECT_NAME}_py PRIVATE _section)

# set_property(TARGET ${PROJECT_NAME}_py PROPERTY POSITION_INDEPENDENT_CODE ON)

install(TARGETS ${PROJECT_NAME} DESTINATION "bin")
