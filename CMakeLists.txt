cmake_minimum_required(VERSION 2.8.11)

set(ProjectName "Boa-QT" CACHE STRING "Project Name")
project(${ProjectName})
set(CMAKE_BUILD_TYPE "DEBUG")

set(ProjectDir "${CMAKE_SOURCE_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ggdb3")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=core2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mtune=native")

if (NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE "RELEASE")
endif()

set(ProjectLibs "-lpthread")
file(GLOB ProjectFiles
    "${ProjectDir}/src/*.hpp"
    "${ProjectDir}/src/*.cpp"
)
source_group("project" FILES ${ProjectFiles})

set(ProjectIncludeDirectories ${CMAKE_CURRENT_BINARY_DIR})

find_package(PkgConfig REQUIRED)
pkg_check_modules(BOTAN REQUIRED botan-2)

find_package(Qt5Widgets)
set(CMAKE_AUTOMOC ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(ProjectBinary "boa-qt")
add_executable(${ProjectBinary} ${ProjectFiles})
set(CMAKE_INSTALL_PREFIX "/usr/local/")
install(TARGETS ${ProjectBinary} RUNTIME DESTINATION "bin/")
target_include_directories(${ProjectBinary} PUBLIC ${ProjectIncludeDirectories} PUBLIC ${BOTAN_INCLUDE_DIRS})
set_target_properties(${ProjectBinary} PROPERTIES PROJECT_LABEL "${ProjectName}")
target_link_libraries(${ProjectBinary} ${ProjectLibs} Qt5::Widgets ${BOTAN_LIBRARIES})
