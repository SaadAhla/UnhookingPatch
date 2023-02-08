cmake_minimum_required(VERSION 3.25)

project(PatchingAPI)

set(CMAKE_CXX_STANDARD 20)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)
set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT PatchingAPI)

add_subdirectory(PatchingAPI)

if(CMAKE_GENERATOR MATCHES "Visual Studio")
	set(CMAKE_SUPPRESS_REGENERATION true)
endif()
