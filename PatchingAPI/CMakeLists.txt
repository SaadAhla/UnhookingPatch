set(CMAKE_SOURCE_DIR src)

add_executable(${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/PatchingAPI.cpp)

if(CMAKE_GENERATOR MATCHES "Visual Studio")
	set_target_properties(${PROJECT_NAME} PROPERTIES FOLDER "PatchingAPI")
endif()