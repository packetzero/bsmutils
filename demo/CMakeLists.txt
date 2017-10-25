set (PROJECT_NAME bsmdemo)
message(STATUS "************  Starting ${PROJECT_NAME}  ************")
project(${PROJECT_NAME})

file(GLOB HDRS "*.h" "../src/include/${CMAKE_SYSTEM_NAME}/*.h" )
file(GLOB SRCS "*.cpp" )

add_executable (${PROJECT_NAME} ${SRCS} ${HDRS})


if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
	target_link_libraries (${PROJECT_NAME} bsmutils
		 "${OS_LIBS}" "${CMAKE_SOURCE_DIR}/deps/libbsm.a")
endif()
