set (PROJECT_NAME bsmpp-tests)
message(STATUS "************  Starting ${PROJECT_NAME}  ************")
project(${PROJECT_NAME})

if (${CMAKE_SYSTEM_NAME} MATCHES "Windows")
        file(GLOB HDRS "*.h" )
        file(GLOB SRCS "*.cpp" )
else()
	file(GLOB HDRS "*.h" "../src/include/${CMAKE_SYSTEM_NAME}/*.h" )
	file(GLOB SRCS "*.cpp" )
endif()

add_executable (${PROJECT_NAME} ${SRCS} ${HDRS})

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	target_link_libraries (${PROJECT_NAME}
		 bsmpp c dl "${OS_LIBS}" "${GTESTDIR}/${CMAKE_SYSTEM_NAME}/libgtest.a")
endif()

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
	target_link_libraries (${PROJECT_NAME} bsmpp
		 "${OS_LIBS}" "${GTESTDIR}/${CMAKE_SYSTEM_NAME}/libgtest.a" )
endif()
