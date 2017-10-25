set (PROJECT_NAME bsmutils-tests)
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


target_link_libraries (${PROJECT_NAME} bsmutils
	 "${OS_LIBS}" "${GTESTDIR}/${CMAKE_SYSTEM_NAME}/libgtest.a"
         "${CMAKE_SOURCE_DIR}/deps/libbsm.a" )
