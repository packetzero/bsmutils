set (PROJECT_NAME bsmutils)
message(STATUS "************  Starting ${PROJECT_NAME}  ************")
project(${PROJECT_NAME})


file(GLOB HDRS "*.h" "../include/*.h*" "${CMAKE_SYSTEM_NAME}/*.h")
file(GLOB SRCS "*.cpp" "${CMAKE_SYSTEM_NAME}/*.cpp")

add_library (${PROJECT_NAME} ${SRCS} ${HDRS})

