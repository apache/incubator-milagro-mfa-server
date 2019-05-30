cmake_minimum_required(VERSION 3.0 FATAL_ERROR)
project(milagro-grpc VERSION 0.1.0 LANGUAGES CXX)
get_filename_component(PROJECT_ROOT ${CMAKE_CURRENT_LIST_FILE} DIRECTORY)
list(APPEND CMAKE_PREFIX_PATH "/usr/local" )
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MODULE_PATH "${PROJECT_ROOT}/cmake")
set(SERVER_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}/include")
set(CPP_MILAGRO_INCLUDE_DIR "/usr/local/include/amcl")
set(CPP_MILAGRO_LIB "/usr/lib/amcl")
set(BSD_ARC_LIB "/usr/lib/x86_64-linux-gnu/libbsd.a")
# Cmake find modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
find_package(Boost 1.50.0 COMPONENTS system  REQUIRED)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)  
set(CPP_REST_FOUND False)
set(protobuf_MODULE_COMPATIBLE TRUE)
find_package(Protobuf REQUIRED)
message(STATUS "Using protobuf ${protobuf_VERSION}")
find_package(GRPC  REQUIRED)
message(STATUS "Using gRPC ${gRPC_VERSION}")

include_directories(${Protobuf_INCLUDE_DIRS})

set(PROTOS
    ${CMAKE_CURRENT_SOURCE_DIR}/protos/mpin.proto
    ${CMAKE_CURRENT_SOURCE_DIR}/protos/dta.proto
    ${CMAKE_CURRENT_SOURCE_DIR}/protos/rps.proto
    ${CMAKE_CURRENT_SOURCE_DIR}/protos/rpa.proto
)
set(PROTO_SRC_DIR ${CMAKE_CURRENT_BINARY_DIR}/proto-generated)
set(PROTO_SRC_PYTHON_DIR ${CMAKE_CURRENT_BINARY_DIR}/protopy-generated)

file(MAKE_DIRECTORY ${PROTO_SRC_DIR})
file(MAKE_DIRECTORY ${PROTO_SRC_PYTHON_DIR})

include_directories(${PROTO_SRC_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${Protobuf_INCLUDE_DIRS})
include_directories(${SERVER_INCLUDE})
include_directories(SYSTEM ${OPENSSL_INCLUDE_DIR})

protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_SRC_DIR} ${PROTOS})
grpc_generate_cpp(GRPC_SRCS GRPC_HDRS ${PROTO_SRC_DIR} ${PROTOS})
#protobuf_generate_python(PY_PROTO ${PROTOS})
#grpc_generate_python(PY_GRPC_SRCS  ${PROTO_SRC_PYTHON_DIR} ${PROTOS})



if(NOT MSVC)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1z")
add_definitions(-DLINUX)
else()
add_definitions(-D_WIN32_WINNT=0x600)
endif()

list(APPEND INCLUDE_EXT_DIRS ${Boost_INCLUDE_DIRS})
include_directories(SYSTEM ${CPP_MILAGRO_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR} ${PROJECT_ROOT}/include)

file(GLOB DTA_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/dta/*.cpp")

if (UNIX)
SET(LINK_FLAGS "-lssl -lcrypto -lboost_system -lbsd")
add_definitions(-Wno-sign-compare -Wno-enum-compare -DBOOST_ALL_DYN_LINK)
endif()

SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${LINK_FLAGS}" )

add_executable(dtaservice 
                ${PROTO_SRCS}
                ${GRPC_SRCS}
                ${DTA_SOURCES}
            )

target_link_libraries(dtaservice PRIVATE 
                      ${OPENSSL_LIBRARIES} 
                      ${CMAKE_DL_LIBS} 
                      ${Boost_SYSTEM_LIBRARY}
                      ${CPP_MILAGRO_LIB}/amcl.a
                      ${BSD_ARC_LIB} 
                      gRPC::grpc++_reflection
                      protobuf::libprotobuf)
