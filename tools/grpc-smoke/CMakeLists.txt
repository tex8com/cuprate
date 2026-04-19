cmake_minimum_required(VERSION 3.20)
project(cuprate_grpc_smoke CXX)

# Standalone C++ smoke test for the cuprated BlockStream gRPC endpoint.
# Independent of the cuprated Cargo build — useful for validating the C++
# gRPC stack against a deployed server BEFORE doing the invasive monero
# wallet integration.
#
# Build (macOS): brew install grpc cmake
#   cd tools/grpc-smoke && cmake -B build && cmake --build build
# Build (Linux): apt install libgrpc++-dev libprotobuf-dev protobuf-compiler-grpc cmake
#
# Run: ./build/smoke <host:port> <start_height> <stop_height> [chunk_blocks_hint=200]
# Example: ./build/smoke 152.53.133.188:18091 1500000 1510000 1000

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)

# Reuse the canonical proto file from the cuprated binary so the smoke test
# can never drift out of sync with the actual server schema.
set(PROTO_FILE "${CMAKE_CURRENT_SOURCE_DIR}/../../binaries/cuprated/proto/cuprate_stream.proto")
set(PROTO_DIR  "${CMAKE_CURRENT_SOURCE_DIR}/../../binaries/cuprated/proto")
set(PROTO_OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/gen")
file(MAKE_DIRECTORY "${PROTO_OUT_DIR}")

# grpc_cpp_plugin location varies by platform. Allow override via -D.
if(NOT DEFINED GRPC_CPP_PLUGIN_PATH)
    find_program(GRPC_CPP_PLUGIN_PATH grpc_cpp_plugin REQUIRED)
endif()

set(GENERATED_PB
    "${PROTO_OUT_DIR}/cuprate_stream.pb.cc"
    "${PROTO_OUT_DIR}/cuprate_stream.pb.h"
    "${PROTO_OUT_DIR}/cuprate_stream.grpc.pb.cc"
    "${PROTO_OUT_DIR}/cuprate_stream.grpc.pb.h"
)

add_custom_command(
    OUTPUT ${GENERATED_PB}
    COMMAND protoc
        --proto_path=${PROTO_DIR}
        --cpp_out=${PROTO_OUT_DIR}
        --grpc_out=${PROTO_OUT_DIR}
        --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN_PATH}
        ${PROTO_FILE}
    DEPENDS ${PROTO_FILE}
    COMMENT "protoc + grpc-cpp-plugin: cuprate_stream.proto"
)

add_executable(smoke
    main.cpp
    ${GENERATED_PB}
)

target_include_directories(smoke PRIVATE ${PROTO_OUT_DIR})
target_link_libraries(smoke PRIVATE
    gRPC::grpc++
    protobuf::libprotobuf
)
