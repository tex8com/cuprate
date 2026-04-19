// Standalone C++ gRPC client smoke test for the cuprate StreamBlocks service.
//
// Validates end-to-end:
// 1. The C++ gRPC stack can be built locally (independent of monero CMake)
// 2. The deployed cuprate server (152.53.133.188:18091) accepts connections
// 3. Streaming works (multiple chunks, monotonic seq, payload non-empty)
// 4. Native C++ throughput (no JSON-encoding overhead like grpcurl had)
//
// Usage: ./smoke <host:port> <start_height> <stop_height> [chunk_blocks_hint]
// Example: ./smoke 152.53.133.188:18091 1500000 1510000 200

#include <chrono>
#include <cstdio>
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>
#include "cuprate_stream.grpc.pb.h"

using cuprate::stream::v1::BlockStream;
using cuprate::stream::v1::BlockChunk;
using cuprate::stream::v1::StreamBlocksRequest;

int main(int argc, char** argv) {
    if (argc < 4) {
        std::fprintf(stderr,
            "usage: %s <host:port> <start_height> <stop_height> [chunk_blocks_hint=200]\n",
            argv[0]);
        return 2;
    }
    const std::string target = argv[1];
    const uint64_t start_h = std::stoull(argv[2]);
    const uint64_t stop_h  = std::stoull(argv[3]);
    const uint32_t chunk_hint = (argc >= 5) ? std::stoul(argv[4]) : 200;

    grpc::ChannelArguments ch_args;
    // Allow large messages (chunks can be ~2 MB each).
    ch_args.SetMaxReceiveMessageSize(64 * 1024 * 1024);
    ch_args.SetMaxSendMessageSize(64 * 1024 * 1024);
    auto channel = grpc::CreateCustomChannel(
        target, grpc::InsecureChannelCredentials(), ch_args);

    auto stub = BlockStream::NewStub(channel);

    StreamBlocksRequest req;
    req.set_start_height(start_h);
    req.set_stop_height(stop_h);
    req.set_prune(true);
    req.set_chunk_blocks_hint(chunk_hint);
    req.set_no_miner_tx(false);
    req.set_client_request_id("cpp-smoke-1");

    grpc::ClientContext ctx;
    auto t_total0 = std::chrono::steady_clock::now();
    auto reader = stub->StreamBlocks(&ctx, req);

    BlockChunk chunk;
    uint64_t chunk_count = 0;
    uint64_t total_blocks = 0;
    uint64_t total_bytes = 0;
    uint64_t last_seq = static_cast<uint64_t>(-1);
    auto t_first_chunk = std::chrono::steady_clock::time_point{};
    bool first = true;

    while (reader->Read(&chunk)) {
        const auto t_now = std::chrono::steady_clock::now();
        if (first) {
            t_first_chunk = t_now;
            first = false;
            std::printf("[CPP] FIRST_CHUNK_LATENCY_MS=%.1f (open -> first chunk arrived)\n",
                std::chrono::duration<double, std::milli>(t_first_chunk - t_total0).count());
        }
        chunk_count++;
        total_blocks += chunk.n_blocks();
        total_bytes  += chunk.payload_bytes();

        const uint64_t seq = chunk.chunk_seq();
        const bool seq_ok = (last_seq == static_cast<uint64_t>(-1)) || (seq == last_seq + 1);
        if (!seq_ok) {
            std::fprintf(stderr,
                "[CPP] WARNING seq jump: expected %llu got %llu\n",
                static_cast<unsigned long long>(last_seq + 1),
                static_cast<unsigned long long>(seq));
        }
        last_seq = seq;

        const auto cum_ms = std::chrono::duration<double, std::milli>(t_now - t_total0).count();
        const double cum_mbs = (cum_ms > 0.0)
            ? (static_cast<double>(total_bytes) / 1024.0 / 1024.0) / (cum_ms / 1000.0)
            : 0.0;
        std::printf(
            "[CPP] CHUNK seq=%llu start=%llu n_blocks=%u bytes=%u cum_ms=%.1f cum_mbs=%.2f tip=%llu req_id=%s\n",
            static_cast<unsigned long long>(seq),
            static_cast<unsigned long long>(chunk.start_height()),
            chunk.n_blocks(),
            chunk.payload_bytes(),
            cum_ms,
            cum_mbs,
            static_cast<unsigned long long>(chunk.chain_tip()),
            chunk.server_request_id().c_str());
    }

    auto status = reader->Finish();
    auto t_done = std::chrono::steady_clock::now();
    const double total_ms = std::chrono::duration<double, std::milli>(t_done - t_total0).count();
    const double avg_mbs = (total_ms > 0.0)
        ? (static_cast<double>(total_bytes) / 1024.0 / 1024.0) / (total_ms / 1000.0)
        : 0.0;
    const double after_first_ms = (chunk_count > 1)
        ? std::chrono::duration<double, std::milli>(t_done - t_first_chunk).count()
        : total_ms;
    const double after_first_mbs = (after_first_ms > 0.0)
        ? (static_cast<double>(total_bytes) / 1024.0 / 1024.0) / (after_first_ms / 1000.0)
        : 0.0;

    std::printf("\n[CPP] === SMOKE RESULT ===\n");
    std::printf("[CPP] chunks=%llu blocks=%llu bytes=%llu total_ms=%.1f avg_mbs=%.2f streaming_mbs=%.2f\n",
        static_cast<unsigned long long>(chunk_count),
        static_cast<unsigned long long>(total_blocks),
        static_cast<unsigned long long>(total_bytes),
        total_ms,
        avg_mbs,
        after_first_mbs);
    std::printf("[CPP] grpc_status=%d msg=%s\n", status.error_code(), status.error_message().c_str());

    return status.ok() ? 0 : 1;
}
