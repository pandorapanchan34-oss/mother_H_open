#ifndef MOTHER_H_TEST_BUILD
#error "MOTHER_H_TEST_BUILD must be defined for this test target"
#endif
#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include "mother_H/resource/resource_guard.hpp"
using namespace mother_h::resource;
namespace {
constexpr std::size_t kWarmups = 2;
constexpr std::size_t kRepeats = 7;
constexpr std::uint64_t kRecordBytes = 100;
constexpr std::uint64_t kPayloadBytes = 50;
constexpr std::array<std::uint64_t, 6> kScales{
    1, 10, 100, 1000, 10000, 100000
};
ResourceLimits make_bench_limits() {
    ResourceLimits limits;
    limits.max_record_bytes = 10000;
    limits.max_payload_bytes = 10000;
    limits.max_total_input_bytes = 1000000000ULL;
    limits.max_records = 10000000ULL;
    limits.max_profiles = 100;
    limits.max_failure_codes_per_profile = 100;
    limits.max_steps = 10000000ULL;
    limits.max_elapsed_time_us = 1000000000ULL;
    return limits;
}
bool check_usage(
    const ResourceGuard& guard,
    std::uint64_t expected_records
) {
    ResourceUsage usage{};
    if (guard.usage(usage) != ResourceStatus::Ok) {
        return false;
    }
    const std::uint64_t expected_bytes =
        expected_records * kRecordBytes;
    return usage.total_input_bytes == expected_bytes &&
        usage.records == expected_records &&
        usage.profiles == 0 &&
        usage.failure_code_entries == 0 &&
        usage.steps == 0 &&
        usage.elapsed_time_us == 0;
}
bool run_single(
    std::uint64_t count,
    std::uint64_t& elapsed_ns
) {
    ResourceGuard guard(make_bench_limits());
    const auto start = std::chrono::steady_clock::now();
    for (std::uint64_t i = 0; i < count; ++i) {
        if (guard.consume_input(
                kRecordBytes, kPayloadBytes) != ResourceStatus::Ok) {
            return false;
        }
    }
    const auto end = std::chrono::steady_clock::now();
    elapsed_ns = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            end - start).count());
    return check_usage(guard, count);
}
bool run_batch(
    const std::vector<InputRecord>& batch,
    std::uint64_t& elapsed_ns
) {
    ResourceGuard guard(make_bench_limits());
    const auto start = std::chrono::steady_clock::now();
    const ResourceStatus status =
        guard.consume_input_batch(
            batch.data(),
            static_cast<std::uint64_t>(batch.size()));
    const auto end = std::chrono::steady_clock::now();
    elapsed_ns = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            end - start).count());
    return status == ResourceStatus::Ok &&
        check_usage(
            guard,
            static_cast<std::uint64_t>(batch.size()));
}
std::uint64_t median(
    std::array<std::uint64_t, kRepeats> samples
) {
    std::sort(samples.begin(), samples.end());
    return samples[kRepeats / 2];
}
bool measure_scale(std::uint64_t count) {
    const std::vector<InputRecord> batch(
        static_cast<std::size_t>(count),
        InputRecord{kRecordBytes, kPayloadBytes});
    std::uint64_t ignored = 0;
    for (std::size_t i = 0; i < kWarmups; ++i) {
        if (!run_single(count, ignored) ||
            !run_batch(batch, ignored)) {
            std::fprintf(
                stderr,
                "Warm-up failed at %llu records\n",
                static_cast<unsigned long long>(count));
            return false;
        }
    }
    std::array<std::uint64_t, kRepeats> single_samples{};
    std::array<std::uint64_t, kRepeats> batch_samples{};
    for (std::size_t i = 0; i < kRepeats; ++i) {
        if (!run_single(count, single_samples[i])) {
            std::fprintf(
                stderr,
                "Single measurement failed at %llu records\n",
                static_cast<unsigned long long>(count));
            return false;
        }
        if (!run_batch(batch, batch_samples[i])) {
            std::fprintf(
                stderr,
                "Batch measurement failed at %llu records\n",
                static_cast<unsigned long long>(count));
            return false;
        }
    }
    const std::uint64_t single_ns = median(single_samples);
    const std::uint64_t batch_ns = median(batch_samples);
    if (single_ns == 0 || batch_ns == 0) {
        std::fprintf(stderr, "Invalid zero-duration measurement\n");
        return false;
    }
    const double single_per_record =
        static_cast<double>(single_ns) /
        static_cast<double>(count);
    const double batch_per_record =
        static_cast<double>(batch_ns) /
        static_cast<double>(count);
    const double speedup =
        static_cast<double>(single_ns) /
        static_cast<double>(batch_ns);
    std::printf(
        "%7llu | %12llu | %12llu | %12.2f | %12.2f | %8.2fx\n",
        static_cast<unsigned long long>(count),
        static_cast<unsigned long long>(single_ns),
        static_cast<unsigned long long>(batch_ns),
        single_per_record,
        batch_per_record,
        speedup);
    return true;
}
} // namespace
int main() {
    std::printf(
        "Records | Single ns | Batch ns | Single ns/rec | Batch ns/rec | Speedup\n");
    std::printf(
        "--------+-----------+----------+---------------+--------------+--------\n");
    for (const std::uint64_t count : kScales) {
        if (!measure_scale(count)) {
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}
