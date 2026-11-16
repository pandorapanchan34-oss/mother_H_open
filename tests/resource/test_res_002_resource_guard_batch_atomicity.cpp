// RES-002: ResourceGuard::consume_input_batch() の原子性と境界値検証
#ifndef MOTHER_H_TEST_BUILD
#error "このテストは MOTHER_H_TEST_BUILD を定義したテストターゲットでのみビルドすること"
#endif
#include <cstdint>
#include <cstdio>
#include <limits>
#include <string>
#include <vector>
#include "mother_H/resource/resource_guard.hpp"
using namespace mother_h::resource;
namespace {
constexpr int kPass = 0;
constexpr int kFail = 1;
constexpr int kInvalid = 2;
constexpr int kUnknown = 3;
int fail(const char* what) {
    std::fprintf(stderr, "[FAIL] %s\n", what);
    return kFail;
}
int invalid(const char* what) {
    std::fprintf(stderr, "[TEST_INVALID] %s\n", what);
    return kInvalid;
}
ResourceLimits make_standard_limits() {
    ResourceLimits l;
    l.max_record_bytes = 1000;
    l.max_payload_bytes = 1000;
    l.max_total_input_bytes = 10000;
    l.max_records = 100;
    l.max_profiles = 10;
    l.max_failure_codes_per_profile = 10;
    l.max_steps = 1000;
    l.max_elapsed_time_us = 1000000;
    return l;
}
bool same_usage(const ResourceUsage& a, const ResourceUsage& b) {
    return a.total_input_bytes == b.total_input_bytes &&
           a.records == b.records &&
           a.profiles == b.profiles &&
           a.failure_code_entries == b.failure_code_entries &&
           a.steps == b.steps &&
           a.elapsed_time_us == b.elapsed_time_us;
}
bool read_usage(const ResourceGuard& g, ResourceUsage& out) {
    return g.usage(out) == ResourceStatus::Ok;
}
} // namespace
int main(int argc, char* argv[]) {
    std::string case_name;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg.rfind("--case=", 0) == 0) case_name = arg.substr(7);
    }
    ResourceGuard guard(make_standard_limits());
    if (guard.consume_input(100, 50) != ResourceStatus::Ok) return invalid("S0の構築に失敗");
    ResourceUsage s0;
    if (!read_usage(guard, s0)) return invalid("S0の取得に失敗");
    // ケース 1: BATCH_OK (複数件の一括適用)
    if (case_name == "BATCH_OK") {
        std::vector<InputRecord> batch = { {100, 50}, {200, 100} };
        if (guard.consume_input_batch(batch.data(), batch.size()) != ResourceStatus::Ok) {
            return fail("正常バッチ予約が拒否された");
        }
        ResourceUsage now;
        if (!read_usage(guard, now)) return fail("usage() 取得失敗");
        ResourceUsage expected = s0;
        expected.total_input_bytes += 300;
        expected.records += 2;
        return same_usage(now, expected) ? kPass : fail("使用量の計算不整合");
    }
    // ケース 2: LIMIT_EXACT (上限ぴったり 10000 バイト)
    if (case_name == "LIMIT_EXACT") {
        std::vector<InputRecord> batch;
        for (int i = 0; i < 9; ++i) batch.push_back({1000, 500});
        batch.push_back({900, 450}); // 合計 9900 (S0の100と合わせて exactly 10000)
        if (guard.consume_input_batch(batch.data(), batch.size()) != ResourceStatus::Ok) {
            return fail("LIMIT_EXACT が拒否された");
        }
        ResourceUsage now;
        if (!read_usage(guard, now)) return fail("usage() 取得失敗");
        ResourceUsage expected = s0;
        expected.total_input_bytes = 10000;
        expected.records += 10;
        return same_usage(now, expected) ? kPass : fail("LIMIT_EXACT の使用量不整合");
    }
    // ケース 3: LIMIT_PLUS_ONE (上限 +1 バイト超過)
    if (case_name == "LIMIT_PLUS_ONE") {
        std::vector<InputRecord> batch;
        for (int i = 0; i < 9; ++i) batch.push_back({1000, 500});
        batch.push_back({901, 450}); // 合計 9901 (S0の100と合わせて 10001)
        const ResourceStatus st = guard.consume_input_batch(batch.data(), batch.size());
        if (st != ResourceStatus::LimitExceeded) return fail("LimitExceeded が返されなかった");
        ResourceUsage now;
        if (!read_usage(guard, now)) return fail("usage() 取得失敗");
        return same_usage(now, s0) ? kPass : fail("LIMIT_PLUS_ONE 失敗後に使用量が変化した");
    }
    // ケース 4: OVERFLOW (個別上限を巨大に設定し、UINT64_MAX 超えの集計オーバーフローを検証)
    if (case_name == "OVERFLOW") {
        ResourceLimits huge_limits = make_standard_limits();
        huge_limits.max_record_bytes = std::numeric_limits<std::uint64_t>::max();
        huge_limits.max_total_input_bytes = std::numeric_limits<std::uint64_t>::max();
        ResourceGuard overflow_guard(huge_limits);
        ResourceUsage overflow_s0;
        if (!read_usage(overflow_guard, overflow_s0)) return invalid("OVERFLOW S0の取得に失敗");
        std::vector<InputRecord> batch = {
            { std::numeric_limits<std::uint64_t>::max() - 50, 10 },
            { 100, 10 }
        };
        const ResourceStatus st = overflow_guard.consume_input_batch(batch.data(), batch.size());
        if (st != ResourceStatus::IntegerOverflow) return fail("IntegerOverflow が返されなかった");
        ResourceUsage now;
        if (!read_usage(overflow_guard, now)) return fail("usage() 取得失敗");
        return same_usage(now, overflow_s0) ? kPass : fail("OVERFLOW 失敗後に使用量が変化した");
    }
    // ケース 5: ATOMICITY_THIRD_FAILURE (3件目で失敗した場合の完全ロールバック)
    if (case_name == "ATOMICITY_THIRD_FAILURE") {
        std::vector<InputRecord> batch = {
            { 1000, 500 },
            { 1000, 500 },
            { 9000, 500 } // 3件目で上限オーバー発火
        };
        const ResourceStatus st = guard.consume_input_batch(batch.data(), batch.size());
        if (st != ResourceStatus::LimitExceeded) return fail("3件目での LimitExceeded 検出に失敗");
        ResourceUsage now;
        if (!read_usage(guard, now)) return fail("usage() 取得失敗");
        return same_usage(now, s0) ? kPass : fail("3件目失敗時に状態がロールバックされなかった");
    }
    // ケース 6: EMPTY_BATCH (空バッチの安全確認)
    if (case_name == "EMPTY_BATCH") {
        std::vector<InputRecord> empty_batch;
        if (guard.consume_input_batch(empty_batch.data(), empty_batch.size()) != ResourceStatus::InvalidRequest) {
            return fail("空バッチで InvalidRequest が返されなかった");
        }
        ResourceUsage now;
        if (!read_usage(guard, now)) return fail("usage() 取得失敗");
        return same_usage(now, s0) ? kPass : fail("空バッチ実行後に使用量が変化した");
    }
    std::fprintf(stderr, "未知のケース: %s\n", case_name.c_str());
    return kUnknown;
}
