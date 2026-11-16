// RES-001: ResourceGuard::reserve() の整合性と例外安全性 (C1〜C7)
//
// 実行: test_res_001_resource_guard_exception_safety --case=C1 (C1〜C7、ケースごとに別プロセス)
//
// 終了コード:
//   0 = PASS
//   1 = FAIL          (期待と異なる結果)
//   2 = TEST_INVALID  (前提の構築に失敗した、または例外注入が発火しなかった)
//   3 = 未知のケース名
// 2 と 3 はPASSではない。CTestでは失敗として扱われる。
//
// このテストは、テストビルド専用の定義 MOTHER_H_TEST_BUILD の下でだけビルドする。

#ifndef MOTHER_H_TEST_BUILD
#error "このテストは MOTHER_H_TEST_BUILD を定義したテストターゲットでのみビルドすること"
#endif

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <unordered_set>
#include <utility>

// ---- 例外注入: FailureCodeSet のアロケータが length_error を投げる ----
struct InjectionControl {
    static inline std::atomic<bool> armed{false};
    static inline std::atomic<int> fires{0};
};

template <class T>
struct ThrowingAllocator {
    using value_type = T;

    ThrowingAllocator() noexcept = default;
    template <class U>
    ThrowingAllocator(const ThrowingAllocator<U>&) noexcept {}

    T* allocate(std::size_t n) {
        if (InjectionControl::armed.load()) {
            ++InjectionControl::fires;
            throw std::length_error("injected length_error");
        }
        return std::allocator<T>{}.allocate(n);
    }
    void deallocate(T* p, std::size_t n) noexcept { std::allocator<T>{}.deallocate(p, n); }

    template <class U>
    bool operator==(const ThrowingAllocator<U>&) const noexcept { return true; }
    template <class U>
    bool operator!=(const ThrowingAllocator<U>&) const noexcept { return false; }
};

using InjectedFailureCodeSet = std::unordered_set<
    std::uint64_t,
    std::hash<std::uint64_t>,
    std::equal_to<std::uint64_t>,
    ThrowingAllocator<std::uint64_t>>;

// 接合部: resource_guard.hpp の FailureCodeSet をこの型に差し替える。
#define MOTHER_H_RESOURCE_GUARD_FAILURE_CODE_SET ::InjectedFailureCodeSet
#include "mother_H/resource/resource_guard.hpp"

using namespace mother_h::resource;

static_assert(noexcept(std::declval<ResourceGuard&>().reserve(
                  std::declval<const ResourceReservation&>())),
              "reserve() は noexcept であること");

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

ResourceLimits make_limits() {
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

// 6項目すべてを比較する。elapsed_time_us は呼び出し側が渡した値の加算で決定的なので、除外しない。
bool same_usage(const ResourceUsage& a, const ResourceUsage& b) {
    return a.total_input_bytes == b.total_input_bytes && a.records == b.records &&
           a.profiles == b.profiles && a.failure_code_entries == b.failure_code_entries &&
           a.steps == b.steps && a.elapsed_time_us == b.elapsed_time_us;
}

bool read_usage(const ResourceGuard& g, ResourceUsage& out) {
    return g.usage(out) == ResourceStatus::Ok;
}

ResourceReservation input_reservation(
    std::uint64_t record_bytes,
    std::uint64_t payload_bytes,
    std::uint64_t total_input_bytes,
    std::uint64_t records
) {
    ResourceReservation r;
    r.record_bytes = record_bytes;
    r.payload_bytes = payload_bytes;
    r.total_input_bytes = total_input_bytes;
    r.records = records;
    return r;
}

ResourceReservation with_failure_code(
    ResourceReservation r,
    std::uint64_t profile_id,
    std::uint64_t failure_code_id
) {
    r.has_profile = true;
    r.profile_id = profile_id;
    r.has_failure_code = true;
    r.failure_code_id = failure_code_id;
    return r;
}

// 拒否されたこと、使用量が基準と同一であること、status()==Ok であることを確認する。
int check_rejected(ResourceGuard& g, const ResourceReservation& r, const ResourceUsage& base) {
    const ResourceStatus st = g.reserve(r);
    if (st != ResourceStatus::InvalidRequest) return fail("戻り値が InvalidRequest ではない");
    ResourceUsage now;
    if (!read_usage(g, now)) return fail("usage() を取得できない");
    if (!same_usage(now, base)) return fail("拒否後に使用量が変化した");
    if (g.status() != ResourceStatus::Ok) return fail("拒否後に status() が Ok ではない");
    return kPass;
}

// 例外注入下で reserve() を実行し、InternalError・使用量不変・status()==Ok を確認する。
int check_injected(ResourceGuard& g, const ResourceReservation& r, const ResourceUsage& base) {
    ResourceUsage usage_before;
    if (!read_usage(g, usage_before)) return invalid("例外注入前の usage() を取得できない");
    if (!same_usage(usage_before, base)) return fail("例外注入前の使用量が基準状態と異なる");
    const auto profiles_before = GuardTestInspector::extract_profiles(g);

    InjectionControl::fires = 0;
    InjectionControl::armed = true;
    const ResourceStatus st = g.reserve(r);  // noexcept。漏れた例外は terminate になる(REDで検出)
    InjectionControl::armed = false;

    if (InjectionControl::fires.load() == 0) {
        return invalid("例外注入が発火しなかった");
    }
    if (st != ResourceStatus::InternalError) return fail("戻り値が InternalError ではない");
    ResourceUsage now;
    if (!read_usage(g, now)) return fail("usage() を取得できない");
    if (!same_usage(now, usage_before) || !same_usage(now, base)) {
        return fail("失敗後に使用量が変化した");
    }
    const auto profiles_after = GuardTestInspector::extract_profiles(g);
    if (profiles_after != profiles_before) return fail("失敗後に profiles_ の内容が変化した");
    if (g.status() != ResourceStatus::Ok) return fail("失敗後に status() が Ok ではない");
    return kPass;
}

}  // namespace

int main(int argc, char* argv[]) {
    std::string case_name;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg.rfind("--case=", 0) == 0) case_name = arg.substr(7);
    }

    ResourceGuard guard(make_limits());

    // 基準状態 S0: consume_input(10, 5) の成功後
    if (guard.reserve(input_reservation(10, 5, 10, 1)) != ResourceStatus::Ok) return invalid("S0の構築に失敗");
    ResourceUsage s0;
    if (!read_usage(guard, s0)) return invalid("S0の取得に失敗");

    if (case_name == "C1") {
        // 単一レコード予約に records=2 を指定: InvalidRequest
        return check_rejected(guard, input_reservation(10, 5, 10, 2), s0);
    }
    if (case_name == "C2") {
        return check_rejected(guard, input_reservation(10, 5, 10, 0), s0);
    }
    if (case_name == "C3") {
        // total_input_bytes(9) < record_bytes(10)
        return check_rejected(guard, input_reservation(10, 5, 10 - 1, 1), s0);
    }
    if (case_name == "C4") {
        // 正常系: records と total_input_bytes だけが増える
        if (guard.reserve(input_reservation(10, 5, 10, 1)) != ResourceStatus::Ok) {
            return fail("戻り値が Ok ではない");
        }
        ResourceUsage now;
        if (!read_usage(guard, now)) return fail("usage() を取得できない");
        ResourceUsage expected = s0;
        expected.records += 1;
        expected.total_input_bytes += 10;
        return same_usage(now, expected) ? kPass : fail("使用量の増分が期待と異なる");
    }
    if (case_name == "C5") {
        // 件数のみの予約(record_bytes=0): records だけが+2
        if (guard.reserve(input_reservation(0, 0, 0, 2)) != ResourceStatus::Ok) {
            return fail("戻り値が Ok ではない");
        }
        ResourceUsage now;
        if (!read_usage(guard, now)) return fail("usage() を取得できない");
        ResourceUsage expected = s0;
        expected.records += 2;
        return same_usage(now, expected) ? kPass : fail("使用量の増分が期待と異なる");
    }
    if (case_name == "C6") {
        // 新規プロファイル + Failure Code の追加中に例外。基準は S0。
        const ResourceReservation r = with_failure_code(input_reservation(10, 5, 10, 1), 1, 100);
        return check_injected(guard, r, s0);
    }
    if (case_name == "C7") {
        // 既存プロファイルへの Failure Code の追加中に例外。基準は S1(先に成功した予約の後)。
        InjectionControl::armed = false;
        const ResourceReservation prep = with_failure_code(input_reservation(10, 5, 10, 1), 1, 100);
        if (guard.reserve(prep) != ResourceStatus::Ok) return invalid("C7の前提予約に失敗");
        ResourceUsage s1;
        if (!read_usage(guard, s1)) return invalid("S1の取得に失敗");

        const ResourceReservation r = with_failure_code(input_reservation(10, 5, 10, 1), 1, 101);
        return check_injected(guard, r, s1);
    }

    std::fprintf(stderr, "未知のケース: %s\n", case_name.c_str());
    return kUnknown;
}
