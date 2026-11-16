#pragma once

#include <cstdint>
#include <limits>
#include <mutex>
#include <new>
#include <system_error>
#include <unordered_map>
#include <unordered_set>

namespace mother_h::policy { class JournalFeedbackEngine; }

namespace mother_h::resource {

struct ResourceLimits {
    std::uint64_t max_record_bytes{0};
    std::uint64_t max_payload_bytes{0};
    std::uint64_t max_total_input_bytes{0};
    std::uint64_t max_records{0};
    std::uint64_t max_profiles{0};
    std::uint64_t max_failure_codes_per_profile{0};
    std::uint64_t max_steps{0};
    std::uint64_t max_elapsed_time_us{0};

    bool valid() const noexcept {
        return max_record_bytes != 0 &&
            max_payload_bytes != 0 &&
            max_total_input_bytes != 0 &&
            max_records != 0 &&
            max_profiles != 0 &&
            max_failure_codes_per_profile != 0 &&
            max_steps != 0 &&
            max_elapsed_time_us != 0;
    }

    bool operator==(const ResourceLimits& other) const noexcept {
        return max_record_bytes == other.max_record_bytes &&
               max_payload_bytes == other.max_payload_bytes &&
               max_total_input_bytes == other.max_total_input_bytes &&
               max_records == other.max_records &&
               max_profiles == other.max_profiles &&
               max_failure_codes_per_profile == other.max_failure_codes_per_profile &&
               max_steps == other.max_steps &&
               max_elapsed_time_us == other.max_elapsed_time_us;
    }

    bool operator!=(const ResourceLimits& other) const noexcept {
        return !(*this == other);
    }
};

enum class ResourceStatus : std::uint8_t {
    Ok,
    LimitExceeded,
    InvalidLimits,
    InvalidRequest,
    IntegerOverflow,
    InternalError
};

struct ResourceUsage {
    std::uint64_t total_input_bytes{0};
    std::uint64_t records{0};
    std::uint64_t profiles{0};
    std::uint64_t failure_code_entries{0};
    std::uint64_t steps{0};
    std::uint64_t elapsed_time_us{0};
};

struct ResourceReservation {
    std::uint64_t record_bytes{0};
    std::uint64_t payload_bytes{0};
    std::uint64_t total_input_bytes{0};
    std::uint64_t records{0};
    std::uint64_t steps{0};
    std::uint64_t elapsed_time_us{0};
    bool has_profile{false};
    std::uint64_t profile_id{0};
    bool has_failure_code{false};
    std::uint64_t failure_code_id{0};

    bool empty() const noexcept {
        return record_bytes == 0 &&
            payload_bytes == 0 &&
            total_input_bytes == 0 &&
            records == 0 &&
            steps == 0 &&
            elapsed_time_us == 0 &&
            !has_profile &&
            !has_failure_code;
    }
};

// バッチ入力用: ガード自身が各レコードを検査し、合計を計算する。
struct InputRecord {
    std::uint64_t record_bytes{0};
    std::uint64_t payload_bytes{0};
};

class ResourceGuard {
public:
    explicit ResourceGuard(ResourceLimits limits) noexcept : limits_(limits) {}

    const ResourceLimits& limits() const noexcept {
        return limits_;
    }

    ResourceUsage usage() const noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            return usage_;
        } catch (...) {
            return ResourceUsage{};
        }
    }

    bool commit_state_from(ResourceGuard&& shadow) noexcept {
        if (this == &shadow) return true;
        try {
            if (limits_ != shadow.limits_) {
                return false;
            }
            std::scoped_lock lock(mutex_, shadow.mutex_);
            if (shadow.validate_usage_locked() != ResourceStatus::Ok) {
                return false;
            }
            std::swap(profiles_, shadow.profiles_);
            std::swap(usage_, shadow.usage_);
            return true;
        } catch (...) {
            return false;
        }
    }

    ResourceStatus status() const noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            return limits_.valid() ? validate_usage_locked() : ResourceStatus::InvalidLimits;
        } catch (...) {
            return ResourceStatus::InternalError;
        }
    }

    ResourceStatus check_input_sizes(
        std::uint64_t record_bytes,
        std::uint64_t payload_bytes
    ) const noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            const ResourceStatus ready = ready_locked();
            if (ready != ResourceStatus::Ok) return ready;
            return check_input_sizes_locked(record_bytes, payload_bytes);
        } catch (...) {
            return ResourceStatus::InternalError;
        }
    }

    ResourceStatus check_record_count(std::uint64_t additional) const noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            const ResourceStatus ready = ready_locked();
            return ready == ResourceStatus::Ok
                ? check_add(usage_.records, additional, limits_.max_records)
                : ready;
        } catch (...) {
            return ResourceStatus::InternalError;
        }
    }

    ResourceStatus check_profile(std::uint64_t profile_id) const noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            const ResourceStatus ready = ready_locked();
            if (ready != ResourceStatus::Ok) return ready;
            return profiles_.find(profile_id) != profiles_.end() ||
                    profiles_.size() < limits_.max_profiles
                ? ResourceStatus::Ok
                : ResourceStatus::LimitExceeded;
        } catch (...) {
            return ResourceStatus::InternalError;
        }
    }

    ResourceStatus check_failure_code(
        std::uint64_t profile_id,
        std::uint64_t failure_code_id
    ) const noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            const ResourceStatus ready = ready_locked();
            if (ready != ResourceStatus::Ok) return ready;
            const auto profile = profiles_.find(profile_id);
            if (profile == profiles_.end()) {
                if (profiles_.size() >= limits_.max_profiles) {
                    return ResourceStatus::LimitExceeded;
                }
                return limits_.max_failure_codes_per_profile == 0
                    ? ResourceStatus::InvalidLimits
                    : ResourceStatus::Ok;
            }
            return profile->second.find(failure_code_id) != profile->second.end() ||
                    profile->second.size() < limits_.max_failure_codes_per_profile
                ? ResourceStatus::Ok
                : ResourceStatus::LimitExceeded;
        } catch (...) {
            return ResourceStatus::InternalError;
        }
    }

    ResourceStatus check_total_input_bytes(std::uint64_t additional) const noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            const ResourceStatus ready = ready_locked();
            return ready == ResourceStatus::Ok
                ? check_add(
                      usage_.total_input_bytes,
                      additional,
                      limits_.max_total_input_bytes)
                : ready;
        } catch (...) {
            return ResourceStatus::InternalError;
        }
    }

    ResourceStatus check_steps(std::uint64_t additional) const noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            const ResourceStatus ready = ready_locked();
            return ready == ResourceStatus::Ok
                ? check_add(usage_.steps, additional, limits_.max_steps)
                : ready;
        } catch (...) {
            return ResourceStatus::InternalError;
        }
    }

    ResourceStatus check_elapsed_time_us(std::uint64_t additional) const noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            const ResourceStatus ready = ready_locked();
            return ready == ResourceStatus::Ok
                ? check_add(
                      usage_.elapsed_time_us,
                      additional,
                      limits_.max_elapsed_time_us)
                : ready;
        } catch (...) {
            return ResourceStatus::InternalError;
        }
    }

    // 契約:
    //  - record_bytes != 0 の予約は単一レコードを表し、records == 1 が必須。
    //    複数レコードを予約する場合は consume_input_batch() を使うこと。
    //  - 失敗時(InternalError を含む)は使用量を変更しない。
    //  - 想定外の例外は InternalError に変換され、noexcept 境界を越えない。
    ResourceStatus reserve(const ResourceReservation& request) noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            const ResourceStatus ready = ready_locked();
            if (ready != ResourceStatus::Ok) return ready;
            if (request.empty() ||
                (request.has_failure_code && !request.has_profile)) {
                return ResourceStatus::InvalidRequest;
            }
            if (request.record_bytes == 0) {
                if (request.payload_bytes != 0 || request.total_input_bytes != 0) {
                    return ResourceStatus::InvalidRequest;
                }
            } else {
                if (request.records != 1 ||
                    request.total_input_bytes < request.record_bytes) {
                    return ResourceStatus::InvalidRequest;
                }
                const ResourceStatus size_status =
                    check_input_sizes_locked(request.record_bytes, request.payload_bytes);
                if (size_status != ResourceStatus::Ok) return size_status;
            }
            return apply_locked(request);
        } catch (...) {
            return ResourceStatus::InternalError;
        }
    }

    ResourceStatus consume_input(
        std::uint64_t record_bytes,
        std::uint64_t payload_bytes
    ) noexcept {
        return reserve(ResourceReservation{
            record_bytes, payload_bytes, record_bytes, 1});
    }

    // 複数レコードを一括で計上する。各レコードの検査と合計の計算はガード側で行う。
    ResourceStatus consume_input_batch(
        const InputRecord* items,
        std::uint64_t count
    ) noexcept {
        if (items == nullptr || count == 0) return ResourceStatus::InvalidRequest;
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            const ResourceStatus ready = ready_locked();
            if (ready != ResourceStatus::Ok) return ready;

            const std::uint64_t maximum = (std::numeric_limits<std::uint64_t>::max)();
            std::uint64_t total = 0;
            for (std::uint64_t i = 0; i < count; ++i) {
                const ResourceStatus size_status = check_input_sizes_locked(
                    items[i].record_bytes, items[i].payload_bytes);
                if (size_status != ResourceStatus::Ok) return size_status;
                if (items[i].record_bytes > maximum - total) {
                    return ResourceStatus::IntegerOverflow;
                }
                total += items[i].record_bytes;
            }

            ResourceReservation request;
            request.records = count;
            request.total_input_bytes = total;
            return apply_locked(request);
        } catch (...) {
            return ResourceStatus::InternalError;
        }
    }

    ResourceStatus consume_record_count(std::uint64_t count) noexcept {
        if (count == 0) return ResourceStatus::InvalidRequest;
        ResourceReservation request;
        request.records = count;
        return reserve(request);
    }

    ResourceStatus consume_profile(std::uint64_t profile_id) noexcept {
        ResourceReservation request;
        request.has_profile = true;
        request.profile_id = profile_id;
        return reserve(request);
    }

    ResourceStatus consume_failure_code(
        std::uint64_t profile_id,
        std::uint64_t failure_code_id
    ) noexcept {
        ResourceReservation request;
        request.has_profile = true;
        request.profile_id = profile_id;
        request.has_failure_code = true;
        request.failure_code_id = failure_code_id;
        return reserve(request);
    }

    ResourceStatus consume_steps(std::uint64_t steps) noexcept {
        if (steps == 0) return ResourceStatus::InvalidRequest;
        ResourceReservation request;
        request.steps = steps;
        return reserve(request);
    }

    ResourceStatus consume_elapsed_time_us(std::uint64_t elapsed_time_us) noexcept {
        if (elapsed_time_us == 0) return ResourceStatus::InvalidRequest;
        ResourceReservation request;
        request.elapsed_time_us = elapsed_time_us;
        return reserve(request);
    }

    ResourceStatus remaining_steps(std::uint64_t& remaining) const noexcept {
        return remaining_for(
            &ResourceUsage::steps, &ResourceLimits::max_steps, remaining);
    }

    ResourceStatus remaining_time_us(std::uint64_t& remaining) const noexcept {
        return remaining_for(
            &ResourceUsage::elapsed_time_us,
            &ResourceLimits::max_elapsed_time_us,
            remaining);
    }

    ResourceStatus usage(ResourceUsage& out) const noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            const ResourceStatus ready = ready_locked();
            if (ready != ResourceStatus::Ok) return ready;
            out = usage_;
            return ResourceStatus::Ok;
        } catch (...) {
            return ResourceStatus::InternalError;
        }
    }

    ResourceStatus reset_usage() noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!limits_.valid()) return ResourceStatus::InvalidLimits;
            profiles_.clear();
            usage_ = {};
            return ResourceStatus::Ok;
        } catch (...) {
            return ResourceStatus::InternalError;
        }
    }

private:
#if defined(MOTHER_H_RESOURCE_GUARD_FAILURE_CODE_SET) && \
    !defined(MOTHER_H_TEST_BUILD)
#error "MOTHER_H_RESOURCE_GUARD_FAILURE_CODE_SET is available only in test builds"
#endif

#ifdef MOTHER_H_RESOURCE_GUARD_FAILURE_CODE_SET
    using FailureCodeSet = MOTHER_H_RESOURCE_GUARD_FAILURE_CODE_SET;
#else
    using FailureCodeSet = std::unordered_set<std::uint64_t>;
#endif

    static ResourceStatus check_add(
        std::uint64_t current,
        std::uint64_t requested,
        std::uint64_t limit
    ) noexcept {
        if (limit == 0) return ResourceStatus::InvalidLimits;
        if (current > limit) return ResourceStatus::InternalError;
        const std::uint64_t maximum = (std::numeric_limits<std::uint64_t>::max)();
        if (requested > maximum - current) return ResourceStatus::IntegerOverflow;
        return requested > limit - current
            ? ResourceStatus::LimitExceeded
            : ResourceStatus::Ok;
    }

    ResourceStatus check_input_sizes_locked(
        std::uint64_t record_bytes,
        std::uint64_t payload_bytes
    ) const noexcept {
        if (record_bytes == 0) return ResourceStatus::InvalidRequest;
        if (record_bytes > limits_.max_record_bytes ||
            payload_bytes > limits_.max_payload_bytes ||
            payload_bytes > record_bytes) {
            return ResourceStatus::LimitExceeded;
        }
        return ResourceStatus::Ok;
    }

    // 呼び出し側が mutex_ を保持し、ready_locked() と形状検査を済ませていること。
    // 呼び出し側の try/catch が例外を受ける。
    ResourceStatus apply_locked(const ResourceReservation& request) {
        ResourceStatus checked = check_add(
            usage_.total_input_bytes,
            request.total_input_bytes,
            limits_.max_total_input_bytes);
        if (checked != ResourceStatus::Ok) return checked;
        checked = check_add(usage_.records, request.records, limits_.max_records);
        if (checked != ResourceStatus::Ok) return checked;
        checked = check_add(usage_.steps, request.steps, limits_.max_steps);
        if (checked != ResourceStatus::Ok) return checked;
        checked = check_add(
            usage_.elapsed_time_us,
            request.elapsed_time_us,
            limits_.max_elapsed_time_us);
        if (checked != ResourceStatus::Ok) return checked;

        bool insert_profile = false;
        bool insert_failure_code = false;
        if (request.has_profile) {
            const auto profile = profiles_.find(request.profile_id);
            insert_profile = profile == profiles_.end();
            if (insert_profile && profiles_.size() >= limits_.max_profiles) {
                return ResourceStatus::LimitExceeded;
            }
            if (request.has_failure_code) {
                insert_failure_code = insert_profile ||
                    profile->second.find(request.failure_code_id) ==
                        profile->second.end();
                if (!insert_profile && insert_failure_code &&
                    profile->second.size() >= limits_.max_failure_codes_per_profile) {
                    return ResourceStatus::LimitExceeded;
                }
                if (insert_failure_code &&
                    usage_.failure_code_entries ==
                        (std::numeric_limits<std::uint64_t>::max)()) {
                    return ResourceStatus::IntegerOverflow;
                }
            }
        }

        // 例外を投げ得る操作はここまでにまとめ、カウンター更新より前に行う。
        if (insert_profile || insert_failure_code) {
            try {
                if (insert_profile) {
                    profiles_.emplace(request.profile_id, FailureCodeSet{});
                }
                if (insert_failure_code) {
                    profiles_.at(request.profile_id).insert(request.failure_code_id);
                }
            } catch (...) {
                // 新規プロファイルを入れていた場合は巻き戻す(erase は noexcept)。
                // 既存プロファイルへの1要素 insert は失敗時に変更なし(強い保証)。
                if (insert_profile) profiles_.erase(request.profile_id);
                return ResourceStatus::InternalError;
            }
        }

        // コミット: 例外を投げない操作のみ。
        usage_.total_input_bytes += request.total_input_bytes;
        usage_.records += request.records;
        usage_.steps += request.steps;
        usage_.elapsed_time_us += request.elapsed_time_us;
        if (insert_profile) ++usage_.profiles;
        if (insert_failure_code) ++usage_.failure_code_entries;
        return ResourceStatus::Ok;
    }

    ResourceStatus validate_usage_locked() const noexcept {
        if (usage_.total_input_bytes > limits_.max_total_input_bytes ||
            usage_.records > limits_.max_records ||
            usage_.profiles != profiles_.size() ||
            usage_.profiles > limits_.max_profiles ||
            usage_.steps > limits_.max_steps ||
            usage_.elapsed_time_us > limits_.max_elapsed_time_us) {
            return ResourceStatus::InternalError;
        }
        std::uint64_t failure_entries = 0;
        for (const auto& profile : profiles_) {
            if (profile.second.size() > limits_.max_failure_codes_per_profile ||
                profile.second.size() >
                    (std::numeric_limits<std::uint64_t>::max)() - failure_entries) {
                return ResourceStatus::InternalError;
            }
            failure_entries += static_cast<std::uint64_t>(profile.second.size());
        }
        return failure_entries == usage_.failure_code_entries
            ? ResourceStatus::Ok
            : ResourceStatus::InternalError;
    }

    ResourceStatus ready_locked() const noexcept {
        if (!limits_.valid()) return ResourceStatus::InvalidLimits;
        return validate_usage_locked();
    }

    ResourceStatus remaining_for(
        std::uint64_t ResourceUsage::*used,
        std::uint64_t ResourceLimits::*maximum,
        std::uint64_t& remaining
    ) const noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            const ResourceStatus ready = ready_locked();
            if (ready != ResourceStatus::Ok) return ready;
            remaining = limits_.*maximum - usage_.*used;
            return ResourceStatus::Ok;
        } catch (...) {
            return ResourceStatus::InternalError;
        }
    }

#ifdef MOTHER_H_TEST_BUILD
    friend struct GuardTestInspector;
#endif

    const ResourceLimits limits_;
    mutable std::mutex mutex_;
    ResourceUsage usage_{};
    std::unordered_map<std::uint64_t, FailureCodeSet> profiles_;
};

#ifdef MOTHER_H_TEST_BUILD
struct GuardTestInspector {
    static std::unordered_map<std::uint64_t, ResourceGuard::FailureCodeSet>
    extract_profiles(const ResourceGuard& guard) {
        std::lock_guard<std::mutex> lock(guard.mutex_);
        return guard.profiles_;
    }

    static ResourceUsage extract_usage(const ResourceGuard& guard) {
        std::lock_guard<std::mutex> lock(guard.mutex_);
        return guard.usage_;
    }
};
#endif

}  // namespace mother_h::resource