#pragma once

#include "mother_H/journal/journal_integrity.hpp"
#include "mother_H/resource/resource_guard.hpp"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <mutex>
#include <optional>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>

namespace mother_h::policy {

struct JournalFeedbackFact {
    std::uint32_t op_id{0};
    std::uint64_t target{0};
    bool succeeded{false};
    std::uint64_t steps_used{0};
    std::uint64_t time_us{0};
    std::uint32_t failure_code{0};
};

struct OpPerformanceProfile {
    std::uint64_t attempts{0};
    std::uint64_t successes{0};
    std::uint64_t total_steps_used{0};
    std::uint64_t total_time_us{0};
    std::uint64_t successful_steps_used{0};
    std::unordered_map<std::uint32_t, std::uint64_t> failure_codes;

    double success_rate() const noexcept {
        return attempts == 0
            ? 0.0
            : static_cast<double>(successes) / static_cast<double>(attempts);
    }

    std::uint64_t avg_steps_on_success() const noexcept {
        return successes == 0 ? 0 : successful_steps_used / successes;
    }

    bool operator==(const OpPerformanceProfile& other) const noexcept {
        return attempts == other.attempts &&
               successes == other.successes &&
               total_steps_used == other.total_steps_used &&
               total_time_us == other.total_time_us &&
               successful_steps_used == other.successful_steps_used &&
               failure_codes == other.failure_codes;
    }

    bool operator!=(const OpPerformanceProfile& other) const noexcept {
        return !(*this == other);
    }
};

struct EngineResourceSnapshot {
    std::unordered_map<std::string, OpPerformanceProfile> stats;
    resource::ResourceUsage usage{};
    std::uint64_t next_lsn{1};
    journal::JournalHash previous_record_hash{};
    bool chain_exhausted{false};

    bool operator==(const EngineResourceSnapshot& other) const noexcept {
        return stats == other.stats &&
               usage.total_input_bytes == other.usage.total_input_bytes &&
               usage.records == other.usage.records &&
               usage.profiles == other.usage.profiles &&
               usage.failure_code_entries == other.usage.failure_code_entries &&
               usage.steps == other.usage.steps &&
               usage.elapsed_time_us == other.usage.elapsed_time_us &&
               next_lsn == other.next_lsn &&
               previous_record_hash == other.previous_record_hash &&
               chain_exhausted == other.chain_exhausted;
    }

    bool operator!=(const EngineResourceSnapshot& other) const noexcept {
        return !(*this == other);
    }
};

enum class TargetParity : std::uint8_t {
    Even,
    Odd
};

struct TargetStructure {
    std::uint32_t decimal_digits{0};
    TargetParity parity{TargetParity::Odd};
    bool is_perfect_square{false};
};

enum class QueryStatus : std::uint8_t {
    Ready,
    NoData,
    InsufficientSamples,
    InvalidQuery,
    InconsistentProfile
};

struct FeedbackEstimate {
    QueryStatus status{QueryStatus::NoData};
    std::uint32_t op_id{0};
    TargetStructure target_structure{};
    std::uint64_t attempts{0};
    std::uint64_t successes{0};
    std::optional<double> success_rate;
    std::optional<std::uint64_t> avg_successful_steps;
    std::optional<std::uint64_t> avg_time_us;
};

enum class FeedbackStatus : std::uint8_t {
    Ingested,
    IntegrityRejected,
    InvalidPayload,
    CounterOverflow,
    InvalidFact,
    ResourceRejected,
    InternalError
};

struct FeedbackIngestResult {
    FeedbackStatus status{FeedbackStatus::InvalidPayload};
    journal::IntegrityStatus integrity_status{journal::IntegrityStatus::Ok};
    resource::ResourceStatus resource_status{resource::ResourceStatus::Ok};

    explicit operator bool() const noexcept {
        return status == FeedbackStatus::Ingested;
    }
};

class JournalFeedbackEngine {
public:
    static constexpr std::size_t kEncodedFactSize = 37;
    static constexpr std::uint64_t kMinimumAttempts = 3;

    explicit JournalFeedbackEngine(resource::ResourceGuard& resources) noexcept
        : resources_(resources) {}

    static std::string encode_fact_payload(const JournalFeedbackFact& fact) {
        std::string payload;
        payload.reserve(kEncodedFactSize);
        payload.append("MHF1", 4);
        append_u32(payload, fact.op_id);
        append_u64(payload, fact.target);
        payload.push_back(fact.succeeded ? '\x01' : '\x00');
        append_u64(payload, fact.steps_used);
        append_u64(payload, fact.time_us);
        append_u32(payload, fact.failure_code);
        return payload;
    }

    const resource::ResourceLimits& limits() const noexcept {
        return resources_.limits();
    }

    std::uint64_t epoch() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return epoch_;
    }

    EngineResourceSnapshot snapshot() const {
        std::lock_guard<std::mutex> lock(mutex_);
        EngineResourceSnapshot snap;
        snap.stats = stats_;
        snap.usage = resources_.usage();
        snap.next_lsn = next_lsn_;
        snap.previous_record_hash = previous_record_hash_;
        snap.chain_exhausted = chain_exhausted_;
        return snap;
    }

    bool commit_state_from(
        JournalFeedbackEngine&& shadow,
        std::uint64_t expected_epoch
    ) noexcept {
        if (this == &shadow) return true;
        try {
            std::scoped_lock lock(mutex_, shadow.mutex_);
            if (epoch_ != expected_epoch) {
                return false;
            }
            if (!resources_.commit_state_from(std::move(shadow.resources_))) {
                return false;
            }
            std::swap(stats_, shadow.stats_);
            std::swap(next_lsn_, shadow.next_lsn_);
            std::swap(previous_record_hash_, shadow.previous_record_hash_);
            std::swap(chain_exhausted_, shadow.chain_exhausted_);
            ++epoch_;
            return true;
        } catch (...) {
            return false;
        }
    }

    bool commit_state_from(JournalFeedbackEngine&& shadow) noexcept {
        return commit_state_from(std::move(shadow), epoch());
    }

#ifdef MOTHER_H_TEST_BUILD
    bool corrupt_profile_for_test(std::uint32_t op_id, std::uint64_t target) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = stats_.find(make_feature_key(op_id, target));
        if (it == stats_.end()) return false;
        it->second.successes = it->second.attempts + 1;
        return true;
    }

    bool seed_profile_for_test(
        std::uint32_t op_id,
        std::uint64_t target,
        const OpPerformanceProfile& profile
    ) {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            stats_[make_feature_key(op_id, target)] = profile;
            return true;
        } catch (...) {
            return false;
        }
    }

    void set_next_lsn_for_test(
        std::uint64_t next_lsn,
        const journal::JournalHash& previous_hash = journal::JournalHash{}
    ) {
        std::lock_guard<std::mutex> lock(mutex_);
        next_lsn_ = next_lsn;
        previous_record_hash_ = previous_hash;
    }
#endif

    FeedbackIngestResult ingest_record(
        const journal::JournalRecord& record,
        const journal::ISecureKeyProvider& keys
    ) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (chain_exhausted_) {
            return {FeedbackStatus::IntegrityRejected,
                    journal::IntegrityStatus::LsnOutOfOrder};
        }

        std::uint64_t record_bytes = 0;
        if (!canonical_record_size(record, record_bytes)) {
            return {FeedbackStatus::ResourceRejected,
                    journal::IntegrityStatus::Ok,
                    resource::ResourceStatus::IntegerOverflow};
        }
        const auto payload_bytes = static_cast<std::uint64_t>(record.payload.size());
        resource::ResourceStatus resource_status =
            resources_.check_input_sizes(record_bytes, payload_bytes);
        if (resource_status == resource::ResourceStatus::Ok) {
            resource_status = resources_.check_record_count(1);
        }
        if (resource_status == resource::ResourceStatus::Ok) {
            resource_status = resources_.check_total_input_bytes(record_bytes);
        }
        if (resource_status != resource::ResourceStatus::Ok) {
            return {FeedbackStatus::ResourceRejected,
                    journal::IntegrityStatus::Ok,
                    resource_status};
        }

        try {
            const journal::IntegrityResult integrity = journal::JournalIntegrity::verify(
                record, next_lsn_, previous_record_hash_, keys);
            if (!integrity) {
                return {FeedbackStatus::IntegrityRejected, integrity.status};
            }

            JournalFeedbackFact fact;
            if (!decode_fact_payload(record.payload, fact)) {
                resource_status = reserve_input(record_bytes, payload_bytes);
                if (resource_status != resource::ResourceStatus::Ok) {
                    return {FeedbackStatus::ResourceRejected,
                            journal::IntegrityStatus::Ok,
                            resource_status};
                }
                advance_chain(integrity.record_hash);
                return {FeedbackStatus::InvalidPayload, journal::IntegrityStatus::Ok};
            }
            if (!valid_fact(fact)) {
                resource_status = reserve_input(record_bytes, payload_bytes);
                if (resource_status != resource::ResourceStatus::Ok) {
                    return {FeedbackStatus::ResourceRejected,
                            journal::IntegrityStatus::Ok,
                            resource_status};
                }
                advance_chain(integrity.record_hash);
                return {FeedbackStatus::InvalidFact, journal::IntegrityStatus::Ok};
            }

            const std::string key = make_feature_key(fact.op_id, fact.target);
            const auto existing = stats_.find(key);
            const OpPerformanceProfile* current =
                existing == stats_.end() ? nullptr : &existing->second;
            if ((current != nullptr &&
                 (!can_add(current->attempts, 1) ||
                  !can_add(current->total_steps_used, fact.steps_used) ||
                  !can_add(current->total_time_us, fact.time_us))) ||
                (fact.succeeded && current != nullptr &&
                 (!can_add(current->successes, 1) ||
                  !can_add(current->successful_steps_used, fact.steps_used)))) {
                return {FeedbackStatus::CounterOverflow, journal::IntegrityStatus::Ok};
            }
            if (!fact.succeeded && current != nullptr) {
                const auto failure = current->failure_codes.find(fact.failure_code);
                if (failure != current->failure_codes.end() &&
                    !can_add(failure->second, 1)) {
                    return {FeedbackStatus::CounterOverflow, journal::IntegrityStatus::Ok};
                }
            }

            OpPerformanceProfile updated =
                existing == stats_.end() ? OpPerformanceProfile{} : existing->second;
            static_assert(
                std::is_nothrow_move_assignable<OpPerformanceProfile>::value,
                "feedback profile commit must not throw");
            if (!checked_add(updated.attempts, 1) ||
                !checked_add(updated.total_steps_used, fact.steps_used) ||
                !checked_add(updated.total_time_us, fact.time_us)) {
                return {FeedbackStatus::CounterOverflow, journal::IntegrityStatus::Ok};
            }
            if (fact.succeeded) {
                if (!checked_add(updated.successes, 1) ||
                    !checked_add(updated.successful_steps_used, fact.steps_used)) {
                    return {FeedbackStatus::CounterOverflow, journal::IntegrityStatus::Ok};
                }
            } else {
                auto failure = updated.failure_codes.find(fact.failure_code);
                if (failure == updated.failure_codes.end()) {
                    updated.failure_codes.emplace(fact.failure_code, 1);
                } else if (!checked_add(failure->second, 1)) {
                    return {FeedbackStatus::CounterOverflow, journal::IntegrityStatus::Ok};
                }
            }

            resource::ResourceReservation reservation;
            reservation.record_bytes = record_bytes;
            reservation.payload_bytes = payload_bytes;
            reservation.total_input_bytes = record_bytes;
            reservation.records = 1;
            reservation.has_profile = true;
            reservation.profile_id = profile_resource_id(fact.op_id, fact.target);
            if (!fact.succeeded) {
                reservation.has_failure_code = true;
                reservation.failure_code_id = fact.failure_code;
            }

            if (existing == stats_.end()) {
                const auto inserted = stats_.emplace(key, std::move(updated));
                if (!inserted.second) {
                    return {FeedbackStatus::InternalError, journal::IntegrityStatus::Ok};
                }
                resource_status = resources_.reserve(reservation);
                if (resource_status != resource::ResourceStatus::Ok) {
                    stats_.erase(inserted.first);
                    return {FeedbackStatus::ResourceRejected,
                            journal::IntegrityStatus::Ok,
                            resource_status};
                }
            } else {
                resource_status = resources_.reserve(reservation);
                if (resource_status != resource::ResourceStatus::Ok) {
                    return {FeedbackStatus::ResourceRejected,
                            journal::IntegrityStatus::Ok,
                            resource_status};
                }
                existing->second = std::move(updated);
            }
            advance_chain(integrity.record_hash);
            ++epoch_;
            return {FeedbackStatus::Ingested, journal::IntegrityStatus::Ok};
        } catch (...) {
            return {FeedbackStatus::InternalError, journal::IntegrityStatus::Ok};
        }
    }

    double predict_success_rate(
        std::uint32_t op_id,
        std::uint64_t target
    ) const {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = stats_.find(make_feature_key(op_id, target));
        if (it != stats_.end() && it->second.attempts >= kMinimumAttempts) {
            return it->second.success_rate();
        }
        return kDefaultSuccessRate;
    }

    // This engine, including estimate(), is intended for single-threaded use.
    // Ready reports usable historical aggregates only; it guarantees neither
    // future success nor the semantic correctness of the recorded facts.
    FeedbackEstimate estimate(
        std::uint32_t op_id,
        std::uint64_t target,
        std::uint64_t minimum_attempts = kMinimumAttempts
    ) const {
        std::lock_guard<std::mutex> lock(mutex_);
        FeedbackEstimate result;
        result.op_id = op_id;
        if (op_id == 0 || target == 0 || minimum_attempts == 0) {
            result.status = QueryStatus::InvalidQuery;
            return result;
        }

        result.target_structure = target_structure(target);
        const auto it = stats_.find(make_feature_key(op_id, target));
        if (it == stats_.end()) {
            result.status = QueryStatus::NoData;
            return result;
        }

        const OpPerformanceProfile& profile = it->second;
        result.attempts = profile.attempts;
        result.successes = profile.successes;
        if (!is_consistent(profile)) {
            result.status = QueryStatus::InconsistentProfile;
            return result;
        }
        if (profile.attempts < minimum_attempts) {
            result.status = QueryStatus::InsufficientSamples;
            return result;
        }

        const double rate =
            static_cast<double>(profile.successes) /
            static_cast<double>(profile.attempts);
        if (!std::isfinite(rate) || rate < 0.0 || rate > 1.0) {
            result.status = QueryStatus::InconsistentProfile;
            return result;
        }
        result.status = QueryStatus::Ready;
        result.success_rate = rate;
        result.avg_successful_steps = profile.avg_steps_on_success();
        result.avg_time_us = profile.total_time_us / profile.attempts;
        return result;
    }

    const std::unordered_map<std::string, OpPerformanceProfile>& stats() const noexcept {
        return stats_;
    }

private:
    static constexpr double kDefaultSuccessRate = 0.20;

    static TargetStructure target_structure(std::uint64_t target) noexcept {
        TargetStructure structure;
        structure.decimal_digits = 1;
        for (std::uint64_t remaining = target; remaining >= 10; remaining /= 10) {
            ++structure.decimal_digits;
        }
        structure.parity = target % 2U == 0U
            ? TargetParity::Even
            : TargetParity::Odd;
        structure.is_perfect_square = is_perfect_square(target);
        return structure;
    }

    static bool is_consistent(const OpPerformanceProfile& profile) noexcept {
        if (profile.attempts == 0 || profile.successes > profile.attempts ||
            profile.successful_steps_used > profile.total_steps_used) {
            return false;
        }

        std::uint64_t failed_attempts = 0;
        for (const auto& entry : profile.failure_codes) {
            if (entry.first == 0 || entry.second == 0 ||
                entry.second > (std::numeric_limits<std::uint64_t>::max)() -
                    failed_attempts) {
                return false;
            }
            failed_attempts += entry.second;
        }
        return failed_attempts == profile.attempts - profile.successes;
    }

    static void append_u32(std::string& output, std::uint32_t value) {
        for (int shift = 24; shift >= 0; shift -= 8) {
            output.push_back(static_cast<char>(value >> shift));
        }
    }

    static void append_u64(std::string& output, std::uint64_t value) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            output.push_back(static_cast<char>(value >> shift));
        }
    }

    static std::uint32_t read_u32(const std::string& input, std::size_t offset) {
        std::uint32_t value = 0;
        for (std::size_t i = 0; i < 4; ++i) {
            value = (value << 8U) |
                static_cast<unsigned char>(input[offset + i]);
        }
        return value;
    }

    static std::uint64_t read_u64(const std::string& input, std::size_t offset) {
        std::uint64_t value = 0;
        for (std::size_t i = 0; i < 8; ++i) {
            value = (value << 8U) |
                static_cast<unsigned char>(input[offset + i]);
        }
        return value;
    }

    static bool decode_fact_payload(
        const std::string& payload,
        JournalFeedbackFact& fact
    ) {
        if (payload.size() != kEncodedFactSize ||
            payload.compare(0, 4, "MHF1", 4) != 0) {
            return false;
        }

        const unsigned char succeeded =
            static_cast<unsigned char>(payload[16]);
        if (succeeded > 1U) return false;

        fact.op_id = read_u32(payload, 4);
        fact.target = read_u64(payload, 8);
        fact.succeeded = succeeded == 1U;
        fact.steps_used = read_u64(payload, 17);
        fact.time_us = read_u64(payload, 25);
        fact.failure_code = read_u32(payload, 33);
        return true;
    }

    resource::ResourceStatus reserve_input(
        std::uint64_t record_bytes,
        std::uint64_t payload_bytes
    ) noexcept {
        resource::ResourceReservation reservation;
        reservation.record_bytes = record_bytes;
        reservation.payload_bytes = payload_bytes;
        reservation.total_input_bytes = record_bytes;
        reservation.records = 1;
        return resources_.reserve(reservation);
    }

    static bool valid_fact(const JournalFeedbackFact& fact) noexcept {
        return fact.op_id != 0 && fact.target != 0 &&
            (fact.succeeded ? fact.failure_code == 0 : fact.failure_code != 0);
    }

    static bool canonical_record_size(
        const journal::JournalRecord& record,
        std::uint64_t& size
    ) noexcept {
        static constexpr std::uint64_t fixed_bytes =
            sizeof("MOTHER_H_JOURNAL_RECORD") + 1U + 8U + 4U + 8U + 8U + 32U + 8U + 32U;
        const std::size_t field_sizes[] = {
            record.key.key_id.size(),
            record.timestamp_utc.size(),
            record.payload.size()
        };
        size = fixed_bytes;
        const auto maximum = (std::numeric_limits<std::uint64_t>::max)();
        for (const std::size_t field_size : field_sizes) {
            const auto field_bytes = static_cast<std::uint64_t>(field_size);
            if (static_cast<std::size_t>(field_bytes) != field_size ||
                field_bytes > maximum - size) {
                return false;
            }
            size += field_bytes;
        }
        return true;
    }

    static std::uint64_t profile_resource_id(
        std::uint32_t op_id,
        std::uint64_t target
    ) noexcept {
        std::uint64_t digits = 1;
        for (std::uint64_t remaining = target; remaining >= 10; remaining /= 10) {
            ++digits;
        }
        const std::uint64_t parity = target % 2U;
        const std::uint64_t square = is_perfect_square(target) ? 1U : 0U;
        return (std::uint64_t{1} << 63U) |
            (static_cast<std::uint64_t>(op_id) << 7U) |
            (digits << 2U) |
            (parity << 1U) |
            square;
    }

    static bool checked_add(std::uint64_t& value, std::uint64_t increment) noexcept {
        if (increment > (std::numeric_limits<std::uint64_t>::max)() - value) {
            return false;
        }
        value += increment;
        return true;
    }

    static bool can_add(std::uint64_t value, std::uint64_t increment) noexcept {
        return increment <= (std::numeric_limits<std::uint64_t>::max)() - value;
    }

    void advance_chain(const journal::JournalHash& record_hash) noexcept {
        previous_record_hash_ = record_hash;
        if (next_lsn_ == (std::numeric_limits<std::uint64_t>::max)()) {
            chain_exhausted_ = true;
        } else {
            ++next_lsn_;
        }
    }

    static bool is_perfect_square(std::uint64_t value) noexcept {
        std::uint64_t low = 0;
        std::uint64_t high = (std::uint64_t{1} << 32U);
        while (low < high) {
            const std::uint64_t middle = low + (high - low) / 2U;
            if (middle != 0 && middle > value / middle) {
                high = middle;
            } else if (middle * middle < value) {
                low = middle + 1U;
            } else {
                return middle * middle == value;
            }
        }
        return low != 0 && low * low == value;
    }

    static std::string make_feature_key(
        std::uint32_t op_id,
        std::uint64_t target
    ) {
        std::size_t digits = 1;
        for (std::uint64_t remaining = target; remaining >= 10; remaining /= 10) {
            ++digits;
        }
        std::string key = "digits=" + std::to_string(digits);
        key += target % 2U == 0U ? ";parity=even" : ";parity=odd";
        key += is_perfect_square(target) ? ";square=yes" : ";square=no";
        key += ";op=" + std::to_string(op_id);
        return key;
    }

    mutable std::mutex mutex_;
    std::unordered_map<std::string, OpPerformanceProfile> stats_;
    resource::ResourceGuard& resources_;
    std::uint64_t next_lsn_{1};
    journal::JournalHash previous_record_hash_{};
    bool chain_exhausted_{false};
    std::uint64_t epoch_{0};
};

}  // namespace mother_h::policy
