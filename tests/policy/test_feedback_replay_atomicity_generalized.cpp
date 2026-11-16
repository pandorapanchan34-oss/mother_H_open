#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <thread>
#include <type_traits>
#include <unordered_set>
#include <utility>
#include <vector>

struct ReplayInjectionControl {
    static inline std::atomic<bool> armed{false};
    static inline std::atomic<unsigned> fires{0};
};

template <class T>
struct ReplayThrowingAllocator {
    using value_type = T;

    ReplayThrowingAllocator() noexcept = default;
    template <class U>
    ReplayThrowingAllocator(const ReplayThrowingAllocator<U>&) noexcept {}

    T* allocate(std::size_t count) {
        if (ReplayInjectionControl::armed.load(std::memory_order_relaxed)) {
            ReplayInjectionControl::fires.fetch_add(1, std::memory_order_relaxed);
            throw std::bad_alloc();
        }
        return std::allocator<T>{}.allocate(count);
    }

    void deallocate(T* pointer, std::size_t count) noexcept {
        std::allocator<T>{}.deallocate(pointer, count);
    }

    template <class U>
    bool operator==(const ReplayThrowingAllocator<U>&) const noexcept {
        return true;
    }

    template <class U>
    bool operator!=(const ReplayThrowingAllocator<U>&) const noexcept {
        return false;
    }
};

using ReplayInjectedFailureCodeSet = std::unordered_set<
    std::uint64_t,
    std::hash<std::uint64_t>,
    std::equal_to<std::uint64_t>,
    ReplayThrowingAllocator<std::uint64_t>>;

#define MOTHER_H_RESOURCE_GUARD_FAILURE_CODE_SET ::ReplayInjectedFailureCodeSet
#include "mother_H/storage/journal_recovery_adapter.hpp"
#include "mother_H/journal/journal_integrity.hpp"

namespace {

using namespace mother_h::journal;
using namespace mother_h::policy;
using namespace mother_h::resource;
using mother_H::storage::JournalRecoveryAdapter;

using GuardProfiles = decltype(
    GuardTestInspector::extract_profiles(std::declval<const ResourceGuard&>()));

constexpr const char* kKeyId = "replay_atomicity_test_key";
constexpr std::uint32_t kKeyVersion = 1;
constexpr std::size_t kReplayTimeoutSeconds = 10;

bool failure(int line, const char* expression) {
    std::fprintf(stderr, "[FAIL] line %d: %s\n", line, expression);
    return false;
}

#define REQUIRE(expression) \
    do { \
        if (!(expression)) return failure(__LINE__, #expression); \
    } while (false)

class TestKeyProvider : public ISecureKeyProvider {
public:
    KeyStatus current_signing_key(KeyMaterial& out) const noexcept override {
        return assign_key(out, KeyReference{kKeyId, kKeyVersion});
    }

    KeyStatus verification_key(
        const KeyReference& reference,
        KeyMaterial& out
    ) const noexcept override {
        if (reference.key_id != kKeyId || reference.version != kKeyVersion) {
            return KeyStatus::NotFound;
        }
        return assign_key(out, reference);
    }

    KeyStatus rotate_key(const std::string&, KeyReference&) noexcept override {
        return KeyStatus::BackendUnavailable;
    }

    KeyStatus revoke_key(const KeyReference&) noexcept override {
        return KeyStatus::BackendUnavailable;
    }

protected:
    static KeyStatus assign_key(KeyMaterial& out, const KeyReference& reference) noexcept {
        try {
            out = KeyMaterial(reference, std::vector<std::uint8_t>(32, 0x5A));
            return KeyStatus::Ok;
        } catch (...) {
            return KeyStatus::NotFound;
        }
    }
};

class BlockingKeyProvider final : public TestKeyProvider {
public:
    KeyStatus verification_key(
        const KeyReference& reference,
        KeyMaterial& out
    ) const noexcept override {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            if (verification_calls_++ == 0) {
                entered_ = true;
                condition_.notify_all();
                if (!condition_.wait_for(
                        lock,
                        std::chrono::seconds(kReplayTimeoutSeconds),
                        [this] { return released_; })) {
                    return KeyStatus::BackendUnavailable;
                }
            }
        }
        return TestKeyProvider::verification_key(reference, out);
    }

    bool wait_until_blocked() const {
        std::unique_lock<std::mutex> lock(mutex_);
        return condition_.wait_for(
            lock,
            std::chrono::seconds(kReplayTimeoutSeconds),
            [this] { return entered_; });
    }

    void release() const {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            released_ = true;
        }
        condition_.notify_all();
    }

private:
    mutable std::mutex mutex_;
    mutable std::condition_variable condition_;
    mutable std::size_t verification_calls_{0};
    mutable bool entered_{false};
    mutable bool released_{false};
};

class ArmOnSecondVerificationKeyProvider final : public TestKeyProvider {
public:
    KeyStatus verification_key(
        const KeyReference& reference,
        KeyMaterial& out
    ) const noexcept override {
        if (verification_calls_.fetch_add(1, std::memory_order_relaxed) == 1) {
            ReplayInjectionControl::armed.store(true, std::memory_order_relaxed);
        }
        return TestKeyProvider::verification_key(reference, out);
    }

private:
    mutable std::atomic<unsigned> verification_calls_{0};
};

ResourceLimits make_limits() {
    ResourceLimits limits{};
    limits.max_record_bytes = 1024 * 1024;
    limits.max_payload_bytes = 128;
    limits.max_total_input_bytes = 10 * 1024 * 1024;
    limits.max_records = 100;
    limits.max_profiles = 50;
    limits.max_failure_codes_per_profile = 10;
    limits.max_steps = 100000;
    limits.max_elapsed_time_us = 10000000;
    return limits;
}

std::vector<JournalFeedbackFact> unique_facts(
    std::size_t count,
    std::uint32_t op_base = 100
) {
    std::vector<JournalFeedbackFact> facts;
    facts.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        const bool succeeded = (i % 2) == 0;
        facts.push_back(JournalFeedbackFact{
            static_cast<std::uint32_t>(op_base + i),
            static_cast<std::uint64_t>(1000 + i),
            succeeded,
            static_cast<std::uint64_t>(10 + i),
            static_cast<std::uint64_t>(20 + i),
            succeeded ? 0U : static_cast<std::uint32_t>(200 + i)
        });
    }
    return facts;
}

std::vector<JournalFeedbackFact> initial_facts() {
    return {
        JournalFeedbackFact{1, 101, true, 3, 5, 0},
        JournalFeedbackFact{2, 202, true, 4, 6, 0}
    };
}

std::vector<JournalFeedbackFact> failure_code_facts(std::size_t count) {
    std::vector<JournalFeedbackFact> facts;
    facts.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        facts.push_back(JournalFeedbackFact{
            700,
            7000,
            false,
            static_cast<std::uint64_t>(10 + i),
            static_cast<std::uint64_t>(20 + i),
            static_cast<std::uint32_t>(301 + i)
        });
    }
    return facts;
}

std::vector<JournalFeedbackFact> distinct_failure_facts(std::size_t count) {
    std::vector<JournalFeedbackFact> facts;
    facts.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        facts.push_back(JournalFeedbackFact{
            static_cast<std::uint32_t>(750 + i),
            static_cast<std::uint64_t>(7500 + i),
            false,
            static_cast<std::uint64_t>(10 + i),
            static_cast<std::uint64_t>(20 + i),
            static_cast<std::uint32_t>(351 + i)
        });
    }
    return facts;
}

bool seal_history(
    const std::vector<JournalFeedbackFact>& facts,
    const ISecureKeyProvider& keys,
    std::vector<JournalRecord>& records
) {
    records.clear();
    records.reserve(facts.size());
    JournalHash previous_hash = JournalIntegrity::genesis_hash();
    for (std::size_t i = 0; i < facts.size(); ++i) {
        JournalRecord record{};
        record.lsn = static_cast<std::uint64_t>(i + 1);
        record.timestamp_utc = "2026-11-15T00:00:00.000000000Z";
        record.payload = JournalFeedbackEngine::encode_fact_payload(facts[i]);
        const IntegrityResult sealed = JournalIntegrity::seal(
            record, record.lsn, previous_hash, keys);
        if (!sealed) {
            return failure(__LINE__, "JournalIntegrity::seal");
        }
        previous_hash = sealed.record_hash;
        records.push_back(std::move(record));
    }
    return true;
}

bool ingest_all(
    JournalFeedbackEngine& engine,
    const std::vector<JournalRecord>& records,
    const ISecureKeyProvider& keys
) {
    for (const JournalRecord& record : records) {
        const FeedbackIngestResult result = engine.ingest_record(record, keys);
        if (result.status != FeedbackStatus::Ingested) {
            return failure(__LINE__, "initial/reference ingest status == Ingested");
        }
    }
    return true;
}

struct LiveState {
    EngineResourceSnapshot snapshot;
    std::uint64_t epoch{0};
    GuardProfiles profiles;
    ResourceStatus status{ResourceStatus::InternalError};
};

LiveState capture_live_state(
    const JournalFeedbackEngine& engine,
    const ResourceGuard& guard
) {
    return LiveState{
        engine.snapshot(),
        engine.epoch(),
        GuardTestInspector::extract_profiles(guard),
        guard.status()
    };
}

bool unchanged_live_state(
    const JournalFeedbackEngine& engine,
    const ResourceGuard& guard,
    const LiveState& before
) {
    REQUIRE(engine.snapshot() == before.snapshot);
    REQUIRE(engine.epoch() == before.epoch);
    REQUIRE(GuardTestInspector::extract_profiles(guard) == before.profiles);
    REQUIRE(guard.status() == before.status);
    REQUIRE(before.status == ResourceStatus::Ok);
    return true;
}

bool same_usage(const ResourceUsage& left, const ResourceUsage& right) {
    return left.total_input_bytes == right.total_input_bytes &&
        left.records == right.records &&
        left.profiles == right.profiles &&
        left.failure_code_entries == right.failure_code_entries &&
        left.steps == right.steps &&
        left.elapsed_time_us == right.elapsed_time_us;
}

bool assert_replay_success(
    const ResourceLimits& limits,
    const std::vector<JournalRecord>& live_initial_records,
    const std::vector<JournalRecord>& replay_records,
    const ISecureKeyProvider& keys,
    const char* label
) {
    ResourceGuard live_guard(limits);
    JournalFeedbackEngine live(live_guard);
    REQUIRE(ingest_all(live, live_initial_records, keys));
    const LiveState before = capture_live_state(live, live_guard);

    ResourceGuard expected_guard(limits);
    JournalFeedbackEngine expected(expected_guard);
    REQUIRE(ingest_all(expected, replay_records, keys));

    JournalRecoveryAdapter adapter;
    REQUIRE(adapter.rebuild_feedback_engine_state(replay_records, keys, live));
    REQUIRE(live.snapshot() == expected.snapshot());
    REQUIRE(GuardTestInspector::extract_profiles(live_guard) ==
            GuardTestInspector::extract_profiles(expected_guard));
    REQUIRE(live_guard.status() == ResourceStatus::Ok);
    REQUIRE(live.epoch() == before.epoch + 1);
    REQUIRE(live.snapshot().usage.records == replay_records.size());
    std::printf("[PASS] %s: bounded replay succeeded and replaced live state\n", label);
    return true;
}

bool assert_replay_failure_unchanged(
    const ResourceLimits& limits,
    const std::vector<JournalRecord>& live_initial_records,
    const std::vector<JournalRecord>& replay_records,
    const ISecureKeyProvider& keys,
    const char* label
) {
    ResourceGuard live_guard(limits);
    JournalFeedbackEngine live(live_guard);
    REQUIRE(ingest_all(live, live_initial_records, keys));
    const LiveState before = capture_live_state(live, live_guard);
    REQUIRE(before.snapshot.usage.records == live_initial_records.size());
    REQUIRE(!before.profiles.empty());

    JournalRecoveryAdapter adapter;
    REQUIRE(!adapter.rebuild_feedback_engine_state(replay_records, keys, live));
    REQUIRE(unchanged_live_state(live, live_guard, before));
    std::printf("[PASS] %s: failed replay preserved complete live state\n", label);
    return true;
}

enum class Mutation {
    HmacMismatch,
    LsnOutOfOrder,
    ChainMismatch,
    InvalidPayload,
    InvalidFact
};

struct ExpectedFailure {
    FeedbackStatus feedback_status;
    IntegrityStatus integrity_status;
};

bool previous_hash_before(
    const std::vector<JournalRecord>& records,
    std::size_t index,
    const ISecureKeyProvider& keys,
    JournalHash& previous_hash
) {
    previous_hash = JournalIntegrity::genesis_hash();
    for (std::size_t i = 0; i < index; ++i) {
        const IntegrityResult verified = JournalIntegrity::verify(
            records[i], static_cast<std::uint64_t>(i + 1), previous_hash, keys);
        REQUIRE(verified);
        previous_hash = verified.record_hash;
    }
    return true;
}

bool mutate_record(
    std::vector<JournalRecord>& records,
    std::size_t index,
    Mutation mutation,
    const ISecureKeyProvider& keys,
    ExpectedFailure& expected
) {
    JournalHash previous_hash{};
    REQUIRE(previous_hash_before(records, index, keys, previous_hash));
    JournalRecord& record = records[index];
    const std::uint64_t expected_lsn = static_cast<std::uint64_t>(index + 1);

    switch (mutation) {
    case Mutation::HmacMismatch:
        record.hmac_sha256[0] ^= 0x80U;
        expected = {FeedbackStatus::IntegrityRejected, IntegrityStatus::HmacMismatch};
        break;
    case Mutation::LsnOutOfOrder:
        record.lsn += 100;
        expected = {FeedbackStatus::IntegrityRejected, IntegrityStatus::LsnOutOfOrder};
        break;
    case Mutation::ChainMismatch: {
        JournalHash wrong_previous_hash = previous_hash;
        wrong_previous_hash[0] ^= 0x80U;
        const IntegrityResult resealed = JournalIntegrity::seal(
            record, expected_lsn, wrong_previous_hash, keys);
        REQUIRE(resealed);
        expected = {FeedbackStatus::IntegrityRejected, IntegrityStatus::ChainMismatch};
        break;
    }
    case Mutation::InvalidPayload: {
        record.payload = "MHF1-invalid";
        const IntegrityResult resealed = JournalIntegrity::seal(
            record, expected_lsn, previous_hash, keys);
        REQUIRE(resealed);
        expected = {FeedbackStatus::InvalidPayload, IntegrityStatus::Ok};
        break;
    }
    case Mutation::InvalidFact: {
        const JournalFeedbackFact invalid_fact{0, 9001, true, 1, 1, 0};
        record.payload = JournalFeedbackEngine::encode_fact_payload(invalid_fact);
        const IntegrityResult resealed = JournalIntegrity::seal(
            record, expected_lsn, previous_hash, keys);
        REQUIRE(resealed);
        expected = {FeedbackStatus::InvalidFact, IntegrityStatus::Ok};
        break;
    }
    }
    return true;
}

bool verify_expected_rejection(
    const std::vector<JournalRecord>& records,
    std::size_t failure_index,
    const ExpectedFailure& expected,
    const ISecureKeyProvider& keys
) {
    ResourceGuard guard(make_limits());
    JournalFeedbackEngine shadow(guard);
    for (std::size_t i = 0; i < records.size(); ++i) {
        const FeedbackIngestResult result = shadow.ingest_record(records[i], keys);
        if (i < failure_index) {
            REQUIRE(result.status == FeedbackStatus::Ingested);
            continue;
        }
        REQUIRE(i == failure_index);
        REQUIRE(result.status == expected.feedback_status);
        REQUIRE(result.integrity_status == expected.integrity_status);
        return true;
    }
    return failure(__LINE__, "expected rejection was observed at the designated record");
}

bool run_rep_gen_00() {
    TestKeyProvider keys;
    std::vector<JournalRecord> live_initial_records;
    std::vector<JournalRecord> replay_records;
    REQUIRE(seal_history(initial_facts(), keys, live_initial_records));
    REQUIRE(seal_history(unique_facts(8, 400), keys, replay_records));

    ResourceLimits limits = make_limits();
    ResourceGuard live_guard(limits);
    JournalFeedbackEngine live(live_guard);
    REQUIRE(ingest_all(live, live_initial_records, keys));
    const std::uint64_t initial_epoch = live.epoch();

    ResourceGuard expected_guard(limits);
    JournalFeedbackEngine expected(expected_guard);
    REQUIRE(ingest_all(expected, replay_records, keys));

    JournalRecoveryAdapter adapter;
    REQUIRE(adapter.rebuild_feedback_engine_state(replay_records, keys, live));
    REQUIRE(live.snapshot() == expected.snapshot());
    REQUIRE(live.snapshot().usage.records == 8);
    REQUIRE(live.epoch() == initial_epoch + 1);
    REQUIRE(GuardTestInspector::extract_profiles(live_guard) ==
            GuardTestInspector::extract_profiles(expected_guard));
    REQUIRE(live_guard.status() == ResourceStatus::Ok);
    std::puts("[PASS] REP-GEN-00: complete eight-record replay replaced live state");
    return true;
}

bool run_rep_gen_01() {
    TestKeyProvider keys;
    std::vector<JournalRecord> live_initial_records;
    std::vector<JournalRecord> valid_records;
    REQUIRE(seal_history(initial_facts(), keys, live_initial_records));
    REQUIRE(seal_history(unique_facts(6, 500), keys, valid_records));

    const Mutation mutations[] = {
        Mutation::HmacMismatch,
        Mutation::LsnOutOfOrder,
        Mutation::ChainMismatch,
        Mutation::InvalidPayload,
        Mutation::InvalidFact
    };
    const char* mutation_names[] = {
        "HmacMismatch",
        "LsnOutOfOrder",
        "ChainMismatch",
        "InvalidPayload",
        "InvalidFact"
    };

    for (std::size_t k = 1; k <= 6; ++k) {
        for (std::size_t m = 0; m < sizeof(mutations) / sizeof(mutations[0]); ++m) {
            std::vector<JournalRecord> corrupted_records = valid_records;
            ExpectedFailure expected{};
            REQUIRE(mutate_record(corrupted_records, k - 1, mutations[m], keys, expected));
            REQUIRE(verify_expected_rejection(corrupted_records, k - 1, expected, keys));

            char label[96]{};
            std::snprintf(
                label,
                sizeof(label),
                "REP-GEN-01 k=%zu %s",
                k,
                mutation_names[m]);
            REQUIRE(assert_replay_failure_unchanged(
                make_limits(),
                live_initial_records,
                corrupted_records,
                keys,
                label));
        }
    }
    std::puts("[PASS] REP-GEN-01: all 30 position/failure combinations verified");
    return true;
}

bool verify_resource_failure_at(
    const std::vector<JournalRecord>& records,
    std::size_t failure_index,
    const ResourceLimits& limits,
    const ISecureKeyProvider& keys
) {
    ResourceGuard guard(limits);
    JournalFeedbackEngine shadow(guard);
    for (std::size_t i = 0; i < records.size(); ++i) {
        const FeedbackIngestResult result = shadow.ingest_record(records[i], keys);
        if (i < failure_index) {
            REQUIRE(result.status == FeedbackStatus::Ingested);
            continue;
        }
        REQUIRE(i == failure_index);
        REQUIRE(result.status == FeedbackStatus::ResourceRejected);
        REQUIRE(result.resource_status == ResourceStatus::LimitExceeded);
        return true;
    }
    return failure(__LINE__, "resource limit rejection observed at designated record");
}

bool calculate_prefix_bytes(
    const std::vector<JournalRecord>& records,
    std::size_t count,
    const ISecureKeyProvider& keys,
    std::uint64_t& total_bytes
) {
    ResourceGuard guard(make_limits());
    JournalFeedbackEngine engine(guard);
    for (std::size_t i = 0; i < count; ++i) {
        const FeedbackIngestResult result = engine.ingest_record(records[i], keys);
        REQUIRE(result.status == FeedbackStatus::Ingested);
    }
    total_bytes = engine.snapshot().usage.total_input_bytes;
    return true;
}

bool run_resource_limit_failure(
    ResourceLimits limits,
    const std::vector<JournalRecord>& live_initial_records,
    const std::vector<JournalRecord>& replay_records,
    std::size_t failure_index,
    const ISecureKeyProvider& keys,
    const char* label
) {
    REQUIRE(verify_resource_failure_at(replay_records, failure_index, limits, keys));
    REQUIRE(assert_replay_failure_unchanged(
        limits, live_initial_records, replay_records, keys, label));
    return true;
}

bool run_rep_gen_02() {
    TestKeyProvider keys;
    std::vector<JournalRecord> live_initial_records;
    REQUIRE(seal_history(
        {JournalFeedbackFact{1, 101, true, 3, 5, 0}},
        keys,
        live_initial_records));

    std::vector<JournalRecord> unique_history;
    REQUIRE(seal_history(unique_facts(4, 600), keys, unique_history));
    for (std::size_t k = 2; k <= 4; ++k) {
        ResourceLimits limits = make_limits();
        limits.max_records = k - 1;
        std::vector<JournalRecord> success_records(
            unique_history.begin(),
            unique_history.begin() + static_cast<std::ptrdiff_t>(k - 1));
        std::vector<JournalRecord> failure_records(
            unique_history.begin(),
            unique_history.begin() + static_cast<std::ptrdiff_t>(k));
        char success_label[80]{};
        char failure_label[80]{};
        std::snprintf(success_label, sizeof(success_label), "REP-GEN-02 max_records k=%zu boundary", k);
        std::snprintf(failure_label, sizeof(failure_label), "REP-GEN-02 max_records k=%zu over", k);
        REQUIRE(assert_replay_success(
            limits, live_initial_records, success_records, keys, success_label));
        REQUIRE(run_resource_limit_failure(
            limits, live_initial_records, failure_records, k - 1, keys, failure_label));
    }

    std::vector<JournalRecord> byte_history;
    REQUIRE(seal_history(unique_facts(3, 700), keys, byte_history));
    for (std::size_t k = 2; k <= 3; ++k) {
        std::uint64_t prefix_bytes = 0;
        std::uint64_t through_k_bytes = 0;
        REQUIRE(calculate_prefix_bytes(byte_history, k - 1, keys, prefix_bytes));
        REQUIRE(calculate_prefix_bytes(byte_history, k, keys, through_k_bytes));
        REQUIRE(through_k_bytes > 0);

        ResourceLimits success_limits = make_limits();
        success_limits.max_total_input_bytes = prefix_bytes;
        std::vector<JournalRecord> success_records(
            byte_history.begin(),
            byte_history.begin() + static_cast<std::ptrdiff_t>(k - 1));
        char success_label[96]{};
        std::snprintf(
            success_label,
            sizeof(success_label),
            "REP-GEN-02 max_total_input_bytes k=%zu exact",
            k);
        REQUIRE(assert_replay_success(
            success_limits, live_initial_records, success_records, keys, success_label));

        ResourceLimits failure_limits = make_limits();
        failure_limits.max_total_input_bytes = through_k_bytes - 1;
        std::vector<JournalRecord> failure_records(
            byte_history.begin(),
            byte_history.begin() + static_cast<std::ptrdiff_t>(k));
        char failure_label[96]{};
        std::snprintf(
            failure_label,
            sizeof(failure_label),
            "REP-GEN-02 max_total_input_bytes k=%zu over",
            k);
        REQUIRE(run_resource_limit_failure(
            failure_limits,
            live_initial_records,
            failure_records,
            k - 1,
            keys,
            failure_label));
    }

    std::vector<JournalRecord> profile_history;
    REQUIRE(seal_history(unique_facts(3, 800), keys, profile_history));
    for (std::size_t k = 2; k <= 3; ++k) {
        ResourceLimits limits = make_limits();
        limits.max_profiles = k - 1;
        std::vector<JournalRecord> success_records(
            profile_history.begin(),
            profile_history.begin() + static_cast<std::ptrdiff_t>(k - 1));
        std::vector<JournalRecord> failure_records(
            profile_history.begin(),
            profile_history.begin() + static_cast<std::ptrdiff_t>(k));
        char success_label[80]{};
        char failure_label[80]{};
        std::snprintf(success_label, sizeof(success_label), "REP-GEN-02 max_profiles k=%zu boundary", k);
        std::snprintf(failure_label, sizeof(failure_label), "REP-GEN-02 max_profiles k=%zu over", k);
        REQUIRE(assert_replay_success(
            limits, live_initial_records, success_records, keys, success_label));
        REQUIRE(run_resource_limit_failure(
            limits, live_initial_records, failure_records, k - 1, keys, failure_label));
    }

    std::vector<JournalRecord> failure_code_history;
    REQUIRE(seal_history(failure_code_facts(3), keys, failure_code_history));
    for (std::size_t k = 2; k <= 3; ++k) {
        ResourceLimits limits = make_limits();
        limits.max_failure_codes_per_profile = k - 1;
        std::vector<JournalRecord> success_records(
            failure_code_history.begin(),
            failure_code_history.begin() + static_cast<std::ptrdiff_t>(k - 1));
        std::vector<JournalRecord> failure_records(
            failure_code_history.begin(),
            failure_code_history.begin() + static_cast<std::ptrdiff_t>(k));
        char success_label[96]{};
        char failure_label[96]{};
        std::snprintf(
            success_label,
            sizeof(success_label),
            "REP-GEN-02 max_failure_codes_per_profile k=%zu boundary",
            k);
        std::snprintf(
            failure_label,
            sizeof(failure_label),
            "REP-GEN-02 max_failure_codes_per_profile k=%zu over",
            k);
        REQUIRE(assert_replay_success(
            limits, live_initial_records, success_records, keys, success_label));
        REQUIRE(run_resource_limit_failure(
            limits, live_initial_records, failure_records, k - 1, keys, failure_label));
    }

    std::puts("[PASS] REP-GEN-02: record/profile/failure-code sweeps and byte k=2,3 verified");
    return true;
}

bool run_rep_gen_03() {
    BlockingKeyProvider keys;
    TestKeyProvider initial_keys;
    std::vector<JournalRecord> replay_records;
    REQUIRE(seal_history(unique_facts(6, 900), keys, replay_records));

    ResourceLimits limits = make_limits();
    ResourceGuard live_guard(limits);
    JournalFeedbackEngine live(live_guard);
    std::vector<JournalRecord> live_initial_records(
        replay_records.begin(), replay_records.begin() + 2);
    REQUIRE(ingest_all(live, live_initial_records, initial_keys));
    const std::uint64_t initial_epoch = live.epoch();

    JournalRecoveryAdapter adapter;
    bool replay_result = true;
    bool worker_threw = false;
    std::thread worker([&] {
        try {
            replay_result = adapter.rebuild_feedback_engine_state(replay_records, keys, live);
        } catch (...) {
            worker_threw = true;
        }
    });

    if (!keys.wait_until_blocked()) {
        keys.release();
        worker.join();
        return failure(__LINE__, "Replay reached the first verification_key wait");
    }

    const FeedbackIngestResult concurrent_ingest =
        live.ingest_record(replay_records[2], keys);
    if (concurrent_ingest.status != FeedbackStatus::Ingested) {
        keys.release();
        worker.join();
        return failure(__LINE__, "concurrent live LSN=3 ingest succeeded");
    }
    const LiveState latest_live_state = capture_live_state(live, live_guard);
    if (latest_live_state.snapshot.usage.records != 3 ||
        latest_live_state.epoch != initial_epoch + 1) {
        keys.release();
        worker.join();
        return failure(__LINE__, "live state advanced while Replay was blocked");
    }

    keys.release();
    worker.join();
    REQUIRE(!worker_threw);
    REQUIRE(!replay_result);
    REQUIRE(unchanged_live_state(live, live_guard, latest_live_state));
    REQUIRE(same_usage(live_guard.usage(), latest_live_state.snapshot.usage));
    std::puts("[PASS] REP-GEN-03: stale Replay lost epoch CAS and retained concurrent live state");
    return true;
}

bool run_rep_gen_04() {
    ReplayInjectionControl::armed.store(false, std::memory_order_relaxed);
    ReplayInjectionControl::fires.store(0, std::memory_order_relaxed);

    TestKeyProvider signing_keys;
    std::vector<JournalRecord> live_initial_records;
    std::vector<JournalRecord> replay_records;
    REQUIRE(seal_history(initial_facts(), signing_keys, live_initial_records));
    REQUIRE(seal_history(distinct_failure_facts(3), signing_keys, replay_records));

    ResourceLimits limits = make_limits();
    ResourceGuard live_guard(limits);
    JournalFeedbackEngine live(live_guard);
    REQUIRE(ingest_all(live, live_initial_records, signing_keys));
    const LiveState before = capture_live_state(live, live_guard);
    REQUIRE(before.snapshot.usage.records == 2);
    REQUIRE(!before.profiles.empty());

    ArmOnSecondVerificationKeyProvider injecting_keys;
    JournalRecoveryAdapter adapter;
    const bool replay_result =
        adapter.rebuild_feedback_engine_state(replay_records, injecting_keys, live);
    ReplayInjectionControl::armed.store(false, std::memory_order_relaxed);

    REQUIRE(ReplayInjectionControl::fires.load(std::memory_order_relaxed) > 0);
    REQUIRE(!replay_result);
    REQUIRE(unchanged_live_state(live, live_guard, before));
    REQUIRE(same_usage(live_guard.usage(), before.snapshot.usage));
    REQUIRE(live_guard.status() == ResourceStatus::Ok);
    std::puts("[PASS] REP-GEN-04: injected shadow reservation exception was caught; live state unchanged");
    return true;
}

bool run_case(const char* name, bool (*test)()) {
    std::printf("[RUN] %s\n", name);
    return test();
}

} // namespace

int main() {
    bool passed = true;
    passed = run_case("REP-GEN-00", run_rep_gen_00) && passed;
    passed = run_case("REP-GEN-01", run_rep_gen_01) && passed;
    passed = run_case("REP-GEN-02", run_rep_gen_02) && passed;
    passed = run_case("REP-GEN-03", run_rep_gen_03) && passed;
    passed = run_case("REP-GEN-04", run_rep_gen_04) && passed;
    if (!passed) {
        return 1;
    }
    std::puts("[RESULT] ALL FEEDBACK REPLAY ATOMICITY GENERALIZATION TESTS PASSED");
    return 0;
}
