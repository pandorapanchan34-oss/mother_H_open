#include "mother_H/journal/journal_integrity.hpp"
#include "mother_H/journal/kek_wrapped_key_store_v2.hpp"
#include "mother_H/policy/journal_feedback_engine.hpp"
#include "mother_H/resource/resource_guard.hpp"
#include "mother_H/storage/journal_recovery_adapter.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <functional>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

using namespace mother_h::journal;
using namespace mother_h::policy;
using namespace mother_h::resource;
using mother_H::storage::JournalRecoveryAdapter;
namespace journal_v2 = mother_h::journal::v2;

constexpr std::chrono::seconds kWatchdog{20};
constexpr std::uint32_t kFeedbackOpId = 41;
constexpr std::uint64_t kFeedbackTarget = 1001;

class ErrorLog {
public:
    void add(std::string message) {
        std::lock_guard<std::mutex> lock(mutex_);
        messages_.push_back(std::move(message));
    }

    bool empty() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return messages_.empty();
    }

    void report() const {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const std::string& message : messages_) {
            std::fprintf(stderr, "[FAIL] %s\n", message.c_str());
        }
    }

private:
    mutable std::mutex mutex_;
    std::vector<std::string> messages_;
};

class StartGate {
public:
    bool wait() {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!condition_.wait_for(lock, kWatchdog, [this] {
                return open_ || cancelled_;
            })) {
            return false;
        }
        return open_ && !cancelled_;
    }

    void open() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            open_ = true;
        }
        condition_.notify_all();
    }

    void cancel() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cancelled_ = true;
        }
        condition_.notify_all();
    }

private:
    std::mutex mutex_;
    std::condition_variable condition_;
    bool open_{false};
    bool cancelled_{false};
};

class Completion {
public:
    void signal() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            ++count_;
        }
        condition_.notify_all();
    }

    bool wait_for(std::size_t expected, std::chrono::seconds timeout) {
        std::unique_lock<std::mutex> lock(mutex_);
        return condition_.wait_for(lock, timeout, [this, expected] {
            return count_ >= expected;
        });
    }

private:
    std::mutex mutex_;
    std::condition_variable condition_;
    std::size_t count_{0};
};

class ReusableBarrier {
public:
    explicit ReusableBarrier(std::size_t participants)
        : participants_(participants) {}

    bool wait() {
        std::unique_lock<std::mutex> lock(mutex_);
        if (broken_) return false;
        const std::size_t generation = generation_;
        if (++arrived_ == participants_) {
            arrived_ = 0;
            ++generation_;
            condition_.notify_all();
            return true;
        }
        if (!condition_.wait_for(lock, kWatchdog, [this, generation] {
                return broken_ || generation_ != generation;
            })) {
            broken_ = true;
            condition_.notify_all();
            return false;
        }
        return !broken_;
    }

    void break_all() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            broken_ = true;
        }
        condition_.notify_all();
    }

private:
    const std::size_t participants_;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::size_t arrived_{0};
    std::size_t generation_{0};
    bool broken_{false};
};

template <typename Function>
std::thread make_worker(
    ErrorLog& errors,
    Completion* completion,
    Function function
) {
    return std::thread(
        [&errors, completion, function = std::move(function)]() mutable {
            try {
                function();
            } catch (const std::exception& exception) {
                errors.add(std::string("worker exception: ") + exception.what());
            } catch (...) {
                errors.add("worker exception: unknown exception");
            }
            if (completion != nullptr) completion->signal();
        });
}

class TestKeyProvider : public ISecureKeyProvider {
public:
    KeyStatus current_signing_key(KeyMaterial& output) const noexcept override {
        return assign_key(output, KeyReference{"feedback-tsan-key", 1});
    }

    KeyStatus verification_key(
        const KeyReference& reference,
        KeyMaterial& output
    ) const noexcept override {
        if (reference != KeyReference{"feedback-tsan-key", 1}) {
            return KeyStatus::NotFound;
        }
        return assign_key(output, reference);
    }

    KeyStatus rotate_key(const std::string&, KeyReference&) noexcept override {
        return KeyStatus::BackendUnavailable;
    }

    KeyStatus revoke_key(const KeyReference&) noexcept override {
        return KeyStatus::BackendUnavailable;
    }

protected:
    static KeyStatus assign_key(
        KeyMaterial& output,
        const KeyReference& reference
    ) noexcept {
        try {
            output = KeyMaterial(reference, std::vector<std::uint8_t>(32, 0x5A));
            return KeyStatus::Ok;
        } catch (...) {
            return KeyStatus::NotFound;
        }
    }
};

class BlockingTestKeyProvider final : public TestKeyProvider {
public:
    void arm_next_verification() {
        std::lock_guard<std::mutex> lock(mutex_);
        armed_ = true;
        entered_ = false;
        released_ = false;
    }

    bool wait_until_entered() {
        std::unique_lock<std::mutex> lock(mutex_);
        return condition_.wait_for(lock, kWatchdog, [this] {
            return entered_;
        });
    }

    void release() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            released_ = true;
        }
        condition_.notify_all();
    }

    KeyStatus verification_key(
        const KeyReference& reference,
        KeyMaterial& output
    ) const noexcept override {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            if (armed_) {
                armed_ = false;
                entered_ = true;
                condition_.notify_all();
                if (!condition_.wait_for(lock, kWatchdog, [this] {
                        return released_;
                    })) {
                    return KeyStatus::BackendUnavailable;
                }
            }
        }
        return TestKeyProvider::verification_key(reference, output);
    }

private:
    mutable std::mutex mutex_;
    mutable std::condition_variable condition_;
    mutable bool armed_{false};
    mutable bool entered_{false};
    mutable bool released_{false};
};

ResourceLimits feedback_limits() {
    ResourceLimits limits{};
    limits.max_record_bytes = 1024 * 1024;
    limits.max_payload_bytes = 128;
    limits.max_total_input_bytes = 1024 * 1024;
    limits.max_records = 128;
    limits.max_profiles = 4;
    limits.max_failure_codes_per_profile = 4;
    limits.max_steps = 10000;
    limits.max_elapsed_time_us = 1000000;
    return limits;
}

bool make_feedback_history(
    std::size_t count,
    const ISecureKeyProvider& keys,
    std::vector<JournalRecord>& records,
    ErrorLog& errors
) {
    records.clear();
    records.reserve(count);
    JournalHash previous_hash = JournalIntegrity::genesis_hash();
    for (std::size_t index = 0; index < count; ++index) {
        const bool succeeded = (index % 3) != 1;
        JournalRecord record{};
        record.lsn = static_cast<std::uint64_t>(index + 1);
        record.timestamp_utc = "2026-11-15T00:00:00.000000000Z";
        record.payload = JournalFeedbackEngine::encode_fact_payload(
            JournalFeedbackFact{
                kFeedbackOpId,
                kFeedbackTarget,
                succeeded,
                static_cast<std::uint64_t>(3 + index % 4),
                static_cast<std::uint64_t>(5 + index % 7),
                succeeded ? 0U : 7U
            });
        const IntegrityResult sealed = JournalIntegrity::seal(
            record, record.lsn, previous_hash, keys);
        if (!sealed) {
            errors.add("could not seal feedback test history");
            return false;
        }
        previous_hash = sealed.record_hash;
        records.push_back(std::move(record));
    }
    return true;
}

bool ingest_prefix(
    JournalFeedbackEngine& engine,
    const std::vector<JournalRecord>& records,
    std::size_t count,
    const ISecureKeyProvider& keys,
    ErrorLog& errors
) {
    for (std::size_t index = 0; index < count; ++index) {
        if (engine.ingest_record(records[index], keys).status !=
            FeedbackStatus::Ingested) {
            errors.add("feedback prefix ingest was not Ingested");
            return false;
        }
    }
    return true;
}

bool valid_feedback_snapshot(const EngineResourceSnapshot& snapshot) {
    if (snapshot.usage.records + 1 != snapshot.next_lsn ||
        snapshot.chain_exhausted ||
        snapshot.usage.profiles != snapshot.stats.size()) {
        return false;
    }

    std::uint64_t attempts = 0;
    std::uint64_t failure_entries = 0;
    for (const auto& entry : snapshot.stats) {
        const OpPerformanceProfile& profile = entry.second;
        if (profile.attempts == 0 || profile.successes > profile.attempts ||
            profile.successful_steps_used > profile.total_steps_used) {
            return false;
        }
        std::uint64_t failed_attempts = 0;
        for (const auto& failure : profile.failure_codes) {
            if (failure.first == 0 || failure.second == 0) return false;
            failed_attempts += failure.second;
        }
        if (failed_attempts != profile.attempts - profile.successes) return false;
        attempts += profile.attempts;
        failure_entries += profile.failure_codes.size();
    }
    return attempts == snapshot.usage.records &&
        failure_entries == snapshot.usage.failure_code_entries;
}

bool valid_feedback_estimate(const FeedbackEstimate& estimate) {
    if (estimate.op_id != kFeedbackOpId ||
        estimate.attempts > 64 ||
        estimate.successes > estimate.attempts) {
        return false;
    }
    if (estimate.status == QueryStatus::NoData) {
        return estimate.attempts == 0 && estimate.successes == 0;
    }
    if (estimate.status != QueryStatus::Ready || !estimate.success_rate) {
        return false;
    }
    return *estimate.success_rate >= 0.0 && *estimate.success_rate <= 1.0;
}

bool run_tsan_fbe_01() {
    ErrorLog errors;
    TestKeyProvider keys;
    std::vector<JournalRecord> records;
    if (!make_feedback_history(64, keys, records, errors)) return false;

    ResourceGuard resources(feedback_limits());
    JournalFeedbackEngine feedback(resources);
    StartGate reader_start;
    StartGate writer_start;
    ReusableBarrier writers_barrier(4);
    Completion readers_ready;
    Completion writers_done;
    std::atomic<bool> stop_readers{false};
    std::array<std::atomic<unsigned>, 64> accepted{};
    std::array<std::atomic<unsigned>, 64> rejected{};
    std::array<std::atomic<std::size_t>, 4> reader_iterations{};
    for (auto& count : accepted) count.store(0, std::memory_order_relaxed);
    for (auto& count : rejected) count.store(0, std::memory_order_relaxed);
    for (auto& count : reader_iterations) count.store(0, std::memory_order_relaxed);

    std::vector<std::thread> threads;
    threads.reserve(8);
    for (std::size_t writer = 0; writer < 4; ++writer) {
        threads.push_back(make_worker(errors, &writers_done, [&, writer] {
            if (!writer_start.wait()) {
                errors.add("writer start gate timed out or was cancelled");
                writers_barrier.break_all();
                return;
            }
            for (std::size_t index = 0; index < records.size(); ++index) {
                if (!writers_barrier.wait()) {
                    errors.add("writer round-start watchdog detected stalled progress");
                    return;
                }
                const FeedbackIngestResult result =
                    feedback.ingest_record(records[index], keys);
                if (result.status == FeedbackStatus::Ingested) {
                    accepted[index].fetch_add(1, std::memory_order_relaxed);
                } else if (result.status == FeedbackStatus::IntegrityRejected &&
                           result.integrity_status == IntegrityStatus::LsnOutOfOrder) {
                    rejected[index].fetch_add(1, std::memory_order_relaxed);
                } else {
                    errors.add("writer received an unexpected ingest rejection");
                }
                if (!writers_barrier.wait()) {
                    errors.add("writer round-end watchdog detected stalled progress");
                    return;
                }
            }
        }));
    }

    for (std::size_t reader = 0; reader < 4; ++reader) {
        threads.push_back(make_worker(errors, nullptr, [&, reader] {
            if (!reader_start.wait()) {
                errors.add("reader start gate timed out or was cancelled");
                return;
            }
            bool reported_ready = false;
            while (!stop_readers.load(std::memory_order_acquire)) {
                const EngineResourceSnapshot snapshot = feedback.snapshot();
                if (!valid_feedback_snapshot(snapshot)) {
                    errors.add("reader observed an inconsistent FBE snapshot");
                    break;
                }
                const FeedbackEstimate estimate =
                    feedback.estimate(kFeedbackOpId, kFeedbackTarget, 1);
                if (!valid_feedback_estimate(estimate)) {
                    errors.add("reader observed an inconsistent FBE estimate");
                    break;
                }
                reader_iterations[reader].fetch_add(1, std::memory_order_relaxed);
                if (!reported_ready) {
                    reported_ready = true;
                    readers_ready.signal();
                }
                std::this_thread::yield();
            }
        }));
    }

    reader_start.open();
    if (!readers_ready.wait_for(4, kWatchdog)) {
        errors.add("FBE-01 watchdog detected readers had not completed an initial read");
        stop_readers.store(true, std::memory_order_release);
        reader_start.cancel();
        writer_start.cancel();
        writers_barrier.break_all();
        for (std::thread& thread : threads) thread.join();
        errors.report();
        return false;
    }

    writer_start.open();
    const bool completed = writers_done.wait_for(4, std::chrono::seconds(60));
    if (!completed) {
        errors.add("writer watchdog detected stalled progress");
        stop_readers.store(true, std::memory_order_release);
        reader_start.cancel();
        writer_start.cancel();
        writers_barrier.break_all();
    }
    stop_readers.store(true, std::memory_order_release);
    for (std::thread& thread : threads) thread.join();

    for (std::size_t index = 0; index < records.size(); ++index) {
        if (accepted[index].load(std::memory_order_relaxed) != 1 ||
            rejected[index].load(std::memory_order_relaxed) != 3) {
            errors.add("same-LSN race did not produce exactly one accept and three LsnOutOfOrder rejects");
            break;
        }
    }
    for (const auto& iterations : reader_iterations) {
        if (iterations.load(std::memory_order_relaxed) == 0) {
            errors.add("a reader made no observable progress");
        }
    }
    const EngineResourceSnapshot final_snapshot = feedback.snapshot();
    if (final_snapshot.usage.records != 64 || final_snapshot.next_lsn != 65 ||
        feedback.epoch() != 64 || !valid_feedback_snapshot(final_snapshot)) {
        errors.add("FBE-01 final state does not match the 64 accepted records");
    }
    errors.report();
    if (!errors.empty()) return false;
    std::puts("[PASS] TSAN-FBE-01: four competing writers and four readers");
    return true;
}

bool run_tsan_fbe_02a() {
    ErrorLog errors;
    TestKeyProvider keys;
    std::vector<JournalRecord> history;
    if (!make_feedback_history(16, keys, history, errors)) return false;

    const ResourceLimits limits = feedback_limits();
    ResourceGuard live_resources(limits);
    JournalFeedbackEngine live(live_resources);
    if (!ingest_prefix(live, history, 3, keys, errors)) return false;
    const EngineResourceSnapshot initial_snapshot = live.snapshot();
    const std::uint64_t initial_epoch = live.epoch();

    ResourceGuard expected_resources(limits);
    JournalFeedbackEngine expected(expected_resources);
    if (!ingest_prefix(expected, history, history.size(), keys, errors)) return false;
    const EngineResourceSnapshot expected_snapshot = expected.snapshot();

    StartGate start;
    Completion replay_done;
    std::atomic<bool> stop_readers{false};
    std::array<std::atomic<std::size_t>, 4> reader_iterations{};
    for (auto& count : reader_iterations) count.store(0, std::memory_order_relaxed);
    std::vector<std::thread> threads;
    threads.reserve(5);

    for (std::size_t reader = 0; reader < 4; ++reader) {
        threads.push_back(make_worker(errors, nullptr, [&, reader] {
            if (!start.wait()) {
                errors.add("FBE-02A reader start gate timed out or was cancelled");
                return;
            }
            while (!stop_readers.load(std::memory_order_acquire)) {
                const EngineResourceSnapshot snapshot = live.snapshot();
                if (snapshot != initial_snapshot && snapshot != expected_snapshot) {
                    errors.add("FBE-02A reader observed a partial replay state");
                    break;
                }
                const FeedbackEstimate estimate =
                    live.estimate(kFeedbackOpId, kFeedbackTarget, 1);
                if (!valid_feedback_estimate(estimate)) {
                    errors.add("FBE-02A reader observed an invalid estimate");
                    break;
                }
                reader_iterations[reader].fetch_add(1, std::memory_order_relaxed);
                std::this_thread::yield();
            }
        }));
    }

    threads.push_back(make_worker(errors, &replay_done, [&] {
        if (!start.wait()) {
            errors.add("FBE-02A replay start gate timed out or was cancelled");
            return;
        }
        const auto ready_deadline = std::chrono::steady_clock::now() + kWatchdog;
        for (;;) {
            bool all_readers_started = true;
            for (const auto& iterations : reader_iterations) {
                if (iterations.load(std::memory_order_acquire) == 0) {
                    all_readers_started = false;
                    break;
                }
            }
            if (all_readers_started) break;
            if (std::chrono::steady_clock::now() >= ready_deadline) {
                errors.add("FBE-02A watchdog detected readers had not started");
                return;
            }
            std::this_thread::yield();
        }

        JournalRecoveryAdapter adapter;
        std::uint64_t previous_epoch = initial_epoch;
        constexpr std::size_t replay_rounds = 24;
        for (std::size_t round = 0; round < replay_rounds; ++round) {
            if (!adapter.rebuild_feedback_engine_state(history, keys, live)) {
                errors.add("FBE-02A full-history replay unexpectedly failed");
                return;
            }
            const std::uint64_t current_epoch = live.epoch();
            if (current_epoch != previous_epoch + 1) {
                errors.add("FBE-02A replay epoch did not increase by one");
                return;
            }
            previous_epoch = current_epoch;
        }
    }));

    start.open();
    const bool completed = replay_done.wait_for(1, std::chrono::seconds(60));
    if (!completed) errors.add("FBE-02A watchdog detected stalled replay progress");
    stop_readers.store(true, std::memory_order_release);
    start.cancel();
    for (std::thread& thread : threads) thread.join();

    if (live.snapshot() != expected_snapshot ||
        live.epoch() != initial_epoch + 24) {
        errors.add("FBE-02A final state is not the committed complete 16-record history");
    }
    for (const auto& iterations : reader_iterations) {
        if (iterations.load(std::memory_order_relaxed) == 0) {
            errors.add("FBE-02A reader made no observable progress");
        }
    }
    errors.report();
    if (!errors.empty()) return false;
    std::puts("[PASS] TSAN-FBE-02A: repeated successful replay commits with readers");
    return true;
}

bool run_tsan_fbe_02b() {
    ErrorLog errors;
    TestKeyProvider signing_keys;
    std::vector<JournalRecord> all_records;
    if (!make_feedback_history(24, signing_keys, all_records, errors)) return false;

    const ResourceLimits limits = feedback_limits();
    ResourceGuard live_resources(limits);
    JournalFeedbackEngine live(live_resources);
    if (!ingest_prefix(live, all_records, 16, signing_keys, errors)) return false;
    const std::uint64_t initial_epoch = live.epoch();

    BlockingTestKeyProvider replay_keys;
    JournalRecoveryAdapter adapter;
    StartGate readers_start;
    Completion readers_ready;
    std::atomic<bool> stop_readers{false};
    std::array<std::atomic<std::size_t>, 4> reader_iterations{};
    for (auto& count : reader_iterations) count.store(0, std::memory_order_relaxed);
    std::vector<std::thread> readers;
    readers.reserve(4);
    for (std::size_t reader = 0; reader < 4; ++reader) {
        readers.push_back(make_worker(errors, nullptr, [&, reader] {
            if (!readers_start.wait()) {
                errors.add("FBE-02B reader start gate timed out or was cancelled");
                return;
            }
            bool reported_ready = false;
            while (!stop_readers.load(std::memory_order_acquire)) {
                const EngineResourceSnapshot snapshot = live.snapshot();
                if (!valid_feedback_snapshot(snapshot) ||
                    snapshot.usage.records > all_records.size()) {
                    errors.add("FBE-02B reader observed an inconsistent snapshot");
                    break;
                }
                const FeedbackEstimate estimate =
                    live.estimate(kFeedbackOpId, kFeedbackTarget, 1);
                if (!valid_feedback_estimate(estimate)) {
                    errors.add("FBE-02B reader observed an invalid estimate");
                    break;
                }
                reader_iterations[reader].fetch_add(1, std::memory_order_relaxed);
                if (!reported_ready) {
                    reported_ready = true;
                    readers_ready.signal();
                }
                std::this_thread::yield();
            }
        }));
    }
    readers_start.open();
    if (!readers_ready.wait_for(4, kWatchdog)) {
        errors.add("FBE-02B watchdog detected readers had not completed an initial read");
        stop_readers.store(true, std::memory_order_release);
        readers_start.cancel();
        for (std::thread& reader : readers) reader.join();
        errors.report();
        return false;
    }

    bool all_rounds_completed = true;
    constexpr std::size_t rounds = 8;
    for (std::size_t round = 0; round < rounds; ++round) {
        const std::size_t prefix_count = 16 + round;
        std::vector<JournalRecord> replay_history(
            all_records.begin(),
            all_records.begin() + static_cast<std::ptrdiff_t>(prefix_count));
        replay_keys.arm_next_verification();
        std::atomic<bool> replay_result{true};
        Completion replay_done;
        std::thread replay_worker = make_worker(errors, &replay_done, [&] {
            replay_result.store(
                adapter.rebuild_feedback_engine_state(replay_history, replay_keys, live),
                std::memory_order_release);
        });

        if (!replay_keys.wait_until_entered()) {
            errors.add("FBE-02B verification-key watchdog detected stalled Replay progress");
            replay_keys.release();
            stop_readers.store(true, std::memory_order_release);
            readers_start.cancel();
            replay_worker.join();
            all_rounds_completed = false;
            break;
        }

        const FeedbackIngestResult ingested =
            live.ingest_record(all_records[prefix_count], replay_keys);
        if (ingested.status != FeedbackStatus::Ingested) {
            errors.add("FBE-02B concurrent next-record ingest was not Ingested");
            replay_keys.release();
            replay_worker.join();
            all_rounds_completed = false;
            break;
        }

        const EngineResourceSnapshot latest_snapshot = live.snapshot();
        const std::uint64_t latest_epoch = live.epoch();
        if (latest_snapshot.usage.records != prefix_count + 1 ||
            latest_snapshot.next_lsn != prefix_count + 2) {
            errors.add("FBE-02B live state did not advance to the concurrent record");
        }

        replay_keys.release();
        const bool replay_completed =
            replay_done.wait_for(1, std::chrono::seconds(60));
        if (!replay_completed) {
            errors.add("FBE-02B watchdog detected stalled Replay completion");
            stop_readers.store(true, std::memory_order_release);
            readers_start.cancel();
            replay_keys.release();
        }
        replay_worker.join();
        if (!replay_completed) {
            all_rounds_completed = false;
            break;
        }
        if (replay_result.load(std::memory_order_acquire)) {
            errors.add("FBE-02B stale Replay unexpectedly won the epoch CAS");
        }
        if (live.snapshot() != latest_snapshot || live.epoch() != latest_epoch) {
            errors.add("FBE-02B stale Replay overwrote the latest live state");
        }
    }

    stop_readers.store(true, std::memory_order_release);
    readers_start.cancel();
    for (std::thread& reader : readers) reader.join();

    if (all_rounds_completed) {
        ResourceGuard expected_resources(limits);
        JournalFeedbackEngine expected(expected_resources);
        if (!ingest_prefix(expected, all_records, 24, signing_keys, errors)) {
            all_rounds_completed = false;
        } else if (live.snapshot() != expected.snapshot() ||
                   live.epoch() != initial_epoch + rounds) {
            errors.add("FBE-02B final state does not contain all eight concurrent ingests");
        }
    }
    for (const auto& iterations : reader_iterations) {
        if (iterations.load(std::memory_order_relaxed) == 0) {
            errors.add("FBE-02B reader made no observable progress");
        }
    }
    errors.report();
    if (!all_rounds_completed || !errors.empty()) return false;
    std::puts("[PASS] TSAN-FBE-02B: eight stale Replay CAS losses preserved concurrent ingests");
    return true;
}

class TemporaryDirectory {
public:
    TemporaryDirectory() {
        static std::atomic<std::uint64_t> sequence{0};
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        path_ = std::filesystem::temp_directory_path();
        path_ /= "mother-h-tsan-" + std::to_string(stamp) + "-" +
            std::to_string(sequence.fetch_add(1, std::memory_order_relaxed));
        std::error_code error;
        std::filesystem::create_directories(path_, error);
        valid_ = !error;
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    bool valid() const noexcept { return valid_; }
    const std::filesystem::path& path() const noexcept { return path_; }

private:
    std::filesystem::path path_;
    bool valid_{false};
};

using MasterKey = std::array<std::uint8_t, 32>;
using AnchorId = std::array<std::uint8_t, 16>;

MasterKey make_master_key() {
    MasterKey key{};
    key.fill(0x56);
    return key;
}

MasterKey make_anchor_key() {
    MasterKey key{};
    key.fill(0x24);
    return key;
}

AnchorId make_anchor_id() {
    AnchorId id{};
    id.fill(0x42);
    return id;
}

bool provision_store_fixture(
    const std::filesystem::path& store_path,
    const std::filesystem::path& wal_path,
    const std::filesystem::path& counter_path,
    const MasterKey& master_key,
    const MasterKey& anchor_key,
    const AnchorId& anchor_id,
    ErrorLog& errors
) {
    journal_v2::FileMonotonicCounterV2 counter(counter_path);
    if (counter.provision(700) != journal_v2::AnchorStatus::Ok) {
        errors.add("KWS fixture counter provisioning failed");
        return false;
    }
    Aes256GcmMasterKekProvider kek(master_key);
    journal_v2::FileMonotonicRevocationAnchorV2 anchor(
        store_path, wal_path, counter, anchor_key, anchor_id);
    journal_v2::KekWrappedDataEncryptionKeyStoreV2 fixture(
        store_path, kek, anchor);
    if (fixture.provision(700, 900) != KeyStatus::Ok) {
        errors.add("KWS fixture store provisioning failed");
        return false;
    }
    return true;
}

class CallbackGate {
public:
    bool enter_and_wait() {
        std::unique_lock<std::mutex> lock(mutex_);
        entered_ = true;
        condition_.notify_all();
        return condition_.wait_for(lock, kWatchdog, [this] {
            return released_;
        });
    }

    bool wait_until_entered() {
        std::unique_lock<std::mutex> lock(mutex_);
        return condition_.wait_for(lock, kWatchdog, [this] {
            return entered_;
        });
    }

    void release() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            released_ = true;
        }
        condition_.notify_all();
    }

private:
    std::mutex mutex_;
    std::condition_variable condition_;
    bool entered_{false};
    bool released_{false};
};

bool run_tsan_kws_01() {
    ErrorLog errors;
    TemporaryDirectory directory;
    if (!directory.valid()) {
        errors.add("KWS temporary directory creation failed");
        errors.report();
        return false;
    }

    const auto store_path = directory.path() / "dek-store.bin";
    const auto wal_path = directory.path() / "anchor.wal";
    const auto counter_path = directory.path() / "counter.bin";
    const MasterKey master_key = make_master_key();
    const MasterKey anchor_key = make_anchor_key();
    const AnchorId anchor_id = make_anchor_id();
    if (!provision_store_fixture(
            store_path,
            wal_path,
            counter_path,
            master_key,
            anchor_key,
            anchor_id,
            errors)) {
        errors.report();
        return false;
    }

    journal_v2::FileMonotonicCounterV2 counter(counter_path);
    Aes256GcmMasterKekProvider kek(master_key);
    journal_v2::FileMonotonicRevocationAnchorV2 anchor(
        store_path, wal_path, counter, anchor_key, anchor_id);
    journal_v2::KekWrappedDataEncryptionKeyStoreV2 store(
        store_path, kek, anchor);
    if (store.load() != KeyStatus::Ok || store.load() != KeyStatus::InvalidRequest) {
        errors.add("KWS load contract failed before/after initialization");
        errors.report();
        return false;
    }

    DataKeyReference target_reference{};
    if (store.generate_key("target-key", target_reference) != KeyStatus::Ok ||
        target_reference.version != 1) {
        errors.add("KWS target key generation failed");
        errors.report();
        return false;
    }

    constexpr std::size_t generator_threads = 4;
    constexpr std::size_t generation_rounds = 4;
    constexpr std::size_t reader_threads = 4;
    constexpr std::size_t read_rounds = 64;
    StartGate start;
    Completion workers_done;
    std::atomic<std::size_t> successful_reads{0};
    std::atomic<std::size_t> busy_reads{0};
    std::atomic<std::size_t> callback_calls{0};
    std::atomic<std::size_t> distinct_issue_successes{0};
    std::atomic<std::size_t> distinct_issue_busy{0};
    std::atomic<std::size_t> shared_issue_successes{0};
    std::atomic<std::size_t> shared_issue_busy{0};
    std::mutex references_mutex;
    std::vector<DataKeyReference> distinct_references;
    std::vector<DataKeyReference> shared_id_references;
    const std::size_t generation_attempts =
        generator_threads * generation_rounds;
    distinct_references.reserve(generation_attempts);
    shared_id_references.reserve(generation_attempts);
    std::vector<std::thread> workers;
    workers.reserve(generator_threads + reader_threads);

    for (std::size_t worker = 0; worker < generator_threads; ++worker) {
        workers.push_back(make_worker(errors, &workers_done, [&, worker] {
            if (!start.wait()) {
                errors.add("KWS generator start gate timed out or was cancelled");
                return;
            }
            for (std::size_t round = 0; round < generation_rounds; ++round) {
                DataKeyReference distinct{};
                const std::string key_id = "parallel-" +
                    std::to_string(worker) + "-" + std::to_string(round);
                const KeyStatus distinct_status =
                    store.generate_key(key_id, distinct);
                if (distinct_status == KeyStatus::BackendUnavailable) {
                    distinct_issue_busy.fetch_add(1, std::memory_order_relaxed);
                } else if (distinct_status != KeyStatus::Ok) {
                    errors.add("parallel distinct-id key generation failed");
                } else {
                    distinct_issue_successes.fetch_add(
                        1, std::memory_order_relaxed);
                    std::lock_guard<std::mutex> lock(references_mutex);
                    distinct_references.push_back(std::move(distinct));
                }

                DataKeyReference shared{};
                const KeyStatus shared_status =
                    store.generate_key("shared-versioned-id", shared);
                if (shared_status == KeyStatus::BackendUnavailable) {
                    shared_issue_busy.fetch_add(1, std::memory_order_relaxed);
                } else if (shared_status != KeyStatus::Ok) {
                    errors.add("parallel shared-id key generation failed");
                } else {
                    shared_issue_successes.fetch_add(
                        1, std::memory_order_relaxed);
                    std::lock_guard<std::mutex> lock(references_mutex);
                    shared_id_references.push_back(std::move(shared));
                }
            }
        }));
    }

    for (std::size_t reader = 0; reader < reader_threads; ++reader) {
        workers.push_back(make_worker(errors, &workers_done, [&, reader] {
            (void)reader;
            if (!start.wait()) {
                errors.add("KWS reader start gate timed out or was cancelled");
                return;
            }
            for (std::size_t round = 0; round < read_rounds; ++round) {
                const KeyStatus status = store.with_key(
                    target_reference,
                    [&](const DataKeyMaterial& material) {
                        callback_calls.fetch_add(1, std::memory_order_relaxed);
                        return material.secret().size() ==
                            DataKeyMaterial::kAes256KeyBytes;
                    });
                if (status != KeyStatus::Ok) {
                    if (status == KeyStatus::BackendUnavailable) {
                        busy_reads.fetch_add(1, std::memory_order_relaxed);
                    } else {
                        errors.add("parallel KWS with_key call returned an unexpected status");
                    }
                    continue;
                }
                successful_reads.fetch_add(1, std::memory_order_relaxed);
            }
        }));
    }

    start.open();
    const std::size_t expected_workers = generator_threads + reader_threads;
    if (!workers_done.wait_for(expected_workers, std::chrono::seconds(90))) {
        errors.add("KWS-01A watchdog detected stalled worker progress");
        start.cancel();
    }
    for (std::thread& worker : workers) worker.join();

    const std::size_t distinct_successes =
        distinct_issue_successes.load(std::memory_order_relaxed);
    const std::size_t shared_successes =
        shared_issue_successes.load(std::memory_order_relaxed);
    const std::size_t successful_generations =
        distinct_successes + shared_successes;
    if (successful_reads.load(std::memory_order_relaxed) +
            busy_reads.load(std::memory_order_relaxed) !=
            reader_threads * read_rounds ||
        callback_calls.load(std::memory_order_relaxed) !=
            successful_reads.load(std::memory_order_relaxed) ||
        distinct_issue_successes.load(std::memory_order_relaxed) +
            distinct_issue_busy.load(std::memory_order_relaxed) !=
            generation_attempts ||
        shared_issue_successes.load(std::memory_order_relaxed) +
            shared_issue_busy.load(std::memory_order_relaxed) !=
            generation_attempts ||
        distinct_references.size() != distinct_successes ||
        shared_id_references.size() != shared_successes ||
        shared_successes == 0) {
        errors.add("KWS-01A concurrent use/generation counts are inconsistent");
    }

    std::set<std::pair<std::string, std::uint32_t>> reference_set;
    for (const DataKeyReference& reference : distinct_references) {
        if (reference.version != 1 ||
            !reference_set.emplace(reference.key_id, reference.version).second) {
            errors.add("KWS-01A distinct key references were not unique");
        }
    }
    std::set<std::uint32_t> shared_versions;
    for (const DataKeyReference& reference : shared_id_references) {
        if (reference.key_id != "shared-versioned-id" ||
            !shared_versions.insert(reference.version).second) {
            errors.add("KWS-01A shared key versions were not unique");
        }
    }
    if (shared_versions.size() != shared_successes ||
        shared_versions.empty() ||
        *shared_versions.begin() != 1 ||
        *shared_versions.rbegin() != shared_successes) {
        errors.add("KWS-01A shared key versions were not contiguous");
    }

    journal_v2::AnchorSnapshot before_revoke{};
    if (anchor.snapshot(before_revoke) != journal_v2::AnchorStatus::Ok ||
        before_revoke.counter != 700 + 1 + successful_generations ||
        before_revoke.generation != 900 + 1 + successful_generations) {
        errors.add("KWS-01A anchor generation/counter did not match successful issues");
    }

    CallbackGate callback_gate;
    StartGate use_start;
    Completion use_done;
    std::atomic<int> use_status{static_cast<int>(KeyStatus::BackendUnavailable)};
    std::atomic<std::size_t> held_callback_calls{0};
    std::thread active_user = make_worker(errors, &use_done, [&] {
        if (!use_start.wait()) {
            errors.add("KWS active-use start gate timed out or was cancelled");
            return;
        }
        const KeyStatus status = store.with_key(
            target_reference,
            [&](const DataKeyMaterial& material) {
                held_callback_calls.fetch_add(1, std::memory_order_relaxed);
                return material.secret().size() ==
                           DataKeyMaterial::kAes256KeyBytes &&
                    callback_gate.enter_and_wait();
            });
        use_status.store(static_cast<int>(status), std::memory_order_release);
    });
    use_start.open();

    if (!callback_gate.wait_until_entered()) {
        errors.add("KWS active-use watchdog detected callback did not enter");
        callback_gate.release();
        active_user.join();
        errors.report();
        return false;
    }

    constexpr std::size_t revoker_threads = 3;
    constexpr std::size_t attempts_per_revoker = 4;
    StartGate revokers_start;
    Completion revokers_done;
    std::atomic<std::size_t> rejected_revocations{0};
    std::vector<std::thread> revokers;
    revokers.reserve(revoker_threads);
    for (std::size_t revoker = 0; revoker < revoker_threads; ++revoker) {
        revokers.push_back(make_worker(errors, &revokers_done, [&, revoker] {
            (void)revoker;
            if (!revokers_start.wait()) {
                errors.add("KWS revoker start gate timed out or was cancelled");
                return;
            }
            for (std::size_t attempt = 0; attempt < attempts_per_revoker; ++attempt) {
                const KeyStatus status = store.revoke_key(target_reference);
                if (status != KeyStatus::BackendUnavailable) {
                    errors.add("KWS revoke during active use was not rejected");
                } else {
                    rejected_revocations.fetch_add(1, std::memory_order_relaxed);
                }
            }
        }));
    }
    revokers_start.open();
    if (!revokers_done.wait_for(revoker_threads, std::chrono::seconds(60))) {
        errors.add("KWS-01B watchdog detected stalled revoker progress");
        revokers_start.cancel();
    }
    callback_gate.release();
    for (std::thread& revoker : revokers) revoker.join();
    active_user.join();

    const std::size_t expected_revocations =
        revoker_threads * attempts_per_revoker;
    if (use_status.load(std::memory_order_acquire) !=
            static_cast<int>(KeyStatus::Ok) ||
        held_callback_calls.load(std::memory_order_relaxed) != 1 ||
        rejected_revocations.load(std::memory_order_relaxed) !=
            expected_revocations) {
        errors.add("KWS-01B active-use/revoke gate results are inconsistent");
    }

    journal_v2::AnchorSnapshot after_rejected_revokes{};
    if (anchor.snapshot(after_rejected_revokes) != journal_v2::AnchorStatus::Ok ||
        !(after_rejected_revokes == before_revoke)) {
        errors.add("KWS-01B rejected revocations changed the anchor state");
    }

    if (store.revoke_key(target_reference) != KeyStatus::Ok) {
        errors.add("KWS revoke after active use did not succeed");
    }

    constexpr std::size_t post_revoke_threads = 4;
    constexpr std::size_t post_revoke_rounds = 16;
    StartGate post_revoke_start;
    Completion post_revoke_done;
    std::atomic<std::size_t> revoked_results{0};
    std::atomic<std::size_t> post_revoke_callbacks{0};
    std::vector<std::thread> post_revoke_workers;
    post_revoke_workers.reserve(post_revoke_threads);
    for (std::size_t worker = 0; worker < post_revoke_threads; ++worker) {
        post_revoke_workers.push_back(make_worker(
            errors, &post_revoke_done, [&, worker] {
                (void)worker;
                if (!post_revoke_start.wait()) {
                    errors.add("KWS post-revoke start gate timed out or was cancelled");
                    return;
                }
                for (std::size_t round = 0; round < post_revoke_rounds; ++round) {
                    const KeyStatus status = store.with_key(
                        target_reference,
                        [&](const DataKeyMaterial&) {
                            post_revoke_callbacks.fetch_add(
                                1, std::memory_order_relaxed);
                            return true;
                        });
                    if (status != KeyStatus::Revoked) {
                        errors.add("post-revoke with_key did not return Revoked");
                    } else {
                        revoked_results.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            }));
    }
    post_revoke_start.open();
    if (!post_revoke_done.wait_for(
            post_revoke_threads, std::chrono::seconds(60))) {
        errors.add("KWS-01B watchdog detected stalled post-revoke progress");
        post_revoke_start.cancel();
    }
    for (std::thread& worker : post_revoke_workers) worker.join();

    journal_v2::AnchorSnapshot final_anchor{};
    std::uint64_t final_counter = 0;
    if (anchor.snapshot(final_anchor) != journal_v2::AnchorStatus::Ok ||
        counter.read(final_counter) != journal_v2::AnchorStatus::Ok ||
        final_anchor.counter != 700 + 1 + successful_generations + 1 ||
        final_anchor.generation != 900 + 1 + successful_generations + 1 ||
        final_counter != final_anchor.counter) {
        errors.add("KWS final anchor/counter state is inconsistent");
    }
    if (revoked_results.load(std::memory_order_relaxed) !=
            post_revoke_threads * post_revoke_rounds ||
        post_revoke_callbacks.load(std::memory_order_relaxed) != 0) {
        errors.add("revoked key was used or invoked a callback");
    }

    errors.report();
    if (!errors.empty()) return false;
    std::puts("[PASS] TSAN-KWS-01: single V2 store concurrent use/generate/revoke");
    return true;
}

bool run_case(const char* name, bool (*test)()) {
    std::printf("[RUN] %s\n", name);
    const bool passed = test();
    if (!passed) std::fprintf(stderr, "[FAIL] %s\n", name);
    return passed;
}

} // namespace

int main() {
    bool passed = true;
    passed = run_case("TSAN-FBE-01", run_tsan_fbe_01) && passed;
    passed = run_case("TSAN-FBE-02A", run_tsan_fbe_02a) && passed;
    passed = run_case("TSAN-FBE-02B", run_tsan_fbe_02b) && passed;
    passed = run_case("TSAN-KWS-01", run_tsan_kws_01) && passed;
    if (!passed) return 1;
    std::puts("[RESULT] ALL FEEDBACK/KEYSTORE CONCURRENCY TESTS PASSED");
    return 0;
}
