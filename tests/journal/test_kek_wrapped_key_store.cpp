#include "mother_H/integration/event_journal.hpp"
#include "mother_H/journal/kek_wrapped_key_store.hpp"

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

using namespace mother_h::journal;
using namespace mb::H;

// Test-only in-memory anchor; it does not satisfy the production durability boundary.
class TestMonotonicAnchor final : public IMonotonicRevocationAnchor {
public:
    explicit TestMonotonicAnchor(std::uint64_t initial = 0)
        : generation_(initial), next_lease_(1), revocation_pending_(false) {}

    bool read_generation(std::uint64_t& generation_out) const noexcept override {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            generation_out = generation_;
            return true;
        } catch (...) {
            return false;
        }
    }

    bool advance(std::uint64_t expected, std::uint64_t next) noexcept override {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            if (generation_ != expected ||
                expected == (std::numeric_limits<std::uint64_t>::max)() ||
                next != expected + 1U ||
                !active_leases_.empty() ||
                revocation_pending_) {
                return false;
            }
            generation_ = next;
            return true;
        } catch (...) {
            return false;
        }
    }

    bool acquire_usage(
        const DataKeyReference& reference,
        std::uint64_t expected_generation,
        UsageLease& lease_out
    ) noexcept override {
        lease_out = 0;
        if (!valid_reference(reference)) return false;
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            if (generation_ != expected_generation || revocation_pending_ ||
                next_lease_ == 0) {
                return false;
            }
            const UsageLease lease = next_lease_;
            active_leases_.emplace(
                lease, LeaseRecord{reference, expected_generation});
            ++next_lease_;
            lease_out = lease;
            return true;
        } catch (...) {
            return false;
        }
    }

    bool release_usage(UsageLease lease) noexcept override {
        if (lease == 0) return false;
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            if (fail_next_release_) {
                fail_next_release_ = false;
                return false;
            }
            return active_leases_.erase(lease) == 1;
        } catch (...) {
            return false;
        }
    }

    bool begin_revocation(
        const DataKeyReference& reference,
        std::uint64_t expected_generation
    ) noexcept override {
        if (!valid_reference(reference)) return false;
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            if (generation_ != expected_generation || revocation_pending_ ||
                !active_leases_.empty()) {
                return false;
            }
            revoking_reference_ = reference;
            revoking_generation_ = expected_generation;
            revocation_pending_ = true;
            return true;
        } catch (...) {
            return false;
        }
    }

    bool commit_revocation(
        const DataKeyReference& reference,
        std::uint64_t expected_generation,
        std::uint64_t next_generation
    ) noexcept override {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!matches_pending(reference, expected_generation) ||
                expected_generation ==
                    (std::numeric_limits<std::uint64_t>::max)() ||
                next_generation != expected_generation + 1U) {
                return false;
            }
            if (fail_next_commit_) {
                fail_next_commit_ = false;
                return false;
            }
            generation_ = next_generation;
            clear_pending();
            return true;
        } catch (...) {
            return false;
        }
    }

    bool cancel_revocation(
        const DataKeyReference& reference,
        std::uint64_t expected_generation
    ) noexcept override {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!matches_pending(reference, expected_generation)) return false;
            clear_pending();
            return true;
        } catch (...) {
            return false;
        }
    }

    std::uint64_t generation() const noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            return generation_;
        } catch (...) {
            return 0;
        }
    }

    void set_for_test(std::uint64_t generation) noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            generation_ = generation;
            active_leases_.clear();
            fail_next_release_ = false;
            fail_next_commit_ = false;
            clear_pending();
        } catch (...) {
        }
    }

    void fail_next_release_for_test() noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            fail_next_release_ = true;
        } catch (...) {
        }
    }

    void fail_next_commit_for_test() noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            fail_next_commit_ = true;
        } catch (...) {
        }
    }

private:
    struct LeaseRecord {
        DataKeyReference reference;
        std::uint64_t generation;
    };

    static bool valid_reference(const DataKeyReference& reference) noexcept {
        return !reference.key_id.empty() && reference.key_id.size() <= 128 &&
            reference.version != 0;
    }

    bool matches_pending(
        const DataKeyReference& reference,
        std::uint64_t expected_generation
    ) const noexcept {
        return revocation_pending_ &&
            revoking_generation_ == expected_generation &&
            revoking_reference_ == reference &&
            generation_ == expected_generation &&
            active_leases_.empty();
    }

    void clear_pending() noexcept {
        revocation_pending_ = false;
        revoking_reference_ = {};
        revoking_generation_ = 0;
    }

    mutable std::mutex mutex_;
    std::uint64_t generation_;
    UsageLease next_lease_;
    std::map<UsageLease, LeaseRecord> active_leases_;
    DataKeyReference revoking_reference_;
    std::uint64_t revoking_generation_{0};
    bool revocation_pending_;
    bool fail_next_release_{false};
    bool fail_next_commit_{false};
};

class TestSystemMacKeyProvider final : public ISecureKeyProvider {
public:
    KeyStatus current_signing_key(KeyMaterial& out) const noexcept override {
        out = KeyMaterial(
            KeyReference{"test-system-mac", 1},
            std::vector<std::uint8_t>(32, 0x5C));
        return KeyStatus::Ok;
    }

    KeyStatus verification_key(
        const KeyReference& reference,
        KeyMaterial& out
    ) const noexcept override {
        if (reference.key_id != "test-system-mac" || reference.version != 1) {
            return KeyStatus::NotFound;
        }
        out = KeyMaterial(reference, std::vector<std::uint8_t>(32, 0x5C));
        return KeyStatus::Ok;
    }

    KeyStatus rotate_key(
        const std::string&,
        KeyReference&
    ) noexcept override {
        return KeyStatus::NotFound;
    }

    KeyStatus revoke_key(const KeyReference&) noexcept override {
        return KeyStatus::NotFound;
    }
};

class MemoryRecordSink final : public IJournalRecordSink {
public:
    JournalSinkStatus append_record(const JournalRecord& record) noexcept override {
        try {
            records_.push_back(record);
            return JournalSinkStatus::Ok;
        } catch (...) {
            return JournalSinkStatus::WriteFailed;
        }
    }

    const std::vector<JournalRecord>& records() const noexcept {
        return records_;
    }

private:
    std::vector<JournalRecord> records_;
};

class TemporaryDirectory {
public:
    TemporaryDirectory() {
        for (unsigned attempt = 0; attempt < 16; ++attempt) {
            std::array<std::uint8_t, 8> random{};
            if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1) {
                throw std::runtime_error("RAND_bytes failed for test directory");
            }
            static constexpr char digits[] = "0123456789abcdef";
            std::string suffix;
            suffix.reserve(random.size() * 2);
            for (const std::uint8_t byte : random) {
                suffix.push_back(digits[byte >> 4U]);
                suffix.push_back(digits[byte & 0x0FU]);
            }
            path_ = std::filesystem::temp_directory_path() /
                ("mother_h_kek_store_test_" + suffix);
            std::error_code error;
            if (std::filesystem::create_directory(path_, error)) return;
            if (error) throw std::filesystem::filesystem_error(
                "create test directory", path_, error);
        }
        throw std::runtime_error("could not create unique test directory");
    }

    ~TemporaryDirectory() {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    const std::filesystem::path& path() const noexcept {
        return path_;
    }

private:
    std::filesystem::path path_;
};

struct SensitiveVector {
    std::vector<std::uint8_t> bytes;
    ~SensitiveVector() {
        if (!bytes.empty()) OPENSSL_cleanse(bytes.data(), bytes.size());
    }
};

bool check(bool condition, const std::string& message) {
    if (condition) return true;
    std::cerr << "[FAIL] " << message << std::endl;
    return false;
}

bool test_shared_anchor_coordination() {
    TestMonotonicAnchor anchor(41);
    const DataKeyReference reference{"shared-anchor-test", 3};
    IMonotonicRevocationAnchor::UsageLease lease = 0;
    if (!check(
            anchor.acquire_usage(reference, 41, lease) && lease != 0,
            "shared anchor refused a current-generation usage lease")) {
        return false;
    }

    IMonotonicRevocationAnchor::UsageLease stale_lease = 99;
    if (!check(
            !anchor.acquire_usage(reference, 40, stale_lease) &&
                stale_lease == 0,
            "shared anchor granted a lease for a stale generation")) {
        return false;
    }

    if (!check(
            !anchor.begin_revocation(reference, 41),
            "revocation started while another client held a usage lease")) {
        return false;
    }
    if (!check(
            anchor.release_usage(lease) && !anchor.release_usage(lease),
            "usage lease release was not exactly-once")) {
        return false;
    }

    if (!check(
            anchor.begin_revocation(reference, 41),
            "revocation did not start after the usage lease was released")) {
        return false;
    }
    IMonotonicRevocationAnchor::UsageLease during_revoke = 0;
    if (!check(
            !anchor.acquire_usage(reference, 41, during_revoke) &&
                during_revoke == 0,
            "usage lease was granted during pending revocation")) {
        return false;
    }
    if (!check(
            anchor.cancel_revocation(reference, 41) &&
                !anchor.cancel_revocation(reference, 41),
            "pending revocation could not be cancelled exactly once")) {
        return false;
    }

    IMonotonicRevocationAnchor::UsageLease after_cancel = 0;
    if (!check(
            anchor.acquire_usage(reference, 41, after_cancel) &&
                anchor.release_usage(after_cancel),
            "cancelled revocation did not restore usage availability")) {
        return false;
    }
    if (!check(
            anchor.begin_revocation(reference, 41) &&
                !anchor.commit_revocation(reference, 41, 43) &&
                anchor.generation() == 41,
            "invalid revocation commit changed the generation")) {
        return false;
    }
    if (!check(
            anchor.commit_revocation(reference, 41, 42) &&
                anchor.generation() == 42,
            "valid revocation did not advance the generation")) {
        return false;
    }
    IMonotonicRevocationAnchor::UsageLease old_generation_lease = 0;
    if (!check(
            !anchor.acquire_usage(reference, 41, old_generation_lease) &&
                old_generation_lease == 0,
            "revoked generation granted a new usage lease")) {
        return false;
    }

    TestMonotonicAnchor racing_anchor(73);
    const DataKeyReference racing_reference{"anchor-race-test", 2};
    std::atomic<bool> start_race{false};
    std::atomic<bool> race_acquired{false};
    std::atomic<bool> race_revocation_started{false};
    IMonotonicRevocationAnchor::UsageLease race_lease = 0;
    std::thread acquirer([&] {
        while (!start_race.load()) std::this_thread::yield();
        race_acquired.store(racing_anchor.acquire_usage(
            racing_reference, 73, race_lease));
    });
    std::thread revoker([&] {
        while (!start_race.load()) std::this_thread::yield();
        race_revocation_started.store(
            racing_anchor.begin_revocation(racing_reference, 73));
    });
    start_race.store(true);
    acquirer.join();
    revoker.join();
    if (!check(
            race_acquired.load() != race_revocation_started.load(),
            "concurrent acquire and revoke both succeeded or both failed")) {
        return false;
    }

    if (race_acquired.load()) {
        if (!check(
                racing_anchor.release_usage(race_lease) &&
                    racing_anchor.begin_revocation(racing_reference, 73),
                "revoke did not proceed after raced lease release")) {
            return false;
        }
    }
    if (!check(
            racing_anchor.commit_revocation(racing_reference, 73, 74),
            "raced revocation did not commit")) {
        return false;
    }
    IMonotonicRevocationAnchor::UsageLease raced_stale_lease = 0;
    if (!check(
            !racing_anchor.acquire_usage(
                racing_reference, 73, raced_stale_lease),
            "concurrent path allowed stale-generation use")) {
        return false;
    }

    std::cout << "[PASS] Shared anchor lease and revocation coordination verified"
              << std::endl;
    return true;
}

void append_u16(std::vector<std::uint8_t>& output, std::uint16_t value) {
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
    output.push_back(static_cast<std::uint8_t>(value));
}

void append_u32(std::vector<std::uint8_t>& output, std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>(value >> 24U));
    output.push_back(static_cast<std::uint8_t>(value >> 16U));
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
    output.push_back(static_cast<std::uint8_t>(value));
}

void append_u64(std::vector<std::uint8_t>& output, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

std::uint16_t read_u16(
    const std::vector<std::uint8_t>& input,
    std::size_t offset
) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(input.at(offset)) << 8U) |
        input.at(offset + 1));
}

std::uint32_t read_u32(
    const std::vector<std::uint8_t>& input,
    std::size_t offset
) {
    return
        (static_cast<std::uint32_t>(input.at(offset)) << 24U) |
        (static_cast<std::uint32_t>(input.at(offset + 1)) << 16U) |
        (static_cast<std::uint32_t>(input.at(offset + 2)) << 8U) |
        static_cast<std::uint32_t>(input.at(offset + 3));
}

std::vector<std::uint8_t> make_store_file(
    std::uint64_t generation,
    const DataKeyReference& reference,
    const std::vector<std::uint8_t>& wrapped,
    bool revoked
) {
    std::vector<std::uint8_t> bytes{
        'M', 'H', 'K', 'W', 'S', '0', '0', '1'};
    append_u64(bytes, generation);
    append_u32(bytes, 1);
    append_u16(bytes, static_cast<std::uint16_t>(reference.key_id.size()));
    bytes.insert(bytes.end(), reference.key_id.begin(), reference.key_id.end());
    append_u32(bytes, reference.version);
    bytes.push_back(revoked ? 1U : 0U);
    append_u32(bytes, static_cast<std::uint32_t>(wrapped.size()));
    bytes.insert(bytes.end(), wrapped.begin(), wrapped.end());
    return bytes;
}

std::vector<std::uint8_t> read_binary(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("could not open test file for reading");
    std::vector<std::uint8_t> bytes;
    char value = 0;
    while (input.get(value)) {
        bytes.push_back(static_cast<std::uint8_t>(
            static_cast<unsigned char>(value)));
    }
    if (!input.eof()) throw std::runtime_error("test file read failed");
    return bytes;
}

void write_binary(
    const std::filesystem::path& path,
    const std::vector<std::uint8_t>& bytes
) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("could not open test file for writing");
    if (!bytes.empty()) {
        output.write(
            reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
    }
    output.flush();
    if (!output) throw std::runtime_error("test file write failed");
}

bool contains_bytes(
    const std::vector<std::uint8_t>& haystack,
    const std::vector<std::uint8_t>& needle
) {
    return !needle.empty() &&
        std::search(
            haystack.begin(), haystack.end(), needle.begin(), needle.end()) !=
            haystack.end();
}

bool verify_journal(
    const std::vector<JournalRecord>& records,
    const TestSystemMacKeyProvider& mac_keys,
    const IDataEncryptionKeyProvider& dek_provider,
    bool expected_erased
) {
    std::vector<mb::cqs13_4::EventPayload> decoded;
    std::vector<bool> erased;
    IntegrityStatus failure{};
    if (!AuthenticatedEventJournal::verify_records(
            records, mac_keys, &dek_provider, decoded, erased, failure) ||
        decoded.size() != records.size() ||
        erased.size() != records.size()) {
        return false;
    }
    for (const bool is_erased : erased) {
        if (is_erased != expected_erased) return false;
    }
    return true;
}

bool test_revoke_persistence_failure(
    const std::filesystem::path& base_path,
    const IContextBoundKeyEncryptionKeyProvider& kek
) {
    const auto parent_path = base_path / "revoke-persist-failure";
    if (!std::filesystem::create_directory(parent_path)) {
        return check(false, "could not create revoke-failure fixture");
    }
    const auto store_path = parent_path / "store.bin";
    TestMonotonicAnchor anchor;
    KekWrappedDataEncryptionKeyStore store(store_path, kek, &anchor);
    DataKeyReference reference{};
    if (!check(
            store.load() == KeyStatus::Ok &&
                store.generate_key("cancel-on-persist-failure", reference) ==
                    KeyStatus::Ok,
            "could not initialize revoke-failure fixture")) {
        return false;
    }

    if (!std::filesystem::remove(store_path) ||
        !std::filesystem::remove(parent_path)) {
        return check(false, "could not sabotage revoke-failure path");
    }
    const std::vector<std::uint8_t> marker{0x42};
    write_binary(parent_path, marker);

    const KeyStatus revoke_status = store.revoke_key(reference);
    bool callback_called = false;
    const KeyStatus use_status = store.with_key(
        reference,
        [&](const DataKeyMaterial&) {
            callback_called = true;
            return true;
        });
    IMonotonicRevocationAnchor::UsageLease lease = 0;
    const bool anchor_reusable =
        anchor.acquire_usage(reference, 1, lease) &&
        anchor.release_usage(lease);
    if (!check(
            revoke_status == KeyStatus::BackendUnavailable &&
                anchor.generation() == 1 &&
                use_status == KeyStatus::Ok && callback_called &&
                anchor_reusable,
            "pre-replacement persistence failure did not cancel revocation")) {
        return false;
    }
    return true;
}

bool test_shared_lease_release_failure(
    const std::filesystem::path& base_path,
    const IContextBoundKeyEncryptionKeyProvider& kek
) {
    const auto directory = base_path / "lease-release-failure";
    if (!std::filesystem::create_directory(directory)) {
        return check(false, "could not create release-failure fixture");
    }
    const auto store_path = directory / "store.bin";
    TestMonotonicAnchor anchor;
    KekWrappedDataEncryptionKeyStore store(store_path, kek, &anchor);
    DataKeyReference reference{};
    if (!check(
            store.load() == KeyStatus::Ok &&
                store.generate_key("lease-release-failure", reference) ==
                    KeyStatus::Ok,
            "could not initialize release-failure fixture")) {
        return false;
    }

    anchor.fail_next_release_for_test();
    bool callback_called = false;
    const KeyStatus first_use = store.with_key(
        reference,
        [&](const DataKeyMaterial&) {
            callback_called = true;
            return true;
        });
    bool second_callback_called = false;
    const KeyStatus second_use = store.with_key(
        reference,
        [&](const DataKeyMaterial&) {
            second_callback_called = true;
            return true;
        });
    const bool no_anchor_lease_remains =
        anchor.begin_revocation(reference, 1) &&
        anchor.cancel_revocation(reference, 1);
    if (!check(
            first_use == KeyStatus::BackendUnavailable && callback_called &&
                second_use == KeyStatus::BackendUnavailable &&
                !second_callback_called && no_anchor_lease_remains,
            "shared lease release failure was ignored or left the store usable")) {
        return false;
    }
    return true;
}

bool test_revocation_commit_failure(
    const std::filesystem::path& base_path,
    const IContextBoundKeyEncryptionKeyProvider& kek
) {
    const auto directory = base_path / "revocation-commit-failure";
    if (!std::filesystem::create_directory(directory)) {
        return check(false, "could not create commit-failure fixture");
    }
    const auto store_path = directory / "store.bin";
    TestMonotonicAnchor anchor;
    DataKeyReference reference{};
    {
        KekWrappedDataEncryptionKeyStore store(store_path, kek, &anchor);
        if (!check(
                store.load() == KeyStatus::Ok &&
                    store.generate_key("commit-failure", reference) ==
                        KeyStatus::Ok,
                "could not initialize commit-failure fixture")) {
            return false;
        }

        anchor.fail_next_commit_for_test();
        if (!check(
                store.revoke_key(reference) == KeyStatus::BackendUnavailable &&
                    store.with_key(
                        reference,
                        [](const DataKeyMaterial&) { return true; }) ==
                        KeyStatus::BackendUnavailable &&
                    anchor.generation() == 1,
                "commit failure did not fail the store closed")) {
            return false;
        }
    }

    KekWrappedDataEncryptionKeyStore reload(store_path, kek, &anchor);
    if (!check(
            reload.load() == KeyStatus::BackendUnavailable,
            "uncommitted replacement file was not rejected on reload")) {
        return false;
    }
    IMonotonicRevocationAnchor::UsageLease lease = 0;
    if (!check(
            !anchor.acquire_usage(reference, 1, lease) &&
                lease == 0,
            "failed commit released the pending revocation lock")) {
        return false;
    }
    return true;
}

bool run_tests() {
    if (!test_shared_anchor_coordination()) return false;

    TemporaryDirectory temporary;
    std::array<std::uint8_t, 32> master_key{};
    std::array<std::uint8_t, 32> wrong_master_key{};
    master_key.fill(0x31);
    wrong_master_key.fill(0x72);
    Aes256GcmMasterKekProvider kek(master_key);
    Aes256GcmMasterKekProvider wrong_kek(wrong_master_key);

    SensitiveVector known_dek;
    known_dek.bytes.assign(DataKeyMaterial::kAes256KeyBytes, 0xA7);
    const DataKeyReference known_reference{"context-bound", 7};
    std::vector<std::uint8_t> known_wrapped;
    if (!check(
            kek.wrap_dek(known_reference, known_dek.bytes, known_wrapped) ==
                KeyStatus::Ok &&
                known_wrapped.size() == Aes256GcmMasterKekProvider::kWrappedDekBytes,
            "AES-256-GCM DEK wrapping failed")) {
        return false;
    }

    SensitiveVector unwrapped;
    if (!check(
            kek.unwrap_dek(known_reference, known_wrapped, unwrapped.bytes) ==
                    KeyStatus::Ok &&
                unwrapped.bytes == known_dek.bytes,
            "correct KEK did not unwrap DEK")) {
        return false;
    }
    SensitiveVector wrong_unwrapped;
    bool wrong_callback_called = false;
    if (!check(
            wrong_kek.unwrap_dek(
                known_reference, known_wrapped, wrong_unwrapped.bytes) ==
                KeyStatus::BackendUnavailable &&
                wrong_unwrapped.bytes.empty(),
            "wrong KEK was not rejected with empty plaintext output")) {
        return false;
    }

    const DataKeyReference swapped_reference{"context-bound", 8};
    SensitiveVector swapped_unwrapped;
    if (!check(
            kek.unwrap_dek(
                swapped_reference, known_wrapped, swapped_unwrapped.bytes) ==
                KeyStatus::BackendUnavailable &&
                swapped_unwrapped.bytes.empty(),
            "changing key version did not fail authentication")) {
        return false;
    }
    const DataKeyReference swapped_id_reference{"other-context", 7};
    SensitiveVector swapped_id_unwrapped;
    if (!check(
            kek.unwrap_dek(
                swapped_id_reference,
                known_wrapped,
                swapped_id_unwrapped.bytes) == KeyStatus::BackendUnavailable &&
                swapped_id_unwrapped.bytes.empty(),
            "changing key ID did not fail authentication")) {
        return false;
    }
    std::vector<std::uint8_t> tampered_wrapped = known_wrapped;
    tampered_wrapped.back() ^= 0x80U;
    SensitiveVector tampered_unwrapped;
    if (!check(
            kek.unwrap_dek(
                known_reference, tampered_wrapped, tampered_unwrapped.bytes) ==
                KeyStatus::BackendUnavailable &&
                tampered_unwrapped.bytes.empty(),
            "GCM tag modification was accepted")) {
        return false;
    }

    const auto store_path = temporary.path() / "dek-store.bin";
    TestMonotonicAnchor anchor;
    DataKeyReference generated_reference{};
    std::vector<std::uint8_t> original_file;
    SensitiveVector generated_dek;
    TestSystemMacKeyProvider mac_keys;
    MemoryRecordSink sink;
    {
        KekWrappedDataEncryptionKeyStore store(store_path, kek, &anchor);
        if (!check(store.load() == KeyStatus::Ok, "empty store load failed") ||
            !check(
                store.generate_key("journal-user", generated_reference) ==
                    KeyStatus::Ok,
                "persistent DEK generation failed") ||
            !check(
                generated_reference.version == 1 && anchor.generation() == 1,
                "initial version or anchor generation is incorrect")) {
            return false;
        }

        const KeyStatus copy_status = store.with_key(
            generated_reference,
            [&](const DataKeyMaterial& material) {
                generated_dek.bytes = material.secret();
                return true;
            });
        if (!check(copy_status == KeyStatus::Ok, "generated DEK was unavailable") ||
            !check(
                generated_dek.bytes.size() == DataKeyMaterial::kAes256KeyBytes,
                "generated DEK length is incorrect")) {
            return false;
        }
        original_file = read_binary(store_path);
        if (!check(
                !contains_bytes(original_file, generated_dek.bytes),
                "persistent store contains the raw DEK")) {
            return false;
        }

        KekWrappedDataEncryptionKeyStore wrong_store(store_path, wrong_kek, &anchor);
        if (!check(
                wrong_store.load() == KeyStatus::Ok,
                "store metadata load should not need the KEK")) {
            return false;
        }
        const KeyStatus wrong_store_status = wrong_store.with_key(
            generated_reference,
            [&](const DataKeyMaterial&) {
                wrong_callback_called = true;
                return true;
            });
        if (!check(
                wrong_store_status == KeyStatus::BackendUnavailable &&
                    !wrong_callback_called,
                "wrong KEK reached the key-use callback")) {
            return false;
        }

        bool throwing_callback_called = false;
        const KeyStatus throwing_callback_status = store.with_key(
            generated_reference,
            [&](const DataKeyMaterial&) -> bool {
                throwing_callback_called = true;
                throw std::runtime_error("injected callback failure");
            });
        if (!check(
                throwing_callback_status == KeyStatus::BackendUnavailable &&
                    throwing_callback_called,
                "callback exception was not surfaced as a failed key use")) {
            return false;
        }

        AuthenticatedEventJournal journal(sink, mac_keys);
        mb::cqs13_4::EventPayload event{};
        event.state = mb::cqs13_4::EventState::HELD;
        event.event_id = "event-kek-1";
        event.request_id = "request-kek-1";
        event.source_concept = "encrypted-journal-secret";
        if (!check(
                static_cast<bool>(
                    journal.append_encrypted(
                        event, generated_reference, store)),
                "encrypted journal append failed") ||
            !check(
                verify_journal(sink.records(), mac_keys, store, false),
                "journal did not verify before revocation")) {
            return false;
        }

        std::mutex gate_mutex;
        std::condition_variable gate_changed;
        bool callback_entered = false;
        bool callback_release = false;
        std::atomic<KeyStatus> worker_status{KeyStatus::BackendUnavailable};
        std::thread worker([&] {
            worker_status.store(store.with_key(
                generated_reference,
                [&](const DataKeyMaterial&) {
                    std::unique_lock<std::mutex> lock(gate_mutex);
                    callback_entered = true;
                    gate_changed.notify_all();
                    gate_changed.wait(lock, [&] { return callback_release; });
                    return true;
                }));
        });

        bool entered = false;
        {
            std::unique_lock<std::mutex> lock(gate_mutex);
            entered = gate_changed.wait_for(
                lock, std::chrono::seconds(5), [&] { return callback_entered; });
        }
        if (!entered) {
            {
                std::lock_guard<std::mutex> lock(gate_mutex);
                callback_release = true;
            }
            gate_changed.notify_all();
            worker.join();
            return check(false, "key-use callback did not start");
        }

        const std::vector<std::uint8_t> file_before_active_revoke =
            read_binary(store_path);
        const KeyStatus active_revoke =
            store.revoke_key(generated_reference);
        const KeyStatus cross_instance_active_revoke =
            wrong_store.revoke_key(generated_reference);
        const KeyStatus active_reload = store.load();
        const bool file_unchanged_during_rejected_revoke =
            read_binary(store_path) == file_before_active_revoke;
        {
            std::lock_guard<std::mutex> lock(gate_mutex);
            callback_release = true;
        }
        gate_changed.notify_all();
        worker.join();
        if (!check(
                active_revoke == KeyStatus::BackendUnavailable &&
                    cross_instance_active_revoke ==
                        KeyStatus::BackendUnavailable &&
                    active_reload == KeyStatus::InvalidRequest &&
                    file_unchanged_during_rejected_revoke &&
                    worker_status.load() == KeyStatus::Ok,
                "shared active key use was not protected from cross-instance revoke")) {
            return false;
        }

        original_file = read_binary(store_path);
        if (!check(
                wrong_store.revoke_key(generated_reference) == KeyStatus::Ok &&
                    anchor.generation() == 2,
                "cross-instance DEK revocation did not commit after use ended")) {
            return false;
        }
        bool stale_callback_called = false;
        const KeyStatus stale_instance_status = store.with_key(
            generated_reference,
            [&](const DataKeyMaterial&) {
                stale_callback_called = true;
                return true;
            });
        const KeyStatus after_revoke = wrong_store.with_key(
            generated_reference,
            [](const DataKeyMaterial&) { return true; });
        if (!check(
                stale_instance_status == KeyStatus::BackendUnavailable &&
                    !stale_callback_called,
                "stale store instance used the key after another instance revoked it") ||
            !check(
                after_revoke == KeyStatus::Revoked,
                "revoked key was not rejected by the revoking instance") ||
            !check(
                verify_journal(sink.records(), mac_keys, wrong_store, true),
                "revoked DEK prevented Journal hash-chain verification")) {
            return false;
        }
    }

    const std::vector<std::uint8_t> revoked_file = read_binary(store_path);
    const std::size_t revoked_state_offset =
        20U + 2U + generated_reference.key_id.size() + 4U;
    if (!check(
            revoked_file.at(revoked_state_offset) == 1 &&
                read_u32(revoked_file, revoked_state_offset + 1U) == 0,
            "revoked store retained its wrapped DEK")) {
        return false;
    }
    {
        KekWrappedDataEncryptionKeyStore reloaded(store_path, kek, &anchor);
        if (!check(
                reloaded.load() == KeyStatus::Ok &&
                    reloaded.with_key(
                        generated_reference,
                        [](const DataKeyMaterial&) { return true; }) ==
                        KeyStatus::Revoked,
                "revoked state was not preserved after reload")) {
            return false;
        }
    }

    anchor.set_for_test(3);
    {
        KekWrappedDataEncryptionKeyStore mismatch_store(store_path, kek, &anchor);
        if (!check(
                mismatch_store.load() == KeyStatus::BackendUnavailable,
                "store/anchor generation mismatch was accepted")) {
            return false;
        }
    }
    anchor.set_for_test(2);

    write_binary(store_path, original_file);
    {
        KekWrappedDataEncryptionKeyStore rollback_store(store_path, kek, &anchor);
        if (!check(
                rollback_store.load() == KeyStatus::BackendUnavailable,
                "restored pre-revocation file was not detected as rollback")) {
            return false;
        }
    }
    write_binary(store_path, revoked_file);

    TestMonotonicAnchor malformed_anchor(1);
    const auto duplicate_path = temporary.path() / "duplicate.bin";
    std::vector<std::uint8_t> duplicate = original_file;
    const std::size_t first_slot = 20;
    const std::uint16_t id_size = read_u16(duplicate, first_slot);
    const std::size_t wrapped_size_offset =
        first_slot + 2U + id_size + 4U + 1U;
    const std::uint32_t wrapped_size = read_u32(duplicate, wrapped_size_offset);
    const std::size_t first_slot_end =
        wrapped_size_offset + 4U + wrapped_size;
    duplicate.insert(
        duplicate.end(),
        original_file.begin() + static_cast<std::ptrdiff_t>(first_slot),
        original_file.begin() + static_cast<std::ptrdiff_t>(first_slot_end));
    duplicate[16] = 0;
    duplicate[17] = 0;
    duplicate[18] = 0;
    duplicate[19] = 2;
    write_binary(duplicate_path, duplicate);
    {
        KekWrappedDataEncryptionKeyStore duplicate_store(
            duplicate_path, kek, &malformed_anchor);
        if (!check(
                duplicate_store.load() == KeyStatus::BackendUnavailable,
                "duplicate key ID/version slot was accepted")) {
            return false;
        }
    }

    std::vector<std::uint8_t> truncated = original_file;
    truncated.pop_back();
    const auto truncated_path = temporary.path() / "truncated.bin";
    write_binary(truncated_path, truncated);
    {
        KekWrappedDataEncryptionKeyStore truncated_store(
            truncated_path, kek, &malformed_anchor);
        if (!check(
                truncated_store.load() == KeyStatus::BackendUnavailable,
                "truncated store file was accepted")) {
            return false;
        }
    }

    std::vector<std::uint8_t> trailing = original_file;
    trailing.push_back(0);
    const auto trailing_path = temporary.path() / "trailing.bin";
    write_binary(trailing_path, trailing);
    {
        KekWrappedDataEncryptionKeyStore trailing_store(
            trailing_path, kek, &malformed_anchor);
        if (!check(
                trailing_store.load() == KeyStatus::BackendUnavailable,
                "trailing data after store EOF was accepted")) {
            return false;
        }
    }

    std::vector<std::uint8_t> oversized(
        KekWrappedDataEncryptionKeyStore::kMaximumFileBytes + 1U, 0);
    const auto oversized_path = temporary.path() / "oversized.bin";
    write_binary(oversized_path, oversized);
    {
        KekWrappedDataEncryptionKeyStore oversized_store(
            oversized_path, kek, &malformed_anchor);
        if (!check(
                oversized_store.load() == KeyStatus::BackendUnavailable,
                "oversized store file was accepted")) {
            return false;
        }
    }

    const auto max_version_path = temporary.path() / "max-version.bin";
    const DataKeyReference max_version_reference{
        "max-version", (std::numeric_limits<std::uint32_t>::max)()};
    std::vector<std::uint8_t> max_version_wrapped;
    if (!check(
            kek.wrap_dek(
                max_version_reference, known_dek.bytes, max_version_wrapped) ==
                KeyStatus::Ok,
            "could not prepare UINT32_MAX version fixture")) {
        return false;
    }
    write_binary(
        max_version_path,
        make_store_file(1, max_version_reference, max_version_wrapped, false));
    TestMonotonicAnchor max_version_anchor(1);
    {
        KekWrappedDataEncryptionKeyStore max_version_store(
            max_version_path, kek, &max_version_anchor);
        DataKeyReference unused{};
        if (!check(
                max_version_store.load() == KeyStatus::Ok &&
                    max_version_store.generate_key("max-version", unused) ==
                        KeyStatus::BackendUnavailable &&
                    max_version_anchor.generation() == 1,
                "UINT32_MAX version was reused or incremented")) {
            return false;
        }
    }

    const auto missing_parent = temporary.path() / "replace-parent";
    std::filesystem::create_directory(missing_parent);
    const auto pre_anchor_path = missing_parent / "store.bin";
    TestMonotonicAnchor pre_anchor_failure_anchor;
    {
        KekWrappedDataEncryptionKeyStore pre_anchor_failure(
            pre_anchor_path, kek, &pre_anchor_failure_anchor);
        if (!check(
                pre_anchor_failure.load() == KeyStatus::Ok,
                "pre-anchor failure fixture did not load")) {
            return false;
        }
        std::filesystem::remove(missing_parent);
        const std::vector<std::uint8_t> parent_marker{0x41};
        write_binary(missing_parent, parent_marker);
        DataKeyReference unused{};
        const KeyStatus status =
            pre_anchor_failure.generate_key("persist-fail", unused);
        const KeyStatus missing_status = pre_anchor_failure.with_key(
            DataKeyReference{"persist-fail", 1},
            [](const DataKeyMaterial&) { return true; });
        if (!check(
                status == KeyStatus::BackendUnavailable &&
                    missing_status == KeyStatus::NotFound &&
                    pre_anchor_failure_anchor.generation() == 0,
                "pre-anchor persistence failure changed in-memory state")) {
            return false;
        }
    }

    const auto replace_failure_directory =
        temporary.path() / "post-anchor-failure";
    std::filesystem::create_directory(replace_failure_directory);
    const auto post_anchor_path = replace_failure_directory / "store.bin";
    TestMonotonicAnchor post_anchor_failure_anchor;
    {
        KekWrappedDataEncryptionKeyStore post_anchor_failure(
            post_anchor_path, kek, &post_anchor_failure_anchor);
        if (!check(
                post_anchor_failure.load() == KeyStatus::Ok,
                "post-anchor failure fixture did not load")) {
            return false;
        }
        std::filesystem::create_directory(post_anchor_path);
        DataKeyReference unused{};
        const KeyStatus status =
            post_anchor_failure.generate_key("replace-fail", unused);
        const KeyStatus closed_status = post_anchor_failure.with_key(
            DataKeyReference{"replace-fail", 1},
            [](const DataKeyMaterial&) { return true; });
        bool temporary_remnant = false;
        for (const auto& entry :
             std::filesystem::directory_iterator(replace_failure_directory)) {
            if (entry.path().filename().string().find("store.bin.tmp-") == 0) {
                temporary_remnant = true;
            }
        }
        if (!check(
                status == KeyStatus::BackendUnavailable &&
                    closed_status == KeyStatus::BackendUnavailable &&
                    post_anchor_failure_anchor.generation() == 1 &&
                    !temporary_remnant,
                "post-anchor replacement failure did not fail closed")) {
            return false;
        }
    }

    const auto no_anchor_path = temporary.path() / "no-anchor.bin";
    KekWrappedDataEncryptionKeyStore no_anchor(no_anchor_path, kek, nullptr);
    if (!check(
            no_anchor.load() == KeyStatus::BackendUnavailable,
            "store without an independent anchor was not fail-closed")) {
        return false;
    }

    if (!test_revoke_persistence_failure(temporary.path(), kek) ||
        !test_shared_lease_release_failure(temporary.path(), kek) ||
        !test_revocation_commit_failure(temporary.path(), kek)) {
        return false;
    }

    std::cout << "[PASS] KEK-wrapped DEK persistence, authentication, revocation, "
                 "and rollback checks verified"
              << std::endl;
    return true;
}

}  // namespace

int main() {
    try {
        return run_tests() ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << "[FAIL] Unhandled test exception: " << error.what()
                  << std::endl;
        return 1;
    }
}
