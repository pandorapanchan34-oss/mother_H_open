#include <cassert>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <random>
#include <string>
#include <vector>
#include "mother_H/storage/file_journal_checkpoint_store.hpp"
#include "mother_H/journal/journal_integrity.hpp"

namespace fs = std::filesystem;
using namespace mother_H::storage;
using namespace mother_h::journal;

class DummyKeyProvider final : public ISecureKeyProvider {
public:
    KeyStatus current_signing_key(KeyMaterial&) const noexcept override {
        return KeyStatus::BackendUnavailable;
    }
    KeyStatus verification_key(const KeyReference&, KeyMaterial&) const noexcept override {
        return KeyStatus::BackendUnavailable;
    }
    KeyStatus rotate_key(const std::string&, KeyReference&) noexcept override {
        return KeyStatus::BackendUnavailable;
    }
    KeyStatus revoke_key(const KeyReference&) noexcept override {
        return KeyStatus::BackendUnavailable;
    }
};

int main() {
    std::cout << "===== CP-06: Checkpoint Storage Independence & Unverified Fail-Closed Test =====\n";

    const auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    std::mt19937_64 rng(static_cast<uint64_t>(now));
    fs::path test_dir = fs::temp_directory_path() / ("mother_h_cp06_test_" + std::to_string(now) + "_" + std::to_string(rng()));
    std::error_code ec;
    if (!fs::create_directory(test_dir, ec) || ec) {
        std::cerr << "[FAIL] Failed to create sandbox directory.\n";
        return 1;
    }

    fs::path cp_path = test_dir / "checkpoint.bin";
    FileJournalCheckpointStore store(cp_path);

    // 1. verify_independence は外部信頼アンカー不在のため常に Unverified を返却する
    JournalStorageIdentity id1{"fs", "dev1:inode1", "domain1", true};
    assert(store.verify_independence(id1) == CheckpointIsolation::Unverified);

    JournalStorageIdentity id_unverified{"fs", "dev1:inode1", "domain1", false};
    assert(store.verify_independence(id_unverified) == CheckpointIsolation::Unverified);

    std::cout << "[PASS] verify_independence consistently returns Unverified\n";

    // 2. JournalIntegrity::verify_chain_and_advance に接続された場合、
    // CheckpointIsolationUnverified で Fail-Closed 拒否されることを検証
    DummyKeyProvider keys;
    std::vector<JournalRecord> empty_chain;
    auto res = JournalIntegrity::verify_chain_and_advance(empty_chain, keys, store, id1);
    assert(res.status == IntegrityStatus::CheckpointIsolationUnverified);

    std::cout << "[PASS] JournalIntegrity safely rejects FileJournalCheckpointStore as CheckpointIsolationUnverified\n";
    std::cout << "[RESULT] ALL CP-06 TESTS PASSED STRICTLY\n";
    return 0;
}
