#include <iostream>
#include <cassert>
#include <fstream>
#include <filesystem>
#include "mother_H/storage/journal_recovery_adapter.hpp"
namespace {
using namespace mother_h::journal;
// CP-04 検証用のテストダブル（鍵プロバイダ・チェックポイントストア）
class TestKeyProvider final : public ISecureKeyProvider {
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
class TestCheckpointStore final : public IJournalCheckpointStore {
public:
    CheckpointStatus load(JournalCheckpoint&) const noexcept override {
        return CheckpointStatus::Ok;
    }
    CheckpointStatus compare_and_advance(const JournalCheckpoint&, const JournalCheckpoint&) noexcept override {
        return CheckpointStatus::Ok;
    }
};
} // namespace
int main() {
    using namespace mother_H::storage;
    std::cout << "[CP-04] Starting Journal Recovery Adapter physical test..." << std::endl;
    JournalRecoveryAdapter adapter;
    TestCheckpointStore store;
    TestKeyProvider keys;
    // 1. 存在しないログファイルに対する Fail-Closed 判定の検証
    auto res = adapter.recover_and_truncate("non_existent_journal.bin", store, keys);
    assert(!res.success); // ログ不在時は Fail-Closed
    std::cout << "[CP-04] Fail-closed on missing log: PASSED" << std::endl;
    std::cout << "[CP-04] Physical Recovery Adapter Test Finished Successfully." << std::endl;
    return 0;
}