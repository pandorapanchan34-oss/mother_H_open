#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <vector>

#include "mother_H/storage/file_journal_checkpoint_store.hpp"

namespace fs = std::filesystem;
using namespace mother_H::storage;
using namespace mother_h::journal;

static bool write_bytes(const fs::path& path, const std::vector<uint8_t>& bytes) {
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open()) return false;
    ofs.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    ofs.flush();
    if (!ofs) return false;
    ofs.close();
    return !ofs.fail();
}

int main() {
    std::cout << "===== Strict Checkpoint Fail-Closed & CAS Contract Test =====\n";

    const auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    std::mt19937_64 rng(static_cast<uint64_t>(now));

    fs::path test_dir = fs::temp_directory_path() / ("mother_h_crit01_tests_" + std::to_string(now) + "_" + std::to_string(rng()));
    std::error_code ec;

    if (!fs::create_directory(test_dir, ec) || ec) {
        std::cerr << "[ERROR] Failed to create sandbox directory.\n";
        return 2;
    }

    fs::path cp_file = test_dir / "checkpoint.bin";
    FileJournalCheckpointStore store(cp_file);
    int failures = 0;

    // TEST 1: 49-byte oversized checkpoint must be rejected with BackendUnavailable
    {
        std::cout << "\n[TEST 1] Oversized 49-byte checkpoint\n";
        std::vector<uint8_t> dummy(49, 0xFF);
        if (!write_bytes(cp_file, dummy)) {
            std::cerr << "[ERROR] Failed to create 49-byte test file.\n";
            return 2;
        }

        JournalCheckpoint loaded{};
        const auto status = store.load(loaded);

        if (status != CheckpointStatus::BackendUnavailable) {
            std::cerr << "[FAIL] Expected BackendUnavailable for 49-byte file, got: " << static_cast<int>(status) << "\n";
            ++failures;
        } else {
            std::cout << "[PASS] Oversized file rejected as BackendUnavailable.\n";
        }

        fs::remove(cp_file, ec);
    }

    // TEST 2: CRIT-01 - Same LSN, Revision Advance (LSN=100, Rev 1 -> 2)
    {
        std::cout << "\n[TEST 2] CRIT-01: Same LSN, Revision Advance (LSN=100, Rev 1 -> 2)\n";
        JournalCheckpoint expected_init{};
        JournalCheckpoint current{};
        current.lsn = 100;
        current.revision = 1;
        current.record_hash.fill(0xAA);

        if (store.compare_and_advance(expected_init, current) != CheckpointStatus::Ok) {
            std::cerr << "[ERROR] Initial checkpoint setup failed.\n";
            return 2;
        }

        JournalCheckpoint next_same_lsn{};
        next_same_lsn.lsn = 100; // 同一 LSN
        next_same_lsn.revision = 2; // revision 増加
        next_same_lsn.record_hash.fill(0xAA);

        const auto status = store.compare_and_advance(current, next_same_lsn);
        if (status != CheckpointStatus::Ok) {
            std::cerr << "[FAIL] Same LSN with advancing revision was rejected! Status: " << static_cast<int>(status) << "\n";
            ++failures;
        } else {
            std::cout << "[PASS] Same LSN with advancing revision successfully accepted (Ok).\n";
        }

        fs::remove(cp_file, ec);
    }

    // TEST 3: CRIT-01 - Same LSN cannot replace its authenticated hash
    {
        std::cout << "\n[TEST 3] CRIT-01: Same LSN cannot replace its authenticated hash\n";
        JournalCheckpoint expected_init{};
        JournalCheckpoint current{};
        current.lsn = 100;
        current.revision = 1;
        current.record_hash.fill(0xAA);

        if (store.compare_and_advance(expected_init, current) != CheckpointStatus::Ok) {
            std::cerr << "[ERROR] Checkpoint setup failed.\n";
            return 2;
        }

        JournalCheckpoint invalid_next{};
        invalid_next.lsn = 100;
        invalid_next.revision = 2;
        invalid_next.record_hash.fill(0xBB);

        const auto status = store.compare_and_advance(current, invalid_next);
        if (status != CheckpointStatus::Conflict) {
            std::cerr << "[FAIL] Same LSN with a changed hash was not rejected! Got: "
                      << static_cast<int>(status) << "\n";
            ++failures;
        } else {
            std::cout << "[PASS] Same LSN with a changed hash rejected as Conflict.\n";
        }

        fs::remove(cp_file, ec);
    }

    // TEST 4: CRIT-01 - Same LSN, Revision Non-Advancement Rejection (LSN=100, Rev 2 -> 2)
    {
        std::cout << "\n[TEST 4] CRIT-01: Same LSN, Revision Non-Advancement (LSN=100, Rev 2 -> 2)\n";
        JournalCheckpoint expected_init{};
        JournalCheckpoint current{};
        current.lsn = 100;
        current.revision = 2;
        current.record_hash.fill(0xBB);

        if (store.compare_and_advance(expected_init, current) != CheckpointStatus::Ok) {
            std::cerr << "[ERROR] Checkpoint setup failed.\n";
            return 2;
        }

        JournalCheckpoint invalid_next{};
        invalid_next.lsn = 100; // 同一 LSN
        invalid_next.revision = 2; // revision 停滞
        invalid_next.record_hash.fill(0xBB);

        const auto status = store.compare_and_advance(current, invalid_next);
        if (status != CheckpointStatus::Conflict) {
            std::cerr << "[FAIL] Same LSN with non-advancing revision was NOT rejected as Conflict! Got: " << static_cast<int>(status) << "\n";
            ++failures;
        } else {
            std::cout << "[PASS] Same LSN with non-advancing revision rejected as Conflict.\n";
        }

        fs::remove(cp_file, ec);
    }

    // TEST 4: BackendUnavailable propagation
    {
        std::cout << "\n[TEST 4] Fail-Closed on unavailable backend\n";
        fs::path invalid_path = test_dir / "directory_as_checkpoint";
        fs::create_directory(invalid_path, ec);

        FileJournalCheckpointStore invalid_store(invalid_path);
        JournalCheckpoint expected{};
        JournalCheckpoint next{};
        next.lsn = 1;
        next.revision = 1;

        const auto status = invalid_store.compare_and_advance(expected, next);
        if (status != CheckpointStatus::BackendUnavailable) {
            std::cerr << "[FAIL] Expected BackendUnavailable without attempting write. Actual: " << static_cast<int>(status) << "\n";
            ++failures;
        } else {
            std::cout << "[PASS] BackendUnavailable propagated correctly.\n";
        }
    }

    std::cout << "\n============================================\n";
    if (failures == 0) {
        std::cout << "[RESULT] ALL CRIT-01 CAS CONTRACT TESTS PASSED (GREEN)\n";
        return 0;
    }

    std::cout << "[RESULT] " << failures << " TEST(S) FAILED (RED)\n";
    return 1;
}