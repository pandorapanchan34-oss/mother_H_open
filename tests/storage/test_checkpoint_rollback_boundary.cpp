#include <cassert>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <random>
#include <string>
#include "mother_H/storage/file_journal_checkpoint_store.hpp"

namespace fs = std::filesystem;
using namespace mother_H::storage;
using namespace mother_h::journal;

int main() {
    std::cout << "===== CP-07: Checkpoint Rollback & CAS Boundary Test =====\n";

    const auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    std::mt19937_64 rng(static_cast<uint64_t>(now));
    fs::path test_dir = fs::temp_directory_path() / ("mother_h_cp07_test_" + std::to_string(now) + "_" + std::to_string(rng()));
    std::error_code ec;
    if (!fs::create_directory(test_dir, ec) || ec) {
        std::cerr << "[FAIL] Failed to create sandbox directory.\n";
        return 1;
    }

    fs::path cp_path = test_dir / "checkpoint.bin";
    FileJournalCheckpointStore store(cp_path);

    // 1. 未存在時に不正な expected を指定した場合は Conflict
    {
        JournalCheckpoint bad_expected{};
        bad_expected.lsn = 5; // 存在しないのに LSN 5 を前提
        JournalCheckpoint next{};
        next.lsn = 6;
        next.revision = 1;
        auto st = store.compare_and_advance(bad_expected, next);
        assert(st == CheckpointStatus::Conflict);
        std::cout << "[PASS] Creating checkpoint with mismatched expected rejected as Conflict\n";
    }

    // 2. 正常な初回作成 (LSN 10, rev 1)
    JournalCheckpoint cp1{};
    cp1.lsn = 10;
    cp1.revision = 1;
    cp1.record_hash.fill(0x11);
    {
        JournalCheckpoint empty_expected{};
        auto st = store.compare_and_advance(empty_expected, cp1);
        assert(st == CheckpointStatus::Ok);

        JournalCheckpoint loaded{};
        assert(store.load(loaded) == CheckpointStatus::Ok);
        assert(loaded.lsn == 10);
        assert(loaded.revision == 1);
        assert(loaded.record_hash == cp1.record_hash);
        std::cout << "[PASS] Initial checkpoint creation succeeded\n";
    }

    // 3. 古い expected (LSN 0) での更新試行 -> Conflict で拒否され、内容は不変
    {
        JournalCheckpoint stale_expected{};
        JournalCheckpoint next{};
        next.lsn = 20;
        next.revision = 2;
        auto st = store.compare_and_advance(stale_expected, next);
        assert(st == CheckpointStatus::Conflict);

        JournalCheckpoint loaded{};
        assert(store.load(loaded) == CheckpointStatus::Ok);
        assert(loaded.lsn == 10);
        assert(loaded.revision == 1);
        std::cout << "[PASS] Stale expected rejected as Conflict; data unchanged\n";
    }

    // 4. expected は一致するが、next.lsn が巻き戻っている (LSN 5 < 10) -> Conflict
    {
        JournalCheckpoint rollback_next{};
        rollback_next.lsn = 5;
        rollback_next.revision = 2;
        rollback_next.record_hash.fill(0x22);
        auto st = store.compare_and_advance(cp1, rollback_next);
        assert(st == CheckpointStatus::Conflict);

        JournalCheckpoint loaded{};
        assert(store.load(loaded) == CheckpointStatus::Ok);
        assert(loaded.lsn == 10);
        std::cout << "[PASS] Rollback LSN rejected as Conflict\n";
    }

    // 5. expected は一致するが、next.revision が同じか古い (rev 1 <= 1) -> Conflict
    {
        JournalCheckpoint bad_rev_next{};
        bad_rev_next.lsn = 15;
        bad_rev_next.revision = 1; // 同じ revision
        auto st = store.compare_and_advance(cp1, bad_rev_next);
        assert(st == CheckpointStatus::Conflict);
        std::cout << "[PASS] Non-advancing revision rejected as Conflict\n";
    }

    // 6. 正常な advance (LSN 20, rev 2)
    JournalCheckpoint cp2{};
    cp2.lsn = 20;
    cp2.revision = 2;
    cp2.record_hash.fill(0x33);
    {
        auto st = store.compare_and_advance(cp1, cp2);
        assert(st == CheckpointStatus::Ok);

        JournalCheckpoint loaded{};
        assert(store.load(loaded) == CheckpointStatus::Ok);
        assert(loaded.lsn == 20);
        assert(loaded.revision == 2);
        assert(loaded.record_hash == cp2.record_hash);
        std::cout << "[PASS] Legitimate advance to LSN 20 succeeded\n";
    }

    std::cout << "[RESULT] ALL CP-07 ROLLBACK & CAS BOUNDARY TESTS PASSED\n";
    return 0;
}
