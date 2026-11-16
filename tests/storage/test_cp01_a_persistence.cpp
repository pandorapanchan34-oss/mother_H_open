#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <string>
#include "mother_H/storage/file_journal_checkpoint_store.hpp"
#define CHECK(condition)                                      \
    do {                                                      \
        if (!(condition)) {                                   \
            std::cerr << "[FAIL] " #condition << '\n';        \
            return 1;                                         \
        }                                                     \
    } while (false)
// CP-01-A: 保存・復元後の全フィールド同値性検証
int main() {
    using namespace mother_H::storage;
    using namespace mother_h::journal;
    const auto unique_id = std::to_string(
        std::filesystem::file_time_type::clock::now()
            .time_since_epoch().count()
    );
    const std::filesystem::path test_dir =
        std::filesystem::current_path() /
        ("cp01_a_persistence_" + unique_id);
    if (!std::filesystem::create_directory(test_dir)) {
        std::cerr << "Could not create unique test directory\n";
        return 2;
    }
    const auto cp_file = test_dir / "checkpoint.bin";
    JournalCheckpoint cp_written{};
    cp_written.lsn = 0x123456789ABCDEF0ULL;
    cp_written.revision = 0xFEDCBA9876543210ULL;
    for (std::size_t i = 0; i < cp_written.record_hash.size(); ++i) {
        cp_written.record_hash[i] =
            static_cast<std::uint8_t>((i * 7 + 13) % 256);
    }
    // Instance A: write and destroy
    {
        FileJournalCheckpointStore store_writer(cp_file);
        JournalCheckpoint expected_empty{};
        const auto status =
            store_writer.compare_and_advance(expected_empty, cp_written);
        CHECK(status == CheckpointStatus::Ok);
    }
    // Instance B: reload from the physical file
    {
        FileJournalCheckpointStore store_reader(cp_file);
        JournalCheckpoint cp_loaded{};
        const auto status = store_reader.load(cp_loaded);
        CHECK(status == CheckpointStatus::Ok);
        CHECK(cp_loaded.lsn == cp_written.lsn);
        CHECK(cp_loaded.revision == cp_written.revision);
        CHECK(cp_loaded.record_hash == cp_written.record_hash);
    }
    std::cout << "[CP-01-A] Persistence & Identity Test Passed\n";
    std::cout << "Test artifacts: " << test_dir.string() << "\n";
    return 0;
}