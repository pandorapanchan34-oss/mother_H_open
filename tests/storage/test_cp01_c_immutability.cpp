#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include "mother_H/storage/file_journal_checkpoint_store.hpp"
int main() {
    using namespace mother_H::storage;
    using namespace mother_h::journal;
    const std::string unique_id =
        "cp01c_" +
        std::to_string(
            std::filesystem::file_time_type::clock::now()
                .time_since_epoch().count()
        );
    const std::filesystem::path test_dir =
        std::filesystem::temp_directory_path() / unique_id;
    if (!std::filesystem::create_directory(test_dir)) {
        std::cerr << "Could not create unique test directory\n";
        return 2;
    }
    const auto corrupt_file = test_dir / "corrupt_cp.bin";
    {
        std::ofstream ofs(corrupt_file, std::ios::binary);
        if (!ofs.is_open()) {
            std::cerr << "Could not create corrupt checkpoint\n";
            return 2;
        }
        ofs.write("BAD_DATA", 8);
        ofs.close();
        if (!ofs) {
            std::cerr << "Could not write corrupt checkpoint\n";
            return 2;
        }
    }
    FileJournalCheckpointStore store(corrupt_file);
    JournalCheckpoint out{};
    out.lsn = 0xDEADBEEF12345678ULL;
    out.revision = 99999;
    out.record_hash.fill(0xAA);
    const JournalCheckpoint original = out;
    const auto status = store.load(out);
    bool passed = true;
    const auto check = [&passed](bool condition, const char* message) {
        if (!condition) {
            std::cerr << "[FAIL] " << message << "\n";
            passed = false;
        }
    };
    check(status != CheckpointStatus::Ok,
          "Corrupt checkpoint must not load successfully");
    check(out.lsn == original.lsn,
          "out.lsn changed after load failure");
    check(out.revision == original.revision,
          "out.revision changed after load failure");
    check(out.record_hash == original.record_hash,
          "out.record_hash changed after load failure");
    if (!passed) {
        std::cerr << "[CP-01-C] Immutability Test FAILED\n";
        std::cerr << "Test artifacts: " << test_dir.string() << "\n";
        return 1;
    }
    std::cout << "[CP-01-C] Immutability Test Passed\n";
    std::cout << "Test artifacts: " << test_dir.string() << "\n";
    return 0;
}