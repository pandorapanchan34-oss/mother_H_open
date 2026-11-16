#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>
#include <chrono>
#include <random>
#include <string>
#include <type_traits>
#include "mother_H/storage/file_journal_checkpoint_store.hpp"
namespace fs = std::filesystem;
using mother_h::journal::CheckpointStatus;
using mother_h::journal::JournalCheckpoint;
using mother_H::storage::FileJournalCheckpointStore;
static_assert(
    std::is_trivially_copyable<JournalCheckpoint>::value,
    "JournalCheckpoint must be trivially copyable"
);
static_assert(
    sizeof(JournalCheckpoint) == 48,
    "This CP-01-B test expects a 48-byte JournalCheckpoint"
);
static bool create_test_file(
    const fs::path& path,
    const std::vector<std::uint8_t>& data
) {
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open()) {
        return false;
    }
    if (!data.empty()) {
        ofs.write(
            reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size())
        );
    }
    ofs.flush();
    if (!ofs.good()) {
        return false;
    }
    ofs.close();
    return !ofs.fail();
}
static bool run_case(
    const std::string& case_name,
    const fs::path& file_path,
    CheckpointStatus expected_status,
    const JournalCheckpoint& sentinel
) {
    FileJournalCheckpointStore store(file_path);
    JournalCheckpoint out = sentinel;
    std::uint8_t backup_bytes[sizeof(JournalCheckpoint)];
    std::memcpy(backup_bytes, &out, sizeof(out));
    const CheckpointStatus actual_status = store.load(out);
    bool case_passed = true;
    // Status verification
    if (actual_status != expected_status) {
        std::cerr
            << "[FAIL] " << case_name
            << ": unexpected status. Expected BackendUnavailable"
            << std::endl;
        case_passed = false;
    }
    // Caller output immutability verification
    if (std::memcmp(
            &out,
            backup_bytes,
            sizeof(JournalCheckpoint)
        ) != 0) {
        std::cerr
            << "[FAIL] " << case_name
            << ": caller output was modified"
            << std::endl;
        case_passed = false;
    }
    if (case_passed) {
        std::cout << "[PASS] " << case_name << std::endl;
    }
    return case_passed;
}
int main() {
    std::cout
        << "===== CP-01-B: Malformed File Fail-Closed Test ====="
        << std::endl;
    // Create a unique test directory. Never remove it.
    const auto now =
        std::chrono::high_resolution_clock::now()
            .time_since_epoch()
            .count();
    std::mt19937_64 rng(
        static_cast<std::uint64_t>(now)
    );
    const std::string unique_name =
        "mother_h_cp01_b_" +
        std::to_string(now) + "_" +
        std::to_string(rng());
    const fs::path test_dir =
        fs::temp_directory_path() / unique_name;
    std::error_code ec;
    if (!fs::create_directory(test_dir, ec) || ec) {
        std::cerr
            << "[FAIL] Could not create unique test directory: "
            << ec.message()
            << std::endl;
        return 1;
    }
    // Sentinel: caller output must remain byte-for-byte unchanged.
    JournalCheckpoint sentinel{};
    std::memset(&sentinel, 0x5A, sizeof(JournalCheckpoint));
    const auto expected = CheckpointStatus::BackendUnavailable;
    int failures = 0;
    // B-01: Empty file (0 bytes)
    {
        const fs::path path = test_dir / "b01_empty.bin";
        if (!create_test_file(path, {})) {
            std::cerr << "[FAIL] B-01: could not create test file"
                      << std::endl;
            ++failures;
        } else if (!run_case("B-01 empty file (0 bytes)",
                             path, expected, sentinel)) {
            ++failures;
        }
    }
    // B-02: Short file (16 bytes)
    {
        const fs::path path = test_dir / "b02_short_16.bin";
        const std::vector<std::uint8_t> data(16, 0xAA);
        if (!create_test_file(path, data)) {
            std::cerr << "[FAIL] B-02: could not create test file"
                      << std::endl;
            ++failures;
        } else if (!run_case("B-02 short file (16 bytes)",
                             path, expected, sentinel)) {
            ++failures;
        }
    }
    // B-03: Short file (47 bytes)
    {
        const fs::path path = test_dir / "b03_short_47.bin";
        const std::vector<std::uint8_t> data(47, 0xBB);
        if (!create_test_file(path, data)) {
            std::cerr << "[FAIL] B-03: could not create test file"
                      << std::endl;
            ++failures;
        } else if (!run_case("B-03 short file (47 bytes)",
                             path, expected, sentinel)) {
            ++failures;
        }
    }
    // B-05: Oversized file (64 bytes)
    {
        const fs::path path = test_dir / "b05_oversized_64.bin";
        const std::vector<std::uint8_t> data(64, 0xCC);
        if (!create_test_file(path, data)) {
            std::cerr << "[FAIL] B-05: could not create test file"
                      << std::endl;
            ++failures;
        } else if (!run_case("B-05 oversized file (64 bytes)",
                             path, expected, sentinel)) {
            ++failures;
        }
    }
    std::cout << std::endl;
    if (failures != 0) {
        std::cerr
            << "[RESULT] FAILURES: " << failures
            << std::endl;
        std::cerr
            << "Test artifacts retained at: "
            << test_dir.string()
            << std::endl;
        return 1;
    }
    std::cout << "[RESULT] ALL CASES PASSED" << std::endl;
    std::cout
        << "Test artifacts retained at: "
        << test_dir.string()
        << std::endl;
    return 0;
}