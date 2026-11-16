/**
 * @file test_mega_chaos_stress.cpp
 * @brief Mother_H Phase 14 Step 6: Mega Chaos Stress Test (Test #9)
 *
 * 網羅する狂気:
 * 1. マルチプロセス・クロスファイア (複数ワーカーによる同時乱戦アペンド)
 * 2. 停止後サボタージュ (ワーカー終了・wait後にファイルをバイナリ破壊)
 * 3. エンドレス・スローター (連続プロセス即死・リカバリの耐久ループ)
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <thread>
#include <chrono>
#include <cassert>
#include <random>
#include <limits>

#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #include <windows.h>
#else
  #include <cerrno>
  #include <unistd.h>
  #include <sys/wait.h>
  #include <signal.h>
  #include <fcntl.h>
#endif

namespace fs = std::filesystem;

uint32_t crc32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int j = 0; j < 8; ++j)
            crc = (crc & 1) ? (crc >> 1) ^ 0xEDB88320u : (crc >> 1);
    }
    return ~crc;
}

#pragma pack(push, 1)
struct RecordHeader {
    uint64_t lsn;
    int64_t  timestamp_ns;
    uint32_t payload_len;
    uint32_t crc;
};
#pragma pack(pop)

struct SabotageResult {
    bool success{false};
    size_t position{0};
    uint64_t expected_lsn{0};
    std::string error;
};

bool force_sync_file(const std::string& path) {
#ifdef _WIN32
    HANDLE h = CreateFileA(path.c_str(), GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    bool ok = (FlushFileBuffers(h) != 0);
    CloseHandle(h);
    return ok;
#else
    int fd = ::open(path.c_str(), O_APPEND | O_WRONLY);
    if (fd < 0) return false;
    bool ok = (::fsync(fd) == 0);
    ::close(fd);
    return ok;
#endif
}

class MegaChaosJournal {
public:
    explicit MegaChaosJournal(const std::string& path) : path_(path) {}

    bool append(uint64_t lsn, int64_t ts, const std::string& payload) {
        RecordHeader h{};
        h.lsn = lsn;
        h.timestamp_ns = ts;
        h.payload_len = static_cast<uint32_t>(payload.size());
        h.crc = 0;

        std::vector<uint8_t> buf(sizeof(RecordHeader) + payload.size());
        std::memcpy(buf.data(), &h, sizeof(RecordHeader));
        std::memcpy(buf.data() + sizeof(RecordHeader), payload.data(), payload.size());

        h.crc = crc32(buf.data(), buf.size());
        std::memcpy(buf.data(), &h, sizeof(RecordHeader));

        {
            std::ofstream ofs(path_, std::ios::binary | std::ios::app);
            if (!ofs) return false;
            ofs.write(reinterpret_cast<const char*>(buf.data()),
                      static_cast<std::streamsize>(buf.size()));
            ofs.flush();
            if (!ofs.good()) return false;
        }
        return force_sync_file(path_);
    }

    uint64_t recover(int64_t& last_ts, bool& halted) const {
        last_ts = 0;
        halted = false;

        std::ifstream ifs(path_, std::ios::binary);
        if (!ifs) return 0;

        uint64_t last_valid_lsn = 0;
        std::vector<uint8_t> buf;

        while (true) {
            RecordHeader h{};
            if (!ifs.read(reinterpret_cast<char*>(&h), sizeof(h))) break;
            if (h.payload_len > 16 * 1024 * 1024) break;

            buf.resize(sizeof(RecordHeader) + h.payload_len);
            std::memcpy(buf.data(), &h, sizeof(RecordHeader));

            if (!ifs.read(reinterpret_cast<char*>(buf.data() + sizeof(RecordHeader)),
                          h.payload_len)) break;

            uint32_t saved_crc = h.crc;
            h.crc = 0;
            std::memcpy(buf.data(), &h, sizeof(RecordHeader));

            if (crc32(buf.data(), buf.size()) != saved_crc) break;
            if (h.timestamp_ns < last_ts) {
                halted = true;
                break;
            }

            last_ts = h.timestamp_ns;
            last_valid_lsn = h.lsn;
        }
        return last_valid_lsn;
    }

    SabotageResult inject_sabotage() {
        std::error_code ec;
        auto size = fs::file_size(path_, ec);
        if (ec) return {false, 0, 0, "could not get file size"};
        if (size == 0 || size > (std::numeric_limits<size_t>::max)()) {
            return {false, 0, 0, "file size is outside the sabotage range"};
        }

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<size_t> pos_dis(
            0, static_cast<size_t>(size) - 1);
        size_t corrupt_pos = pos_dis(gen);
        return inject_sabotage_at(corrupt_pos);
    }

    SabotageResult inject_sabotage_at(size_t corrupt_pos) {
        std::error_code ec;
        const auto file_size = fs::file_size(path_, ec);
        if (ec) return {false, corrupt_pos, 0, "could not get file size"};
        if (file_size == 0 ||
            file_size > (std::numeric_limits<size_t>::max)() ||
            corrupt_pos >= static_cast<size_t>(file_size)) {
            return {false, corrupt_pos, 0, "corruption position is out of range"};
        }

        uint64_t expected_lsn = 0;
        if (!find_expected_lsn(corrupt_pos, static_cast<size_t>(file_size),
                               expected_lsn)) {
            return {false, corrupt_pos, 0,
                    "could not validate record boundaries before corruption"};
        }

        std::fstream fs_io(path_, std::ios::in | std::ios::out | std::ios::binary);
        if (!fs_io) {
            return {false, corrupt_pos, expected_lsn,
                    "could not open journal for corruption"};
        }
        char original = 0;
        fs_io.seekg(static_cast<std::streamoff>(corrupt_pos));
        fs_io.read(&original, 1);
        if (fs_io.gcount() != 1 || !fs_io.good()) {
            return {false, corrupt_pos, expected_lsn,
                    "could not read original corruption byte"};
        }
        const char changed = static_cast<char>(
            static_cast<unsigned char>(original) ^ 0x01U);
        fs_io.clear();
        fs_io.seekp(static_cast<std::streamoff>(corrupt_pos));
        fs_io.write(&changed, 1);
        fs_io.flush();
        if (!fs_io.good()) {
            return {false, corrupt_pos, expected_lsn,
                    "could not write corruption byte"};
        }
        fs_io.close();
        if (fs_io.fail() || !force_sync_file(path_)) {
            return {false, corrupt_pos, expected_lsn,
                    "could not flush corruption to storage"};
        }
        return {true, corrupt_pos, expected_lsn, {}};
    }

    void remove() {
        std::error_code ec;
        fs::remove(path_, ec);
    }

    const std::string& path() const { return path_; }

private:
    bool find_expected_lsn(size_t corrupt_pos, size_t file_size,
                           uint64_t& expected_lsn) const {
        constexpr uint32_t kMaxPayloadSize = 16 * 1024 * 1024;
        std::ifstream input(path_, std::ios::binary);
        if (!input) return false;

        size_t offset = 0;
        uint64_t last_valid_lsn = 0;
        int64_t last_valid_ts = 0;
        bool recovery_stopped = false;

        while (offset < file_size) {
            const size_t remaining = file_size - offset;
            if (remaining < sizeof(RecordHeader)) {
                if (corrupt_pos >= offset) {
                    expected_lsn = last_valid_lsn;
                    return true;
                }
                return false;
            }

            input.clear();
            input.seekg(static_cast<std::streamoff>(offset));
            RecordHeader header{};
            input.read(reinterpret_cast<char*>(&header), sizeof(header));
            if (input.gcount() != static_cast<std::streamsize>(sizeof(header))) {
                return false;
            }
            const uint64_t preceding_valid_lsn = last_valid_lsn;

            if (header.payload_len >
                (std::numeric_limits<size_t>::max)() - sizeof(RecordHeader)) {
                return false;
            }
            const size_t record_size =
                sizeof(RecordHeader) + static_cast<size_t>(header.payload_len);
            if (record_size > remaining) {
                if (corrupt_pos >= offset) {
                    expected_lsn = last_valid_lsn;
                    return true;
                }
                return false;
            }

            if (header.payload_len > kMaxPayloadSize) {
                recovery_stopped = true;
            } else {
                std::vector<uint8_t> record(record_size);
                RecordHeader crc_header = header;
                const uint32_t saved_crc = crc_header.crc;
                crc_header.crc = 0;
                std::memcpy(record.data(), &crc_header, sizeof(crc_header));
                if (header.payload_len != 0) {
                    input.clear();
                    input.seekg(static_cast<std::streamoff>(
                        offset + sizeof(RecordHeader)));
                    input.read(
                        reinterpret_cast<char*>(
                            record.data() + sizeof(RecordHeader)),
                        static_cast<std::streamsize>(header.payload_len));
                    if (input.gcount() !=
                        static_cast<std::streamsize>(header.payload_len)) {
                        return false;
                    }
                }
                const bool crc_valid =
                    crc32(record.data(), record.size()) == saved_crc;
                const bool timestamp_valid = header.timestamp_ns >= last_valid_ts;

                if (!recovery_stopped) {
                    if (!crc_valid || !timestamp_valid) {
                        recovery_stopped = true;
                    } else {
                        last_valid_lsn = header.lsn;
                        last_valid_ts = header.timestamp_ns;
                    }
                }
            }

            if (corrupt_pos >= offset && corrupt_pos < offset + record_size) {
                expected_lsn = preceding_valid_lsn;
                return true;
            }
            offset += record_size;
        }
        return false;
    }

    std::string path_;
};

std::string make_temp_path(const std::string& prefix) {
    auto dir = fs::temp_directory_path();
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 99999999);
    return (dir / (prefix + "_" + std::to_string(dis(gen)) + ".dat")).string();
}

bool run_deterministic_sabotage_tests() {
    const std::string base_path = make_temp_path("mega_chaos_deterministic");
    MegaChaosJournal base(base_path);
    base.remove();
    const std::string first_payload = "FIRST_RECORD_PAYLOAD";
    const std::string second_payload = "SECOND_RECORD_PAYLOAD";
    if (!base.append(1, 1000, first_payload) ||
        !base.append(2, 2000, second_payload)) {
        std::cerr << "[ERROR] Could not create deterministic test journal\n";
        base.remove();
        return false;
    }

    const size_t first_record_size =
        sizeof(RecordHeader) + first_payload.size();
    const size_t second_record_start = first_record_size;
    struct CorruptionCase {
        const char* name;
        size_t position;
        uint64_t expected_lsn;
    };
    const CorruptionCase cases[] = {
        {"first-record-header", 0, 0},
        {"first-record-payload", sizeof(RecordHeader), 0},
        {"first-record-crc", offsetof(RecordHeader, crc), 0},
        {"later-record-header", second_record_start, 1},
        {"later-record-payload",
         second_record_start + sizeof(RecordHeader), 1},
        {"later-record-crc",
         second_record_start + offsetof(RecordHeader, crc), 1}
    };

    bool all_ok = true;
    for (const auto& test_case : cases) {
        const std::string case_path =
            make_temp_path(std::string("mega_chaos_") + test_case.name);
        std::error_code ec;
        fs::copy_file(base_path, case_path, fs::copy_options::overwrite_existing,
                      ec);
        if (ec) {
            std::cerr << "[ERROR] " << test_case.name
                      << ": could not copy test journal\n";
            all_ok = false;
            continue;
        }

        MegaChaosJournal test_journal(case_path);
        const SabotageResult sabotage =
            test_journal.inject_sabotage_at(test_case.position);
        if (!sabotage.success) {
            std::cerr << "[ERROR] " << test_case.name << ": "
                      << sabotage.error << "\n";
            all_ok = false;
            test_journal.remove();
            continue;
        }

        int64_t last_ts = 0;
        bool halted = false;
        const uint64_t recovered_lsn = test_journal.recover(last_ts, halted);
        if (sabotage.expected_lsn != test_case.expected_lsn ||
            recovered_lsn != test_case.expected_lsn) {
            std::cerr << "[FAIL] " << test_case.name
                      << ": expected LSN " << test_case.expected_lsn
                      << ", scanner expected " << sabotage.expected_lsn
                      << ", recovered " << recovered_lsn << "\n";
            all_ok = false;
        }
        test_journal.remove();
    }

    const std::string tail_path =
        make_temp_path("mega_chaos_incomplete_tail");
    MegaChaosJournal tail_journal(tail_path);
    tail_journal.remove();
    if (!tail_journal.append(1, 1000, first_payload)) {
        std::cerr << "[ERROR] Could not create incomplete-tail base record\n";
        tail_journal.remove();
        base.remove();
        return false;
    }
    {
        std::ofstream output(tail_path, std::ios::binary | std::ios::app);
        RecordHeader partial_header{};
        partial_header.lsn = 2;
        partial_header.timestamp_ns = 2000;
        partial_header.payload_len = 10;
        partial_header.crc = 0;
        const char partial_payload[] = "abc";
        output.write(reinterpret_cast<const char*>(&partial_header),
                     sizeof(partial_header));
        output.write(partial_payload, sizeof(partial_payload) - 1);
        output.flush();
        if (!output.good()) {
            std::cerr << "[ERROR] Could not append incomplete tail\n";
            all_ok = false;
        }
    }
    if (all_ok) {
        std::error_code ec;
        const auto tail_size = fs::file_size(tail_path, ec);
        if (ec || tail_size == 0) {
            std::cerr << "[ERROR] Could not inspect incomplete-tail journal\n";
            all_ok = false;
        } else {
            const SabotageResult sabotage =
                tail_journal.inject_sabotage_at(
                    static_cast<size_t>(tail_size - 1));
            int64_t last_ts = 0;
            bool halted = false;
            const uint64_t recovered_lsn =
                tail_journal.recover(last_ts, halted);
            if (!sabotage.success || sabotage.expected_lsn != 1 ||
                recovered_lsn != 1) {
                std::cerr << "[FAIL] incomplete-tail: expected LSN 1, scanner "
                          << sabotage.expected_lsn << ", recovered "
                          << recovered_lsn;
                if (!sabotage.success) {
                    std::cerr << ", error: " << sabotage.error;
                }
                std::cerr << "\n";
                all_ok = false;
            }
        }
    }
    tail_journal.remove();
    base.remove();
    if (all_ok) {
        std::cout << "[OK] Deterministic header/payload/CRC and incomplete-tail cases\n";
    }
    return all_ok;
}

int main(int argc, char* argv[]) {
    // ワーカーモード
    if (argc > 1 && std::string(argv[1]) == "worker_chaos") {
        std::string path = (argc > 2) ? argv[2] : "mega_chaos.dat";
        uint64_t start_lsn = (argc > 3) ? std::stoull(argv[3]) : 1000;

        MegaChaosJournal j(path);
        uint64_t lsn = start_lsn;
        while (true) {
            j.append(lsn, 2'000'000 + static_cast<int64_t>(lsn), "MEGA_CROSSFIRE_PAYLOAD");
            ++lsn;
        }
        return 0;
    }

    std::cout << "=== Starting MEGA CHAOS STRESS TEST (Test #9) ===\n";

    std::string path = make_temp_path("mega_chaos");
    MegaChaosJournal journal(path);
    journal.remove();

    constexpr int ITERATIONS = 5;
    bool all_ok = run_deterministic_sabotage_tests();

    for (int iter = 1; iter <= ITERATIONS; ++iter) {
        std::cout << "[LOOP " << iter << "/" << ITERATIONS << "] Spawning workers & initiating slaughter...\n";

        // ベースチェックポイント
        journal.append(static_cast<uint64_t>(iter * 10),
                       1000 * iter,
                       "BASE_CHECKPOINT_" + std::to_string(iter));

#ifdef _WIN32
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi1{}, pi2{};

        auto spawn = [&](uint64_t start_lsn, PROCESS_INFORMATION& pi) -> bool {
            std::string cmd = std::string(argv[0]) + " worker_chaos \"" + path + "\" " + std::to_string(start_lsn);
            std::vector<char> cmd_line(cmd.begin(), cmd.end());
            cmd_line.push_back('\0');
            return CreateProcessA(nullptr, cmd_line.data(),
                                  nullptr, nullptr, FALSE, 0,
                                  nullptr, nullptr, &si, &pi) != 0;
        };

        const bool spawned1 = spawn(1000 + iter * 1000, pi1);
        const bool spawned2 = spawned1 && spawn(5000 + iter * 1000, pi2);
        if (!spawned1 || !spawned2) {
            std::cerr << "[ERROR] Failed to spawn workers\n";
            PROCESS_INFORMATION* workers[] = {&pi1, &pi2};
            for (auto* worker : workers) {
                if (worker->hProcess != nullptr) {
                    TerminateProcess(worker->hProcess, 1);
                    WaitForSingleObject(worker->hProcess, INFINITE);
                    CloseHandle(worker->hProcess);
                    CloseHandle(worker->hThread);
                }
            }
            all_ok = false;
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(25));

        // 両ワーカー即死
        TerminateProcess(pi1.hProcess, 1);
        TerminateProcess(pi2.hProcess, 1);
        const DWORD wait1 = WaitForSingleObject(pi1.hProcess, INFINITE);
        const DWORD wait2 = WaitForSingleObject(pi2.hProcess, INFINITE);
        CloseHandle(pi1.hProcess); CloseHandle(pi1.hThread);
        CloseHandle(pi2.hProcess); CloseHandle(pi2.hThread);
        if (wait1 != WAIT_OBJECT_0 || wait2 != WAIT_OBJECT_0) {
            std::cerr << "[ERROR] Failed to wait for worker termination\n";
            all_ok = false;
            break;
        }

#else
        pid_t p1 = fork();
        if (p1 == 0) {
            execl(argv[0], argv[0], "worker_chaos", path.c_str(),
                  std::to_string(1000 + iter * 1000).c_str(), nullptr);
            _exit(1);
        }
        pid_t p2 = -1;
        if (p1 > 0) p2 = fork();
        if (p2 == 0) {
            execl(argv[0], argv[0], "worker_chaos", path.c_str(),
                  std::to_string(5000 + iter * 1000).c_str(), nullptr);
            _exit(1);
        }

        if (p1 < 0 || p2 < 0) {
            std::cerr << "[ERROR] Failed to fork workers\n";
            pid_t workers[] = {p1, p2};
            for (const pid_t worker : workers) {
                if (worker > 0) {
                    if (kill(worker, SIGKILL) != 0 && errno != ESRCH) {
                        all_ok = false;
                    }
                    int status = 0;
                    pid_t waited = 0;
                    do {
                        waited = waitpid(worker, &status, 0);
                    } while (waited < 0 && errno == EINTR);
                    if (waited != worker) all_ok = false;
                }
            }
            all_ok = false;
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(25));

        auto stop_and_wait = [](pid_t worker) {
            if (kill(worker, SIGKILL) != 0 && errno != ESRCH) return false;
            int status = 0;
            pid_t waited = 0;
            do {
                waited = waitpid(worker, &status, 0);
            } while (waited < 0 && errno == EINTR);
            return waited == worker;
        };
        const bool stopped1 = stop_and_wait(p1);
        const bool stopped2 = stop_and_wait(p2);
        if (!stopped1 || !stopped2) {
            std::cerr << "[ERROR] Failed to stop and wait for workers\n";
            all_ok = false;
            break;
        }
#endif

        const SabotageResult sabotage = journal.inject_sabotage();
        if (!sabotage.success) {
            std::cerr << "[ERROR] Sabotage failed: " << sabotage.error << "\n";
            all_ok = false;
            break;
        }
        std::cout << "  -> Corrupted byte: " << sabotage.position
                  << ", expected LSN: " << sabotage.expected_lsn << "\n";

        // リカバリ
        int64_t ts = 0;
        bool halted = false;
        uint64_t recovered_lsn = journal.recover(ts, halted);

        std::cout << "  -> Recovered LSN: " << recovered_lsn
                  << ", Halted: " << std::boolalpha << halted << "\n";

        if (recovered_lsn != sabotage.expected_lsn) {
            std::cerr << "[FAIL] Expected LSN " << sabotage.expected_lsn
                      << " for corruption at byte " << sabotage.position
                      << ", recovered " << recovered_lsn << "\n";
            all_ok = false;
        }
        // halted はサボタージュや競合で起こり得るので、ここでは警告に留める
        if (halted) {
            std::cout << "  [WARN] Time-warp detected (acceptable under extreme sabotage)\n";
        }
    }

    journal.remove();

    std::cout << "====================================================\n";
    if (all_ok) {
        std::cout << " MEGA CHAOS STRESS TEST PASSED WITH ABSOLUTE GLORY!\n";
        std::cout << "====================================================\n";
        return 0;
    } else {
        std::cout << " MEGA CHAOS STRESS TEST FAILED\n";
        std::cout << "====================================================\n";
        return 1;
    }
}