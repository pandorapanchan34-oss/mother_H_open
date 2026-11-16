/**
 * @file test_process_killer_chaos.cpp
 * @brief Mother_H Phase 14 Step 5: Hard Process Killer & Recovery Chaos Test (Test #8)
 * 目的: 書き込み中のプロセスを容赦なく強制終了させ、
 *       残されたダーティなジャーナルを安全にリカバリできることを証明する
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

#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #include <windows.h>
#else
  #include <unistd.h>
  #include <sys/wait.h>
  #include <signal.h>
  #include <fcntl.h>
#endif

namespace fs = std::filesystem;

// ------------------------------------------------------------
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

// ------------------------------------------------------------
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

// ------------------------------------------------------------
class ProcessKillerJournal {
public:
    explicit ProcessKillerJournal(const std::string& path) : path_(path) {}

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

    uint64_t recover(int64_t& last_ts, bool& halted) {
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

    void remove() {
        std::error_code ec;
        fs::remove(path_, ec);
    }

    const std::string& path() const { return path_; }

private:
    std::string path_;
};

// ------------------------------------------------------------
std::string make_temp_path(const std::string& prefix) {
    auto dir = fs::temp_directory_path();
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 99999999);
    return (dir / (prefix + "_" + std::to_string(dis(gen)) + ".dat")).string();
}

// ------------------------------------------------------------
int main(int argc, char* argv[]) {
    // ワーカーモード（子プロセス）
    if (argc > 1 && std::string(argv[1]) == "worker_chaos") {
        std::string path = (argc > 2) ? argv[2] : "killer_chaos_journal.dat";
        ProcessKillerJournal j(path);

        uint64_t lsn = 100;
        while (true) {
            j.append(lsn, 1000000 + static_cast<int64_t>(lsn), "KILLER_PAYLOAD_DATA_STREAM");
            ++lsn;
            // ウェイトなしで限界まで書き続ける
        }
        return 0;
    }

    // 親プロセス（司令塔）
    std::cout << "=== Starting Hard Process Killer Chaos Test (Test #8) ===\n";

    std::string path = make_temp_path("killer_chaos");
    ProcessKillerJournal j(path);
    j.remove();

    // 事前に安全なベースデータを書く
    j.append(1, 1000, "SAFE_BASE_1");
    j.append(2, 2000, "SAFE_BASE_2");

    std::cout << "[PARENT] Safe base records written (LSN 1-2)\n";

#ifdef _WIN32
    // Windows: CreateProcess + TerminateProcess
    std::string cmd = std::string(argv[0]) + " worker_chaos \"" + path + "\"";
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi{};

    std::vector<char> cmd_line(cmd.begin(), cmd.end());
    cmd_line.push_back('\0');

    if (!CreateProcessA(nullptr, cmd_line.data(),
                        nullptr, nullptr, FALSE, 0,
                        nullptr, nullptr, &si, &pi)) {
        std::cerr << "[ERROR] Failed to spawn worker process. Error=" << GetLastError() << "\n";
        return 1;
    }

    std::cout << "[PARENT] Worker process spawned. Waiting a moment...\n";
    std::this_thread::sleep_for(std::chrono::milliseconds(30));

    std::cout << "[KILLER] Executing hard TerminateProcess !!!\n";
    TerminateProcess(pi.hProcess, 1);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

#else
    // Linux / macOS
    pid_t pid = fork();
    if (pid == 0) {
        // 子プロセス
        execl(argv[0], argv[0], "worker_chaos", path.c_str(), nullptr);
        _exit(1);
    } else if (pid > 0) {
        std::cout << "[PARENT] Worker process spawned (pid=" << pid << "). Waiting...\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(30));

        std::cout << "[KILLER] Executing hard SIGKILL !!!\n";
        kill(pid, SIGKILL);
        int status = 0;
        waitpid(pid, &status, 0);
    } else {
        std::cerr << "[ERROR] fork failed\n";
        return 1;
    }
#endif

    // 強制終了後のダーティファイルをリカバリ
    std::cout << "[PARENT] Recovering from dirty journal...\n";
    int64_t ts = 0;
    bool halted = false;
    uint64_t recovered_lsn = j.recover(ts, halted);

    std::cout << "[RESULT] Recovered LSN after hard kill : " << recovered_lsn << "\n";
    std::cout << "[RESULT] halted                        : " << std::boolalpha << halted << "\n";

    // 検証
    bool success = true;
    if (recovered_lsn < 2) {
        std::cerr << "[FAIL] Recovered LSN is less than safe base (2)\n";
        success = false;
    }
    if (halted) {
        std::cerr << "[FAIL] Time-warp (halted) detected unexpectedly\n";
        success = false;
    }

    j.remove();

    std::cout << "====================================================\n";
    if (success) {
        std::cout << " HARD PROCESS KILLER CHAOS TEST PASSED SUCCESSFULLY!\n";
        std::cout << "====================================================\n";
        return 0;
    } else {
        std::cout << " HARD PROCESS KILLER CHAOS TEST FAILED\n";
        std::cout << "====================================================\n";
        return 1;
    }
}