/**
 * @file test_real_chaos.cpp
 * @brief クロスプラットフォーム対応・改善版（最終修正）
 *        - 強制ディスク同期
 *        - 一時ファイル
 *        - 並行時のタイムスタンプ逆転を完全防止
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <atomic>
#include <thread>
#include <mutex>
#include <chrono>
#include <filesystem>
#include <random>
#include <cassert>

#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #include <windows.h>
#else
  #include <unistd.h>
  #include <fcntl.h>
#endif

namespace fs = std::filesystem;

// ------------------------------------------------------------
// 簡易CRC32
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
// クロスプラットフォーム強制ディスク同期
// ------------------------------------------------------------
bool force_sync_file(const std::string& path) {
#ifdef _WIN32
    HANDLE h = CreateFileA(
        path.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
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
// ジャーナル本体
// ------------------------------------------------------------
class RealJournal {
public:
    explicit RealJournal(const std::string& path) : path_(path) {}

    bool append(uint64_t lsn, int64_t ts, const std::string& payload) {
        std::lock_guard<std::mutex> lock(mtx_);

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

    void corrupt_at(size_t offset, uint8_t xor_mask = 0xFF) {
        std::fstream fs(path_, std::ios::in | std::ios::out | std::ios::binary);
        if (!fs) return;
        fs.seekp(static_cast<std::streamoff>(offset));
        char b = 0;
        fs.read(&b, 1);
        b ^= static_cast<char>(xor_mask);
        fs.seekp(static_cast<std::streamoff>(offset));
        fs.write(&b, 1);
        fs.flush();
    }

    size_t file_size() const {
        std::error_code ec;
        auto sz = fs::file_size(path_, ec);
        return ec ? 0 : static_cast<size_t>(sz);
    }

    void remove() {
        std::error_code ec;
        fs::remove(path_, ec);
    }

private:
    std::string path_;
    std::mutex  mtx_;
};

// ------------------------------------------------------------
// テスト用ユーティリティ
// ------------------------------------------------------------
static int g_fail = 0;

#define CHECK(cond) do { \
    if (!(cond)) { \
        ++g_fail; \
        std::cerr << "[FAIL] " << __FILE__ << ":" << __LINE__ << "  " #cond "\n"; \
    } \
} while (0)

void print_ok(const std::string& name) {
    std::cout << "[PASS] " << name << "\n";
}

std::string make_temp_path(const std::string& prefix) {
    auto dir = fs::temp_directory_path();
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 99999999);
    return (dir / (prefix + "_" + std::to_string(dis(gen)) + ".dat")).string();
}

// ------------------------------------------------------------
// テストケース
// ------------------------------------------------------------
void test_normal() {
    std::string path = make_temp_path("chaos_normal");
    RealJournal j(path);
    j.remove();

    j.append(1, 1000, "A");
    j.append(2, 2000, "B");
    j.append(3, 3000, "C");

    int64_t ts = 0;
    bool halted = false;
    uint64_t lsn = j.recover(ts, halted);

    CHECK(lsn == 3);
    CHECK(ts == 3000);
    CHECK(!halted);
    print_ok("Normal append + recover");
    j.remove();
}

void test_partial_tail() {
    std::string path = make_temp_path("chaos_partial");
    RealJournal j(path);
    j.remove();

    j.append(10, 10000, "FULL_RECORD");

    {
        std::ofstream ofs(path, std::ios::binary | std::ios::app);
        RecordHeader h{11, 11000, 100, 0};
        ofs.write(reinterpret_cast<const char*>(&h), 8);
        ofs.flush();
    }

    int64_t ts = 0;
    bool halted = false;
    uint64_t lsn = j.recover(ts, halted);

    CHECK(lsn == 10);
    print_ok("Partial tail (header truncated)");
    j.remove();
}

void test_partial_payload() {
    std::string path = make_temp_path("chaos_partial_payload");
    RealJournal j(path);
    j.remove();

    j.append(20, 20000, "GOOD");

    {
        std::ofstream ofs(path, std::ios::binary | std::ios::app);
        RecordHeader h{21, 21000, 50, 0};
        ofs.write(reinterpret_cast<const char*>(&h), sizeof(h));
        ofs.write("INCOMPLETE", 10);
        ofs.flush();
    }

    int64_t ts = 0;
    bool halted = false;
    uint64_t lsn = j.recover(ts, halted);

    CHECK(lsn == 20);
    print_ok("Partial payload (truncated mid-record)");
    j.remove();
}

void test_bit_flip() {
    std::string path = make_temp_path("chaos_corrupt");
    RealJournal j(path);
    j.remove();

    j.append(100, 100000, "GOOD1");
    j.append(101, 100100, "GOOD2");
    size_t size_before_third = j.file_size();
    j.append(102, 100200, "DOOMED");

    j.corrupt_at(size_before_third + 4);

    int64_t ts = 0;
    bool halted = false;
    uint64_t lsn = j.recover(ts, halted);

    CHECK(lsn == 101);
    print_ok("Bit-flip / corruption detection");
    j.remove();
}

void test_time_warp() {
    std::string path = make_temp_path("chaos_time");
    RealJournal j(path);
    j.remove();

    j.append(200, 5000, "T1");
    j.append(201, 4999, "TIME_WARP");

    int64_t ts = 0;
    bool halted = false;
    uint64_t lsn = j.recover(ts, halted);

    CHECK(halted == true);
    CHECK(lsn == 200);
    print_ok("Monotonic time-warp detection");
    j.remove();
}

void test_concurrent_append() {
    std::string path = make_temp_path("chaos_concurrent");
    RealJournal j(path);
    j.remove();

    constexpr int NUM_THREADS = 4;
    constexpr int OPS = 200;          // 合計 800

    // ★ ここが重要：LSN と timestamp の発行を完全に直列化する
    std::mutex gen_mtx;
    uint64_t next_lsn = 1;
    int64_t  next_ts  = 1;

    std::vector<std::thread> threads;

    for (int t = 0; t < NUM_THREADS; ++t) {
        threads.emplace_back([&]() {
            for (int i = 0; i < OPS; ++i) {
                uint64_t lsn;
                int64_t  ts;

                // 発行と append を同じロックで保護
                {
                    std::lock_guard<std::mutex> lock(gen_mtx);
                    lsn = next_lsn++;
                    ts  = next_ts++;
                    // append もこのロック内で呼ぶことで順序を保証
                    j.append(lsn, ts, "data_" + std::to_string(lsn));
                }
            }
        });
    }
    for (auto& th : threads) th.join();

    int64_t ts = 0;
    bool halted = false;
    uint64_t recovered = j.recover(ts, halted);

    CHECK(recovered > 0);
    CHECK(!halted);
    CHECK(recovered == static_cast<uint64_t>(NUM_THREADS * OPS));

    std::cout << "  recovered LSN = " << recovered
              << " (expected " << NUM_THREADS * OPS << ")\n";

    if (g_fail == 0) {
        print_ok("Concurrent append + recover (with mutex)");
    }
    j.remove();
}

// ------------------------------------------------------------
int main() {
    std::cout << "=== Improved Cross-Platform Chaos Resistance Test ===\n\n";

    test_normal();
    test_partial_tail();
    test_partial_payload();
    test_bit_flip();
    test_time_warp();
    test_concurrent_append();

    std::cout << "\n====================================================\n";
    if (g_fail == 0) {
        std::cout << "ALL IMPROVED CHAOS TESTS PASSED\n";
        std::cout << "Files were created in system temp directory and cleaned up.\n";
        return 0;
    } else {
        std::cerr << g_fail << " TEST(S) FAILED\n";
        return 1;
    }
}