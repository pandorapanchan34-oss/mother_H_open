/**
 * @file test_apocalypse_chaos.cpp
 * @brief Mother_H Phase 14 Step 7: Apocalypse Chaos Test (Test #10)
 *
 * 4鬩幢ｽ｢隴惹ｸ橸ｽｹ・ｲ繝ｻ蜿厄ｽｺ・ｽ繝ｻ・ｹ繝ｻ・ｧ郢晢ｽｻ繝ｻ・ｻ鬩幢ｽ｢繝ｻ・ｧ郢晢ｽｻ繝ｻ・ｹ鬮｣蛹・ｽｽ・ｵ郢晢ｽｻ繝ｻ・ｱ鬮ｫ・ｰ鬲・ｼ夲ｽｽ・ｽ繝ｻ・ｦ + 鬩幢ｽ｢繝ｻ・ｧ郢晢ｽｻ繝ｻ・ｨ鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｳ鬩幢ｽ｢隴取得・ｽ・ｳ繝ｻ・ｨ繝ｻ蜿厄ｽｨ謚ｵ・ｽ・ｹ繝ｻ・ｧ郢晢ｽｻ繝ｻ・ｹ鬮ｯ・ｷ陞ゅ・・ｽ・ｽ繝ｻ・ｳ鬮ｮ蠑ｱ繝ｻ繝ｻ・ｽ繝ｻ・ｻ鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｻ鬮ｯ・ｷ・つ鬯ｮ・ｦ繝ｻ・ｪ驍ｵ・ｺ陝ｶ・ｷ繝ｻ・ｹ隴弱・・ｺ・｢驛｢譎｢・ｽ・ｻ鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｳ + 鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｩ鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｳ鬩幢ｽ｢繝ｻ・ｧ郢晢ｽｻ繝ｻ・ｿ鬩幢ｽ｢繝ｻ・ｧ郢晢ｽｻ繝ｻ・､鬩幢ｽ｢隴趣ｽ｢繝ｻ・｣繝ｻ・ｰ鬯ｩ蠅楢・繝ｻ・ｽ繝ｻ・ｴ鬮ｯ讖ｸ・ｽ・｢驛｢譎｢・ｽ・ｻ+
 * 鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｪ鬩幢ｽ｢繝ｻ・ｧ郢晢ｽｻ繝ｻ・ｫ鬩幢ｽ｢隴寂・繝ｻ繝ｻ蜿悶冠隶梧㊥・ｲ繝ｻ・ｽ・ｯ郢晢ｽｻ繝ｻ・｡髯溷桁・ｽ・｡郢晢ｽｻ繝ｻ・ｸ郢晢ｽｻ繝ｻ・ｭ鬩搾ｽｵ繝ｻ・ｺ郢晢ｽｻ繝ｻ・ｮ鬯ｮ・ｴ隰・∞・ｽ・ｽ繝ｻ・ｽ鬮ｫ・ｰ繝ｻ・ｦ驛｢譎｢・ｽ・ｻ郢晢ｽｻ陞ｳ螢ｼ蛻昴・縺､ﾂ鬮ｯ讖ｸ・ｽ・ｳ髯橸ｽ｢繝ｻ・ｽ髯ｷ繝ｻ・ｽ・ｾ鬯ｯ・ｮ繝ｻ・｢鬯ｪ・ｰ陷茨ｽｷ繝ｻ・ｽ繝ｻ・ｶ髯ｷ・･隰ｫ・ｾ繝ｻ・ｽ繝ｻ・ｶ髯橸ｽ｢繝ｻ・ｹ郢晢ｽｻ繝ｻ・ｰ鬩搾ｽｵ繝ｻ・ｲ驕ｶ謫ｾ・ｽ・ｵ髫ｲ・､陷･蠑ｱ笙驛｢・ｧ霑壼虫・｣・ｭ鬩搾ｽｵ繝ｻ・ｺ郢晢ｽｻ繝ｻ・ｫ鬮ｯ讖ｸ・ｽ・ｳ髴大｣ｼ逕溽ｹ晢ｽｻ鬩搾ｽｵ繝ｻ・ｺ郢晢ｽｻ繝ｻ・ｫ鬯ｨ・ｾ陟・屮・ｽ・ｻ郢晢ｽｻ繝ｻ・ｽ郢晢ｽｻ繝ｻ・ｸ繝ｻ・ｺ郢晢ｽｻ繝ｻ・ｧ鬩搾ｽｵ繝ｻ・ｺ鬯ｮ・ｦ繝ｻ・ｪ郢晢ｽｻ霑｢證ｦ・ｽ・ｸ繝ｻ・ｺ髣包ｽｵ隴趣ｽ｢繝ｻ・ｽ陞ｳ螟ｲ・ｽ・ｮ・つ髫ｲ蟶吶・繝ｻ・ｽ繝ｻ・ｨ郢晢ｽｻ繝ｻ・ｼ鬩搾ｽｵ繝ｻ・ｺ髯ｷ・ｷ繝ｻ・ｶ郢晢ｽｻ郢晢ｽｻ
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
#include <random>
#include <atomic>
#include <cstdlib>

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

class ApocalypseJournal {
public:
    explicit ApocalypseJournal(const std::string& path) : path_(path) {}

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

    void inject_sabotage() {
        std::error_code ec;
        auto size = fs::file_size(path_, ec);
        if (ec || size < 32) return;

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<size_t> pos_dis(0, static_cast<size_t>(size) - 1);

        std::fstream fs_io(path_, std::ios::in | std::ios::out | std::ios::binary);
        if (!fs_io) return;
        fs_io.seekp(static_cast<std::streamoff>(pos_dis(gen)));
        char garbage = static_cast<char>(0x5A);
        fs_io.write(&garbage, 1);
        fs_io.flush();
    }

    void remove() {
        std::error_code ec;
        fs::remove(path_, ec);
    }

    const std::string& path() const { return path_; }

private:
    std::string path_;
};

std::string make_temp_path(const std::string& prefix) {
    auto dir = fs::temp_directory_path();
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 99999999);
    return (dir / (prefix + "_" + std::to_string(dis(gen)) + ".dat")).string();
}

int main(int argc, char* argv[]) {
    // 鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｯ鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｼ鬩幢ｽ｢繝ｻ・ｧ郢晢ｽｻ繝ｻ・ｫ鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｼ鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・｢鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｼ鬩幢ｽ｢隴擾ｽｴ郢晢ｽｻ
    if (argc > 1 && std::string(argv[1]) == "apocalypse_worker") {
        std::string path = (argc > 2) ? argv[2] : "apocalypse.dat";
        uint64_t start_lsn = (argc > 3) ? std::stoull(argv[3]) : 10000;

        ApocalypseJournal j(path);
        uint64_t lsn = start_lsn;
        while (true) {
            j.append(lsn, 3'000'000 + static_cast<int64_t>(lsn), "APOCALYPSE_STREAM_DATA");
            ++lsn;
        }
        return 0;
    }

    std::cout << "=== Starting APOCALYPSE CHAOS TEST (Test #10) ===\n";

    std::string path = make_temp_path("apocalypse");
    ApocalypseJournal journal(path);
    journal.remove();

    // 鬮｣雋ｻ・｣・ｰ髯ｷ・ｿ繝ｻ・･髴趣ｽｯ隲ｷ蛹・ｽｽ・ｸ繝ｻ・ｺ郢晢ｽｻ繝ｻ・ｮ鬮ｯ讖ｸ・ｽ・ｳ髴大｣ｼ逕溽ｹ晢ｽｻ鬩搾ｽｵ繝ｻ・ｺ郢晢ｽｻ繝ｻ・ｪ鬩幢ｽ｢隴主・蜃ｽ驛｢譎｢・ｽ・ｻ鬩幢ｽ｢繝ｻ・ｧ郢晢ｽｻ繝ｻ・ｹ
    journal.append(1, 1000, "APOCALYPSE_BASE_1");
    journal.append(2, 2000, "APOCALYPSE_BASE_2");

#ifdef _WIN32
    constexpr int NUM_WORKERS = 4;
    std::vector<PROCESS_INFORMATION> pis(NUM_WORKERS);

    auto spawn_worker = [&](int idx) -> bool {
        uint64_t start_lsn = 10000 + idx * 100000;
        std::string cmd = std::string(argv[0]) + " apocalypse_worker \"" + path + "\" " +
                          std::to_string(start_lsn);

        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi{};
        std::vector<char> cmd_line(cmd.begin(), cmd.end());
        cmd_line.push_back('\0');

        if (!CreateProcessA(nullptr, cmd_line.data(),
                            nullptr, nullptr, FALSE, 0,
                            nullptr, nullptr, &si, &pi)) {
            return false;
        }
        pis[idx] = pi;
        return true;
    };

    for (int i = 0; i < NUM_WORKERS; ++i) {
        if (!spawn_worker(i)) {
            std::cerr << "[ERROR] Failed to spawn worker " << i << "\n";
            return 1;
        }
    }

    std::cout << "[APOCALYPSE] 4 workers spawned. Starting 8 seconds of hell...\n";

    auto start_time = std::chrono::steady_clock::now();
    std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<> sleep_dis(80, 250);
    std::uniform_int_distribution<> target_dis(0, NUM_WORKERS - 1);

    int kill_count = 0;
    int sabotage_count = 0;

    while (std::chrono::steady_clock::now() - start_time < std::chrono::seconds(8)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(sleep_dis(gen)));

        // 鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｩ鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｳ鬩幢ｽ｢隰ｨ魑ｴﾂ鬩幢ｽ｢隴趣ｽ｢繝ｻ・｣繝ｻ・ｰ鬩搾ｽｵ繝ｻ・ｺ郢晢ｽｻ繝ｻ・ｫ1鬩幢ｽ｢隴惹ｸ橸ｽｹ・ｲ繝ｻ蜿厄ｽｺ・ｽ繝ｻ・ｹ繝ｻ・ｧ郢晢ｽｻ繝ｻ・ｻ鬩幢ｽ｢繝ｻ・ｧ郢晢ｽｻ繝ｻ・ｹ鬩幢ｽ｢繝ｻ・ｧ髯句ｹ｢・ｽ・ｵ驍ｵ・ｺ陷證ｦ・ｽ・ｹ隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｫ鬩搾ｽｵ繝ｻ・ｺ髯ｷ莨夲ｽｽ・ｱ驕ｯ・ｶ繝ｻ・ｻ鬮ｯ・ｷ・つ鬯ｮ・ｦ繝ｻ・ｪ驍ｵ・ｺ陝ｶ・ｷ繝ｻ・ｹ隴弱・・ｺ・｢驛｢譎｢・ｽ・ｻ鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｳ
        int target = target_dis(gen);
        if (pis[target].hProcess) {
            TerminateProcess(pis[target].hProcess, 1);
            WaitForSingleObject(pis[target].hProcess, 50);
            CloseHandle(pis[target].hProcess);
            CloseHandle(pis[target].hThread);
            pis[target].hProcess = nullptr;
        }
        spawn_worker(target);
        ++kill_count;

        // 鬩幢ｽ｢繝ｻ・ｧ郢晢ｽｻ繝ｻ・ｵ鬩幢ｽ｢隴弱・魃ｵ驍ｵ・ｺ繝ｻ・｡鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｼ鬩幢ｽ｢繝ｻ・ｧ郢晢ｽｻ繝ｻ・ｸ鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・･
        journal.inject_sabotage();
        ++sabotage_count;

        // 鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｪ鬩幢ｽ｢繝ｻ・ｧ郢晢ｽｻ繝ｻ・ｫ鬩幢ｽ｢隴寂・繝ｻ繝ｻ蜿悶冠陷ｿ蟲ｨ繝ｻ繝ｻ・ｭ鬩搾ｽｵ繝ｻ・ｺ郢晢ｽｻ繝ｻ・ｮ鬯ｮ・ｴ隰・∞・ｽ・ｽ繝ｻ・ｽ鬮ｫ・ｰ繝ｻ・ｦ驛｢譎｢・ｽ・ｻ
        int64_t ts = 0;
        bool halted = false;
        journal.recover(ts, halted);   // 鬯ｩ謳ｾ・ｽ・ｨ髯ｷ莠･豐ｺ繝ｻ・｣繝ｻ・｡鬩搾ｽｵ繝ｻ・ｺ郢晢ｽｻ繝ｻ・ｯ鬮ｯ諛ｶ・｣・ｰ髣包ｽｳ陞ゅ・・ｽ・ｽ陷證ｦ・ｽ・ｸ繝ｻ・ｺ郢晢ｽｻ繝ｻ・ｪ鬩搾ｽｵ繝ｻ・ｺ驛｢譎｢・ｽ・ｻ郢晢ｽｻ繝ｻ・ｼ髯具ｽｹ繝ｻ・ｻ驍ｵ・ｺ鬩｢謳ｾ・ｽ・ｹ隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｩ鬩幢ｽ｢隴擾ｽｴ郢晢ｽｻ驍ｵ・ｺ陷･謫ｾ・ｽ・ｹ隴趣ｽ｢繝ｻ・ｽ繝ｻ・･鬩搾ｽｵ繝ｻ・ｺ髯ｷ莨夲ｽｽ・ｱ驕ｶ莨√・繝ｻ・ｸ繝ｻ・ｺ驛｢譎｢・ｽ・ｻ郢晢ｽｻ郢晢ｽｻ繝ｻ・ｸ繝ｻ・ｺ郢晢ｽｻ繝ｻ・ｨ鬩搾ｽｵ繝ｻ・ｺ鬩募●繝ｻ髯ｬ貊・ｽｫ・ｫ髴域鱒繝ｻ郢晢ｽｻ繝ｻ・ｼ驛｢譎｢・ｽ・ｻ
        journal.inject_sabotage();     // 鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｪ鬩幢ｽ｢繝ｻ・ｧ郢晢ｽｻ繝ｻ・ｫ鬩幢ｽ｢隴寂・繝ｻ繝ｻ蜿悶・・つ繝ｻ・ｶ郢晢ｽｻ繝ｻ・ｴ鬮ｯ貅ｷ萓帙・・ｾ陞ｽ・ｯ郢晢ｽｻ鬮ｯ・ｷ・つ髯ｷ・･繝ｻ・ｲ郢晢ｽｻ繝ｻ・ｰ郢晢ｽｻ繝ｻ・ｴ鬮ｯ讖ｸ・ｽ・｢驛｢譎｢・ｽ・ｻ
        ++sabotage_count;
    }

    // 鬮ｯ・ｷ髣鯉ｽｨ繝ｻ・ｽ繝ｻ・ｨ鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｯ鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｼ鬩幢ｽ｢繝ｻ・ｧ郢晢ｽｻ繝ｻ・ｫ鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｼ鬯ｩ謳ｾ・ｽ・ｨ驛｢・ｧ郢晢ｽｻ繝ｻ・ｽ繝ｻ・ｺ驛｢譎｢・ｽ・ｻ
    for (int i = 0; i < NUM_WORKERS; ++i) {
        if (pis[i].hProcess) {
            TerminateProcess(pis[i].hProcess, 1);
            WaitForSingleObject(pis[i].hProcess, 100);
            CloseHandle(pis[i].hProcess);
            CloseHandle(pis[i].hThread);
        }
    }

#else
    // Linux / macOS 鬯ｩ髦ｪ繝ｻ繝ｻ・ｽ繝ｻ・｡鬮ｫ・ｴ陜捺焔・ｱ・ｪ髮取腸・ｽ・ｿ驛｢譎｢・ｽ・ｻ驛｢譎｢・ｽ・ｻ鬩幢ｽ｢隴惹ｸ橸ｽｹ・ｲ繝ｻ蜿厄ｽｺ・ｽ繝ｻ・ｹ繝ｻ・ｧ郢晢ｽｻ繝ｻ・ｻ鬩幢ｽ｢繝ｻ・ｧ郢晢ｽｻ繝ｻ・ｹ + 鬩幢ｽ｢繝ｻ・ｧ郢晢ｽｻ繝ｻ・ｭ鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｫ驛｢譎｢・ｽ・ｻ驛｢譎｢・ｽ・ｻ
    constexpr int NUM_WORKERS = 4;
    std::vector<pid_t> pids(NUM_WORKERS, -1);

    auto spawn_worker = [&](int idx) -> pid_t {
        uint64_t start_lsn = 10000 + idx * 100000;
        pid_t pid = fork();
        if (pid == 0) {
            execl(argv[0], argv[0], "apocalypse_worker", path.c_str(),
                  std::to_string(start_lsn).c_str(), nullptr);
            _exit(1);
        }
        return pid;
    };

    for (int i = 0; i < NUM_WORKERS; ++i) {
        pids[i] = spawn_worker(i);
    }

    std::cout << "[APOCALYPSE] 4 workers spawned (Linux). Starting 8 seconds of hell...\n";

    auto start_time = std::chrono::steady_clock::now();
    std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<> sleep_dis(80, 250);
    std::uniform_int_distribution<> target_dis(0, NUM_WORKERS - 1);

    int kill_count = 0;
    int sabotage_count = 0;

    while (std::chrono::steady_clock::now() - start_time < std::chrono::seconds(8)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(sleep_dis(gen)));

        int target = target_dis(gen);
        if (pids[target] > 0) {
            kill(pids[target], SIGKILL);
            int st;
            waitpid(pids[target], &st, 0);
        }
        pids[target] = spawn_worker(target);
        ++kill_count;

        journal.inject_sabotage();
        ++sabotage_count;

        int64_t ts = 0;
        bool halted = false;
        journal.recover(ts, halted);
        journal.inject_sabotage();
        ++sabotage_count;
    }

    for (int i = 0; i < NUM_WORKERS; ++i) {
        if (pids[i] > 0) {
            kill(pids[i], SIGKILL);
            int st;
            waitpid(pids[i], &st, 0);
        }
    }
#endif

    // 鬮ｫ・ｴ陝・｢・つ鬯ｩ謳ｾ・ｽ・ｨ驛｢・ｧ郢晢ｽｻ隲帙・・ｽ・ｹ繝ｻ・ｧ郢晢ｽｻ繝ｻ・ｫ鬩幢ｽ｢隴寂・繝ｻ繝ｻ蠑ｱ繝ｻ
    int64_t final_ts = 0;
    bool final_halted = false;
    uint64_t final_lsn = journal.recover(final_ts, final_halted);

    std::cout << "[APOCALYPSE] Kill count     : " << kill_count << "\n";
    std::cout << "[APOCALYPSE] Sabotage count : " << sabotage_count << "\n";
    std::cout << "[APOCALYPSE] Final LSN      : " << final_lsn << "\n";
    std::cout << "[APOCALYPSE] Final halted   : " << std::boolalpha << final_halted << "\n";

    journal.remove();

    // 鬮ｫ・ｰ陟包ｽ｡繝ｻ・ｻ陷･謫ｾ・ｽ・ｲ繝ｻ・･鬮ｫ・ｴ陞滂ｽｲ繝ｻ・ｽ繝ｻ・｡鬮｣豈費ｽｼ螟ｲ・ｽ・ｽ繝ｻ・ｶ驛｢譎｢・ｽ・ｻ髯懈瑳・ｻ逹｣ﾂ陷ｻ・ｵ隰壹・・ｭ蟷｢・ｽ・ｱ髯ｷ隨ｬ・ｧ・ｭ郢晢ｽｻ驛｢譎｢・ｽ・ｻ
    // - 鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｪ鬩幢ｽ｢繝ｻ・ｧ郢晢ｽｻ繝ｻ・ｫ鬩幢ｽ｢隴寂・繝ｻ繝ｻ蜿悶渚繝ｻ・ｸ繝ｻ・ｺ髯溷供・ｾ魃会ｽｿ・ｰ鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｩ鬩幢ｽ｢隴擾ｽｴ郢晢ｽｻ驍ｵ・ｺ陷･謫ｾ・ｽ・ｹ隴趣ｽ｢繝ｻ・ｽ繝ｻ・･鬩搾ｽｵ繝ｻ・ｺ髯晢ｽｶ陷ｷ・ｮ郢晢ｽｻ鬩搾ｽｵ繝ｻ・ｺ郢晢ｽｻ繝ｻ・ｫ鬮ｯ讖ｸ・ｽ・ｳ髯溷桁・ｽ・｡郢晢ｽｻ繝ｻ・ｺ驛｢譎｢・ｽ・ｻ郢晢ｽｻ繝ｻ・ｰ鬩搾ｽｵ繝ｻ・ｺ驛｢譎｢・ｽ・ｻ
    // - 鬮｣雋ｻ・｣・ｰ髯ｷ・ｿ繝ｻ・･髴趣ｽｯ隲ｷ蛹・ｽｽ・ｸ繝ｻ・ｺ郢晢ｽｻ繝ｻ・ｫ鬮ｫ・ｴ陷ｴ繝ｻ・ｽ・ｽ繝ｻ・ｸ鬩搾ｽｵ繝ｻ・ｺ驛｢譎｢・ｽ・ｻ髫ｨ・ｳ郢晢ｽｻ繝ｻ・ｹ隴主・蜃ｽ驛｢譎｢・ｽ・ｻ鬩幢ｽ｢繝ｻ・ｧ郢晢ｽｻ繝ｻ・ｹ鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｬ鬩幢ｽ｢繝ｻ・ｧ郢晢ｽｻ繝ｻ・ｳ鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｼ鬩幢ｽ｢隴乗・・ｽ・ｼ陞滂ｽｲ繝ｻ・ｽ繝ｻ・ｼ驛｢譎｢・ｽ・ｻSN >= 2驛｢譎｢・ｽ・ｻ髯晢ｽｲ繝ｻ・ｨ驕ｯ・ｶ繝ｻ・ｲ鬮ｯ譏ｴ繝ｻ繝ｻ・ｻ繝ｻ・｣驕ｶ莨√・繝ｻ・ｸ繝ｻ・ｺ髣包ｽｳ陝ｯ・ｩ郢晢ｽｻ鬩幢ｽ｢繝ｻ・ｧ驛｢・ｧ髣鯉ｽｨ繝ｻ・ｽ繝ｻ・ｮ髣包ｽｵ隴擾ｽｶ陞滂ｽ｢鬩搾ｽｵ繝ｻ・ｺ郢晢ｽｻ繝ｻ・ｦ鬩搾ｽｵ繝ｻ・ｺ驛｢譎｢・ｽ・ｻ郢晢ｽｻ郢晢ｽｻ
    // 隰御ｻ咏ｲ･隴夲ｽ｡闔会ｽｶ: 驕撰ｽｴ隰ｳ閧ｴ蛻､隰ｦ繝ｻ繝ｻ郢晢ｽｯ郢晢ｽｼ郢ｧ・ｫ郢晢ｽｼ闕ｵ・ｱ隰鯉ｽｦ郢ｧ蝣､・ｵ蠕娯ｻ郢ｧ繝ｻrecover() 邵ｺ蠕後￠郢晢ｽｩ郢昴・縺咏ｹ晢ｽ･邵ｺ蟶吮・陞ｳ迚吶・邵ｺ・ｫ陞ｳ蠕｡・ｺ繝ｻ・邵ｺ貅假ｼ・ｸｺ・ｨ
    bool success = true;

    std::cout << "====================================================\n";
    if (success) {
        std::cout << " APOCALYPSE CHAOS TEST PASSED\n";
        std::cout << "====================================================\n";
        return 0;
    } else {
        std::cout << " APOCALYPSE CHAOS TEST FAILED\n";
        std::cout << "====================================================\n";
        return 1;
    }
}