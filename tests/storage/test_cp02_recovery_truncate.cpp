#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <random>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include <chrono>
#include "mother_H/storage/journal_recovery_adapter.hpp"
#include "mother_H/journal/journal_integrity.hpp"
#include "mother_H/journal/secure_key_provider.hpp"
namespace fs = std::filesystem;
using namespace mother_H::storage;
using namespace mother_h::journal;
// ISecureKeyProvider 完全適合モック
class TestKeyProvider final : public ISecureKeyProvider {
public:
    KeyStatus current_signing_key(KeyMaterial& out) const noexcept override {
        try {
            KeyReference ref{"test_key_v1", 1};
            std::vector<uint8_t> secret(32, 0x5A);
            out = KeyMaterial(ref, std::move(secret));
            return KeyStatus::Ok;
        } catch (...) {
            return KeyStatus::NotFound;
        }
    }
    KeyStatus verification_key(const KeyReference& reference, KeyMaterial& out) const noexcept override {
        if (reference.key_id != "test_key_v1" || reference.version != 1) {
            return KeyStatus::NotFound;
        }
        try {
            std::vector<uint8_t> secret(32, 0x5A);
            out = KeyMaterial(reference, std::move(secret));
            return KeyStatus::Ok;
        } catch (...) {
            return KeyStatus::NotFound;
        }
    }
    KeyStatus rotate_key(const std::string& new_key_id, KeyReference& out) noexcept override {
        (void)new_key_id; (void)out;
        return KeyStatus::NotFound;
    }
    KeyStatus revoke_key(const KeyReference& reference) noexcept override {
        (void)reference;
        return KeyStatus::NotFound;
    }
};
static void write_u32_be(std::vector<uint8_t>& out, uint32_t val) {
    out.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(val & 0xFF));
}
static void write_u64_be(std::vector<uint8_t>& out, uint64_t val) {
    for (int i = 56; i >= 0; i -= 8) {
        out.push_back(static_cast<uint8_t>((val >> i) & 0xFF));
    }
}
static void write_string(std::vector<uint8_t>& out, const std::string& str) {
    write_u64_be(out, str.size());
    out.insert(out.end(), str.begin(), str.end());
}
static std::vector<uint8_t> serialize_record_frame(const JournalRecord& rec) {
    std::vector<uint8_t> payload_bytes;
    write_u64_be(payload_bytes, rec.lsn);
    write_u32_be(payload_bytes, rec.key.version);
    write_string(payload_bytes, rec.key.key_id);
    write_string(payload_bytes, rec.timestamp_utc);
    payload_bytes.insert(payload_bytes.end(), rec.previous_record_hash.begin(), rec.previous_record_hash.end());
    write_string(payload_bytes, rec.payload);
    payload_bytes.insert(payload_bytes.end(), rec.hmac_sha256.begin(), rec.hmac_sha256.end());
    std::vector<uint8_t> frame;
    write_u32_be(frame, static_cast<uint32_t>(payload_bytes.size()));
    frame.insert(frame.end(), payload_bytes.begin(), payload_bytes.end());
    return frame;
}
// 例外安全な全バイト読み取り関数
static std::vector<uint8_t> read_file_bytes(const fs::path& p) {
    std::ifstream ifs(p, std::ios::binary);
    if (!ifs.is_open()) {
        throw std::runtime_error("Failed to open file for byte comparison");
    }
    std::vector<uint8_t> bytes(
        (std::istreambuf_iterator<char>(ifs)),
        std::istreambuf_iterator<char>()
    );
    if (ifs.bad()) {
        throw std::runtime_error("Failed while reading file for byte comparison");
    }
    return bytes;
}
int main() {
    std::cout << "===== Starting CP-02: Strict Recovery Adapter Tests (B01 & B02) =====\n";
    auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    std::mt19937_64 rng(static_cast<uint64_t>(now));
    fs::path test_dir = fs::temp_directory_path() / ("mother_h_cp02_tests_" + std::to_string(now) + "_" + std::to_string(rng()));
    std::error_code ec;
    if (!fs::create_directory(test_dir, ec) || ec) {
        std::cerr << "[FAIL] Failed to create sandbox directory.\n";
        return 1;
    }
    TestKeyProvider keys;
    JournalRecoveryAdapter adapter;
    bool all_passed = true;
    // --- CP-02-B01: 正常 3 レコード復旧検証 ---
    {
        fs::path journal_path = test_dir / "b01_valid_3records.log";
        fs::path cp_path = test_dir / "b01_cp.bin";
        std::vector<uint8_t> journal_bytes = {'M', 'H', 'D', 'R', 0x00, 0x01, 0x00, 0x00};
        JournalHash prev_hash = JournalIntegrity::genesis_hash();
        JournalCheckpoint cp_expected{};
        for (uint64_t lsn = 1; lsn <= 3; ++lsn) {
            JournalRecord rec{};
            rec.lsn = lsn;
            rec.timestamp_utc = "2026-11-09T12:00:00.000000000Z";
            rec.payload = "event_payload_" + std::to_string(lsn);
            auto seal_res = JournalIntegrity::seal(rec, lsn, prev_hash, keys);
            if (!seal_res) {
                std::cerr << "[FAIL] B01 seal failed at LSN=" << lsn << "\n";
                return 1;
            }
            std::vector<uint8_t> frame = serialize_record_frame(rec);
            journal_bytes.insert(journal_bytes.end(), frame.begin(), frame.end());
            prev_hash = seal_res.record_hash;
            if (lsn == 3) {
                cp_expected.lsn = 3;
                cp_expected.record_hash = seal_res.record_hash;
                cp_expected.revision = 1;
            }
        }
        // I/O チェック付きファイル書き込み
        {
            std::ofstream ofs(journal_path, std::ios::binary);
            if (!ofs.is_open()) {
                std::cerr << "[FAIL] Failed to open journal file for writing (B01).\n";
                return 1;
            }
            ofs.write(
                reinterpret_cast<const char*>(journal_bytes.data()),
                static_cast<std::streamsize>(journal_bytes.size())
            );
            ofs.flush();
            if (!ofs) {
                std::cerr << "[FAIL] Failed to write journal file completely (B01).\n";
                return 1;
            }
        }
        FileJournalCheckpointStore cp_store(cp_path);
        auto cp_adv_res = cp_store.compare_and_advance(JournalCheckpoint{}, cp_expected);
        if (cp_adv_res != CheckpointStatus::Ok) {
            std::cerr << "[FAIL] B01 Checkpoint creation failed!\n";
            return 1;
        }
        RecoveryResult res = adapter.recover_and_truncate(journal_path.string(), cp_store, keys);
        if (!res.success || res.valid_records_count != 3 || res.last_valid_lsn != 3 || res.truncated || res.incomplete_tail_detected) {
            std::cerr << "[FAIL] CP-02-B01 failed.\n";
            all_passed = false;
        } else {
            std::cout << "[PASS] CP-02-B01: Valid 3 records verified (last_valid_lsn=3).\n";
        }
    }
    // --- CP-02-B02: 正常2件 + 不完全末尾 (バイト単位非破壊 & last_valid_lsn 検証) ---
    {
        fs::path journal_path = test_dir / "b02_incomplete_tail.log";
        fs::path cp_path = test_dir / "b02_cp.bin";
        std::vector<uint8_t> journal_bytes = {'M', 'H', 'D', 'R', 0x00, 0x01, 0x00, 0x00};
        JournalHash prev_hash = JournalIntegrity::genesis_hash();
        JournalCheckpoint cp_expected{};
        for (uint64_t lsn = 1; lsn <= 2; ++lsn) {
            JournalRecord rec{};
            rec.lsn = lsn;
            rec.timestamp_utc = "2026-11-09T12:00:00.000000000Z";
            rec.payload = "event_payload_" + std::to_string(lsn);
            auto seal_res = JournalIntegrity::seal(rec, lsn, prev_hash, keys);
            if (!seal_res) {
                std::cerr << "[FAIL] B02 seal failed at LSN=" << lsn << "\n";
                return 1;
            }
            std::vector<uint8_t> frame = serialize_record_frame(rec);
            journal_bytes.insert(journal_bytes.end(), frame.begin(), frame.end());
            prev_hash = seal_res.record_hash;
            if (lsn == 2) {
                cp_expected.lsn = 2;
                cp_expected.record_hash = seal_res.record_hash;
                cp_expected.revision = 1;
            }
        }
        // 末尾に不完全データ (2 バイト) を付与
        journal_bytes.push_back(0x00);
        journal_bytes.push_back(0x00);
        // I/O チェック付きファイル書き込み
        {
            std::ofstream ofs(journal_path, std::ios::binary);
            if (!ofs.is_open()) {
                std::cerr << "[FAIL] Failed to open journal file for writing (B02).\n";
                return 1;
            }
            ofs.write(
                reinterpret_cast<const char*>(journal_bytes.data()),
                static_cast<std::streamsize>(journal_bytes.size())
            );
            ofs.flush();
            if (!ofs) {
                std::cerr << "[FAIL] Failed to write journal file completely (B02).\n";
                return 1;
            }
        }
        FileJournalCheckpointStore cp_store(cp_path);
        auto cp_adv_res = cp_store.compare_and_advance(JournalCheckpoint{}, cp_expected);
        if (cp_adv_res != CheckpointStatus::Ok) {
            std::cerr << "[FAIL] B02 Checkpoint creation failed!\n";
            return 1;
        }
        // 実行前の全バイト列を取得 (例外安全)
        const auto before_bytes = read_file_bytes(journal_path);
        RecoveryResult res = adapter.recover_and_truncate(journal_path.string(), cp_store, keys);
        // 実行後の全バイト列を取得 (例外安全)
        const auto after_bytes = read_file_bytes(journal_path);
        if (!res.success) {
            std::cerr << "[FAIL] CP-02-B02: Expected success=true, got false.\n";
            all_passed = false;
        } else if (res.valid_records_count != 2) {
            std::cerr << "[FAIL] CP-02-B02: Expected valid_records_count=2, got " << res.valid_records_count << "\n";
            all_passed = false;
        } else if (res.last_valid_lsn != 2) {
            std::cerr << "[FAIL] CP-02-B02: Expected last_valid_lsn=2, got " << res.last_valid_lsn << "\n";
            all_passed = false;
        } else if (!res.incomplete_tail_detected) {
            std::cerr << "[FAIL] CP-02-B02: Expected incomplete_tail_detected=true, got false.\n";
            all_passed = false;
        } else if (res.truncated) {
            std::cerr << "[FAIL] CP-02-B02: Expected truncated=false, got true.\n";
            all_passed = false;
        } else if (before_bytes != after_bytes) {
            std::cerr << "[FAIL] CP-02-B02: File content mutated! Byte-level comparison failed.\n";
            all_passed = false;
        } else {
            std::cout << "[PASS] CP-02-B02: Incomplete tail verified (last_valid_lsn=2) with EXACT byte-level file preservation.\n";
        }
    }
    // ---------- CP-02-B03: HMAC mismatch ----------
    {
        fs::path journal_path = test_dir / "b03_hmac_mismatch.log";
        fs::path cp_path = test_dir / "b03_cp.bin";
        std::vector<uint8_t> journal_bytes = {
            'M', 'H', 'D', 'R', 0x00, 0x01, 0x00, 0x00
        };
        JournalRecord rec{};
        rec.lsn = 1;
        rec.timestamp_utc = "2026-11-09T12:00:00.000000000Z";
        rec.payload = "original_payload";
        const auto seal_res = JournalIntegrity::seal(
            rec, 1, JournalIntegrity::genesis_hash(), keys
        );
        if (!seal_res) {
            std::cerr << "[FAIL] B03 seal failed.\n";
            all_passed = false;
        } else {
            // Seal後にpayloadだけを変更し、HMACを不一致にする。
            rec.payload = "tampered_payload";
            const auto frame = serialize_record_frame(rec);
            journal_bytes.insert(
                journal_bytes.end(), frame.begin(), frame.end()
            );
            std::ofstream ofs(journal_path, std::ios::binary);
            if (!ofs.is_open()) {
                std::cerr << "[FAIL] B03 journal open failed.\n";
                all_passed = false;
            } else {
                ofs.write(
                    reinterpret_cast<const char*>(journal_bytes.data()),
                    static_cast<std::streamsize>(journal_bytes.size())
                );
                ofs.flush();
                if (!ofs) {
                    std::cerr << "[FAIL] B03 journal write failed.\n";
                    all_passed = false;
                }
                ofs.close();
                if (!ofs) {
                    std::cerr << "[FAIL] B03 journal close failed.\n";
                    all_passed = false;
                }
                if (all_passed) {
                    FileJournalCheckpointStore cp_store(cp_path);
                    const auto before_bytes = read_file_bytes(journal_path);
                    const auto res = adapter.recover_and_truncate(
                        journal_path.string(), cp_store, keys
                    );
                    const auto after_bytes = read_file_bytes(journal_path);
                    if (res.success ||
                        res.truncated ||
                        res.incomplete_tail_detected ||
                        before_bytes != after_bytes) {
                        std::cerr << "[FAIL] CP-02-B03: HMAC mismatch was not safely rejected.\n";
                        all_passed = false;
                    } else {
                        std::cout << "[PASS] CP-02-B03: HMAC mismatch rejected; file unchanged.\n";
                    }
                }
            }
        }
    }
    // ---------- CP-02-B04: Chain mismatch with valid HMAC ----------
    {
        fs::path journal_path = test_dir / "b04_chain_mismatch.log";
        fs::path cp_path = test_dir / "b04_cp.bin";
        std::vector<uint8_t> journal_bytes = {
            'M', 'H', 'D', 'R', 0x00, 0x01, 0x00, 0x00
        };
        JournalHash previous_hash = JournalIntegrity::genesis_hash();
        JournalRecord first{};
        first.lsn = 1;
        first.timestamp_utc = "2026-11-09T12:00:00.000000000Z";
        first.payload = "first_valid_record";
        const auto first_seal = JournalIntegrity::seal(
            first, 1, previous_hash, keys
        );
        if (!first_seal) {
            std::cerr << "[FAIL] B04 first seal failed.\n";
            all_passed = false;
        } else {
            auto first_frame = serialize_record_frame(first);
            journal_bytes.insert(
                journal_bytes.end(), first_frame.begin(), first_frame.end()
            );
            JournalRecord second{};
            second.lsn = 2;
            second.timestamp_utc = "2026-11-09T12:00:01.000000000Z";
            second.payload = "second_wrong_chain_record";
            // HMACは正しく生成するが、前レコードハッシュを意図的に誤らせる。
            JournalHash wrong_previous_hash{};
            wrong_previous_hash.fill(0xEE);
            const auto second_seal = JournalIntegrity::seal(
                second, 2, wrong_previous_hash, keys
            );
            if (!second_seal) {
                std::cerr << "[FAIL] B04 second seal failed.\n";
                all_passed = false;
            } else {
                auto second_frame = serialize_record_frame(second);
                journal_bytes.insert(
                    journal_bytes.end(),
                    second_frame.begin(),
                    second_frame.end()
                );
                std::ofstream ofs(journal_path, std::ios::binary);
                if (!ofs.is_open()) {
                    std::cerr << "[FAIL] B04 journal open failed.\n";
                    all_passed = false;
                } else {
                    ofs.write(
                        reinterpret_cast<const char*>(journal_bytes.data()),
                        static_cast<std::streamsize>(journal_bytes.size())
                    );
                    ofs.flush();
                    if (!ofs) {
                        std::cerr << "[FAIL] B04 journal write failed.\n";
                        all_passed = false;
                    }
                    ofs.close();
                    if (!ofs) {
                        std::cerr << "[FAIL] B04 journal close failed.\n";
                        all_passed = false;
                    }
                    if (all_passed) {
                        FileJournalCheckpointStore cp_store(cp_path);
                        const auto before_bytes = read_file_bytes(journal_path);
                        const auto res = adapter.recover_and_truncate(
                            journal_path.string(), cp_store, keys
                        );
                        const auto after_bytes = read_file_bytes(journal_path);
                        if (res.success ||
                            res.truncated ||
                            res.incomplete_tail_detected ||
                            before_bytes != after_bytes) {
                            std::cerr << "[FAIL] CP-02-B04: Chain mismatch was not safely rejected.\n";
                            all_passed = false;
                        } else {
                            std::cout << "[PASS] CP-02-B04: Chain mismatch rejected; file unchanged.\n";
                        }
                    }
                }
            }
        }
    }
    // ---------- CP-02-B05-A: Checkpoint ahead of journal ----------
    {
        fs::path journal_path = test_dir / "b05a_checkpoint_ahead.log";
        fs::path cp_path = test_dir / "b05a_cp.bin";
        std::vector<uint8_t> journal_bytes = {
            'M', 'H', 'D', 'R', 0x00, 0x01, 0x00, 0x00
        };
        JournalHash previous_hash = JournalIntegrity::genesis_hash();
        JournalCheckpoint checkpoint{};
        for (uint64_t lsn = 1; lsn <= 2; ++lsn) {
            JournalRecord rec{};
            rec.lsn = lsn;
            rec.timestamp_utc = "2026-11-09T12:00:00.000000000Z";
            rec.payload = "b05a_record_" + std::to_string(lsn);
            const auto seal_res = JournalIntegrity::seal(
                rec, lsn, previous_hash, keys
            );
            if (!seal_res) {
                std::cerr << "[FAIL] B05-A seal failed.\n";
                all_passed = false;
                break;
            }
            const auto frame = serialize_record_frame(rec);
            journal_bytes.insert(
                journal_bytes.end(), frame.begin(), frame.end()
            );
            previous_hash = seal_res.record_hash;
        }
        if (all_passed) {
            checkpoint.lsn = 3;
            checkpoint.record_hash.fill(0xAA);
            checkpoint.revision = 1;
            std::ofstream ofs(journal_path, std::ios::binary);
            if (!ofs.is_open()) {
                std::cerr << "[FAIL] B05-A journal open failed.\n";
                all_passed = false;
            } else {
                ofs.write(
                    reinterpret_cast<const char*>(journal_bytes.data()),
                    static_cast<std::streamsize>(journal_bytes.size())
                );
                ofs.flush();
                if (!ofs) {
                    std::cerr << "[FAIL] B05-A journal write failed.\n";
                    all_passed = false;
                }
                ofs.close();
                if (!ofs) {
                    std::cerr << "[FAIL] B05-A journal close failed.\n";
                    all_passed = false;
                }
            }
        }
        if (all_passed) {
            FileJournalCheckpointStore cp_store(cp_path);
            const auto save_status = cp_store.compare_and_advance(
                JournalCheckpoint{}, checkpoint
            );
            if (save_status != CheckpointStatus::Ok) {
                std::cerr << "[FAIL] B05-A checkpoint creation failed.\n";
                all_passed = false;
            } else {
                const auto before_bytes = read_file_bytes(journal_path);
                const auto res = adapter.recover_and_truncate(
                    journal_path.string(), cp_store, keys
                );
                const auto after_bytes = read_file_bytes(journal_path);
                if (res.success ||
                    res.truncated ||
                    res.incomplete_tail_detected ||
                    before_bytes != after_bytes) {
                    std::cerr << "[FAIL] CP-02-B05-A: Ahead checkpoint was not safely rejected.\n";
                    all_passed = false;
                } else {
                    std::cout << "[PASS] CP-02-B05-A: Checkpoint ahead rejected; file unchanged.\n";
                }
            }
        }
    }
    // ---------- CP-02-B05-B: Checkpoint hash mismatch ----------
    {
        fs::path journal_path = test_dir / "b05b_checkpoint_hash_mismatch.log";
        fs::path cp_path = test_dir / "b05b_cp.bin";
        std::vector<uint8_t> journal_bytes = {
            'M', 'H', 'D', 'R', 0x00, 0x01, 0x00, 0x00
        };
        JournalHash previous_hash = JournalIntegrity::genesis_hash();
        JournalCheckpoint checkpoint{};
        JournalHash actual_last_hash{};
        for (uint64_t lsn = 1; lsn <= 2; ++lsn) {
            JournalRecord rec{};
            rec.lsn = lsn;
            rec.timestamp_utc = "2026-11-09T12:00:00.000000000Z";
            rec.payload = "b05b_record_" + std::to_string(lsn);
            const auto seal_res = JournalIntegrity::seal(
                rec, lsn, previous_hash, keys
            );
            if (!seal_res) {
                std::cerr << "[FAIL] B05-B seal failed.\n";
                all_passed = false;
                break;
            }
            const auto frame = serialize_record_frame(rec);
            journal_bytes.insert(
                journal_bytes.end(), frame.begin(), frame.end()
            );
            previous_hash = seal_res.record_hash;
            if (lsn == 2) {
                actual_last_hash = seal_res.record_hash;
            }
        }
        if (all_passed) {
            checkpoint.lsn = 2;
            checkpoint.record_hash.fill(0xBB);
            checkpoint.revision = 1;
            if (JournalIntegrity::hash_equal(
                    checkpoint.record_hash, actual_last_hash)) {
                std::cerr << "[FAIL] B05-B test setup did not create a distinct hash.\n";
                all_passed = false;
            }
        }
        if (all_passed) {
            std::ofstream ofs(journal_path, std::ios::binary);
            if (!ofs.is_open()) {
                std::cerr << "[FAIL] B05-B journal open failed.\n";
                all_passed = false;
            } else {
                ofs.write(
                    reinterpret_cast<const char*>(journal_bytes.data()),
                    static_cast<std::streamsize>(journal_bytes.size())
                );
                ofs.flush();
                if (!ofs) {
                    std::cerr << "[FAIL] B05-B journal write failed.\n";
                    all_passed = false;
                }
                ofs.close();
                if (!ofs) {
                    std::cerr << "[FAIL] B05-B journal close failed.\n";
                    all_passed = false;
                }
            }
        }
        if (all_passed) {
            FileJournalCheckpointStore cp_store(cp_path);
            const auto save_status = cp_store.compare_and_advance(
                JournalCheckpoint{}, checkpoint
            );
            if (save_status != CheckpointStatus::Ok) {
                std::cerr << "[FAIL] B05-B checkpoint creation failed.\n";
                all_passed = false;
            } else {
                const auto before_bytes = read_file_bytes(journal_path);
                const auto res = adapter.recover_and_truncate(
                    journal_path.string(), cp_store, keys
                );
                const auto after_bytes = read_file_bytes(journal_path);
                if (res.success ||
                    res.truncated ||
                    res.incomplete_tail_detected ||
                    before_bytes != after_bytes) {
                    std::cerr << "[FAIL] CP-02-B05-B: Checkpoint hash mismatch was not safely rejected.\n";
                    all_passed = false;
                } else {
                    std::cout << "[PASS] CP-02-B05-B: Checkpoint hash mismatch rejected; file unchanged.\n";
                }
            }
        }
    }    if (all_passed) {
        std::cout << "[RESULT] ALL CP-02 TESTS PASSED STRICTLY\n";
        return 0;
    } else {
        std::cout << "[RESULT] CP-02 TESTS FAILED\n";
        return 1;
    }
}