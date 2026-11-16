#ifndef MOTHER_H_STORAGE_JOURNAL_RECOVERY_ADAPTER_HPP
#define MOTHER_H_STORAGE_JOURNAL_RECOVERY_ADAPTER_HPP
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>
#include <utility>
#include "mother_H/journal/journal_integrity.hpp"
#include "mother_H/policy/journal_feedback_engine.hpp"
#include "mother_H/storage/file_journal_checkpoint_store.hpp"
namespace mother_H::storage {
// ① RecoveryResult の構造
struct RecoveryResult {
    bool success{false};
    std::uint64_t valid_records_count{0};
    std::uint64_t last_valid_lsn{0};
    // 実際にファイルを切り詰めた場合だけ true
    bool truncated{false};
    // 不完全な末尾を検出した場合 true
    bool incomplete_tail_detected{false};
};
class JournalRecoveryAdapter {
public:
    JournalRecoveryAdapter() = default;
    ~JournalRecoveryAdapter() = default;
    // CP-02-A 正式規格 v1.0 に準拠した Fail-Closed リカバリ処理
    RecoveryResult recover_and_truncate(
        const std::string& journal_path,
        mother_h::journal::IJournalCheckpointStore& checkpoint_store,
        const mother_h::journal::ISecureKeyProvider& keys
    ) {
        RecoveryResult res{};
        std::error_code ec;
        if (!std::filesystem::exists(journal_path, ec) || ec) {
            return res; // Fail-Closed
        }
        std::ifstream ifs(journal_path, std::ios::binary);
        if (!ifs.is_open()) return res;
        // --- Step 1: ファイルヘッダー検証 (8 Bytes: "MHDR" + Major(2B) + Minor(2B)) ---
        uint8_t header[8];
        ifs.read(reinterpret_cast<char*>(header), sizeof(header));
        if (ifs.gcount() != sizeof(header)) return res;
        if (header[0] != 'M' || header[1] != 'H' || header[2] != 'D' || header[3] != 'R') {
            return res; // ヘッダーマジック不一致
        }
        uint16_t major_ver = (static_cast<uint16_t>(header[4]) << 8) | header[5];
        uint16_t minor_ver = (static_cast<uint16_t>(header[6]) << 8) | header[7];
        if (major_ver != 1 || minor_ver != 0) {
            return res; // バージョン厳格不適合 -> Fail-Closed
        }
        std::uint64_t expected_lsn = 1;
        mother_h::journal::JournalHash prev_hash = mother_h::journal::JournalIntegrity::genesis_hash();
        std::size_t valid_count = 0;
        bool incomplete_tail_detected = false;
        auto read_u32 = [](const uint8_t* p) -> uint32_t {
            return (static_cast<uint32_t>(p[0]) << 24) |
                   (static_cast<uint32_t>(p[1]) << 16) |
                   (static_cast<uint32_t>(p[2]) << 8)  |
                   static_cast<uint32_t>(p[3]);
        };
        auto read_u64 = [](const uint8_t* p) -> uint64_t {
            uint64_t val = 0;
            for (int i = 0; i < 8; ++i) {
                val = (val << 8) | p[i];
            }
            return val;
        };
        std::vector<mother_h::journal::JournalHash> record_hashes;
        // --- Step 2: フレーム読み込みと非破壊解釈 ---
        while (true) {
            // フレーム長の先頭1バイトを読む
            uint8_t len_buf[4]{};
            ifs.read(reinterpret_cast<char*>(&len_buf[0]), 1);
            if (ifs.gcount() == 0) {
                if (ifs.eof() && !ifs.bad()) {
                    break; // 正常なファイル終端
                }
                return res; // 読み込み障害
            }
            if (ifs.bad()) {
                return res;
            }
            // 残り3バイトを読む
            ifs.read(reinterpret_cast<char*>(&len_buf[1]), 3);
            if (ifs.gcount() != 3) {
                if (ifs.eof() && !ifs.bad()) {
                    incomplete_tail_detected = true;
                    break;
                }
                return res;
            }
            constexpr std::size_t kMaxRecordSize = 1024 * 1024;
            constexpr std::size_t kMinFrameSize = 100;
            const uint32_t frame_len = read_u32(len_buf);
            // 不正なフレーム長は不完全な末尾として扱わない
            if (frame_len < kMinFrameSize ||
                frame_len > kMaxRecordSize) {
                return res;
            }
            std::vector<uint8_t> payload_buf(frame_len);
            ifs.read(
                reinterpret_cast<char*>(payload_buf.data()),
                static_cast<std::streamsize>(frame_len)
            );
            if (ifs.gcount() != static_cast<std::streamsize>(frame_len)) {
                if (ifs.eof() && !ifs.bad()) {
                    incomplete_tail_detected = true;
                    break;
                }
                return res;
            }
            if (ifs.bad()) {
                return res;
            }
            // オーバーフロー対策済みセーフデシリアライズ
            std::size_t offset = 0;
            auto can_read = [&](std::size_t len) -> bool {
                return offset <= payload_buf.size() && len <= (payload_buf.size() - offset);
            };
            if (!can_read(8)) return res;
            mother_h::journal::JournalRecord rec{};
            rec.lsn = read_u64(&payload_buf[offset]); offset += 8;
            if (!can_read(4)) return res;
            rec.key.version = read_u32(&payload_buf[offset]); offset += 4;
            if (!can_read(8)) return res;
            uint64_t key_id_len = read_u64(&payload_buf[offset]); offset += 8;
            if (!can_read(key_id_len)) return res;
            rec.key.key_id = std::string(reinterpret_cast<const char*>(&payload_buf[offset]), key_id_len);
            offset += key_id_len;
            if (!can_read(8)) return res;
            uint64_t ts_len = read_u64(&payload_buf[offset]); offset += 8;
            if (!can_read(ts_len)) return res;
            rec.timestamp_utc = std::string(reinterpret_cast<const char*>(&payload_buf[offset]), ts_len);
            offset += ts_len;
            if (!can_read(32)) return res;
            std::memcpy(rec.previous_record_hash.data(), &payload_buf[offset], 32);
            offset += 32;
            if (!can_read(8)) return res;
            uint64_t payload_len = read_u64(&payload_buf[offset]); offset += 8;
            if (!can_read(payload_len)) return res;
            rec.payload = std::string(reinterpret_cast<const char*>(&payload_buf[offset]), payload_len);
            offset += payload_len;
            if (!can_read(32)) return res;
            std::memcpy(rec.hmac_sha256.data(), &payload_buf[offset], 32);
            offset += 32;
            // 余剰バイトの有無を検査
            if (offset != payload_buf.size()) {
                return res; // 余剰バイト検知 -> Fail-Closed
            }
            // Integrity 検証
            auto verify_res = mother_h::journal::JournalIntegrity::verify(
                rec, expected_lsn, prev_hash, keys
            );
            if (!verify_res) {
                // 完全なレコードの破損 -> 切り詰めず Fail-Closed 終了
                return res;
            }
            prev_hash = verify_res.record_hash;
            record_hashes.push_back(prev_hash);
            expected_lsn++;
            valid_count++;
        }
        ifs.close();
        // --- Step 3: チェックポイントストアの厳格照合 ---
        mother_h::journal::JournalCheckpoint cp{};
        const auto cp_status = checkpoint_store.load(cp);
        if (cp_status != mother_h::journal::CheckpointStatus::Ok &&
            cp_status != mother_h::journal::CheckpointStatus::NotFound) {
            return res; // BackendUnavailable 等のエラーは Fail-Closed
        }
        if (cp_status == mother_h::journal::CheckpointStatus::Ok) {
            if (cp.lsn > valid_count) {
                return res; // Checkpoint が未来を示している -> ロールバック検知
            }
            if (cp.lsn > 0) {
                const auto& target_hash = record_hashes[cp.lsn - 1];
                if (!mother_h::journal::JournalIntegrity::hash_equal(cp.record_hash, target_hash)) {
                    return res; // チェックポイントハッシュ不一致 -> Fail-Closed
                }
            }
        }
        // --- Step 4: 判定の確定 ---
        // この段階ではファイルを一切変更しない。
        res.success = true;
        res.valid_records_count = valid_count;
        res.last_valid_lsn =
            (valid_count > 0) ? valid_count : 0;
        res.incomplete_tail_detected = incomplete_tail_detected;
        // 物理切り詰めは実行していない
        res.truncated = false;
        return res;
    }
    template <typename FeedbackEngineType>
    bool rebuild_feedback_engine_state(
        const std::vector<mother_h::journal::JournalRecord>& records,
        const mother_h::journal::ISecureKeyProvider& keys,
        FeedbackEngineType& engine
    ) {
        const std::uint64_t base_epoch = engine.epoch();
        mother_h::resource::ResourceGuard shadow_guard(engine.limits());
        FeedbackEngineType shadow_engine(shadow_guard);

        for (const auto& rec : records) {
            const auto result = shadow_engine.ingest_record(rec, keys);

            if (result.status != mother_h::policy::FeedbackStatus::Ingested) {
                return false;
            }
        }

        return engine.commit_state_from(std::move(shadow_engine), base_epoch);
    }
};
} // namespace mother_H::storage
#endif // MOTHER_H_STORAGE_JOURNAL_RECOVERY_ADAPTER_HPP