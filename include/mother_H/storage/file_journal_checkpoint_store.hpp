#ifndef MOTHER_H_STORAGE_FILE_JOURNAL_CHECKPOINT_STORE_HPP
#define MOTHER_H_STORAGE_FILE_JOURNAL_CHECKPOINT_STORE_HPP

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <utility>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

#include "mother_H/journal/journal_integrity.hpp"

namespace mother_H::storage {

class FileJournalCheckpointStore : public mother_h::journal::IJournalCheckpointStore {
public:
    explicit FileJournalCheckpointStore(std::filesystem::path file_path)
        : file_path_(std::move(file_path)) {}
    ~FileJournalCheckpointStore() override = default;

    mother_h::journal::CheckpointStatus load(mother_h::journal::JournalCheckpoint& out) const noexcept override {
        std::error_code ec;
        const bool exists = std::filesystem::exists(file_path_, ec);
        if (ec) {
            return mother_h::journal::CheckpointStatus::BackendUnavailable;
        }
        if (!exists) {
            return mother_h::journal::CheckpointStatus::NotFound;
        }
        std::ifstream ifs(file_path_, std::ios::binary | std::ios::ate);
        if (!ifs.is_open()) {
            return mother_h::journal::CheckpointStatus::BackendUnavailable;
        }
        const auto file_size = ifs.tellg();
        if (file_size == std::streampos(-1) ||
            file_size != static_cast<std::streampos>(sizeof(mother_h::journal::JournalCheckpoint))) {
            return mother_h::journal::CheckpointStatus::BackendUnavailable;
        }
        ifs.seekg(0, std::ios::beg);
        if (!ifs.good()) {
            return mother_h::journal::CheckpointStatus::BackendUnavailable;
        }
        mother_h::journal::JournalCheckpoint candidate{};
        ifs.read(
            reinterpret_cast<char*>(&candidate),
            static_cast<std::streamsize>(sizeof(candidate))
        );
        if (ifs.gcount() != static_cast<std::streamsize>(sizeof(candidate)) || !ifs.good()) {
            return mother_h::journal::CheckpointStatus::BackendUnavailable;
        }
        out = candidate;
        return mother_h::journal::CheckpointStatus::Ok;
    }

    mother_h::journal::CheckpointStatus compare_and_advance(
        const mother_h::journal::JournalCheckpoint& expected,
        const mother_h::journal::JournalCheckpoint& next) noexcept override {
        // 1. 現在のチェックポイント状態を照合 (CAS)
        mother_h::journal::JournalCheckpoint current{};
        const auto load_status = load(current);

        if (load_status == mother_h::journal::CheckpointStatus::BackendUnavailable) {
            return mother_h::journal::CheckpointStatus::BackendUnavailable;
        }

        if (load_status == mother_h::journal::CheckpointStatus::NotFound) {
            // 初期作成時: expected は初期値 (LSN 0, revision 0, genesis_hash) でなければならない
            if (expected.lsn != 0 || expected.revision != 0 ||
                !mother_h::journal::JournalIntegrity::hash_equal(
                    expected.record_hash, mother_h::journal::JournalIntegrity::genesis_hash())) {
                return mother_h::journal::CheckpointStatus::Conflict;
            }
            // next の revision は 1 以上でなければならない
            if (next.revision == 0) {
                return mother_h::journal::CheckpointStatus::Conflict;
            }
        } else if (load_status == mother_h::journal::CheckpointStatus::Ok) {
            // 既存チェックポイントとの厳格な同値比較 (CAS)
            if (current.lsn != expected.lsn ||
                current.revision != expected.revision ||
                !mother_h::journal::JournalIntegrity::hash_equal(
                    current.record_hash, expected.record_hash)) {
                return mother_h::journal::CheckpointStatus::Conflict;
            }

            // A revision-only update may not replace the authenticated hash at the same LSN.
            if (next.lsn < current.lsn || next.revision <= current.revision ||
                (next.lsn == current.lsn &&
                 !mother_h::journal::JournalIntegrity::hash_equal(
                     next.record_hash, current.record_hash))) {
                return mother_h::journal::CheckpointStatus::Conflict;
            }
        } else {
            return mother_h::journal::CheckpointStatus::Conflict;
        }

        // 2. 一時ファイルパスのユニーク生成 (衝突防止)
        const auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
        std::filesystem::path tmp_path = file_path_;
        tmp_path += ".tmp." + std::to_string(now) + "_" + std::to_string(temp_counter_++);

        // 3. 一時ファイルへの書き込みとフラッシュ
        {
            std::ofstream ofs(tmp_path, std::ios::binary | std::ios::trunc);
            if (!ofs.is_open()) {
                return mother_h::journal::CheckpointStatus::BackendUnavailable;
            }
            ofs.write(reinterpret_cast<const char*>(&next), sizeof(next));
            ofs.flush();
            if (!ofs.good()) {
                std::error_code ec;
                std::filesystem::remove(tmp_path, ec);
                return mother_h::journal::CheckpointStatus::BackendUnavailable;
            }
        }

        // 4. アトミックな置換
        if (!atomic_replace(tmp_path, file_path_)) {
            std::error_code ec;
            std::filesystem::remove(tmp_path, ec);
            return mother_h::journal::CheckpointStatus::BackendUnavailable;
        }

        return mother_h::journal::CheckpointStatus::Ok;
    }

    mother_h::journal::CheckpointIsolation verify_independence(
        const mother_h::journal::JournalStorageIdentity& journal_storage) const noexcept override {
        (void)journal_storage;
        // Draft v1.1 仕様: 外部信頼アンカー不在時は独立性を自称せず Unverified を返す
        return mother_h::journal::CheckpointIsolation::Unverified;
    }

private:
    static bool atomic_replace(
        const std::filesystem::path& source,
        const std::filesystem::path& destination
    ) noexcept {
#ifdef _WIN32
        return ::MoveFileExW(
            source.c_str(), destination.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
        ) != 0;
#else
        std::error_code ec;
        std::filesystem::rename(source, destination, ec);
        return !ec;
#endif
    }

    std::filesystem::path file_path_;
    inline static std::atomic<std::uint64_t> temp_counter_{0};
};

} // namespace mother_H::storage

#endif // MOTHER_H_STORAGE_FILE_JOURNAL_CHECKPOINT_STORE_HPP
