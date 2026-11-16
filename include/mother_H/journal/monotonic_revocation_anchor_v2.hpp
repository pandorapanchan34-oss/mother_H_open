#pragma once

#include "mother_H/journal/secure_key_provider.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace mother_h::journal::v2 {

enum class AnchorStatus : std::uint8_t {
    Ok,
    Busy,
    RecoveryRequired,
    StaleSnapshot,
    NotProvisioned,
    AlreadyProvisioned,
    InvalidRequest,
    Corrupt,
    AuthenticationFailed,
    RollbackDetected,
    CounterMismatch,
    IoError,
    Indeterminate,
    Poisoned,
    Unsupported
};

enum class CounterAdvanceResult : std::uint8_t {
    Applied,
    NotApplied,
    Indeterminate
};

class IMonotonicCounterV2 {
public:
    virtual ~IMonotonicCounterV2() = default;
    virtual AnchorStatus read(std::uint64_t& value_out) const noexcept = 0;
    // Applied and NotApplied require a fresh read of expected+1 and expected,
    // respectively. Indeterminate is never retried before Recovery reads again.
    // The anchor must exclude all other writers and restrict TPM write access.
    virtual CounterAdvanceResult advance(
        std::uint64_t expected
    ) noexcept = 0;
};

class FileMonotonicCounterV2 final : public IMonotonicCounterV2 {
public:
    explicit FileMonotonicCounterV2(std::filesystem::path path)
        : path_(std::move(path)) {}

    AnchorStatus provision(std::uint64_t initial_value) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        std::error_code error;
        if (std::filesystem::exists(path_, error) || error) {
            return error ? AnchorStatus::IoError
                         : AnchorStatus::AlreadyProvisioned;
        }
        std::array<std::uint8_t, 16> bytes{};
        std::copy(kMagic.begin(), kMagic.end(), bytes.begin());
        write_u64(bytes.data() + 8, initial_value);
        write_u32(bytes.data() + 4, crc32(bytes.data() + 8, 8));
        return write_new_file(path_, bytes) && sync_parent(path_)
            ? AnchorStatus::Ok
            : AnchorStatus::IoError;
    }

    AnchorStatus read(std::uint64_t& value_out) const noexcept override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::array<std::uint8_t, 16> bytes{};
        if (!read_exact(path_, bytes.data(), bytes.size())) {
            return AnchorStatus::IoError;
        }
        if (!std::equal(kMagic.begin(), kMagic.end(), bytes.begin()) ||
            read_u32(bytes.data() + 4) != crc32(bytes.data() + 8, 8)) {
            return AnchorStatus::Corrupt;
        }
        value_out = read_u64(bytes.data() + 8);
        return AnchorStatus::Ok;
    }

    CounterAdvanceResult advance(std::uint64_t expected) noexcept override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::array<std::uint8_t, 16> bytes{};
        if (!read_exact(path_, bytes.data(), bytes.size()) ||
            !std::equal(kMagic.begin(), kMagic.end(), bytes.begin()) ||
            read_u32(bytes.data() + 4) != crc32(bytes.data() + 8, 8)) {
            return CounterAdvanceResult::Indeterminate;
        }
        const std::uint64_t current = read_u64(bytes.data() + 8);
        if (current != expected) {
            return CounterAdvanceResult::Indeterminate;
        }
        if (expected == (std::numeric_limits<std::uint64_t>::max)()) {
            return CounterAdvanceResult::NotApplied;
        }
        write_u64(bytes.data() + 8, expected + 1U);
        write_u32(bytes.data() + 4, crc32(bytes.data() + 8, 8));
        if (atomic_write(path_, bytes)) {
            std::array<std::uint8_t, 16> confirmed{};
            if (read_exact(path_, confirmed.data(), confirmed.size()) &&
                std::equal(kMagic.begin(), kMagic.end(), confirmed.begin()) &&
                read_u32(confirmed.data() + 4) ==
                    crc32(confirmed.data() + 8, 8) &&
                read_u64(confirmed.data() + 8) == expected + 1U) {
                return CounterAdvanceResult::Applied;
            }
        }

        std::array<std::uint8_t, 16> observed{};
        if (!read_exact(path_, observed.data(), observed.size()) ||
            !std::equal(kMagic.begin(), kMagic.end(), observed.begin()) ||
            read_u32(observed.data() + 4) !=
                crc32(observed.data() + 8, 8)) {
            return CounterAdvanceResult::Indeterminate;
        }
        const auto value = read_u64(observed.data() + 8);
        if (value == expected + 1U) return CounterAdvanceResult::Applied;
        if (value == expected) return CounterAdvanceResult::NotApplied;
        return CounterAdvanceResult::Indeterminate;
    }

private:
    static constexpr std::array<std::uint8_t, 4> kMagic{{'M', 'H', 'C', '2'}};

    static void write_u32(std::uint8_t* output, std::uint32_t value) noexcept {
        for (unsigned i = 0; i != 4; ++i) {
            output[i] = static_cast<std::uint8_t>(value >> (24U - 8U * i));
        }
    }

    static std::uint32_t read_u32(const std::uint8_t* input) noexcept {
        std::uint32_t value = 0;
        for (unsigned i = 0; i != 4; ++i) {
            value = (value << 8U) | input[i];
        }
        return value;
    }

    static void write_u64(std::uint8_t* output, std::uint64_t value) noexcept {
        for (unsigned i = 0; i != 8; ++i) {
            output[i] =
                static_cast<std::uint8_t>(value >> (56U - 8U * i));
        }
    }

    static std::uint64_t read_u64(const std::uint8_t* input) noexcept {
        std::uint64_t value = 0;
        for (unsigned i = 0; i != 8; ++i) {
            value = (value << 8U) | input[i];
        }
        return value;
    }

    static std::uint32_t crc32(
        const std::uint8_t* data,
        std::size_t size
    ) noexcept {
        std::uint32_t crc = 0xFFFFFFFFU;
        for (std::size_t i = 0; i < size; ++i) {
            crc ^= data[i];
            for (unsigned bit = 0; bit < 8; ++bit) {
                crc = (crc >> 1U) ^ (0xEDB88320U & (0U - (crc & 1U)));
            }
        }
        return ~crc;
    }

    static bool read_exact(
        const std::filesystem::path& path,
        std::uint8_t* output,
        std::size_t size
    ) noexcept {
        try {
            std::ifstream input(path, std::ios::binary);
            if (!input) return false;
            input.read(reinterpret_cast<char*>(output),
                       static_cast<std::streamsize>(size));
            return input.gcount() == static_cast<std::streamsize>(size) &&
                input.peek() == std::char_traits<char>::eof();
        } catch (...) {
            return false;
        }
    }

    static bool atomic_write(
        const std::filesystem::path& path,
        const std::array<std::uint8_t, 16>& bytes
    ) noexcept {
        try {
            std::array<std::uint8_t, 8> random{};
            if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1)
                return false;
            static constexpr char hex[] = "0123456789abcdef";
            std::string suffix;
            for (const auto value : random) {
                suffix.push_back(hex[value >> 4U]);
                suffix.push_back(hex[value & 0x0FU]);
            }
            auto temporary = path;
            temporary += ".tmp-" + suffix;
            if (!write_new_file(temporary, bytes)) return false;
#ifdef _WIN32
            if (!MoveFileExW(temporary.c_str(), path.c_str(),
                             MOVEFILE_REPLACE_EXISTING |
                                 MOVEFILE_WRITE_THROUGH)) {
                DeleteFileW(temporary.c_str());
                return false;
            }
            return true;
#else
            if (::rename(temporary.c_str(), path.c_str()) != 0) {
                ::unlink(temporary.c_str());
                return false;
            }
            return sync_parent(path);
#endif
        } catch (...) {
            return false;
        }
    }

    static bool write_new_file(
        const std::filesystem::path& path,
        const std::array<std::uint8_t, 16>& bytes
    ) noexcept {
#ifdef _WIN32
        HANDLE file = CreateFileW(
            path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return false;
        DWORD written = 0;
        const bool ok =
            WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()),
                      &written, nullptr) != 0 &&
            written == bytes.size() && FlushFileBuffers(file) != 0;
        const bool closed = CloseHandle(file) != 0;
        return ok && closed;
#else
        const int file = ::open(
            path.c_str(), O_WRONLY | O_CREAT | O_EXCL,
            S_IRUSR | S_IWUSR);
        if (file < 0) return false;
        std::size_t offset = 0;
        bool ok = true;
        while (offset < bytes.size()) {
            const ssize_t count = ::write(
                file, bytes.data() + offset, bytes.size() - offset);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) {
                ok = false;
                break;
            }
            offset += static_cast<std::size_t>(count);
        }
        if (ok && ::fsync(file) != 0) ok = false;
        const bool closed = ::close(file) == 0;
        return ok && closed;
#endif
    }

    static bool sync_parent(const std::filesystem::path& path) noexcept {
#ifdef _WIN32
        (void)path;
        return true;
#else
        auto parent = path.parent_path();
        if (parent.empty()) parent = ".";
        const int directory = ::open(parent.c_str(), O_RDONLY);
        if (directory < 0) return false;
        const bool synced = ::fsync(directory) == 0;
        const bool closed = ::close(directory) == 0;
        return synced && closed;
#endif
    }

    std::filesystem::path path_;
    mutable std::mutex mutex_;
};

struct AnchorSnapshot {
    std::array<std::uint8_t, 16> anchor_id{};
    std::uint64_t counter{0};
    std::uint64_t counter_origin{0};
    std::uint64_t generation{0};
    std::uint64_t generation_origin{0};
    std::array<std::uint8_t, 32> store_digest{};
    std::uint64_t wal_sequence{0};
    std::array<std::uint8_t, 32> wal_head{};

    bool operator==(const AnchorSnapshot& other) const noexcept {
        return anchor_id == other.anchor_id && counter == other.counter &&
            counter_origin == other.counter_origin &&
            generation == other.generation &&
            generation_origin == other.generation_origin &&
            store_digest == other.store_digest &&
            wal_sequence == other.wal_sequence && wal_head == other.wal_head;
    }
};

enum class UpdateKind : std::uint8_t { Issue = 1, Revoke = 2 };
using AnchorToken = std::uint64_t;

class IMonotonicRevocationAnchorV2 {
public:
    virtual ~IMonotonicRevocationAnchorV2() = default;
    virtual AnchorStatus provision(
        std::uint64_t initial_counter,
        std::uint64_t initial_generation,
        const std::array<std::uint8_t, 32>& initial_store_digest
    ) noexcept = 0;
    virtual AnchorStatus recover() noexcept = 0;
    virtual AnchorStatus checkpoint() noexcept = 0;
    virtual AnchorStatus snapshot(AnchorSnapshot& output) noexcept = 0;
    virtual AnchorStatus acquire_usage(
        const DataKeyReference& reference,
        const AnchorSnapshot& expected,
        AnchorToken& token_out
    ) noexcept = 0;
    virtual AnchorStatus release_usage(AnchorToken token) noexcept = 0;
    virtual AnchorStatus prepare_update(
        UpdateKind kind,
        const DataKeyReference& reference,
        const AnchorSnapshot& expected,
        const std::array<std::uint8_t, 32>& new_store_digest,
        AnchorToken& token_out
    ) noexcept = 0;
    virtual AnchorStatus commit_update(AnchorToken token) noexcept = 0;
    virtual AnchorStatus abort_update(AnchorToken token) noexcept = 0;
};

class FileMonotonicRevocationAnchorV2 final
    : public IMonotonicRevocationAnchorV2 {
public:
    static constexpr std::size_t kMacKeyBytes = 32;
    static constexpr std::size_t kMaximumWalBytes = 16U * 1024U * 1024U;
    using Digest = std::array<std::uint8_t, 32>;

    FileMonotonicRevocationAnchorV2(
        std::filesystem::path store_path,
        std::filesystem::path wal_path,
        IMonotonicCounterV2& counter,
        const std::array<std::uint8_t, kMacKeyBytes>& mac_key,
        const std::array<std::uint8_t, 16>& anchor_id
    )
        : store_path_(std::move(store_path)),
          wal_path_(std::move(wal_path)),
          lock_path_(wal_path_.string() + ".lock"),
          counter_(counter),
          mac_key_(mac_key),
          anchor_id_(anchor_id) {}

    FileMonotonicRevocationAnchorV2(
        const FileMonotonicRevocationAnchorV2&
    ) = delete;
    FileMonotonicRevocationAnchorV2& operator=(
        const FileMonotonicRevocationAnchorV2&
    ) = delete;

    ~FileMonotonicRevocationAnchorV2() override {
        OPENSSL_cleanse(mac_key_.data(), mac_key_.size());
    }

    AnchorStatus provision(
        std::uint64_t initial_counter,
        std::uint64_t initial_generation,
        const Digest& initial_store_digest
    ) noexcept override {
        std::lock_guard<std::mutex> guard(mutex_);
        if (poisoned_) return AnchorStatus::Poisoned;
        FileLock lock;
        AnchorStatus status = lock.acquire(lock_path_, true);
        if (status != AnchorStatus::Ok) return status;
        std::error_code error;
        const bool wal_exists = std::filesystem::exists(wal_path_, error);
        if (error) return AnchorStatus::IoError;
        std::uint64_t observed = 0;
        status = counter_.read(observed);
        if (status != AnchorStatus::Ok) return status;
        if (observed != initial_counter) {
            return AnchorStatus::CounterMismatch;
        }
        const Digest current_store = digest_file(store_path_);
        if (current_store != initial_store_digest) {
            return AnchorStatus::StaleSnapshot;
        }
        counter_origin_ = initial_counter;
        generation_origin_ = initial_generation;
        if (wal_exists) {
            ParsedWal existing;
            status = read_wal(existing);
            if (status != AnchorStatus::Ok || !existing.records.empty() ||
                existing.partial_tail ||
                existing.base_sequence != 0 ||
                existing.base_counter != initial_counter ||
                existing.base_generation != initial_generation ||
                existing.base_digest != initial_store_digest) {
                return status == AnchorStatus::Ok
                    ? AnchorStatus::AlreadyProvisioned
                    : status;
            }
        } else if (!write_header(
                       initial_counter, initial_generation, initial_counter,
                       initial_generation, initial_store_digest, 0, Digest{})) {
            return AnchorStatus::IoError;
        }
        Record genesis{};
        genesis.type = RecordType::Genesis;
        genesis.old_counter = initial_counter;
        genesis.new_counter = initial_counter;
        genesis.old_generation = initial_generation;
        genesis.new_generation = initial_generation;
        genesis.old_digest = initial_store_digest;
        genesis.new_digest = initial_store_digest;
        return append_record(genesis, Digest{});
    }

    AnchorStatus checkpoint() noexcept override {
        std::lock_guard<std::mutex> guard(mutex_);
        if (poisoned_) return AnchorStatus::Poisoned;
        FileLock lock;
        AnchorStatus status = lock.acquire(lock_path_, true);
        if (status != AnchorStatus::Ok) return status;
        ParsedWal wal;
        State state{};
        std::uint64_t counter_value = 0;
        status = load_stable(wal, state, counter_value);
        if (status != AnchorStatus::Ok) return status;
        if (wal.records.empty() && wal.base_sequence == 0) {
            return AnchorStatus::NotProvisioned;
        }
        std::vector<std::uint8_t> header;
        if (!encode_header(state.counter, state.generation, state.digest,
                           wal.tail_sequence, wal.head, header)) {
            return AnchorStatus::IoError;
        }
        return atomic_replace_file(wal_path_, header)
            ? AnchorStatus::Ok
            : AnchorStatus::IoError;
    }

    AnchorStatus recover() noexcept override {
        std::lock_guard<std::mutex> guard(mutex_);
        if (poisoned_) return AnchorStatus::Poisoned;
        FileLock lock;
        AnchorStatus status = lock.acquire(lock_path_, true);
        if (status != AnchorStatus::Ok) return status;
        ParsedWal wal;
        status = read_wal(wal);
        if (status != AnchorStatus::Ok) return status;
        if (wal.records.empty() && wal.base_sequence == 0) {
            return AnchorStatus::NotProvisioned;
        }
        State state{};
        status = validate_records(wal, state);
        if (status != AnchorStatus::Ok) return status;
        std::uint64_t counter_value = 0;
        status = counter_.read(counter_value);
        if (status != AnchorStatus::Ok) return status;
        status = validate_mapping(state.counter, state.generation);
        if (status != AnchorStatus::Ok) return status;
        if (wal.partial_tail && !state.pending) {
            return AnchorStatus::Corrupt;
        }
        if (state.pending == false) {
            status = validate_stable(state, counter_value);
            if (status != AnchorStatus::Ok) return status;
            return digest_file(store_path_) == state.digest
                ? AnchorStatus::Ok
                : AnchorStatus::StaleSnapshot;
        }

        const Record prepare = wal.records.back();
        const Digest store_digest = digest_file(store_path_);
        if (wal.partial_tail) {
            if (counter_value != prepare.new_counter ||
                store_digest != prepare.new_digest) {
                return AnchorStatus::Corrupt;
            }
            if (!truncate_wal(wal.valid_bytes)) return AnchorStatus::IoError;
            return append_commit(prepare, wal.head);
        }
        if (counter_value == prepare.old_counter &&
            store_digest == prepare.old_digest) {
            Record aborted = prepare;
            aborted.type = RecordType::Abort;
            aborted.old_counter = prepare.old_counter;
            aborted.new_counter = prepare.old_counter;
            aborted.old_generation = prepare.old_generation;
            aborted.new_generation = prepare.old_generation;
            aborted.new_digest = prepare.old_digest;
            return append_record(aborted, wal.head);
        }
        if (store_digest != prepare.new_digest) return AnchorStatus::Corrupt;
        if (counter_value == prepare.old_counter) {
            const auto result = counter_.advance(prepare.old_counter);
            if (result == CounterAdvanceResult::Indeterminate) {
                return AnchorStatus::Indeterminate;
            }
            if (result == CounterAdvanceResult::NotApplied) {
                std::uint64_t after = 0;
                if (counter_.read(after) != AnchorStatus::Ok ||
                    after != prepare.old_counter) {
                    return AnchorStatus::Indeterminate;
                }
                return AnchorStatus::RecoveryRequired;
            }
            counter_value = prepare.new_counter;
        }
        status = counter_.read(counter_value);
        if (status != AnchorStatus::Ok) return AnchorStatus::Indeterminate;
        if (counter_value != prepare.new_counter) {
            return AnchorStatus::CounterMismatch;
        }
        return append_commit(prepare, wal.head);
    }

    AnchorStatus snapshot(AnchorSnapshot& output) noexcept override {
        std::lock_guard<std::mutex> guard(mutex_);
        if (poisoned_) return AnchorStatus::Poisoned;
        FileLock lock;
        AnchorStatus status = lock.acquire(lock_path_, false);
        if (status != AnchorStatus::Ok) return status;
        State state{};
        ParsedWal wal;
        std::uint64_t counter_value = 0;
        status = load_stable(wal, state, counter_value);
        if (status != AnchorStatus::Ok) return status;
        output = make_snapshot(state, tail_record(wal));
        return AnchorStatus::Ok;
    }

    AnchorStatus acquire_usage(
        const DataKeyReference& reference,
        const AnchorSnapshot& expected,
        AnchorToken& token_out
    ) noexcept override {
        token_out = 0;
        if (!valid_reference(reference)) return AnchorStatus::InvalidRequest;
        std::lock_guard<std::mutex> guard(mutex_);
        if (poisoned_) return AnchorStatus::Poisoned;
        FileLock lock;
        AnchorStatus status = lock.acquire(lock_path_, false);
        if (status != AnchorStatus::Ok) return status;
        State state{};
        ParsedWal wal;
        std::uint64_t counter_value = 0;
        status = load_stable(wal, state, counter_value);
        if (status != AnchorStatus::Ok) return status;
        const AnchorSnapshot current =
            make_snapshot(state, tail_record(wal));
        if (!(current == expected)) return AnchorStatus::StaleSnapshot;
        if (next_token_ == 0) return AnchorStatus::Poisoned;
        token_out = next_token_++;
        held_locks_.emplace(token_out, std::move(lock));
        return AnchorStatus::Ok;
    }

    AnchorStatus release_usage(AnchorToken token) noexcept override {
        return release_token(token, TokenKind::Usage);
    }

    AnchorStatus prepare_update(
        UpdateKind kind,
        const DataKeyReference& reference,
        const AnchorSnapshot& expected,
        const Digest& new_store_digest,
        AnchorToken& token_out
    ) noexcept override {
        token_out = 0;
        if (!valid_reference(reference) ||
            (kind != UpdateKind::Issue && kind != UpdateKind::Revoke)) {
            return AnchorStatus::InvalidRequest;
        }
        std::lock_guard<std::mutex> guard(mutex_);
        if (poisoned_) return AnchorStatus::Poisoned;
        FileLock lock;
        AnchorStatus status = lock.acquire(lock_path_, true);
        if (status != AnchorStatus::Ok) return status;
        State state{};
        ParsedWal wal;
        std::uint64_t counter_value = 0;
        status = load_stable(wal, state, counter_value);
        if (status != AnchorStatus::Ok) return status;
        if (!(make_snapshot(state, tail_record(wal)) == expected)) {
            return AnchorStatus::StaleSnapshot;
        }
        if (poisoned_) return AnchorStatus::Poisoned;
        if (state.generation ==
                (std::numeric_limits<std::uint64_t>::max)() ||
            state.counter == (std::numeric_limits<std::uint64_t>::max)()) {
            return AnchorStatus::CounterMismatch;
        }
        Record prepare{};
        prepare.type = RecordType::Prepare;
        prepare.txid = random_txid();
        if (prepare.txid == std::array<std::uint8_t, 16>{}) {
            return AnchorStatus::IoError;
        }
        prepare.operation = static_cast<std::uint8_t>(kind);
        prepare.reference = reference;
        prepare.old_counter = state.counter;
        prepare.new_counter = state.counter + 1U;
        prepare.old_generation = state.generation;
        prepare.new_generation = state.generation + 1U;
        prepare.old_digest = state.digest;
        prepare.new_digest = new_store_digest;
        status = append_record(prepare, wal.head);
        if (status != AnchorStatus::Ok) return status;
        if (next_token_ == 0) return AnchorStatus::Poisoned;
        token_out = next_token_++;
        pending_tokens_.emplace(token_out, prepare);
        held_locks_.emplace(token_out, std::move(lock));
        return AnchorStatus::Ok;
    }

    AnchorStatus commit_update(AnchorToken token) noexcept override {
        std::lock_guard<std::mutex> guard(mutex_);
        const auto pending = pending_tokens_.find(token);
        if (pending == pending_tokens_.end() ||
            held_locks_.find(token) == held_locks_.end()) {
            return AnchorStatus::InvalidRequest;
        }
        const Record prepare = pending->second;
        if (digest_file(store_path_) != prepare.new_digest) {
            release_failed_token(token);
            return AnchorStatus::StaleSnapshot;
        }
        std::uint64_t counter_value = 0;
        AnchorStatus status = counter_.read(counter_value);
        if (status != AnchorStatus::Ok) return status;
        if (counter_value == prepare.old_counter) {
            const CounterAdvanceResult advanced =
                counter_.advance(prepare.old_counter);
            if (advanced == CounterAdvanceResult::Indeterminate) {
                release_failed_token(token);
                return AnchorStatus::Indeterminate;
            }
            if (advanced == CounterAdvanceResult::NotApplied) {
                std::uint64_t observed = 0;
                if (counter_.read(observed) != AnchorStatus::Ok ||
                    observed == prepare.old_counter) {
                    release_failed_token(token);
                    return AnchorStatus::RecoveryRequired;
                }
                if (observed != prepare.new_counter) {
                    release_failed_token(token);
                    return AnchorStatus::CounterMismatch;
                }
            }
        } else if (counter_value != prepare.new_counter) {
            release_failed_token(token);
            return AnchorStatus::CounterMismatch;
        }
        status = counter_.read(counter_value);
        if (status != AnchorStatus::Ok) {
            release_failed_token(token);
            return AnchorStatus::Indeterminate;
        }
        if (counter_value != prepare.new_counter) {
            release_failed_token(token);
            return AnchorStatus::CounterMismatch;
        }

        ParsedWal wal;
        status = read_wal(wal);
        if (status != AnchorStatus::Ok || wal.records.empty() ||
            wal.records.back().type != RecordType::Prepare ||
            wal.records.back().txid != prepare.txid) {
            release_failed_token(token);
            return status == AnchorStatus::Ok ? AnchorStatus::Corrupt : status;
        }
        status = append_commit(prepare, wal.head);
        if (status != AnchorStatus::Ok) {
            release_failed_token(token);
            return status;
        }
        pending_tokens_.erase(pending);
        return release_token_locked(token, TokenKind::Update);
    }

    AnchorStatus abort_update(AnchorToken token) noexcept override {
        std::lock_guard<std::mutex> guard(mutex_);
        const auto pending = pending_tokens_.find(token);
        if (pending == pending_tokens_.end() ||
            held_locks_.find(token) == held_locks_.end()) {
            return AnchorStatus::InvalidRequest;
        }
        const Record prepare = pending->second;
        std::uint64_t counter_value = 0;
        AnchorStatus status = counter_.read(counter_value);
        if (status != AnchorStatus::Ok) return status;
        if (counter_value != prepare.old_counter ||
            digest_file(store_path_) != prepare.old_digest) {
            release_failed_token(token);
            return AnchorStatus::RecoveryRequired;
        }
        ParsedWal wal;
        status = read_wal(wal);
        if (status != AnchorStatus::Ok || wal.records.empty() ||
            wal.records.back().type != RecordType::Prepare ||
            wal.records.back().txid != prepare.txid) {
            release_failed_token(token);
            return status == AnchorStatus::Ok ? AnchorStatus::Corrupt : status;
        }
        Record abort = prepare;
        abort.type = RecordType::Abort;
        abort.new_counter = abort.old_counter;
        abort.new_generation = abort.old_generation;
        abort.new_digest = abort.old_digest;
        status = append_record(abort, wal.head);
        if (status != AnchorStatus::Ok) {
            release_failed_token(token);
            return status;
        }
        pending_tokens_.erase(pending);
        return release_token_locked(token, TokenKind::Update);
    }

private:
    enum class RecordType : std::uint8_t {
        Genesis = 1,
        Prepare = 2,
        Commit = 3,
        Abort = 4
    };

    struct Record {
        RecordType type{RecordType::Genesis};
        std::uint64_t sequence{0};
        std::array<std::uint8_t, 16> txid{};
        std::uint8_t operation{0};
        DataKeyReference reference;
        std::uint64_t old_counter{0};
        std::uint64_t new_counter{0};
        std::uint64_t old_generation{0};
        std::uint64_t new_generation{0};
        Digest old_digest{};
        Digest new_digest{};
        Digest previous_hash{};
        Digest hash{};
    };

    struct State {
        std::uint64_t counter{0};
        std::uint64_t generation{0};
        Digest digest{};
        bool pending{false};
    };

    struct ParsedWal {
        std::vector<Record> records;
        Digest head{};
        std::size_t valid_bytes{0};
        bool partial_tail{false};
        std::uint64_t base_counter{0};
        std::uint64_t base_generation{0};
        Digest base_digest{};
        std::uint64_t base_sequence{0};
        Digest base_hash{};
        std::uint64_t tail_sequence{0};
    };

    class FileLock {
    public:
        FileLock() = default;
        FileLock(const FileLock&) = delete;
        FileLock& operator=(const FileLock&) = delete;
        FileLock(FileLock&& other) noexcept { move_from(other); }
        FileLock& operator=(FileLock&& other) noexcept {
            if (this != &other) {
                release();
                move_from(other);
            }
            return *this;
        }
        ~FileLock() { release(); }

        AnchorStatus acquire(
            const std::filesystem::path& path,
            bool exclusive
        ) noexcept {
#ifdef _WIN32
            handle_ = CreateFileW(
                path.c_str(), GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL, nullptr);
            if (handle_ == INVALID_HANDLE_VALUE) return AnchorStatus::IoError;
            OVERLAPPED overlapped{};
            const DWORD flags = LOCKFILE_FAIL_IMMEDIATELY |
                (exclusive ? LOCKFILE_EXCLUSIVE_LOCK : 0U);
            if (!LockFileEx(handle_, flags, 0, 1, 0, &overlapped)) {
                const DWORD error = GetLastError();
                CloseHandle(handle_);
                handle_ = INVALID_HANDLE_VALUE;
                return error == ERROR_LOCK_VIOLATION
                    ? AnchorStatus::Busy
                    : AnchorStatus::IoError;
            }
            overlapped_ = overlapped;
            return AnchorStatus::Ok;
#else
            descriptor_ = ::open(
                path.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
            if (descriptor_ < 0) return AnchorStatus::IoError;
            const int operation = (exclusive ? LOCK_EX : LOCK_SH) | LOCK_NB;
            if (::flock(descriptor_, operation) != 0) {
                const int error = errno;
                ::close(descriptor_);
                descriptor_ = -1;
                return error == EWOULDBLOCK || error == EAGAIN
                    ? AnchorStatus::Busy
                    : AnchorStatus::IoError;
            }
            return AnchorStatus::Ok;
#endif
        }

        AnchorStatus release() noexcept {
#ifdef _WIN32
            if (handle_ == INVALID_HANDLE_VALUE) return AnchorStatus::Ok;
            const bool unlocked = UnlockFileEx(handle_, 0, 1, 0, &overlapped_) != 0;
            const bool closed = CloseHandle(handle_) != 0;
            handle_ = INVALID_HANDLE_VALUE;
            return unlocked && closed ? AnchorStatus::Ok : AnchorStatus::IoError;
#else
            if (descriptor_ < 0) return AnchorStatus::Ok;
            const bool unlocked = ::flock(descriptor_, LOCK_UN) == 0;
            const bool closed = ::close(descriptor_) == 0;
            descriptor_ = -1;
            return unlocked && closed ? AnchorStatus::Ok : AnchorStatus::IoError;
#endif
        }

    private:
        void move_from(FileLock& other) noexcept {
#ifdef _WIN32
            handle_ = other.handle_;
            overlapped_ = other.overlapped_;
            other.handle_ = INVALID_HANDLE_VALUE;
#else
            descriptor_ = other.descriptor_;
            other.descriptor_ = -1;
#endif
        }
#ifdef _WIN32
        HANDLE handle_{INVALID_HANDLE_VALUE};
        OVERLAPPED overlapped_{};
#else
        int descriptor_{-1};
#endif
    };

    enum class TokenKind : std::uint8_t { Usage, Update };

    static bool valid_reference(const DataKeyReference& reference) noexcept {
        if (reference.key_id.empty() || reference.key_id.size() > 128 ||
            reference.version == 0) {
            return false;
        }
        return std::all_of(
            reference.key_id.begin(), reference.key_id.end(),
            [](unsigned char ch) {
                return (ch >= 'a' && ch <= 'z') ||
                    (ch >= 'A' && ch <= 'Z') ||
                    (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' ||
                    ch == '.';
            });
    }

    static void append_u32(std::vector<std::uint8_t>& out, std::uint32_t v) {
        for (unsigned i = 0; i != 4; ++i) {
            out.push_back(static_cast<std::uint8_t>(v >> (24U - 8U * i)));
        }
    }

    static void append_u64(std::vector<std::uint8_t>& out, std::uint64_t v) {
        for (unsigned i = 0; i != 8; ++i) {
            out.push_back(static_cast<std::uint8_t>(v >> (56U - 8U * i)));
        }
    }

    static std::uint32_t read_u32(const std::uint8_t* p) noexcept {
        return (static_cast<std::uint32_t>(p[0]) << 24U) |
            (static_cast<std::uint32_t>(p[1]) << 16U) |
            (static_cast<std::uint32_t>(p[2]) << 8U) |
            static_cast<std::uint32_t>(p[3]);
    }

    static std::uint64_t read_u64(const std::uint8_t* p) noexcept {
        std::uint64_t value = 0;
        for (unsigned i = 0; i != 8; ++i) value = (value << 8U) | p[i];
        return value;
    }

    static bool digest_bytes(const std::uint8_t* data, std::size_t size,
                            Digest& out) noexcept {
        unsigned int written = 0;
        return EVP_Digest(data, size, out.data(), &written, EVP_sha256(),
                          nullptr) == 1 &&
            written == out.size();
    }

    static Digest digest_file(const std::filesystem::path& path) noexcept {
        Digest digest{};
        try {
            std::ifstream input(path, std::ios::binary);
            if (!input) return digest;
            std::vector<std::uint8_t> bytes;
            char buffer[8192];
            while (input) {
                input.read(buffer, sizeof(buffer));
                const auto got = input.gcount();
                if (got > 0) {
                    if (static_cast<std::size_t>(got) >
                        kMaximumWalBytes - bytes.size()) {
                        return Digest{};
                    }
                    bytes.insert(bytes.end(),
                        reinterpret_cast<const std::uint8_t*>(buffer),
                        reinterpret_cast<const std::uint8_t*>(buffer) + got);
                }
            }
            if (!input.eof() ||
                !digest_bytes(bytes.data(), bytes.size(), digest)) {
                return Digest{};
            }
            return digest;
        } catch (...) {
            return Digest{};
        }
    }

    static std::array<std::uint8_t, 16> random_txid() noexcept {
        std::array<std::uint8_t, 16> value{};
        if (RAND_bytes(value.data(), static_cast<int>(value.size())) != 1) {
            value.fill(0);
        }
        return value;
    }

    std::vector<std::uint8_t> encode_record(
        const Record& record,
        const Digest& previous
    ) const {
        std::vector<std::uint8_t> body;
        body.push_back(static_cast<std::uint8_t>(record.type));
        append_u64(body, record.sequence);
        body.insert(body.end(), record.txid.begin(), record.txid.end());
        body.push_back(record.operation);
        append_u16(body, static_cast<std::uint16_t>(
            record.reference.key_id.size()));
        body.insert(body.end(), record.reference.key_id.begin(),
                    record.reference.key_id.end());
        append_u32(body, record.reference.version);
        append_u64(body, record.old_counter);
        append_u64(body, record.new_counter);
        append_u64(body, record.old_generation);
        append_u64(body, record.new_generation);
        body.insert(body.end(), record.old_digest.begin(), record.old_digest.end());
        body.insert(body.end(), record.new_digest.begin(), record.new_digest.end());
        body.insert(body.end(), previous.begin(), previous.end());
        static constexpr std::uint8_t domain[] = {
            'M','o','t','h','e','r','_','H','/','A','n','c','h','o','r','/','V','2'};
        std::vector<std::uint8_t> mac_input(
            std::begin(domain), std::end(domain));
        mac_input.insert(mac_input.end(), body.begin(), body.end());
        Digest mac{};
        unsigned int mac_size = 0;
        if (HMAC(EVP_sha256(), mac_key_.data(),
                 static_cast<int>(mac_key_.size()), mac_input.data(),
                 mac_input.size(), mac.data(), &mac_size) == nullptr ||
            mac_size != mac.size()) {
            return {};
        }
        body.insert(body.end(), mac.begin(), mac.end());
        std::vector<std::uint8_t> frame{'M','H','V','2'};
        append_u32(frame, static_cast<std::uint32_t>(body.size()));
        frame.insert(frame.end(), body.begin(), body.end());
        return frame;
    }

    static void append_u16(std::vector<std::uint8_t>& out, std::uint16_t v) {
        out.push_back(static_cast<std::uint8_t>(v >> 8U));
        out.push_back(static_cast<std::uint8_t>(v));
    }

    AnchorStatus append_record(Record record, const Digest& previous) noexcept {
        try {
            ParsedWal wal;
            const AnchorStatus read_status = read_wal(wal);
            if (read_status != AnchorStatus::Ok) return read_status;
            if (wal.partial_tail || wal.head != previous) {
                return AnchorStatus::Corrupt;
            }
            const std::uint64_t last_sequence = wal.records.empty()
                ? wal.base_sequence
                : wal.records.back().sequence;
            if (last_sequence ==
                (std::numeric_limits<std::uint64_t>::max)()) {
                return AnchorStatus::CounterMismatch;
            }
            record.sequence = last_sequence + 1U;
            record.previous_hash = previous;
            const auto frame = encode_record(record, previous);
            if (frame.empty() || frame.size() >
                    kMaximumWalBytes - wal.valid_bytes) {
                return AnchorStatus::IoError;
            }
            std::ofstream output(wal_path_,
                std::ios::binary | std::ios::app);
            if (!output) return AnchorStatus::IoError;
            output.write(reinterpret_cast<const char*>(frame.data()),
                         static_cast<std::streamsize>(frame.size()));
            output.flush();
            if (!output) return AnchorStatus::IoError;
            return sync_file(wal_path_) ? AnchorStatus::Ok
                                        : AnchorStatus::IoError;
        } catch (...) {
            return AnchorStatus::IoError;
        }
    }

    static Digest hash_frame(const std::vector<std::uint8_t>& frame) noexcept {
        Digest hash{};
        digest_bytes(frame.data(), frame.size(), hash);
        return hash;
    }

    AnchorStatus append_commit(const Record& prepare,
                               const Digest& previous) noexcept {
        Record commit = prepare;
        commit.type = RecordType::Commit;
        return append_record(commit, previous);
    }

    AnchorStatus read_wal(ParsedWal& output) const noexcept {
        try {
            output = {};
            std::ifstream input(wal_path_, std::ios::binary);
            if (!input) {
                std::error_code error;
                return std::filesystem::exists(wal_path_, error) || error
                    ? AnchorStatus::IoError
                    : AnchorStatus::NotProvisioned;
            }
            std::vector<std::uint8_t> bytes;
            char buffer[8192];
            while (input) {
                input.read(buffer, sizeof(buffer));
                const auto got = input.gcount();
                if (got > 0) {
                    const auto count = static_cast<std::size_t>(got);
                    if (count > kMaximumWalBytes - bytes.size()) {
                        return AnchorStatus::Corrupt;
                    }
                    bytes.insert(bytes.end(),
                        reinterpret_cast<const std::uint8_t*>(buffer),
                        reinterpret_cast<const std::uint8_t*>(buffer) + count);
                }
            }
            if (!input.eof()) return AnchorStatus::IoError;
            constexpr std::size_t kHeaderBytes =
                4U + 16U + 8U * 4U + 32U * 2U + 8U + 32U;
            if (bytes.size() < kHeaderBytes ||
                bytes[0] != 'M' || bytes[1] != 'H' ||
                bytes[2] != 'A' || bytes[3] != '2') {
                return AnchorStatus::Corrupt;
            }
            if (!verify_header(bytes.data(), kHeaderBytes)) {
                return AnchorStatus::AuthenticationFailed;
            }
            output.base_counter = read_u64(bytes.data() + 36);
            output.base_generation = read_u64(bytes.data() + 44);
            std::copy(bytes.begin() + 52, bytes.begin() + 84,
                      output.base_digest.begin());
            output.base_sequence = read_u64(bytes.data() + 84);
            std::copy(bytes.begin() + 92, bytes.begin() + 124,
                      output.base_hash.begin());
            std::size_t offset = kHeaderBytes;
            output.valid_bytes = kHeaderBytes;
            output.head = output.base_hash;
            output.tail_sequence = output.base_sequence;
            Digest previous = output.base_hash;
            while (offset < bytes.size()) {
                if (bytes.size() - offset < 8U) {
                    output.partial_tail = true;
                    break;
                }
                if (bytes[offset] != 'M' || bytes[offset + 1] != 'H' ||
                    bytes[offset + 2] != 'V' || bytes[offset + 3] != '2') {
                    return AnchorStatus::Corrupt;
                }
                const std::uint32_t body_size = read_u32(bytes.data() + offset + 4);
                if (body_size < kMinimumBodyBytes ||
                    body_size > kMaximumRecordBytes) {
                    return AnchorStatus::Corrupt;
                }
                if (bytes.size() - offset - 8U < body_size) {
                    output.partial_tail = true;
                    break;
                }
                Record record{};
                std::size_t consumed = 0;
                if (!decode_record(bytes.data() + offset + 8, body_size,
                                   record, previous, consumed) ||
                    consumed != body_size) {
                    return AnchorStatus::AuthenticationFailed;
                }
                const std::vector<std::uint8_t> frame(
                    bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                    bytes.begin() + static_cast<std::ptrdiff_t>(
                        offset + 8U + body_size));
                previous = hash_frame(frame);
                record.hash = previous;
                output.records.push_back(std::move(record));
                offset += 8U + body_size;
                output.valid_bytes = offset;
                output.tail_sequence = output.records.back().sequence;
            }
            output.head = previous;
            return AnchorStatus::Ok;
        } catch (...) {
            return AnchorStatus::IoError;
        }
    }

    static constexpr std::size_t kMinimumBodyBytes =
        1U + 8U + 16U + 1U + 2U + 4U + 8U * 4U + 32U * 3U + 32U;
    static constexpr std::size_t kMaximumRecordBytes = 512U;

    bool decode_record(
        const std::uint8_t* data,
        std::size_t size,
        Record& record,
        const Digest& expected_previous,
        std::size_t& consumed
    ) const noexcept {
        if (size < kMinimumBodyBytes) return false;
        const std::uint8_t* p = data;
        const std::uint8_t* end = data + size;
        const auto type = *p++;
        if (type < static_cast<std::uint8_t>(RecordType::Genesis) ||
            type > static_cast<std::uint8_t>(RecordType::Abort)) return false;
        record.type = static_cast<RecordType>(type);
        record.sequence = read_u64(p); p += 8;
        std::copy(p, p + 16, record.txid.begin()); p += 16;
        record.operation = *p++;
        if (end - p < 2) return false;
        const std::uint16_t id_size =
            static_cast<std::uint16_t>((p[0] << 8U) | p[1]);
        p += 2;
        if (id_size > 128 || end - p < id_size + 4U + 8U * 4U + 32U * 3U + 32U) {
            return false;
        }
        record.reference.key_id.assign(
            reinterpret_cast<const char*>(p), id_size);
        p += id_size;
        record.reference.version = read_u32(p); p += 4;
        record.old_counter = read_u64(p); p += 8;
        record.new_counter = read_u64(p); p += 8;
        record.old_generation = read_u64(p); p += 8;
        record.new_generation = read_u64(p); p += 8;
        std::copy(p, p + 32, record.old_digest.begin()); p += 32;
        std::copy(p, p + 32, record.new_digest.begin()); p += 32;
        std::copy(p, p + 32, record.previous_hash.begin()); p += 32;
        if (record.previous_hash != expected_previous ||
            static_cast<std::size_t>(end - p) != 32U) return false;
        static constexpr std::uint8_t domain[] = {
            'M','o','t','h','e','r','_','H','/','A','n','c','h','o','r','/','V','2'};
        std::vector<std::uint8_t> mac_input(
            std::begin(domain), std::end(domain));
        mac_input.insert(mac_input.end(), data, p);
        Digest expected_mac{};
        unsigned int mac_size = 0;
        if (HMAC(EVP_sha256(), mac_key_.data(),
                 static_cast<int>(mac_key_.size()), mac_input.data(),
                 mac_input.size(), expected_mac.data(), &mac_size) == nullptr ||
            mac_size != expected_mac.size() ||
            CRYPTO_memcmp(expected_mac.data(), p, expected_mac.size()) != 0) {
            return false;
        }
        consumed = size;
        return true;
    }

    AnchorStatus validate_records(
        const ParsedWal& wal,
        State& state
    ) const noexcept {
        const auto& records = wal.records;
        state.counter = wal.base_counter;
        state.generation = wal.base_generation;
        state.digest = wal.base_digest;
        if (wal.base_sequence == 0) {
            if (records.empty() || records.front().type != RecordType::Genesis ||
                records.front().sequence != 1) {
                return AnchorStatus::Corrupt;
            }
            const Record& genesis = records.front();
            if (genesis.old_counter != genesis.new_counter ||
                genesis.old_generation != genesis.new_generation ||
                genesis.old_digest != genesis.new_digest ||
                genesis.new_counter != wal.base_counter ||
                genesis.new_generation != wal.base_generation ||
                genesis.new_digest != wal.base_digest) {
                return AnchorStatus::Corrupt;
            }
        } else if (records.empty()) {
            return AnchorStatus::Ok;
        }
        const std::size_t first_transition = wal.base_sequence == 0 ? 1U : 0U;
        for (std::size_t i = first_transition; i < records.size(); ++i) {
            const Record& record = records[i];
            const std::uint64_t previous_sequence = i == 0
                ? wal.base_sequence
                : records[i - 1].sequence;
            if (previous_sequence ==
                    (std::numeric_limits<std::uint64_t>::max)() ||
                record.sequence != previous_sequence + 1U) {
                return AnchorStatus::Corrupt;
            }
            if (state.pending) {
                const Record& prepare = records[i - 1];
                if (record.type != RecordType::Commit &&
                    record.type != RecordType::Abort) {
                    return AnchorStatus::Corrupt;
                }
                if (record.txid != prepare.txid ||
                    record.old_counter != prepare.old_counter ||
                    record.old_generation != prepare.old_generation ||
                    record.old_digest != prepare.old_digest) {
                    return AnchorStatus::Corrupt;
                }
                if (record.type == RecordType::Commit) {
                    if (record.new_counter != prepare.new_counter ||
                        record.new_generation != prepare.new_generation ||
                        record.new_digest != prepare.new_digest) {
                        return AnchorStatus::Corrupt;
                    }
                    state.counter = record.new_counter;
                    state.generation = record.new_generation;
                    state.digest = record.new_digest;
                } else {
                    if (record.new_counter != prepare.old_counter ||
                        record.new_generation != prepare.old_generation ||
                        record.new_digest != prepare.old_digest) {
                        return AnchorStatus::Corrupt;
                    }
                }
                state.pending = false;
            } else if (record.type == RecordType::Prepare) {
                if (record.old_counter != state.counter ||
                    record.old_generation != state.generation ||
                    record.old_digest != state.digest ||
                    state.counter ==
                        (std::numeric_limits<std::uint64_t>::max)() ||
                    state.generation ==
                        (std::numeric_limits<std::uint64_t>::max)() ||
                    record.new_counter != state.counter + 1U ||
                    record.new_generation != state.generation + 1U) {
                    return AnchorStatus::Corrupt;
                }
                state.pending = true;
            } else {
                return AnchorStatus::Corrupt;
            }
        }
        return AnchorStatus::Ok;
    }

    AnchorStatus validate_stable(
        const State& state,
        std::uint64_t counter_value
    ) const noexcept {
        if (state.pending) return AnchorStatus::RecoveryRequired;
        if (counter_value != state.counter) {
            return counter_value > state.counter
                ? AnchorStatus::RollbackDetected
                : AnchorStatus::CounterMismatch;
        }
        return validate_mapping(state.counter, state.generation);
    }

    AnchorStatus validate_mapping(
        std::uint64_t counter_value,
        std::uint64_t generation_value
    ) const noexcept {
        if (generation_value < generation_origin_ ||
            counter_value < counter_origin_ ||
            generation_value - generation_origin_ >
                (std::numeric_limits<std::uint64_t>::max)() - counter_origin_) {
            return AnchorStatus::CounterMismatch;
        }
        const std::uint64_t expected_counter = counter_origin_ +
            (generation_value - generation_origin_);
        return expected_counter == counter_value
            ? AnchorStatus::Ok
            : AnchorStatus::CounterMismatch;
    }

    AnchorStatus load_stable(
        ParsedWal& wal,
        State& state,
        std::uint64_t& counter_value
    ) const noexcept {
        AnchorStatus status = read_wal(wal);
        if (status != AnchorStatus::Ok) return status;
        if (wal.partial_tail) return AnchorStatus::RecoveryRequired;
        if (wal.records.empty() && wal.base_sequence == 0)
            return AnchorStatus::NotProvisioned;
        status = validate_records(wal, state);
        if (status != AnchorStatus::Ok) return status;
        if (state.pending) return AnchorStatus::RecoveryRequired;
        status = validate_mapping(state.counter, state.generation);
        if (status != AnchorStatus::Ok) return status;
        if (wal.base_sequence == 0 &&
            (wal.records.front().txid != std::array<std::uint8_t, 16>{} ||
             wal.records.front().old_counter != counter_origin_ ||
             wal.records.front().old_generation != generation_origin_)) {
            return AnchorStatus::Corrupt;
        }
        status = counter_.read(counter_value);
        if (status != AnchorStatus::Ok) return status;
        status = validate_stable(state, counter_value);
        if (status != AnchorStatus::Ok) return status;
        if (digest_file(store_path_) != state.digest) {
            return AnchorStatus::StaleSnapshot;
        }
        return AnchorStatus::Ok;
    }

    AnchorSnapshot make_snapshot(
        const State& state,
        const Record& tail
    ) const noexcept {
        AnchorSnapshot snapshot{};
        snapshot.anchor_id = anchor_id_;
        snapshot.counter = state.counter;
        snapshot.counter_origin = counter_origin_;
        snapshot.generation = state.generation;
        snapshot.generation_origin = generation_origin_;
        snapshot.store_digest = state.digest;
        snapshot.wal_sequence = tail.sequence;
        snapshot.wal_head = tail.hash;
        return snapshot;
    }

    static Record tail_record(const ParsedWal& wal) noexcept {
        if (!wal.records.empty()) return wal.records.back();
        Record tail{};
        tail.sequence = wal.base_sequence;
        tail.hash = wal.base_hash;
        return tail;
    }

    bool truncate_wal(std::size_t size) const noexcept {
        try {
#ifdef _WIN32
            HANDLE file = CreateFileW(wal_path_.c_str(), GENERIC_WRITE,
                FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (file == INVALID_HANDLE_VALUE) return false;
            LARGE_INTEGER position{};
            position.QuadPart = static_cast<LONGLONG>(size);
            const bool ok = SetFilePointerEx(file, position, nullptr, FILE_BEGIN) &&
                SetEndOfFile(file) && FlushFileBuffers(file);
            const bool closed = CloseHandle(file) != 0;
            return ok && closed;
#else
            const int fd = ::open(wal_path_.c_str(), O_WRONLY);
            if (fd < 0) return false;
            const bool ok = ::ftruncate(fd, static_cast<off_t>(size)) == 0 &&
                ::fsync(fd) == 0;
            const bool closed = ::close(fd) == 0;
            return ok && closed;
#endif
        } catch (...) {
            return false;
        }
    }

    AnchorStatus release_token(AnchorToken token, TokenKind kind) noexcept {
        std::lock_guard<std::mutex> guard(mutex_);
        if (kind == TokenKind::Update &&
            pending_tokens_.find(token) != pending_tokens_.end()) {
            return AnchorStatus::RecoveryRequired;
        }
        return release_token_locked(token, kind);
    }

    AnchorStatus release_token_locked(AnchorToken token, TokenKind) noexcept {
        auto it = held_locks_.find(token);
        if (it == held_locks_.end()) return AnchorStatus::InvalidRequest;
        const AnchorStatus status = it->second.release();
        held_locks_.erase(it);
        if (status != AnchorStatus::Ok) poisoned_ = true;
        return status;
    }

    void release_failed_token(AnchorToken token) noexcept {
        pending_tokens_.erase(token);
        release_token_locked(token, TokenKind::Update);
    }

    bool encode_header(
        std::uint64_t base_counter,
        std::uint64_t base_generation,
        const Digest& base_digest,
        std::uint64_t base_sequence,
        const Digest& base_hash,
        std::vector<std::uint8_t>& header
    ) const noexcept {
        try {
            header = {'M', 'H', 'A', '2'};
            header.insert(
                header.end(), anchor_id_.begin(), anchor_id_.end());
            append_u64(header, counter_origin_);
            append_u64(header, generation_origin_);
            append_u64(header, base_counter);
            append_u64(header, base_generation);
            header.insert(
                header.end(), base_digest.begin(), base_digest.end());
            append_u64(header, base_sequence);
            header.insert(header.end(), base_hash.begin(), base_hash.end());
            static constexpr std::uint8_t domain[] = {
                'M','o','t','h','e','r','_','H','/','A','n','c','h','o','r',
                '/','V','2','/','H','e','a','d','e','r'};
            std::vector<std::uint8_t> mac_input(
                std::begin(domain), std::end(domain));
            mac_input.insert(mac_input.end(), header.begin(), header.end());
            Digest mac{};
            unsigned int written = 0;
            if (HMAC(EVP_sha256(), mac_key_.data(),
                     static_cast<int>(mac_key_.size()), mac_input.data(),
                     mac_input.size(), mac.data(), &written) == nullptr ||
                written != mac.size()) {
                return false;
            }
            header.insert(header.end(), mac.begin(), mac.end());
            return true;
        } catch (...) {
            return false;
        }
    }

    bool write_header(
        std::uint64_t initial_counter,
        std::uint64_t initial_generation,
        std::uint64_t base_counter,
        std::uint64_t base_generation,
        const Digest& base_digest,
        std::uint64_t base_sequence,
        const Digest& base_hash
    ) noexcept {
        std::vector<std::uint8_t> header;
        if (!encode_header(base_counter, base_generation, base_digest,
                           base_sequence, base_hash, header) ||
            initial_counter != counter_origin_ ||
            initial_generation != generation_origin_ ||
            !write_new_file(wal_path_, header) || !sync_file(wal_path_)) {
            return false;
        }
        return sync_parent(wal_path_);
    }

    bool verify_header(
        const std::uint8_t* bytes,
        std::size_t size
    ) const noexcept {
        if (size != 4U + 16U + 8U * 4U + 32U * 2U + 8U + 32U ||
            !std::equal(anchor_id_.begin(), anchor_id_.end(), bytes + 4)) {
            return false;
        }
        const auto initial_counter = read_u64(bytes + 20);
        const auto initial_generation = read_u64(bytes + 28);
        static constexpr std::uint8_t domain[] = {
            'M','o','t','h','e','r','_','H','/','A','n','c','h','o','r',
            '/','V','2','/','H','e','a','d','e','r'};
        std::vector<std::uint8_t> mac_input(
            std::begin(domain), std::end(domain));
        mac_input.insert(mac_input.end(), bytes, bytes + 124);
        Digest expected{};
        unsigned int written = 0;
        if (HMAC(EVP_sha256(), mac_key_.data(),
                 static_cast<int>(mac_key_.size()), mac_input.data(),
                 mac_input.size(), expected.data(), &written) == nullptr ||
            written != expected.size() ||
            CRYPTO_memcmp(expected.data(), bytes + 124, expected.size()) != 0) {
            return false;
        }
        if (counter_origin_ != 0 || generation_origin_ != 0) {
            return counter_origin_ == initial_counter &&
                generation_origin_ == initial_generation;
        }
        counter_origin_ = initial_counter;
        generation_origin_ = initial_generation;
        return true;
    }

    static bool atomic_replace_file(
        const std::filesystem::path& path,
        const std::vector<std::uint8_t>& bytes
    ) noexcept {
        try {
            std::array<std::uint8_t, 8> random{};
            if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1)
                return false;
            static constexpr char hex[] = "0123456789abcdef";
            std::string suffix;
            suffix.reserve(random.size() * 2U);
            for (const auto value : random) {
                suffix.push_back(hex[value >> 4U]);
                suffix.push_back(hex[value & 0x0FU]);
            }
            auto temporary = path;
            temporary += ".tmp-" + suffix;
            if (!write_new_file(temporary, bytes) || !sync_file(temporary)) {
                return false;
            }
#ifdef _WIN32
            if (!MoveFileExW(temporary.c_str(), path.c_str(),
                             MOVEFILE_REPLACE_EXISTING |
                                 MOVEFILE_WRITE_THROUGH)) {
                DeleteFileW(temporary.c_str());
                return false;
            }
            return true;
#else
            if (::rename(temporary.c_str(), path.c_str()) != 0) {
                ::unlink(temporary.c_str());
                return false;
            }
            return sync_parent(path);
#endif
        } catch (...) {
            return false;
        }
    }

    static bool write_new_file(
        const std::filesystem::path& path,
        const std::vector<std::uint8_t>& bytes
    ) noexcept {
        try {
#ifdef _WIN32
            HANDLE file = CreateFileW(
                path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE) return false;
            std::size_t offset = 0;
            bool ok = true;
            while (offset < bytes.size()) {
                DWORD written = 0;
                const DWORD request = static_cast<DWORD>((std::min)(
                    bytes.size() - offset,
                    static_cast<std::size_t>(
                        (std::numeric_limits<DWORD>::max)())));
                if (!WriteFile(file, bytes.data() + offset, request, &written,
                               nullptr) || written == 0) {
                    ok = false;
                    break;
                }
                offset += written;
            }
            if (ok && !FlushFileBuffers(file)) ok = false;
            const bool closed = CloseHandle(file) != 0;
            return ok && closed;
#else
            const int file = ::open(
                path.c_str(), O_WRONLY | O_CREAT | O_EXCL,
                S_IRUSR | S_IWUSR);
            if (file < 0) return false;
            std::size_t offset = 0;
            bool ok = true;
            while (offset < bytes.size()) {
                const ssize_t written = ::write(
                    file, bytes.data() + offset, bytes.size() - offset);
                if (written < 0 && errno == EINTR) continue;
                if (written <= 0) {
                    ok = false;
                    break;
                }
                offset += static_cast<std::size_t>(written);
            }
            if (ok && ::fsync(file) != 0) ok = false;
            const bool closed = ::close(file) == 0;
            return ok && closed;
#endif
        } catch (...) {
            return false;
        }
    }

    static bool sync_file(const std::filesystem::path& path) noexcept {
#ifdef _WIN32
        HANDLE file = CreateFileW(
            path.c_str(), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return false;
        const bool synced = FlushFileBuffers(file) != 0;
        const bool closed = CloseHandle(file) != 0;
        return synced && closed;
#else
        const int file = ::open(path.c_str(), O_RDONLY);
        if (file < 0) return false;
        const bool synced = ::fsync(file) == 0;
        const bool closed = ::close(file) == 0;
        return synced && closed;
#endif
    }

    static bool sync_parent(const std::filesystem::path& path) noexcept {
#ifdef _WIN32
        (void)path;
        return true;
#else
        auto parent = path.parent_path();
        if (parent.empty()) parent = ".";
        const int directory = ::open(parent.c_str(), O_RDONLY);
        if (directory < 0) return false;
        const bool synced = ::fsync(directory) == 0;
        const bool closed = ::close(directory) == 0;
        return synced && closed;
#endif
    }

    std::filesystem::path store_path_;
    std::filesystem::path wal_path_;
    std::filesystem::path lock_path_;
    IMonotonicCounterV2& counter_;
    std::array<std::uint8_t, kMacKeyBytes> mac_key_{};
    std::array<std::uint8_t, 16> anchor_id_{};
    mutable std::mutex mutex_;
    mutable std::uint64_t counter_origin_{0};
    mutable std::uint64_t generation_origin_{0};
    AnchorToken next_token_{1};
    bool poisoned_{false};
    std::map<AnchorToken, FileLock> held_locks_;
    std::map<AnchorToken, Record> pending_tokens_;
};

}  // namespace mother_h::journal::v2
