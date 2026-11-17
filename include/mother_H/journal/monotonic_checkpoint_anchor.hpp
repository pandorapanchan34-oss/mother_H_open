#ifndef MOTHER_H_JOURNAL_MONOTONIC_CHECKPOINT_ANCHOR_HPP
#define MOTHER_H_JOURNAL_MONOTONIC_CHECKPOINT_ANCHOR_HPP

#include "mother_H/journal/journal_integrity.hpp"
#include "mother_H/journal/monotonic_revocation_anchor_v2.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <mutex>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace mother_h::journal {

using CheckpointDigest = std::array<std::uint8_t, 32>;
using AnchorId = std::array<std::uint8_t, 16>;
using TransactionId = std::array<std::uint8_t, 16>;

enum class AnchoredStoreStatus : std::uint8_t {
    Ok = 0,
    NotFound,
    Conflict,
    LockBusy,
    BackendUnavailable,
    RecoveryRequired,
    AuthenticationFailed,
    Corrupt,
    RollbackDetected,
    Poisoned
};

enum class RollbackAssuranceLevel : std::uint8_t {
    SoftwareOnly = 0,
    ExternalMonotonicAnchor = 1
};

struct PoisonLatchResult {
    AnchoredStoreStatus status{AnchoredStoreStatus::Poisoned};
    bool is_poisoned{true};
    bool persisted{false};
    AnchoredStoreStatus persistence_error{AnchoredStoreStatus::Ok};
};

struct AnchoredOperationResult {
    AnchoredStoreStatus detail{AnchoredStoreStatus::BackendUnavailable};
    CheckpointStatus store_status{CheckpointStatus::BackendUnavailable};
    bool is_poisoned{false};

    explicit operator bool() const noexcept {
        return detail == AnchoredStoreStatus::Ok && !is_poisoned;
    }
};

struct CheckpointTrustedBinding {
    AnchorId trusted_anchor_id{};
    std::uint64_t expected_counter_origin{0};
    std::uint64_t expected_generation_origin{0};
    std::array<std::uint8_t, 32> master_mac_key{};
    bool has_external_monotonic_anchor{false};

    ~CheckpointTrustedBinding() {
        OPENSSL_cleanse(master_mac_key.data(), master_mac_key.size());
    }
};

class CheckpointDigestCalculator final {
public:
    static constexpr std::array<std::uint8_t, 8> kMagic{{
        'M', 'H', '-', 'C', 'P', '-', 'D', 'G'
    }};
    static constexpr std::uint16_t kFormatVersion = 0x0001U;
    static constexpr std::uint16_t kReservedZero = 0x0000U;
    static constexpr std::size_t kCanonicalSize = 124U;

    static CheckpointDigest zero_digest() noexcept { return {}; }

    static bool compute_state_digest(
        const AnchorId& anchor_id,
        const JournalCheckpoint& state,
        const CheckpointDigest& previous_committed_digest,
        std::uint64_t counter_origin,
        std::uint64_t generation_origin,
        CheckpointDigest& digest_out
    ) noexcept {
        std::array<std::uint8_t, kCanonicalSize> buf{};
        std::size_t off = 0;

        std::copy(kMagic.begin(), kMagic.end(), buf.begin() + off);
        off += kMagic.size();

        write_be16(buf.data() + off, kFormatVersion);
        off += 2;

        write_be16(buf.data() + off, kReservedZero);
        off += 2;

        std::copy(anchor_id.begin(), anchor_id.end(), buf.begin() + off);
        off += anchor_id.size();

        write_be64(buf.data() + off, state.lsn);
        off += 8;

        write_be64(buf.data() + off, state.revision);
        off += 8;

        std::copy(state.record_hash.begin(), state.record_hash.end(), buf.begin() + off);
        off += state.record_hash.size();

        std::copy(previous_committed_digest.begin(), previous_committed_digest.end(), buf.begin() + off);
        off += previous_committed_digest.size();

        write_be64(buf.data() + off, counter_origin);
        off += 8;

        write_be64(buf.data() + off, generation_origin);
        off += 8;

        return sha256(buf.data(), buf.size(), digest_out);
    }

    static bool compute_genesis_digest(
        const AnchorId& anchor_id,
        std::uint64_t counter_origin,
        std::uint64_t generation_origin,
        CheckpointDigest& genesis_out
    ) noexcept {
        JournalCheckpoint genesis{};
        genesis.lsn = 0;
        genesis.revision = 0;
        genesis.record_hash = JournalIntegrity::genesis_hash();
        return compute_state_digest(
            anchor_id, genesis, zero_digest(),
            counter_origin, generation_origin, genesis_out
        );
    }

    static bool derive_subkey(
        const std::array<std::uint8_t, 32>& master_key,
        const char* domain_label,
        const AnchorId& anchor_id,
        std::array<std::uint8_t, 32>& derived_out
    ) noexcept {
        if (domain_label == nullptr) return false;
        const std::size_t label_len = std::strlen(domain_label);
        std::array<std::uint8_t, 128> msg{};
        if (label_len == 0 || label_len + anchor_id.size() > msg.size()) {
            return false;
        }
        std::memcpy(msg.data(), domain_label, label_len);
        std::memcpy(msg.data() + label_len, anchor_id.data(), anchor_id.size());
        const bool ok = hmac_sha256(
            master_key.data(), master_key.size(),
            msg.data(), label_len + anchor_id.size(), derived_out);
        OPENSSL_cleanse(msg.data(), msg.size());
        return ok;
    }

    static bool sha256(
        const std::uint8_t* data,
        std::size_t len,
        CheckpointDigest& out
    ) noexcept {
        unsigned int out_len = 0;
        if (EVP_Digest(data, len, out.data(), &out_len, EVP_sha256(), nullptr) != 1) {
            return false;
        }
        return out_len == out.size();
    }

    static bool hmac_sha256(
        const std::uint8_t* key,
        std::size_t key_len,
        const std::uint8_t* data,
        std::size_t data_len,
        CheckpointDigest& out
    ) noexcept {
        unsigned int out_len = 0;
        if (HMAC(EVP_sha256(), key, static_cast<int>(key_len),
                 data, data_len, out.data(), &out_len) == nullptr) {
            return false;
        }
        return out_len == out.size();
    }

    static bool constant_time_equal(
        const CheckpointDigest& a,
        const CheckpointDigest& b
    ) noexcept {
        return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
    }

    static void write_be16(std::uint8_t* p, std::uint16_t v) noexcept {
        p[0] = static_cast<std::uint8_t>((v >> 8U) & 0xFFU);
        p[1] = static_cast<std::uint8_t>(v & 0xFFU);
    }

    static std::uint16_t read_be16(const std::uint8_t* p) noexcept {
        return static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(p[0]) << 8U) |
            static_cast<std::uint16_t>(p[1])
        );
    }

    static void write_be64(std::uint8_t* p, std::uint64_t v) noexcept {
        for (unsigned i = 0; i < 8; ++i) {
            p[i] = static_cast<std::uint8_t>((v >> (56U - 8U * i)) & 0xFFU);
        }
    }

    static std::uint64_t read_be64(const std::uint8_t* p) noexcept {
        std::uint64_t v = 0;
        for (unsigned i = 0; i < 8; ++i) {
            v = (v << 8U) | static_cast<std::uint64_t>(p[i]);
        }
        return v;
    }
};

class IPoisonLatchStore {
public:
    virtual ~IPoisonLatchStore() = default;

    virtual AnchoredStoreStatus initialize_clean(
        const AnchorId& anchor_id
    ) noexcept = 0;

    virtual AnchoredStoreStatus check_status(
        const AnchorId& expected_anchor_id,
        bool expect_provisioned,
        bool& poisoned_out
    ) const noexcept = 0;

    virtual PoisonLatchResult latch_poisoned(
        const AnchorId& anchor_id,
        std::uint16_t reason_code
    ) noexcept = 0;
};

class FilePoisonLatchStore final : public IPoisonLatchStore {
public:
    static constexpr std::array<std::uint8_t, 8> kMagic{{
        'M', 'H', '-', 'P', 'L', '-', 'V', '1'
    }};
    static constexpr std::uint16_t kVersion = 1U;
    static constexpr std::uint8_t kStateClean = 0x00U;
    static constexpr std::uint8_t kStatePoisoned = 0xFFU;
    static constexpr std::size_t kRecordBytes = 72U;

    FilePoisonLatchStore(
        std::filesystem::path latch_path,
        const CheckpointTrustedBinding& binding
    ) : latch_path_(std::move(latch_path)),
        anchor_id_(binding.trusted_anchor_id) {
        key_valid_ = CheckpointDigestCalculator::derive_subkey(
            binding.master_mac_key, "MH-POISON-LATCH-V1",
            anchor_id_, subkey_
        );
    }

    ~FilePoisonLatchStore() override {
        OPENSSL_cleanse(subkey_.data(), subkey_.size());
    }

    AnchoredStoreStatus initialize_clean(
        const AnchorId& anchor_id
    ) noexcept override {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!key_valid_ || anchor_id != anchor_id_) {
            return AnchoredStoreStatus::AuthenticationFailed;
        }
        std::error_code ec;
        const bool exists = std::filesystem::exists(latch_path_, ec);
        if (ec) {
            return AnchoredStoreStatus::BackendUnavailable;
        }
        if (exists) {
            bool poisoned = true;
            const auto st = check_status_unlocked(anchor_id, true, poisoned);
            if (st != AnchoredStoreStatus::Ok || poisoned) {
                return AnchoredStoreStatus::Poisoned;
            }
            return AnchoredStoreStatus::Ok;
        }
        std::array<std::uint8_t, kRecordBytes> rec{};
        if (!encode_record(kStateClean, anchor_id, 0, rec)) {
            return AnchoredStoreStatus::BackendUnavailable;
        }
        return durable_replace(latch_path_, rec.data(), rec.size())
            ? AnchoredStoreStatus::Ok
            : AnchoredStoreStatus::BackendUnavailable;
    }

    AnchoredStoreStatus check_status(
        const AnchorId& expected_anchor_id,
        bool expect_provisioned,
        bool& poisoned_out
    ) const noexcept override {
        std::lock_guard<std::mutex> lock(mutex_);
        return check_status_unlocked(expected_anchor_id, expect_provisioned, poisoned_out);
    }

    PoisonLatchResult latch_poisoned(
        const AnchorId& anchor_id,
        std::uint16_t reason_code
    ) noexcept override {
        std::lock_guard<std::mutex> lock(mutex_);
        memory_poisoned_ = true;

        PoisonLatchResult res{};
        res.status = AnchoredStoreStatus::Poisoned;
        res.is_poisoned = true;
        res.persisted = false;

        if (!key_valid_ || anchor_id != anchor_id_) {
            res.persistence_error = AnchoredStoreStatus::AuthenticationFailed;
            return res;
        }
        std::array<std::uint8_t, kRecordBytes> rec{};
        if (!encode_record(kStatePoisoned, anchor_id, reason_code, rec)) {
            res.persistence_error = AnchoredStoreStatus::BackendUnavailable;
            return res;
        }
        if (!durable_replace(latch_path_, rec.data(), rec.size())) {
            res.persistence_error = AnchoredStoreStatus::BackendUnavailable;
            return res;
        }
        res.persisted = true;
        res.persistence_error = AnchoredStoreStatus::Ok;
        return res;
    }

private:
    AnchoredStoreStatus check_status_unlocked(
        const AnchorId& expected_anchor_id,
        bool expect_provisioned,
        bool& poisoned_out
    ) const noexcept {
        poisoned_out = true;
        if (memory_poisoned_) {
            return AnchoredStoreStatus::Poisoned;
        }
        if (!key_valid_ || expected_anchor_id != anchor_id_) {
            return AnchoredStoreStatus::AuthenticationFailed;
        }
        std::error_code ec;
        const bool exists = std::filesystem::exists(latch_path_, ec);
        if (ec) {
            return AnchoredStoreStatus::BackendUnavailable;
        }
        if (!exists) {
            if (!expect_provisioned) {
                poisoned_out = false;
                return AnchoredStoreStatus::NotFound;
            }
            return AnchoredStoreStatus::Poisoned;
        }

        try {
            std::array<std::uint8_t, kRecordBytes> rec{};
            std::ifstream ifs(latch_path_, std::ios::binary);
            if (!ifs.is_open()) return AnchoredStoreStatus::BackendUnavailable;
            ifs.read(reinterpret_cast<char*>(rec.data()), static_cast<std::streamsize>(rec.size()));
            if (ifs.gcount() != static_cast<std::streamsize>(rec.size()) ||
                ifs.peek() != std::char_traits<char>::eof()) {
                return AnchoredStoreStatus::Poisoned;
            }

            if (!std::equal(kMagic.begin(), kMagic.end(), rec.begin())) {
                return AnchoredStoreStatus::Poisoned;
            }
            const std::uint16_t ver = CheckpointDigestCalculator::read_be16(rec.data() + 8);
            if (ver != kVersion) {
                return AnchoredStoreStatus::Poisoned;
            }
            const std::uint8_t state = rec[10];
            AnchorId stored_id{};
            std::copy(rec.begin() + 16, rec.begin() + 32, stored_id.begin());
            if (stored_id != expected_anchor_id) {
                return AnchoredStoreStatus::Poisoned;
            }

            CheckpointDigest expected_mac{};
            if (!CheckpointDigestCalculator::hmac_sha256(
                    subkey_.data(), subkey_.size(), rec.data(), 40U, expected_mac)) {
                return AnchoredStoreStatus::BackendUnavailable;
            }
            CheckpointDigest actual_mac{};
            std::copy(rec.begin() + 40, rec.end(), actual_mac.begin());
            if (!CheckpointDigestCalculator::constant_time_equal(expected_mac, actual_mac)) {
                return AnchoredStoreStatus::Poisoned;
            }

            if (state == kStateClean) {
                poisoned_out = false;
                return AnchoredStoreStatus::Ok;
            }
            return AnchoredStoreStatus::Poisoned;
        } catch (...) {
            return AnchoredStoreStatus::BackendUnavailable;
        }
    }

    bool encode_record(
        std::uint8_t state,
        const AnchorId& anchor_id,
        std::uint16_t reason_code,
        std::array<std::uint8_t, kRecordBytes>& out
    ) const noexcept {
        out.fill(0);
        std::copy(kMagic.begin(), kMagic.end(), out.begin());
        CheckpointDigestCalculator::write_be16(out.data() + 8, kVersion);
        out[10] = state;
        std::copy(anchor_id.begin(), anchor_id.end(), out.begin() + 16);
        CheckpointDigestCalculator::write_be16(out.data() + 32, reason_code);
        CheckpointDigest mac{};
        if (!CheckpointDigestCalculator::hmac_sha256(
                subkey_.data(), subkey_.size(), out.data(), 40U, mac)) {
            return false;
        }
        std::copy(mac.begin(), mac.end(), out.begin() + 40);
        return true;
    }

    static bool durable_replace(
        const std::filesystem::path& target,
        const std::uint8_t* data,
        std::size_t size
    ) noexcept {
        try {
            std::array<std::uint8_t, 8> rnd{};
            if (RAND_bytes(rnd.data(), static_cast<int>(rnd.size())) != 1) return false;
            static constexpr char hex[] = "0123456789abcdef";
            std::string suffix;
            for (auto b : rnd) {
                suffix.push_back(hex[b >> 4U]);
                suffix.push_back(hex[b & 0x0FU]);
            }
            auto tmp = target;
            tmp += ".tmp-" + suffix;
#ifdef _WIN32
            HANDLE h = ::CreateFileW(
                tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h == INVALID_HANDLE_VALUE) return false;
            DWORD written = 0;
            const bool ok =
                ::WriteFile(h, data, static_cast<DWORD>(size), &written, nullptr) != 0 &&
                written == size && ::FlushFileBuffers(h) != 0;
            const bool closed = ::CloseHandle(h) != 0;
            if (!ok || !closed) {
                ::DeleteFileW(tmp.c_str());
                return false;
            }
            if (::MoveFileExW(tmp.c_str(), target.c_str(),
                              MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
                ::DeleteFileW(tmp.c_str());
                return false;
            }
            return true;
#else
            const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
            if (fd < 0) return false;
            std::size_t off = 0;
            bool ok = true;
            while (off < size) {
                const ssize_t n = ::write(fd, data + off, size - off);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0) { ok = false; break; }
                off += static_cast<std::size_t>(n);
            }
            if (ok && ::fsync(fd) != 0) ok = false;
            const bool closed = ::close(fd) == 0;
            if (!ok || !closed) {
                ::unlink(tmp.c_str());
                return false;
            }
            if (::rename(tmp.c_str(), target.c_str()) != 0) {
                ::unlink(tmp.c_str());
                return false;
            }
            auto parent = target.parent_path();
            if (parent.empty()) parent = ".";
            const int pfd = ::open(parent.c_str(), O_RDONLY);
            if (pfd < 0) return false;
            const bool psync = ::fsync(pfd) == 0;
            const bool pclose = ::close(pfd) == 0;
            return psync && pclose;
#endif
        } catch (...) {
            return false;
        }
    }

    std::filesystem::path latch_path_;
    AnchorId anchor_id_{};
    std::array<std::uint8_t, 32> subkey_{};
    bool key_valid_{false};
    mutable std::mutex mutex_;
    mutable bool memory_poisoned_{false};
};

struct CheckpointAnchorObservation {
    AnchorId anchor_id{};
    std::uint64_t counter_origin{0};
    std::uint64_t generation_origin{0};
    std::uint64_t committed_revision{0};
    std::uint64_t committed_lsn{0};
    JournalHash committed_record_hash{};
    CheckpointDigest committed_digest{};
    std::uint64_t wal_sequence{0};
    CheckpointDigest wal_head{};

    RollbackAssuranceLevel assurance_level{RollbackAssuranceLevel::SoftwareOnly};
    bool snapshot_rollback_protected{false};

    bool has_pending{false};
    TransactionId pending_txid{};
    std::uint64_t pending_old_revision{0};
    std::uint64_t pending_new_revision{0};
    std::uint64_t pending_new_lsn{0};
    JournalHash pending_new_record_hash{};
    CheckpointDigest pending_old_digest{};
    CheckpointDigest pending_new_digest{};
};

class IMonotonicCheckpointAnchor {
public:
    virtual ~IMonotonicCheckpointAnchor() = default;

    virtual AnchoredStoreStatus provision(
        const CheckpointTrustedBinding& binding
    ) noexcept = 0;

    virtual AnchoredStoreStatus inspect_for_recovery(
        const CheckpointTrustedBinding& binding,
        CheckpointAnchorObservation& obs_out
    ) noexcept = 0;

    virtual AnchoredStoreStatus read_committed(
        const CheckpointTrustedBinding& binding,
        CheckpointAnchorObservation& obs_out
    ) const noexcept = 0;

    virtual AnchoredStoreStatus prepare_advance(
        const CheckpointTrustedBinding& binding,
        const JournalCheckpoint& expected_current,
        const CheckpointDigest& expected_current_digest,
        const JournalCheckpoint& next,
        const CheckpointDigest& next_digest,
        TransactionId& txid_out
    ) noexcept = 0;

    virtual AnchoredStoreStatus commit_advance(
        const CheckpointTrustedBinding& binding,
        const TransactionId& txid,
        std::uint64_t next_revision,
        const CheckpointDigest& next_digest
    ) noexcept = 0;

    virtual AnchoredStoreStatus abort_advance(
        const CheckpointTrustedBinding& binding,
        const TransactionId& txid,
        std::uint64_t expected_committed_revision,
        const CheckpointDigest& expected_committed_digest
    ) noexcept = 0;
};

class FileMonotonicCheckpointAnchor final : public IMonotonicCheckpointAnchor {
public:
    static constexpr std::array<std::uint8_t, 8> kWalMagic{{
        'M', 'H', 'C', 'P', 'W', 'A', 'L', '1'
    }};
    static constexpr std::uint16_t kWalVersion = 1U;
    static constexpr std::size_t kHeaderBytes = 108U;
    static constexpr std::size_t kRecordBytes = 216U;
    static constexpr std::size_t kMaxWalBytes = 16U * 1024U * 1024U;

    enum class WalRecordType : std::uint8_t {
        Genesis = 1,
        Prepare = 2,
        Commit  = 3,
        Abort   = 4
    };

    FileMonotonicCheckpointAnchor(
        std::filesystem::path wal_path,
        v2::IMonotonicCounterV2& monotonic_counter
    ) : wal_path_(std::move(wal_path)),
        counter_(monotonic_counter) {}

    ~FileMonotonicCheckpointAnchor() override = default;

    AnchoredStoreStatus provision(
        const CheckpointTrustedBinding& binding
    ) noexcept override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::array<std::uint8_t, 32> wal_key{};
        struct KeyCleanser {
            std::array<std::uint8_t, 32>& k;
            ~KeyCleanser() { OPENSSL_cleanse(k.data(), k.size()); }
        } cleanser{wal_key};

        if (!CheckpointDigestCalculator::derive_subkey(
                binding.master_mac_key, "MH-CP-ANCHOR-WAL-V1",
                binding.trusted_anchor_id, wal_key)) {
            return AnchoredStoreStatus::BackendUnavailable;
        }

        std::error_code ec;
        const bool exists = std::filesystem::exists(wal_path_, ec);
        if (ec) return AnchoredStoreStatus::BackendUnavailable;
        if (exists) return AnchoredStoreStatus::Conflict;

        std::uint64_t counter_val = 0;
        if (counter_.read(counter_val) != v2::AnchorStatus::Ok || counter_val != 0) {
            return AnchoredStoreStatus::RollbackDetected;
        }

        CheckpointDigest genesis_digest{};
        if (!CheckpointDigestCalculator::compute_genesis_digest(
                binding.trusted_anchor_id,
                binding.expected_counter_origin,
                binding.expected_generation_origin,
                genesis_digest)) {
            return AnchoredStoreStatus::BackendUnavailable;
        }

        std::array<std::uint8_t, kHeaderBytes> hdr{};
        std::copy(kWalMagic.begin(), kWalMagic.end(), hdr.begin());
        CheckpointDigestCalculator::write_be16(hdr.data() + 8, kWalVersion);
        std::copy(binding.trusted_anchor_id.begin(), binding.trusted_anchor_id.end(), hdr.begin() + 12);
        CheckpointDigestCalculator::write_be64(hdr.data() + 28, binding.expected_counter_origin);
        CheckpointDigestCalculator::write_be64(hdr.data() + 36, binding.expected_generation_origin);
        std::copy(genesis_digest.begin(), genesis_digest.end(), hdr.begin() + 44);

        CheckpointDigest hdr_mac{};
        if (!CheckpointDigestCalculator::hmac_sha256(
                wal_key.data(), wal_key.size(), hdr.data(), 76U, hdr_mac)) {
            return AnchoredStoreStatus::BackendUnavailable;
        }
        std::copy(hdr_mac.begin(), hdr_mac.end(), hdr.begin() + 76);

        TransactionId genesis_tx{};
        if (RAND_bytes(genesis_tx.data(), static_cast<int>(genesis_tx.size())) != 1) {
            return AnchoredStoreStatus::BackendUnavailable;
        }

        std::array<std::uint8_t, kRecordBytes> gen_rec{};
        if (!encode_wal_record(
                WalRecordType::Genesis, 1U, genesis_tx,
                0, 0, 0, JournalIntegrity::genesis_hash(),
                genesis_digest, genesis_digest,
                CheckpointDigestCalculator::zero_digest(),
                wal_key, gen_rec)) {
            return AnchoredStoreStatus::BackendUnavailable;
        }

        try {
            std::vector<std::uint8_t> initial_wal;
            initial_wal.reserve(kHeaderBytes + kRecordBytes);
            initial_wal.insert(initial_wal.end(), hdr.begin(), hdr.end());
            initial_wal.insert(initial_wal.end(), gen_rec.begin(), gen_rec.end());

            return write_entire_wal_durable(wal_path_, initial_wal)
                ? AnchoredStoreStatus::Ok
                : AnchoredStoreStatus::BackendUnavailable;
        } catch (...) {
            return AnchoredStoreStatus::BackendUnavailable;
        }
    }

    AnchoredStoreStatus inspect_for_recovery(
        const CheckpointTrustedBinding& binding,
        CheckpointAnchorObservation& obs_out
    ) noexcept override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::array<std::uint8_t, 32> wal_key{};
        struct KeyCleanser {
            std::array<std::uint8_t, 32>& k;
            ~KeyCleanser() { OPENSSL_cleanse(k.data(), k.size()); }
        } cleanser{wal_key};

        if (!CheckpointDigestCalculator::derive_subkey(
                binding.master_mac_key, "MH-CP-ANCHOR-WAL-V1",
                binding.trusted_anchor_id, wal_key)) {
            return AnchoredStoreStatus::BackendUnavailable;
        }

        std::size_t valid_bytes = 0;
        bool has_partial_tail = false;
        const AnchoredStoreStatus st = parse_and_verify_wal(
            binding, wal_key, obs_out, valid_bytes, has_partial_tail);
        if (st != AnchoredStoreStatus::Ok) {
            return st;
        }

        std::uint64_t counter_val = 0;
        if (counter_.read(counter_val) != v2::AnchorStatus::Ok) {
            return AnchoredStoreStatus::BackendUnavailable;
        }
        if (!obs_out.has_pending) {
            if (counter_val != obs_out.committed_revision) {
                return AnchoredStoreStatus::RollbackDetected;
            }
        } else {
            if (counter_val != obs_out.pending_old_revision &&
                counter_val != obs_out.pending_new_revision) {
                return AnchoredStoreStatus::RollbackDetected;
            }
        }

        if (has_partial_tail) {
            if (!truncate_and_sync_wal(wal_path_, valid_bytes)) {
                return AnchoredStoreStatus::BackendUnavailable;
            }
        }
        return AnchoredStoreStatus::Ok;
    }

    AnchoredStoreStatus read_committed(
        const CheckpointTrustedBinding& binding,
        CheckpointAnchorObservation& obs_out
    ) const noexcept override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::array<std::uint8_t, 32> wal_key{};
        struct KeyCleanser {
            std::array<std::uint8_t, 32>& k;
            ~KeyCleanser() { OPENSSL_cleanse(k.data(), k.size()); }
        } cleanser{wal_key};

        if (!CheckpointDigestCalculator::derive_subkey(
                binding.master_mac_key, "MH-CP-ANCHOR-WAL-V1",
                binding.trusted_anchor_id, wal_key)) {
            return AnchoredStoreStatus::BackendUnavailable;
        }

        std::size_t valid_bytes = 0;
        bool has_partial_tail = false;
        const AnchoredStoreStatus st = parse_and_verify_wal(
            binding, wal_key, obs_out, valid_bytes, has_partial_tail);
        if (st != AnchoredStoreStatus::Ok) {
            return st;
        }
        if (has_partial_tail || obs_out.has_pending) {
            return AnchoredStoreStatus::RecoveryRequired;
        }

        std::uint64_t counter_val = 0;
        if (counter_.read(counter_val) != v2::AnchorStatus::Ok) {
            return AnchoredStoreStatus::BackendUnavailable;
        }
        if (counter_val != obs_out.committed_revision) {
            return AnchoredStoreStatus::RollbackDetected;
        }
        return AnchoredStoreStatus::Ok;
    }

    AnchoredStoreStatus prepare_advance(
        const CheckpointTrustedBinding& binding,
        const JournalCheckpoint& expected_current,
        const CheckpointDigest& expected_current_digest,
        const JournalCheckpoint& next,
        const CheckpointDigest& next_digest,
        TransactionId& txid_out
    ) noexcept override {
        std::lock_guard<std::mutex> lock(mutex_);
        txid_out = {};

        std::array<std::uint8_t, 32> wal_key{};
        struct KeyCleanser {
            std::array<std::uint8_t, 32>& k;
            ~KeyCleanser() { OPENSSL_cleanse(k.data(), k.size()); }
        } cleanser{wal_key};

        if (!CheckpointDigestCalculator::derive_subkey(
                binding.master_mac_key, "MH-CP-ANCHOR-WAL-V1",
                binding.trusted_anchor_id, wal_key)) {
            return AnchoredStoreStatus::BackendUnavailable;
        }

        CheckpointAnchorObservation obs{};
        std::size_t valid_bytes = 0;
        bool has_partial_tail = false;
        const AnchoredStoreStatus st = parse_and_verify_wal(
            binding, wal_key, obs, valid_bytes, has_partial_tail);
        if (st != AnchoredStoreStatus::Ok) return st;
        if (has_partial_tail || obs.has_pending) {
            return AnchoredStoreStatus::RecoveryRequired;
        }

        std::uint64_t counter_val = 0;
        if (counter_.read(counter_val) != v2::AnchorStatus::Ok) {
            return AnchoredStoreStatus::BackendUnavailable;
        }
        if (counter_val != obs.committed_revision) {
            return AnchoredStoreStatus::RollbackDetected;
        }
        if (obs.committed_revision != expected_current.revision ||
            obs.committed_lsn != expected_current.lsn ||
            !CheckpointDigestCalculator::constant_time_equal(
                obs.committed_digest, expected_current_digest)) {
            return AnchoredStoreStatus::Conflict;
        }
        if (obs.committed_revision == (std::numeric_limits<std::uint64_t>::max)() ||
            next.revision != obs.committed_revision + 1U) {
            return AnchoredStoreStatus::Conflict;
        }

        if (RAND_bytes(txid_out.data(), static_cast<int>(txid_out.size())) != 1) {
            return AnchoredStoreStatus::BackendUnavailable;
        }

        std::array<std::uint8_t, kRecordBytes> rec{};
        if (!encode_wal_record(
                WalRecordType::Prepare, obs.wal_sequence + 1U, txid_out,
                obs.committed_revision, next.revision,
                next.lsn, next.record_hash,
                obs.committed_digest, next_digest,
                obs.wal_head, wal_key, rec)) {
            return AnchoredStoreStatus::BackendUnavailable;
        }

        return append_wal_record_durable(wal_path_, rec)
            ? AnchoredStoreStatus::Ok
            : AnchoredStoreStatus::BackendUnavailable;
    }

    AnchoredStoreStatus commit_advance(
        const CheckpointTrustedBinding& binding,
        const TransactionId& txid,
        std::uint64_t next_revision,
        const CheckpointDigest& next_digest
    ) noexcept override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::array<std::uint8_t, 32> wal_key{};
        struct KeyCleanser {
            std::array<std::uint8_t, 32>& k;
            ~KeyCleanser() { OPENSSL_cleanse(k.data(), k.size()); }
        } cleanser{wal_key};

        if (!CheckpointDigestCalculator::derive_subkey(
                binding.master_mac_key, "MH-CP-ANCHOR-WAL-V1",
                binding.trusted_anchor_id, wal_key)) {
            return AnchoredStoreStatus::BackendUnavailable;
        }

        CheckpointAnchorObservation obs{};
        std::size_t valid_bytes = 0;
        bool has_partial_tail = false;
        const AnchoredStoreStatus st = parse_and_verify_wal(
            binding, wal_key, obs, valid_bytes, has_partial_tail);
        if (st != AnchoredStoreStatus::Ok) return st;
        if (has_partial_tail) return AnchoredStoreStatus::RecoveryRequired;

        if (!obs.has_pending || obs.pending_txid != txid ||
            obs.pending_new_revision != next_revision ||
            !CheckpointDigestCalculator::constant_time_equal(
                obs.pending_new_digest, next_digest)) {
            return AnchoredStoreStatus::Conflict;
        }

        std::uint64_t counter_val = 0;
        if (counter_.read(counter_val) != v2::AnchorStatus::Ok) {
            return AnchoredStoreStatus::BackendUnavailable;
        }
        if (counter_val == obs.pending_old_revision) {
            const auto adv = counter_.advance(obs.pending_old_revision);
            if (adv == v2::CounterAdvanceResult::Indeterminate) {
                return AnchoredStoreStatus::RecoveryRequired;
            }
            if (adv == v2::CounterAdvanceResult::NotApplied) {
                return AnchoredStoreStatus::BackendUnavailable;
            }
        } else if (counter_val != obs.pending_new_revision) {
            return AnchoredStoreStatus::RollbackDetected;
        }

        std::array<std::uint8_t, kRecordBytes> rec{};
        if (!encode_wal_record(
                WalRecordType::Commit, obs.wal_sequence + 1U, txid,
                obs.pending_old_revision, obs.pending_new_revision,
                obs.pending_new_lsn, obs.pending_new_record_hash,
                obs.pending_old_digest, obs.pending_new_digest,
                obs.wal_head, wal_key, rec)) {
            return AnchoredStoreStatus::BackendUnavailable;
        }

        return append_wal_record_durable(wal_path_, rec)
            ? AnchoredStoreStatus::Ok
            : AnchoredStoreStatus::RecoveryRequired;
    }

    AnchoredStoreStatus abort_advance(
        const CheckpointTrustedBinding& binding,
        const TransactionId& txid,
        std::uint64_t expected_committed_revision,
        const CheckpointDigest& expected_committed_digest
    ) noexcept override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::array<std::uint8_t, 32> wal_key{};
        struct KeyCleanser {
            std::array<std::uint8_t, 32>& k;
            ~KeyCleanser() { OPENSSL_cleanse(k.data(), k.size()); }
        } cleanser{wal_key};

        if (!CheckpointDigestCalculator::derive_subkey(
                binding.master_mac_key, "MH-CP-ANCHOR-WAL-V1",
                binding.trusted_anchor_id, wal_key)) {
            return AnchoredStoreStatus::BackendUnavailable;
        }

        CheckpointAnchorObservation obs{};
        std::size_t valid_bytes = 0;
        bool has_partial_tail = false;
        const AnchoredStoreStatus st = parse_and_verify_wal(
            binding, wal_key, obs, valid_bytes, has_partial_tail);
        if (st != AnchoredStoreStatus::Ok) return st;
        if (has_partial_tail) return AnchoredStoreStatus::RecoveryRequired;

        if (!obs.has_pending || obs.pending_txid != txid ||
            obs.committed_revision != expected_committed_revision ||
            !CheckpointDigestCalculator::constant_time_equal(
                obs.committed_digest, expected_committed_digest)) {
            return AnchoredStoreStatus::Conflict;
        }

        std::uint64_t counter_val = 0;
        if (counter_.read(counter_val) != v2::AnchorStatus::Ok) {
            return AnchoredStoreStatus::BackendUnavailable;
        }
        if (counter_val != obs.committed_revision) {
            return AnchoredStoreStatus::RollbackDetected;
        }

        std::array<std::uint8_t, kRecordBytes> rec{};
        if (!encode_wal_record(
                WalRecordType::Abort, obs.wal_sequence + 1U, txid,
                obs.committed_revision, obs.committed_revision,
                obs.committed_lsn, obs.committed_record_hash,
                obs.committed_digest, obs.committed_digest,
                obs.wal_head, wal_key, rec)) {
            return AnchoredStoreStatus::BackendUnavailable;
        }

        return append_wal_record_durable(wal_path_, rec)
            ? AnchoredStoreStatus::Ok
            : AnchoredStoreStatus::RecoveryRequired;
    }

private:
    AnchoredStoreStatus parse_and_verify_wal(
        const CheckpointTrustedBinding& binding,
        const std::array<std::uint8_t, 32>& wal_key,
        CheckpointAnchorObservation& obs_out,
        std::size_t& valid_bytes_out,
        bool& partial_tail_out
    ) const noexcept {
        obs_out = {};
        valid_bytes_out = 0;
        partial_tail_out = false;

        std::error_code ec;
        const bool exists = std::filesystem::exists(wal_path_, ec);
        if (ec) return AnchoredStoreStatus::BackendUnavailable;
        if (!exists) return AnchoredStoreStatus::NotFound;

        try {
            std::ifstream ifs(wal_path_, std::ios::binary | std::ios::ate);
            if (!ifs.is_open()) return AnchoredStoreStatus::BackendUnavailable;
            const auto raw_size = ifs.tellg();
            if (raw_size < static_cast<std::streampos>(kHeaderBytes) ||
                static_cast<std::size_t>(raw_size) > kMaxWalBytes) {
                return AnchoredStoreStatus::Corrupt;
            }
            const std::size_t total_size = static_cast<std::size_t>(raw_size);
            ifs.seekg(0, std::ios::beg);
            std::vector<std::uint8_t> buf(total_size);
            ifs.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(total_size));
            if (ifs.gcount() != static_cast<std::streamsize>(total_size)) {
                return AnchoredStoreStatus::BackendUnavailable;
            }

            if (!std::equal(kWalMagic.begin(), kWalMagic.end(), buf.begin())) {
                return AnchoredStoreStatus::Corrupt;
            }
            if (CheckpointDigestCalculator::read_be16(buf.data() + 8) != kWalVersion ||
                CheckpointDigestCalculator::read_be16(buf.data() + 10) != 0U) {
                return AnchoredStoreStatus::Corrupt;
            }

            AnchorId file_anchor_id{};
            std::copy(buf.begin() + 12, buf.begin() + 28, file_anchor_id.begin());
            const std::uint64_t cnt_origin = CheckpointDigestCalculator::read_be64(buf.data() + 28);
            const std::uint64_t gen_origin = CheckpointDigestCalculator::read_be64(buf.data() + 36);

            if (file_anchor_id != binding.trusted_anchor_id ||
                cnt_origin != binding.expected_counter_origin ||
                gen_origin != binding.expected_generation_origin) {
                return AnchoredStoreStatus::AuthenticationFailed;
            }

            CheckpointDigest expected_hdr_mac{};
            if (!CheckpointDigestCalculator::hmac_sha256(
                    wal_key.data(), wal_key.size(), buf.data(), 76U, expected_hdr_mac)) {
                return AnchoredStoreStatus::BackendUnavailable;
            }
            CheckpointDigest actual_hdr_mac{};
            std::copy(buf.begin() + 76, buf.begin() + 108, actual_hdr_mac.begin());
            if (!CheckpointDigestCalculator::constant_time_equal(expected_hdr_mac, actual_hdr_mac)) {
                return AnchoredStoreStatus::AuthenticationFailed;
            }

            obs_out.anchor_id = file_anchor_id;
            obs_out.counter_origin = cnt_origin;
            obs_out.generation_origin = gen_origin;
            std::copy(buf.begin() + 44, buf.begin() + 76, obs_out.committed_digest.begin());
            obs_out.committed_record_hash = JournalIntegrity::genesis_hash();
            obs_out.wal_sequence = 0;
            obs_out.wal_head = CheckpointDigestCalculator::zero_digest();

            obs_out.assurance_level = binding.has_external_monotonic_anchor
                ? RollbackAssuranceLevel::ExternalMonotonicAnchor
                : RollbackAssuranceLevel::SoftwareOnly;
            obs_out.snapshot_rollback_protected = binding.has_external_monotonic_anchor;

            std::size_t offset = kHeaderBytes;
            while (offset < buf.size()) {
                const std::size_t remaining = buf.size() - offset;
                if (remaining < kRecordBytes) {
                    partial_tail_out = true;
                    break;
                }

                const std::uint8_t* rec = buf.data() + offset;

                for (std::size_t r = 1; r < 8; ++r) {
                    if (rec[r] != 0) return AnchoredStoreStatus::Corrupt;
                }

                CheckpointDigest expected_rec_mac{};
                if (!CheckpointDigestCalculator::hmac_sha256(
                        wal_key.data(), wal_key.size(), rec, 184U, expected_rec_mac)) {
                    return AnchoredStoreStatus::BackendUnavailable;
                }
                CheckpointDigest actual_rec_mac{};
                std::copy(rec + 184U, rec + 216U, actual_rec_mac.begin());
                if (!CheckpointDigestCalculator::constant_time_equal(expected_rec_mac, actual_rec_mac)) {
                    return AnchoredStoreStatus::AuthenticationFailed;
                }

                const auto rtype = static_cast<WalRecordType>(rec[0]);
                const std::uint64_t seq = CheckpointDigestCalculator::read_be64(rec + 8U);
                if (seq != obs_out.wal_sequence + 1U) {
                    return AnchoredStoreStatus::Corrupt;
                }

                CheckpointDigest prev_head{};
                std::copy(rec + 152U, rec + 184U, prev_head.begin());
                if (!CheckpointDigestCalculator::constant_time_equal(prev_head, obs_out.wal_head)) {
                    return AnchoredStoreStatus::Corrupt;
                }

                TransactionId txid{};
                std::copy(rec + 16U, rec + 32U, txid.begin());
                const std::uint64_t old_rev = CheckpointDigestCalculator::read_be64(rec + 32U);
                const std::uint64_t new_rev = CheckpointDigestCalculator::read_be64(rec + 40U);
                const std::uint64_t new_lsn = CheckpointDigestCalculator::read_be64(rec + 48U);
                JournalHash new_rhash{};
                std::copy(rec + 56U, rec + 88U, new_rhash.begin());
                CheckpointDigest old_dig{};
                std::copy(rec + 88U, rec + 120U, old_dig.begin());
                CheckpointDigest new_dig{};
                std::copy(rec + 120U, rec + 152U, new_dig.begin());

                if (seq == 1U) {
                    if (rtype != WalRecordType::Genesis ||
                        old_rev != 0 || new_rev != 0 || new_lsn != 0 ||
                        new_rhash != JournalIntegrity::genesis_hash() ||
                        !CheckpointDigestCalculator::constant_time_equal(
                            old_dig, obs_out.committed_digest) ||
                        !CheckpointDigestCalculator::constant_time_equal(
                            new_dig, obs_out.committed_digest)) {
                        return AnchoredStoreStatus::Corrupt;
                    }
                } else {
                    switch (rtype) {
                        case WalRecordType::Prepare: {
                            if (obs_out.has_pending ||
                                old_rev != obs_out.committed_revision ||
                                obs_out.committed_revision == (std::numeric_limits<std::uint64_t>::max)() ||
                                new_rev != obs_out.committed_revision + 1U ||
                                new_lsn < obs_out.committed_lsn ||
                                !CheckpointDigestCalculator::constant_time_equal(
                                    old_dig, obs_out.committed_digest)) {
                                return AnchoredStoreStatus::Corrupt;
                            }
                            obs_out.has_pending = true;
                            obs_out.pending_txid = txid;
                            obs_out.pending_old_revision = old_rev;
                            obs_out.pending_new_revision = new_rev;
                            obs_out.pending_new_lsn = new_lsn;
                            obs_out.pending_new_record_hash = new_rhash;
                            obs_out.pending_old_digest = old_dig;
                            obs_out.pending_new_digest = new_dig;
                            break;
                        }
                        case WalRecordType::Commit: {
                            if (!obs_out.has_pending ||
                                txid != obs_out.pending_txid ||
                                old_rev != obs_out.pending_old_revision ||
                                new_rev != obs_out.pending_new_revision ||
                                new_lsn != obs_out.pending_new_lsn ||
                                new_rhash != obs_out.pending_new_record_hash ||
                                !CheckpointDigestCalculator::constant_time_equal(
                                    old_dig, obs_out.pending_old_digest) ||
                                !CheckpointDigestCalculator::constant_time_equal(
                                    new_dig, obs_out.pending_new_digest)) {
                                return AnchoredStoreStatus::Corrupt;
                            }
                            obs_out.committed_revision = new_rev;
                            obs_out.committed_lsn = new_lsn;
                            obs_out.committed_record_hash = new_rhash;
                            obs_out.committed_digest = new_dig;
                            obs_out.has_pending = false;
                            obs_out.pending_txid = {};
                            break;
                        }
                        case WalRecordType::Abort: {
                            if (!obs_out.has_pending ||
                                txid != obs_out.pending_txid ||
                                old_rev != obs_out.committed_revision ||
                                new_rev != obs_out.committed_revision ||
                                new_lsn != obs_out.committed_lsn ||
                                new_rhash != obs_out.committed_record_hash ||
                                !CheckpointDigestCalculator::constant_time_equal(
                                    old_dig, obs_out.committed_digest) ||
                                !CheckpointDigestCalculator::constant_time_equal(
                                    new_dig, obs_out.committed_digest)) {
                                return AnchoredStoreStatus::Corrupt;
                            }
                            obs_out.has_pending = false;
                            obs_out.pending_txid = {};
                            break;
                        }
                        case WalRecordType::Genesis:
                        default:
                            return AnchoredStoreStatus::Corrupt;
                    }
                }

                CheckpointDigest next_head{};
                if (!CheckpointDigestCalculator::sha256(rec, kRecordBytes, next_head)) {
                    return AnchoredStoreStatus::BackendUnavailable;
                }
                obs_out.wal_sequence = seq;
                obs_out.wal_head = next_head;
                offset += kRecordBytes;
            }

            if (obs_out.wal_sequence == 0) {
                return AnchoredStoreStatus::Corrupt;
            }

            valid_bytes_out = offset;
            return AnchoredStoreStatus::Ok;
        } catch (...) {
            return AnchoredStoreStatus::BackendUnavailable;
        }
    }

    static bool encode_wal_record(
        WalRecordType type,
        std::uint64_t seq,
        const TransactionId& txid,
        std::uint64_t old_rev,
        std::uint64_t new_rev,
        std::uint64_t new_lsn,
        const JournalHash& new_rhash,
        const CheckpointDigest& old_dig,
        const CheckpointDigest& new_dig,
        const CheckpointDigest& prev_head,
        const std::array<std::uint8_t, 32>& wal_key,
        std::array<std::uint8_t, kRecordBytes>& out
    ) noexcept {
        out.fill(0);
        out[0] = static_cast<std::uint8_t>(type);
        CheckpointDigestCalculator::write_be64(out.data() + 8, seq);
        std::copy(txid.begin(), txid.end(), out.begin() + 16);
        CheckpointDigestCalculator::write_be64(out.data() + 32, old_rev);
        CheckpointDigestCalculator::write_be64(out.data() + 40, new_rev);
        CheckpointDigestCalculator::write_be64(out.data() + 48, new_lsn);
        std::copy(new_rhash.begin(), new_rhash.end(), out.begin() + 56);
        std::copy(old_dig.begin(), old_dig.end(), out.begin() + 88);
        std::copy(new_dig.begin(), new_dig.end(), out.begin() + 120);
        std::copy(prev_head.begin(), prev_head.end(), out.begin() + 152);

        CheckpointDigest mac{};
        if (!CheckpointDigestCalculator::hmac_sha256(
                wal_key.data(), wal_key.size(), out.data(), 184U, mac)) {
            return false;
        }
        std::copy(mac.begin(), mac.end(), out.begin() + 184);
        return true;
    }

    static bool write_entire_wal_durable(
        const std::filesystem::path& path,
        const std::vector<std::uint8_t>& bytes
    ) noexcept {
        try {
#ifdef _WIN32
            HANDLE h = ::CreateFileW(
                path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h == INVALID_HANDLE_VALUE) return false;
            DWORD written = 0;
            const bool ok =
                ::WriteFile(h, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) != 0 &&
                written == bytes.size() && ::FlushFileBuffers(h) != 0;
            const bool closed = ::CloseHandle(h) != 0;
            return ok && closed;
#else
            const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
            if (fd < 0) return false;
            std::size_t off = 0;
            bool ok = true;
            while (off < bytes.size()) {
                const ssize_t n = ::write(fd, bytes.data() + off, bytes.size() - off);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0) { ok = false; break; }
                off += static_cast<std::size_t>(n);
            }
            if (ok && ::fsync(fd) != 0) ok = false;
            const bool closed = ::close(fd) == 0;
            if (!ok || !closed) return false;
            auto parent = path.parent_path();
            if (parent.empty()) parent = ".";
            const int pfd = ::open(parent.c_str(), O_RDONLY);
            if (pfd < 0) return false;
            const bool psync = ::fsync(pfd) == 0;
            const bool pclose = ::close(pfd) == 0;
            return psync && pclose;
#endif
        } catch (...) {
            return false;
        }
    }

    static bool append_wal_record_durable(
        const std::filesystem::path& path,
        const std::array<std::uint8_t, kRecordBytes>& rec
    ) noexcept {
        try {
#ifdef _WIN32
            HANDLE h = ::CreateFileW(
                path.c_str(), FILE_APPEND_DATA, 0, nullptr, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h == INVALID_HANDLE_VALUE) return false;
            DWORD written = 0;
            const bool ok =
                ::WriteFile(h, rec.data(), static_cast<DWORD>(rec.size()), &written, nullptr) != 0 &&
                written == rec.size() && ::FlushFileBuffers(h) != 0;
            const bool closed = ::CloseHandle(h) != 0;
            return ok && closed;
#else
            const int fd = ::open(path.c_str(), O_WRONLY | O_APPEND);
            if (fd < 0) return false;
            std::size_t off = 0;
            bool ok = true;
            while (off < rec.size()) {
                const ssize_t n = ::write(fd, rec.data() + off, rec.size() - off);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0) { ok = false; break; }
                off += static_cast<std::size_t>(n);
            }
            if (ok && ::fsync(fd) != 0) ok = false;
            const bool closed = ::close(fd) == 0;
            return ok && closed;
#endif
        } catch (...) {
            return false;
        }
    }

    static bool truncate_and_sync_wal(
        const std::filesystem::path& path,
        std::size_t valid_bytes
    ) noexcept {
        try {
#ifdef _WIN32
            HANDLE h = ::CreateFileW(
                path.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h == INVALID_HANDLE_VALUE) return false;
            LARGE_INTEGER li{};
            li.QuadPart = static_cast<LONGLONG>(valid_bytes);
            const bool ok =
                ::SetFilePointerEx(h, li, nullptr, FILE_BEGIN) != 0 &&
                ::SetEndOfFile(h) != 0 &&
                ::FlushFileBuffers(h) != 0;
            const bool closed = ::CloseHandle(h) != 0;
            return ok && closed;
#else
            const int fd = ::open(path.c_str(), O_WRONLY);
            if (fd < 0) return false;
            const bool ok = (::ftruncate(fd, static_cast<off_t>(valid_bytes)) == 0) &&
                            (::fsync(fd) == 0);
            const bool closed = ::close(fd) == 0;
            return ok && closed;
#endif
        } catch (...) {
            return false;
        }
    }

    std::filesystem::path wal_path_;
    v2::IMonotonicCounterV2& counter_;
    mutable std::mutex mutex_;
};

} // namespace mother_h::journal

#endif // MOTHER_H_JOURNAL_MONOTONIC_CHECKPOINT_ANCHOR_HPP