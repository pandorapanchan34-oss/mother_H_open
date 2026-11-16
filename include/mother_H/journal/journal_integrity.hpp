#pragma once

#include "mother_H/journal/secure_key_provider.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace mother_h::journal {

using JournalHash = std::array<std::uint8_t, 32>;

struct JournalRecord {
    std::uint64_t lsn{0};
    std::string timestamp_utc;
    KeyReference key;
    JournalHash previous_record_hash{};
    std::string payload;
    JournalHash hmac_sha256{};
};

struct JournalCheckpoint {
    std::uint64_t lsn{0};
    JournalHash record_hash{};
    std::uint64_t revision{0};
};

struct JournalStorageIdentity {
    // Opaque canonical identifiers supplied by the Journal storage adapter.
    // object_id must resolve aliases such as hardlinks and symlinks.
    std::string backend_id;
    std::string object_id;
    // Identifies the snapshot/restore or administrative rollback boundary.
    std::string rollback_domain_id;
    bool verified{false};
};

enum class CheckpointStatus : std::uint8_t {
    Ok,
    NotFound,
    Conflict,
    BackendUnavailable
};

enum class CheckpointIsolation : std::uint8_t {
    Independent,
    SameStorage,
    SameRollbackDomain,
    Unverified,
    BackendUnavailable
};

class IJournalCheckpointStore {
public:
    virtual ~IJournalCheckpointStore() = default;

    // Must compare canonical backing-store identities, not path strings.
    // Implementations must resolve aliases such as symlinks and hardlinks and
    // reject a checkpoint in the Journal's rollback/trust domain. Returning
    // Independent is a trusted-backend attestation, not a property this
    // interface can establish by itself.
    virtual CheckpointIsolation verify_independence(
        const JournalStorageIdentity& journal_storage
    ) const noexcept {
        (void)journal_storage;
        return CheckpointIsolation::Unverified;
    }

    virtual CheckpointStatus load(JournalCheckpoint& out) const noexcept = 0;
    // Must atomically compare the complete expected checkpoint and only
    // replace it with a strictly newer revision and LSN.
    virtual CheckpointStatus compare_and_advance(
        const JournalCheckpoint& expected,
        const JournalCheckpoint& next
    ) noexcept = 0;
};

enum class IntegrityStatus : std::uint8_t {
    Ok,
    InvalidRecord,
    InvalidTimestamp,
    InvalidKeyReference,
    KeyUnavailable,
    KeyRevoked,
    KeyProviderUnavailable,
    HmacFailure,
    HmacMismatch,
    LsnOutOfOrder,
    ChainMismatch,
    CheckpointUnavailable,
    CheckpointIsolationUnverified,
    CheckpointSharesStorage,
    CheckpointSharesRollbackDomain,
    CheckpointInvalid,
    RollbackDetected,
    CheckpointUpdateFailed
};

struct IntegrityResult {
    IntegrityStatus status{IntegrityStatus::Ok};
    JournalHash record_hash{};

    explicit operator bool() const noexcept {
        return status == IntegrityStatus::Ok;
    }
};

class JournalIntegrity {
public:
    static constexpr std::size_t kHmacSize = 32;
    static constexpr std::size_t kMaxKeyIdBytes = 128;
    static constexpr std::uint8_t kFormatVersion = 1;

    static JournalHash genesis_hash() noexcept { return {}; }

    static IntegrityResult seal(
        JournalRecord& record,
        std::uint64_t expected_lsn,
        const JournalHash& previous_record_hash,
        const ISecureKeyProvider& keys
    ) {
        static_assert(
            std::is_nothrow_move_assignable<JournalRecord>::value,
            "JournalRecord commit must not throw");
        if (expected_lsn == 0 || record.lsn != expected_lsn) {
            return {IntegrityStatus::LsnOutOfOrder, {}};
        }
        JournalRecord candidate = record;
        candidate.previous_record_hash = previous_record_hash;

        KeyMaterial key;
        const KeyStatus key_status = keys.current_signing_key(key);
        const IntegrityStatus mapped = map_key_status(key_status);
        if (mapped != IntegrityStatus::Ok) return {mapped, {}};
        if (!valid_key_reference(key.reference()) || key.secret().size() < kHmacSize) {
            return {IntegrityStatus::InvalidKeyReference, {}};
        }
        candidate.key = key.reference();

        std::vector<std::uint8_t> canonical;
        const IntegrityStatus canonical_status = canonical_bytes(candidate, canonical);
        if (canonical_status != IntegrityStatus::Ok) {
            return {canonical_status, {}};
        }
        if (!calculate_hmac(canonical, key.secret(), candidate.hmac_sha256)) {
            return {IntegrityStatus::HmacFailure, {}};
        }
        JournalHash hash{};
        if (!calculate_record_hash(canonical, candidate.hmac_sha256, hash)) {
            return {IntegrityStatus::HmacFailure, {}};
        }
        record = std::move(candidate);
        return {IntegrityStatus::Ok, hash};
    }

    static IntegrityResult verify(
        const JournalRecord& record,
        std::uint64_t expected_lsn,
        const JournalHash& expected_previous_hash,
        const ISecureKeyProvider& keys
    ) {
        if (record.lsn == 0 || record.lsn != expected_lsn) {
            return {IntegrityStatus::LsnOutOfOrder, {}};
        }
        if (!hash_equal(record.previous_record_hash, expected_previous_hash)) {
            return {IntegrityStatus::ChainMismatch, {}};
        }
        if (!valid_key_reference(record.key)) {
            return {IntegrityStatus::InvalidKeyReference, {}};
        }

        KeyMaterial key;
        const KeyStatus key_status = keys.verification_key(record.key, key);
        const IntegrityStatus mapped = map_key_status(key_status);
        if (mapped != IntegrityStatus::Ok) return {mapped, {}};
        if (key.reference() != record.key || key.secret().size() < kHmacSize) {
            return {IntegrityStatus::InvalidKeyReference, {}};
        }

        std::vector<std::uint8_t> canonical;
        const IntegrityStatus canonical_status = canonical_bytes(record, canonical);
        if (canonical_status != IntegrityStatus::Ok) {
            return {canonical_status, {}};
        }

        JournalHash calculated{};
        if (!calculate_hmac(canonical, key.secret(), calculated)) {
            return {IntegrityStatus::HmacFailure, {}};
        }
        if (!hash_equal(calculated, record.hmac_sha256)) {
            return {IntegrityStatus::HmacMismatch, {}};
        }

        JournalHash record_hash{};
        if (!calculate_record_hash(canonical, record.hmac_sha256, record_hash)) {
            return {IntegrityStatus::HmacFailure, {}};
        }
        return {IntegrityStatus::Ok, record_hash};
    }

    // Verifies the complete journal from LSN 1, checks the externally stored
    // anchor, and advances that anchor only after the entire chain is valid.
    // Callers must persist journal records before advancing the checkpoint.
    static IntegrityResult verify_chain_and_advance(
        const std::vector<JournalRecord>& records,
        const ISecureKeyProvider& keys,
        IJournalCheckpointStore& checkpoints
    ) {
        // The compatibility overload lacks storage identity and therefore
        // cannot establish anti-rollback isolation.
        return verify_chain_and_advance(
            records, keys, checkpoints, JournalStorageIdentity{});
    }

    static IntegrityResult verify_chain_and_advance(
        const std::vector<JournalRecord>& records,
        const ISecureKeyProvider& keys,
        IJournalCheckpointStore& checkpoints,
        const JournalStorageIdentity& journal_storage
    ) {
        if (!journal_storage.verified || journal_storage.backend_id.empty() ||
            journal_storage.object_id.empty() ||
            journal_storage.rollback_domain_id.empty()) {
            return {IntegrityStatus::CheckpointIsolationUnverified, {}};
        }
        switch (checkpoints.verify_independence(journal_storage)) {
            case CheckpointIsolation::Independent:
                break;
            case CheckpointIsolation::SameStorage:
                return {IntegrityStatus::CheckpointSharesStorage, {}};
            case CheckpointIsolation::SameRollbackDomain:
                return {IntegrityStatus::CheckpointSharesRollbackDomain, {}};
            case CheckpointIsolation::Unverified:
                return {IntegrityStatus::CheckpointIsolationUnverified, {}};
            case CheckpointIsolation::BackendUnavailable:
                return {IntegrityStatus::CheckpointUnavailable, {}};
        }

        JournalCheckpoint checkpoint;
        const CheckpointStatus loaded = checkpoints.load(checkpoint);
        if (loaded != CheckpointStatus::Ok) {
            return {IntegrityStatus::CheckpointUnavailable, {}};
        }
        if (checkpoint.lsn == 0 &&
            !hash_equal(checkpoint.record_hash, genesis_hash())) {
            return {IntegrityStatus::CheckpointInvalid, {}};
        }
        if (checkpoint.lsn > 0 &&
            hash_equal(checkpoint.record_hash, genesis_hash())) {
            return {IntegrityStatus::CheckpointInvalid, {}};
        }

        JournalHash previous_hash = genesis_hash();
        bool checkpoint_seen = checkpoint.lsn == 0;
        std::uint64_t expected_lsn = 1;
        for (std::size_t index = 0; index < records.size(); ++index) {
            const auto& record = records[index];
            const IntegrityResult verified =
                verify(record, expected_lsn, previous_hash, keys);
            if (!verified) return verified;
            previous_hash = verified.record_hash;

            if (record.lsn == checkpoint.lsn) {
                if (!hash_equal(previous_hash, checkpoint.record_hash)) {
                    return {IntegrityStatus::RollbackDetected, {}};
                }
                checkpoint_seen = true;
            }
            if (index + 1U < records.size()) {
                if (expected_lsn == (std::numeric_limits<std::uint64_t>::max)()) {
                    return {IntegrityStatus::LsnOutOfOrder, {}};
                }
                ++expected_lsn;
            }
        }

        const std::uint64_t last_lsn = records.empty() ? 0 : records.back().lsn;
        if (!checkpoint_seen || last_lsn < checkpoint.lsn) {
            return {IntegrityStatus::RollbackDetected, {}};
        }
        if (last_lsn == checkpoint.lsn) {
            return {IntegrityStatus::Ok, previous_hash};
        }
        if (checkpoint.revision == (std::numeric_limits<std::uint64_t>::max)()) {
            return {IntegrityStatus::CheckpointInvalid, {}};
        }

        const JournalCheckpoint next{last_lsn, previous_hash, checkpoint.revision + 1};
        const CheckpointStatus update =
            checkpoints.compare_and_advance(checkpoint, next);
        if (update == CheckpointStatus::BackendUnavailable) {
            return {IntegrityStatus::CheckpointUnavailable, {}};
        }
        if (update != CheckpointStatus::Ok) {
            return {IntegrityStatus::CheckpointUpdateFailed, {}};
        }
        return {IntegrityStatus::Ok, previous_hash};
    }

    static bool is_canonical_utc_timestamp(std::string_view value) noexcept {
        if (value.size() != 30 || value[4] != '-' || value[7] != '-' ||
            value[10] != 'T' || value[13] != ':' || value[16] != ':' ||
            value[19] != '.' || value[29] != 'Z') {
            return false;
        }
        constexpr std::size_t digit_positions[] = {
            0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18,
            20, 21, 22, 23, 24, 25, 26, 27, 28
        };
        for (const std::size_t position : digit_positions) {
            if (value[position] < '0' || value[position] > '9') return false;
        }

        const unsigned year = decimal(value, 0, 4);
        const unsigned month = decimal(value, 5, 2);
        const unsigned day = decimal(value, 8, 2);
        const unsigned hour = decimal(value, 11, 2);
        const unsigned minute = decimal(value, 14, 2);
        const unsigned second = decimal(value, 17, 2);
        if (year == 0 || month == 0 || month > 12 || hour > 23 ||
            minute > 59 || second > 59) {
            return false;
        }
        constexpr unsigned month_days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
        unsigned max_day = month_days[month - 1];
        if (month == 2 && is_leap_year(year)) ++max_day;
        return day > 0 && day <= max_day;
    }

    static bool hash_equal(const JournalHash& left, const JournalHash& right) noexcept {
        return CRYPTO_memcmp(left.data(), right.data(), left.size()) == 0;
    }

private:
    static unsigned decimal(std::string_view value, std::size_t start, std::size_t length) noexcept {
        unsigned result = 0;
        for (std::size_t i = start; i < start + length; ++i) {
            result = result * 10U + static_cast<unsigned>(value[i] - '0');
        }
        return result;
    }

    static bool is_leap_year(unsigned year) noexcept {
        return year % 4U == 0U && (year % 100U != 0U || year % 400U == 0U);
    }

    static bool valid_key_reference(const KeyReference& reference) noexcept {
        if (reference.version == 0 || reference.key_id.empty() ||
            reference.key_id.size() > kMaxKeyIdBytes) {
            return false;
        }
        for (const unsigned char c : reference.key_id) {
            const bool valid =
                (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
            if (!valid) return false;
        }
        return true;
    }

    static IntegrityStatus map_key_status(KeyStatus status) noexcept {
        switch (status) {
            case KeyStatus::Ok: return IntegrityStatus::Ok;
            case KeyStatus::NotFound: return IntegrityStatus::KeyUnavailable;
            case KeyStatus::Revoked: return IntegrityStatus::KeyRevoked;
            case KeyStatus::InvalidRequest: return IntegrityStatus::InvalidKeyReference;
            case KeyStatus::BackendUnavailable: return IntegrityStatus::KeyProviderUnavailable;
        }
        return IntegrityStatus::KeyProviderUnavailable;
    }

    static void append_u32(std::vector<std::uint8_t>& output, std::uint32_t value) {
        for (int shift = 24; shift >= 0; shift -= 8) {
            output.push_back(static_cast<std::uint8_t>(value >> shift));
        }
    }

    static void append_u64(std::vector<std::uint8_t>& output, std::uint64_t value) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            output.push_back(static_cast<std::uint8_t>(value >> shift));
        }
    }

    static void append_string(std::vector<std::uint8_t>& output, std::string_view value) {
        append_u64(output, static_cast<std::uint64_t>(value.size()));
        output.insert(output.end(), value.begin(), value.end());
    }

    static IntegrityStatus canonical_bytes(
        const JournalRecord& record,
        std::vector<std::uint8_t>& output
    ) {
        if (!valid_key_reference(record.key)) return IntegrityStatus::InvalidKeyReference;
        if (!is_canonical_utc_timestamp(record.timestamp_utc)) {
            return IntegrityStatus::InvalidTimestamp;
        }
        if (record.lsn == 0) return IntegrityStatus::InvalidRecord;

        static constexpr char domain[] = "MOTHER_H_JOURNAL_RECORD";
        output.clear();
        output.insert(output.end(), domain, domain + sizeof(domain));
        output.push_back(kFormatVersion);
        append_u64(output, record.lsn);
        append_u32(output, record.key.version);
        append_string(output, record.key.key_id);
        append_string(output, record.timestamp_utc);
        output.insert(output.end(),
                      record.previous_record_hash.begin(),
                      record.previous_record_hash.end());
        append_string(output, record.payload);
        return IntegrityStatus::Ok;
    }

    static bool calculate_hmac(
        const std::vector<std::uint8_t>& canonical,
        const std::vector<std::uint8_t>& secret,
        JournalHash& output
    ) noexcept {
        if (secret.size() < kHmacSize ||
            secret.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
            return false;
        }
        unsigned int output_size = 0;
        const unsigned char* result = HMAC(
            EVP_sha256(),
            secret.data(),
            static_cast<int>(secret.size()),
            canonical.data(),
            canonical.size(),
            output.data(),
            &output_size);
        return result != nullptr && output_size == output.size();
    }

    static bool calculate_record_hash(
        const std::vector<std::uint8_t>& canonical,
        const JournalHash& mac,
        JournalHash& output
    ) noexcept {
        EVP_MD_CTX* context = EVP_MD_CTX_new();
        if (context == nullptr) return false;
        unsigned int output_size = 0;
        const bool ok =
            EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1 &&
            EVP_DigestUpdate(context, canonical.data(), canonical.size()) == 1 &&
            EVP_DigestUpdate(context, mac.data(), mac.size()) == 1 &&
            EVP_DigestFinal_ex(context, output.data(), &output_size) == 1 &&
            output_size == output.size();
        EVP_MD_CTX_free(context);
        return ok;
    }
};

}  // namespace mother_h::journal
