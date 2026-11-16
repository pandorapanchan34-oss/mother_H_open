#pragma once

#include "mother_H/core/phase13_4_state_policy.hpp"
#include "mother_H/journal/journal_integrity.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <chrono>
#include <ctime>
#include <cstring>
#include <iomanip>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace mb::H {

enum class JournalSinkStatus : std::uint8_t {
    Ok,
    Unavailable,
    WriteFailed
};

class IJournalRecordSink {
public:
    virtual ~IJournalRecordSink() = default;
    virtual JournalSinkStatus append_record(
        const mother_h::journal::JournalRecord& record
    ) noexcept = 0;
};

enum class EventJournalStatus : std::uint8_t {
    Ok,
    InvalidEvent,
    LsnOutOfOrder,
    IntegrityFailure,
    StorageFailure,
    InternalError
};

struct EventJournalResult {
    EventJournalStatus status{EventJournalStatus::InternalError};
    mother_h::journal::IntegrityStatus integrity_status{mother_h::journal::IntegrityStatus::Ok};
    mother_h::journal::JournalHash record_hash{};
    std::uint64_t lsn{0};

    explicit operator bool() const noexcept {
        return status == EventJournalStatus::Ok;
    }
};

class AuthenticatedEventJournal {
public:
    AuthenticatedEventJournal(
        IJournalRecordSink& sink,
        const mother_h::journal::ISecureKeyProvider& keys
    ) noexcept
        : sink_(sink), keys_(keys) {}

    EventJournalResult append(
        const mb::cqs13_4::EventPayload& event,
        std::uint64_t lsn
    ) noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            return append_locked(event, lsn);
        } catch (...) {
            return {EventJournalStatus::InternalError,
                    mother_h::journal::IntegrityStatus::Ok, {}};
        }
    }

    EventJournalResult append(const mb::cqs13_4::EventPayload& event) noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            return append_locked(event, next_lsn_);
        } catch (...) {
            return {EventJournalStatus::InternalError,
                    mother_h::journal::IntegrityStatus::Ok, {}};
        }
    }

    EventJournalResult append_encrypted(
        const mb::cqs13_4::EventPayload& event,
        const mother_h::journal::DataKeyReference& dek_ref,
        const mother_h::journal::IDataEncryptionKeyProvider& dek_provider
    ) noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            return append_encrypted_locked(event, dek_ref, dek_provider, next_lsn_);
        } catch (...) {
            return {EventJournalStatus::InternalError,
                    mother_h::journal::IntegrityStatus::Ok, {}};
        }
    }

    std::uint64_t next_lsn() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return next_lsn_;
    }

    bool resume_from_records(
        const std::vector<mother_h::journal::JournalRecord>& records,
        const mother_h::journal::IDataEncryptionKeyProvider* dek_provider
    ) noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            if (next_lsn_ != 1 || exhausted_ ||
                previous_record_hash_ !=
                    mother_h::journal::JournalIntegrity::genesis_hash()) {
                return false;
            }

            std::uint64_t expected_lsn = 1;
            auto previous_hash =
                mother_h::journal::JournalIntegrity::genesis_hash();
            bool staged_exhausted = false;
            for (std::size_t i = 0; i < records.size(); ++i) {
                const auto& record = records[i];
                const auto verified = mother_h::journal::JournalIntegrity::verify(
                    record, expected_lsn, previous_hash, keys_);
                if (!verified) return false;
                mb::cqs13_4::EventPayload event;
                bool erased = false;
                if (!decode_event_payload(record.payload, dek_provider, event, erased)) {
                    return false;
                }
                previous_hash = verified.record_hash;
                if (expected_lsn ==
                    (std::numeric_limits<std::uint64_t>::max)()) {
                    if (i + 1U != records.size()) return false;
                    staged_exhausted = true;
                } else {
                    ++expected_lsn;
                }
            }
            previous_record_hash_ = previous_hash;
            exhausted_ = staged_exhausted;
            next_lsn_ = staged_exhausted
                ? (std::numeric_limits<std::uint64_t>::max)()
                : expected_lsn;
            return true;
        } catch (...) {
            return false;
        }
    }

    bool resume_from_records(
        const std::vector<mother_h::journal::JournalRecord>& records
    ) noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            if (next_lsn_ != 1 || exhausted_ ||
                previous_record_hash_ !=
                    mother_h::journal::JournalIntegrity::genesis_hash()) {
                return false;
            }

            std::uint64_t expected_lsn = 1;
            auto previous_hash =
                mother_h::journal::JournalIntegrity::genesis_hash();
            bool staged_exhausted = false;
            for (std::size_t i = 0; i < records.size(); ++i) {
                const auto& record = records[i];
                const auto verified = mother_h::journal::JournalIntegrity::verify(
                    record, expected_lsn, previous_hash, keys_);
                if (!verified) return false;
                mb::cqs13_4::EventPayload event;
                if (!decode_event_payload(record.payload, event)) return false;
                previous_hash = verified.record_hash;
                if (expected_lsn ==
                    (std::numeric_limits<std::uint64_t>::max)()) {
                    if (i + 1U != records.size()) return false;
                    staged_exhausted = true;
                } else {
                    ++expected_lsn;
                }
            }
            previous_record_hash_ = previous_hash;
            exhausted_ = staged_exhausted;
            next_lsn_ = staged_exhausted
                ? (std::numeric_limits<std::uint64_t>::max)()
                : expected_lsn;
            return true;
        } catch (...) {
            return false;
        }
    }

    static bool encode_event_payload(
        const mb::cqs13_4::EventPayload& event,
        std::string& output
    ) {
        if (event.event_id.empty() || event.request_id.empty() ||
            event.state == mb::cqs13_4::EventState::NONE ||
            event.state == mb::cqs13_4::EventState::UNKNOWN) {
            return false;
        }

        std::string encoded("MHE1", 4);
        encoded.push_back(static_cast<char>(event.state));
        if (!append_field(encoded, event.event_id) ||
            !append_field(encoded, event.request_id) ||
            !append_field(encoded, event.parent_event_id) ||
            !append_field(encoded, event.source_concept) ||
            !append_field(encoded, event.supplement_text) ||
            !append_field(encoded, event.constraints_json)) {
            return false;
        }
        output.swap(encoded);
        return true;
    }

    static bool decode_event_payload(
        const std::string& payload,
        mb::cqs13_4::EventPayload& output
    ) {
        if (payload.size() < 5 || payload.compare(0, 4, "MHE1", 4) != 0) {
            return false;
        }
        const auto state = static_cast<mb::cqs13_4::EventState>(
            static_cast<unsigned char>(payload[4]));
        if (state < mb::cqs13_4::EventState::HELD ||
            state > mb::cqs13_4::EventState::CANCELLED) {
            return false;
        }

        std::size_t offset = 5;
        std::string fields[6];
        for (auto& field : fields) {
            if (!read_field(payload, offset, field)) return false;
        }
        if (offset != payload.size() || fields[0].empty() || fields[1].empty()) {
            return false;
        }

        mb::cqs13_4::EventPayload decoded;
        decoded.state = state;
        decoded.event_id = std::move(fields[0]);
        decoded.request_id = std::move(fields[1]);
        decoded.parent_event_id = std::move(fields[2]);
        decoded.source_concept = std::move(fields[3]);
        decoded.supplement_text = std::move(fields[4]);
        decoded.constraints_json = std::move(fields[5]);
        output = std::move(decoded);
        return true;
    }

    static constexpr std::size_t kGcmIvBytes = 12;
    static constexpr std::size_t kGcmTagBytes = 16;
    static constexpr std::size_t kMaxGcmInputBytes =
        static_cast<std::size_t>((std::numeric_limits<int>::max)() - 64);

    static bool encode_encrypted_event_payload(
        const mb::cqs13_4::EventPayload& event,
        const mother_h::journal::DataKeyReference& dek_ref,
        const mother_h::journal::IDataEncryptionKeyProvider& dek_provider,
        std::string& output
    ) {
        if (event.event_id.empty() || event.request_id.empty() ||
            event.state == mb::cqs13_4::EventState::NONE ||
            event.state == mb::cqs13_4::EventState::UNKNOWN ||
            dek_ref.key_id.empty() || dek_ref.version == 0) {
            return false;
        }

        std::string header("MHE2", 4);
        header.push_back(static_cast<char>(event.state));
        if (!append_field(header, event.event_id) ||
            !append_field(header, event.request_id) ||
            !append_field(header, event.parent_event_id) ||
            !append_field(header, dek_ref.key_id)) {
            return false;
        }
        append_u32_str(header, dek_ref.version);

        std::string plaintext;
        if (!append_field(plaintext, event.source_concept) ||
            !append_field(plaintext, event.supplement_text) ||
            !append_field(plaintext, event.constraints_json)) {
            cleanse_string(plaintext);
            return false;
        }
        if (header.size() > kMaxGcmInputBytes ||
            plaintext.size() > kMaxGcmInputBytes) {
            cleanse_string(plaintext);
            return false;
        }

        std::string encoded;
        const auto status = dek_provider.with_key(
            dek_ref,
            [&](const mother_h::journal::DataKeyMaterial& dek) -> bool {
                if (dek.secret().size() !=
                    mother_h::journal::DataKeyMaterial::kAes256KeyBytes) {
                    return false;
                }

                unsigned char iv[kGcmIvBytes];
                if (RAND_bytes(iv, static_cast<int>(kGcmIvBytes)) != 1) {
                    return false;
                }

                std::vector<unsigned char> ciphertext(plaintext.size() + 16U);
                unsigned char tag[kGcmTagBytes];
                EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
                if (ctx == nullptr) return false;

                int len = 0;
                int total_len = 0;
                bool ok =
                    EVP_EncryptInit_ex(
                        ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
                    EVP_CIPHER_CTX_ctrl(
                        ctx,
                        EVP_CTRL_GCM_SET_IVLEN,
                        static_cast<int>(kGcmIvBytes),
                        nullptr) == 1 &&
                    EVP_EncryptInit_ex(
                        ctx, nullptr, nullptr, dek.secret().data(), iv) == 1 &&
                    EVP_EncryptUpdate(
                        ctx,
                        nullptr,
                        &len,
                        reinterpret_cast<const unsigned char*>(header.data()),
                        static_cast<int>(header.size())) == 1 &&
                    (plaintext.empty() ||
                     EVP_EncryptUpdate(
                         ctx,
                         ciphertext.data(),
                         &len,
                         reinterpret_cast<const unsigned char*>(plaintext.data()),
                         static_cast<int>(plaintext.size())) == 1);
                if (ok) {
                    total_len = len;
                    ok = EVP_EncryptFinal_ex(
                        ctx, ciphertext.data() + total_len, &len) == 1;
                    total_len += len;
                }
                if (ok) {
                    ok = EVP_CIPHER_CTX_ctrl(
                        ctx,
                        EVP_CTRL_GCM_GET_TAG,
                        static_cast<int>(kGcmTagBytes),
                        tag) == 1;
                }
                EVP_CIPHER_CTX_free(ctx);
                if (!ok) return false;

                encoded = header;
                encoded.append(reinterpret_cast<const char*>(iv), kGcmIvBytes);
                encoded.append(
                    reinterpret_cast<const char*>(ciphertext.data()),
                    static_cast<std::size_t>(total_len));
                encoded.append(reinterpret_cast<const char*>(tag), kGcmTagBytes);
                return true;
            });

        cleanse_string(plaintext);
        if (status != mother_h::journal::KeyStatus::Ok) return false;
        output.swap(encoded);
        return true;
    }

    static bool decode_event_payload(
        const std::string& payload,
        const mother_h::journal::IDataEncryptionKeyProvider* dek_provider,
        mb::cqs13_4::EventPayload& output,
        bool& cryptographically_erased
    ) {
        cryptographically_erased = false;
        if (payload.size() >= 5 && payload.compare(0, 4, "MHE1", 4) == 0) {
            return decode_event_payload(payload, output);
        }
        if (payload.size() < 5 || payload.compare(0, 4, "MHE2", 4) != 0) {
            return false;
        }

        const auto state = static_cast<mb::cqs13_4::EventState>(
            static_cast<unsigned char>(payload[4]));
        if (state < mb::cqs13_4::EventState::HELD ||
            state > mb::cqs13_4::EventState::CANCELLED) {
            return false;
        }

        std::size_t offset = 5;
        std::string header_fields[4];
        for (auto& field : header_fields) {
            if (!read_field(payload, offset, field)) return false;
        }
        std::uint32_t dek_version = 0;
        if (!read_u32_str(payload, offset, dek_version)) return false;

        if (header_fields[0].empty() || header_fields[1].empty() ||
            header_fields[3].empty() || dek_version == 0) {
            return false;
        }

        const std::size_t header_end = offset;
        if (payload.size() - header_end < kGcmIvBytes + kGcmTagBytes) {
            return false;
        }
        const std::size_t cipher_len =
            payload.size() - header_end - kGcmIvBytes - kGcmTagBytes;
        if (header_end > kMaxGcmInputBytes ||
            cipher_len > kMaxGcmInputBytes) {
            return false;
        }

        mb::cqs13_4::EventPayload decoded;
        decoded.state = state;
        decoded.event_id = std::move(header_fields[0]);
        decoded.request_id = std::move(header_fields[1]);
        decoded.parent_event_id = std::move(header_fields[2]);
        if (dek_provider == nullptr) return false;

        const unsigned char* iv =
            reinterpret_cast<const unsigned char*>(payload.data() + header_end);
        const unsigned char* cipher_ptr = iv + kGcmIvBytes;
        const unsigned char* tag_ptr = cipher_ptr + cipher_len;
        std::string plaintext(cipher_len, '\0');
        const auto status = dek_provider->with_key(
            mother_h::journal::DataKeyReference{header_fields[3], dek_version},
            [&](const mother_h::journal::DataKeyMaterial& dek) -> bool {
                if (dek.secret().size() !=
                    mother_h::journal::DataKeyMaterial::kAes256KeyBytes) {
                    return false;
                }
                EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
                if (ctx == nullptr) return false;

                int len = 0;
                int total_len = 0;
                unsigned char tag_copy[kGcmTagBytes];
                std::memcpy(tag_copy, tag_ptr, kGcmTagBytes);

                bool ok =
                    EVP_DecryptInit_ex(
                        ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
                    EVP_CIPHER_CTX_ctrl(
                        ctx,
                        EVP_CTRL_GCM_SET_IVLEN,
                        static_cast<int>(kGcmIvBytes),
                        nullptr) == 1 &&
                    EVP_DecryptInit_ex(
                        ctx, nullptr, nullptr, dek.secret().data(), iv) == 1 &&
                    EVP_DecryptUpdate(
                        ctx,
                        nullptr,
                        &len,
                        reinterpret_cast<const unsigned char*>(payload.data()),
                        static_cast<int>(header_end)) == 1 &&
                    (cipher_len == 0 ||
                     EVP_DecryptUpdate(
                         ctx,
                         reinterpret_cast<unsigned char*>(plaintext.data()),
                         &len,
                         cipher_ptr,
                         static_cast<int>(cipher_len)) == 1);
                if (ok) {
                    total_len = len;
                    ok =
                        EVP_CIPHER_CTX_ctrl(
                            ctx,
                            EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(kGcmTagBytes),
                            tag_copy) == 1 &&
                        EVP_DecryptFinal_ex(
                            ctx,
                            reinterpret_cast<unsigned char*>(plaintext.data()) +
                                total_len,
                            &len) == 1;
                    total_len += len;
                }
                EVP_CIPHER_CTX_free(ctx);
                if (!ok) return false;
                plaintext.resize(static_cast<std::size_t>(total_len));
                return true;
            });

        if (status == mother_h::journal::KeyStatus::Revoked) {
            cleanse_string(plaintext);
            cryptographically_erased = true;
            output = std::move(decoded);
            return true;
        }
        if (status != mother_h::journal::KeyStatus::Ok) {
            cleanse_string(plaintext);
            return false;
        }

        std::size_t plaintext_offset = 0;
        std::string secret_fields[3];
        for (auto& field : secret_fields) {
            if (!read_field(plaintext, plaintext_offset, field)) {
                for (auto& partial : secret_fields) cleanse_string(partial);
                cleanse_string(plaintext);
                return false;
            }
        }
        const bool exact = plaintext_offset == plaintext.size();
        cleanse_string(plaintext);
        if (!exact) {
            for (auto& field : secret_fields) cleanse_string(field);
            return false;
        }

        decoded.source_concept = std::move(secret_fields[0]);
        decoded.supplement_text = std::move(secret_fields[1]);
        decoded.constraints_json = std::move(secret_fields[2]);
        output = std::move(decoded);
        return true;
    }

    static bool verify_records(
        const std::vector<mother_h::journal::JournalRecord>& records,
        const mother_h::journal::ISecureKeyProvider& keys,
        const mother_h::journal::IDataEncryptionKeyProvider* dek_provider,
        std::vector<mb::cqs13_4::EventPayload>& events,
        std::vector<bool>& erased_flags,
        mother_h::journal::IntegrityStatus& failure
    ) {
        std::vector<mb::cqs13_4::EventPayload> verified_events;
        std::vector<bool> verified_erased;
        std::uint64_t expected_lsn = 1;
        auto previous_hash =
            mother_h::journal::JournalIntegrity::genesis_hash();
        for (std::size_t index = 0; index < records.size(); ++index) {
            const auto& record = records[index];
            const auto verified = mother_h::journal::JournalIntegrity::verify(
                record, expected_lsn, previous_hash, keys);
            if (!verified) {
                failure = verified.status;
                return false;
            }
            mb::cqs13_4::EventPayload event;
            bool erased = false;
            if (!decode_event_payload(record.payload, dek_provider, event, erased)) {
                failure = mother_h::journal::IntegrityStatus::InvalidRecord;
                return false;
            }
            verified_events.push_back(std::move(event));
            verified_erased.push_back(erased);
            previous_hash = verified.record_hash;
            if (expected_lsn ==
                    (std::numeric_limits<std::uint64_t>::max)() &&
                index + 1U != records.size()) {
                failure = mother_h::journal::IntegrityStatus::LsnOutOfOrder;
                return false;
            }
            if (expected_lsn !=
                (std::numeric_limits<std::uint64_t>::max)()) {
                ++expected_lsn;
            }
        }
        events.swap(verified_events);
        erased_flags.swap(verified_erased);
        failure = mother_h::journal::IntegrityStatus::Ok;
        return true;
    }

    static bool verify_records(
        const std::vector<mother_h::journal::JournalRecord>& records,
        const mother_h::journal::ISecureKeyProvider& keys,
        std::vector<mb::cqs13_4::EventPayload>& events,
        mother_h::journal::IntegrityStatus& failure
    ) {
        std::vector<mb::cqs13_4::EventPayload> verified_events;
        auto expected_lsn = std::uint64_t{1};
        auto previous_hash = mother_h::journal::JournalIntegrity::genesis_hash();
        for (std::size_t index = 0; index < records.size(); ++index) {
            const auto& record = records[index];
            const auto verified = mother_h::journal::JournalIntegrity::verify(
                record, expected_lsn, previous_hash, keys);
            if (!verified) {
                failure = verified.status;
                return false;
            }
            mb::cqs13_4::EventPayload event;
            if (!decode_event_payload(record.payload, event)) {
                failure = mother_h::journal::IntegrityStatus::InvalidRecord;
                return false;
            }
            verified_events.push_back(std::move(event));
            previous_hash = verified.record_hash;
            if (expected_lsn == (std::numeric_limits<std::uint64_t>::max)() &&
                index + 1U != records.size()) {
                failure = mother_h::journal::IntegrityStatus::LsnOutOfOrder;
                return false;
            }
            if (expected_lsn != (std::numeric_limits<std::uint64_t>::max)()) {
                ++expected_lsn;
            }
        }
        events.swap(verified_events);
        failure = mother_h::journal::IntegrityStatus::Ok;
        return true;
    }

private:
    EventJournalResult append_encrypted_locked(
        const mb::cqs13_4::EventPayload& event,
        const mother_h::journal::DataKeyReference& dek_ref,
        const mother_h::journal::IDataEncryptionKeyProvider& dek_provider,
        std::uint64_t lsn
    ) {
        if (exhausted_ || lsn == 0 || lsn != next_lsn_) {
            return {EventJournalStatus::LsnOutOfOrder,
                    mother_h::journal::IntegrityStatus::LsnOutOfOrder, {}};
        }

        std::string payload;
        if (!encode_encrypted_event_payload(event, dek_ref, dek_provider, payload)) {
            return {EventJournalStatus::InvalidEvent,
                    mother_h::journal::IntegrityStatus::InvalidRecord, {}};
        }

        mother_h::journal::JournalRecord record;
        record.lsn = lsn;
        record.timestamp_utc = timestamp_utc_now();
        record.payload = std::move(payload);
        const auto sealed = mother_h::journal::JournalIntegrity::seal(
            record, lsn, previous_record_hash_, keys_);
        if (!sealed) {
            return {EventJournalStatus::IntegrityFailure, sealed.status, {}};
        }

        const JournalSinkStatus stored = sink_.append_record(record);
        if (stored != JournalSinkStatus::Ok) {
            return {EventJournalStatus::StorageFailure,
                    mother_h::journal::IntegrityStatus::Ok, {}};
        }

        previous_record_hash_ = sealed.record_hash;
        if (next_lsn_ == (std::numeric_limits<std::uint64_t>::max)()) {
            exhausted_ = true;
        } else {
            ++next_lsn_;
        }
        return {EventJournalStatus::Ok, mother_h::journal::IntegrityStatus::Ok,
                sealed.record_hash, lsn};
    }

    static void cleanse_string(std::string& value) noexcept {
        if (!value.empty()) {
            OPENSSL_cleanse(&value[0], value.size());
            value.clear();
        }
    }

    static void append_u32_str(std::string& output, std::uint32_t value) {
        for (int shift = 24; shift >= 0; shift -= 8) {
            output.push_back(static_cast<char>(value >> shift));
        }
    }

    static bool read_u32_str(
        const std::string& input,
        std::size_t& offset,
        std::uint32_t& value
    ) {
        if (offset > input.size() || input.size() - offset < 4) return false;
        std::uint32_t parsed = 0;
        for (std::size_t i = 0; i < 4; ++i) {
            parsed = (parsed << 8U) |
                static_cast<unsigned char>(input[offset + i]);
        }
        offset += 4;
        value = parsed;
        return true;
    }

    EventJournalResult append_locked(
        const mb::cqs13_4::EventPayload& event,
        std::uint64_t lsn
    ) {
        if (exhausted_ || lsn == 0 || lsn != next_lsn_) {
            return {EventJournalStatus::LsnOutOfOrder,
                    mother_h::journal::IntegrityStatus::LsnOutOfOrder, {}};
        }

        std::string payload;
        if (!encode_event_payload(event, payload)) {
            return {EventJournalStatus::InvalidEvent,
                    mother_h::journal::IntegrityStatus::InvalidRecord, {}};
        }

        mother_h::journal::JournalRecord record;
        record.lsn = lsn;
        record.timestamp_utc = timestamp_utc_now();
        record.payload = std::move(payload);
        const auto sealed = mother_h::journal::JournalIntegrity::seal(
            record, lsn, previous_record_hash_, keys_);
        if (!sealed) {
            return {EventJournalStatus::IntegrityFailure, sealed.status, {}};
        }

        const JournalSinkStatus stored = sink_.append_record(record);
        if (stored != JournalSinkStatus::Ok) {
            return {EventJournalStatus::StorageFailure,
                    mother_h::journal::IntegrityStatus::Ok, {}};
        }

        previous_record_hash_ = sealed.record_hash;
        if (next_lsn_ == (std::numeric_limits<std::uint64_t>::max)()) {
            exhausted_ = true;
        } else {
            ++next_lsn_;
        }
        return {EventJournalStatus::Ok, mother_h::journal::IntegrityStatus::Ok,
                sealed.record_hash, lsn};
    }

    static bool append_field(std::string& output, const std::string& field) {
        if (field.size() > (std::numeric_limits<std::uint32_t>::max)()) {
            return false;
        }
        const auto size = static_cast<std::uint32_t>(field.size());
        for (int shift = 24; shift >= 0; shift -= 8) {
            output.push_back(static_cast<char>(size >> shift));
        }
        output.append(field);
        return true;
    }

    static bool read_field(
        const std::string& input,
        std::size_t& offset,
        std::string& field
    ) {
        if (offset > input.size() || input.size() - offset < 4) return false;
        std::uint32_t size = 0;
        for (std::size_t i = 0; i < 4; ++i) {
            size = (size << 8U) |
                static_cast<unsigned char>(input[offset + i]);
        }
        offset += 4;
        if (size > input.size() - offset) return false;
        field.assign(input.data() + offset, size);
        offset += size;
        return true;
    }

    static std::string timestamp_utc_now() {
        using Clock = std::chrono::system_clock;
        const auto now = Clock::now();
        const auto seconds = std::chrono::time_point_cast<std::chrono::seconds>(now);
        const auto fraction = std::chrono::duration_cast<std::chrono::nanoseconds>(
            now - seconds).count();
        const std::time_t time = Clock::to_time_t(now);
        std::tm utc{};
#if defined(_WIN32)
        if (gmtime_s(&utc, &time) != 0) {
            throw std::runtime_error("UTC clock conversion failed");
        }
#else
        if (gmtime_r(&time, &utc) == nullptr) {
            throw std::runtime_error("UTC clock conversion failed");
        }
#endif
        std::ostringstream result;
        result << std::put_time(&utc, "%Y-%m-%dT%H:%M:%S")
               << '.' << std::setw(9) << std::setfill('0') << fraction << 'Z';
        return result.str();
    }

    IJournalRecordSink& sink_;
    const mother_h::journal::ISecureKeyProvider& keys_;
    mutable std::mutex mutex_;
    std::uint64_t next_lsn_{1};
    mother_h::journal::JournalHash previous_record_hash_{};
    bool exhausted_{false};
};

}  // namespace mb::H
