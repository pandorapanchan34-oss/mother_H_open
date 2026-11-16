#pragma once

#include "mother_H/auth/external_access_governance.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
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
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace mother_h::auth {

class FileTransactionalRegistryStore final : public ITransactionalRegistryStore {
public:
    static constexpr std::size_t kMaximumFileBytes = 64U * 1024U * 1024U;

    FileTransactionalRegistryStore(
        std::filesystem::path path,
        const mother_h::journal::ISecureKeyProvider& integrity_keys
    )
        : path_(std::move(path)),
          wal_path_(with_suffix(path_, ".wal")),
          lock_path_(with_suffix(path_, ".lock")),
          integrity_keys_(integrity_keys),
          process_mutex_(shared_mutex_for(path_)) {}

    std::string_view name() const noexcept override {
        return "FileTransactionalRegistryStore";
    }

    RegistryStoreStatus read(RegistryState& out) const noexcept override {
        try {
            if (!ensure_parent()) return RegistryStoreStatus::Unavailable;
            std::lock_guard<std::mutex> local(*process_mutex_);
            ProcessLock lock(lock_path_);
            if (!lock.locked()) return RegistryStoreStatus::Unavailable;
            RegistryState candidate;
            const auto status = recover_locked(candidate);
            if (status != RegistryStoreStatus::Ok) return status;
            out = std::move(candidate);
            return RegistryStoreStatus::Ok;
        } catch (...) {
            return RegistryStoreStatus::Unavailable;
        }
    }

    RegistryStoreStatus transact(const Mutation& mutation) noexcept override {
        if (!mutation) return RegistryStoreStatus::Rejected;
        try {
            if (!ensure_parent()) return RegistryStoreStatus::Unavailable;
            std::lock_guard<std::mutex> local(*process_mutex_);
            ProcessLock lock(lock_path_);
            if (!lock.locked()) return RegistryStoreStatus::Unavailable;
            RegistryState current;
            const auto recovered = recover_locked(current);
            if (recovered != RegistryStoreStatus::Ok) return recovered;
            RegistryState next = current;
            if (!mutation(next)) return RegistryStoreStatus::Rejected;
            if (current.store_revision ==
                (std::numeric_limits<std::uint64_t>::max)())
                return RegistryStoreStatus::Indeterminate;
            next.store_revision = current.store_revision + 1U;
            std::string txid;
            if (!random_txid(txid)) return RegistryStoreStatus::Unavailable;
            std::vector<std::uint8_t> payload;
            if (!serialize_state(next, payload))
                return RegistryStoreStatus::Unavailable;
            std::vector<std::uint8_t> wal_image;
            if (!seal(kWalDomain, txid, next.store_revision, payload, wal_image))
                return RegistryStoreStatus::Unavailable;
            if (!durable_replace(wal_path_, wal_image))
                return RegistryStoreStatus::Indeterminate;
#ifdef MOTHER_H_TEST_BUILD
            if (after_wal_flush_hook_) after_wal_flush_hook_();
#endif
            std::vector<std::uint8_t> body_image;
            if (!seal(kBodyDomain, txid, next.store_revision, payload, body_image) ||
                !durable_replace(path_, body_image))
                return RegistryStoreStatus::Indeterminate;
            if (!remove_durable(wal_path_))
                return RegistryStoreStatus::Indeterminate;
            return RegistryStoreStatus::Ok;
        } catch (...) {
            return RegistryStoreStatus::Indeterminate;
        }
    }

#ifdef MOTHER_H_TEST_BUILD
    void set_after_wal_flush_hook_for_testing(std::function<void()> hook) {
        after_wal_flush_hook_ = std::move(hook);
    }
#endif

private:
    static constexpr std::string_view kWalDomain =
        "MOTHER_H_AUTH_REGISTRY_WAL_V1";
    static constexpr std::string_view kBodyDomain =
        "MOTHER_H_AUTH_REGISTRY_BODY_V1";
    static constexpr std::string_view kMagic = "MHAR001";
    static constexpr std::size_t kTagBytes = 32U;

    class ProcessLock {
    public:
        explicit ProcessLock(const std::filesystem::path& path) noexcept {
#ifdef _WIN32
            handle_ = CreateFileW(
                path.c_str(), GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL, nullptr);
            if (handle_ == INVALID_HANDLE_VALUE) return;
            OVERLAPPED overlapped{};
            if (LockFileEx(handle_, LOCKFILE_EXCLUSIVE_LOCK, 0,
                           MAXDWORD, MAXDWORD, &overlapped) == 0) {
                CloseHandle(handle_);
                handle_ = INVALID_HANDLE_VALUE;
                return;
            }
            overlapped_ = overlapped;
            locked_ = true;
#else
            fd_ = ::open(path.c_str(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
            if (fd_ < 0) return;
            while (::flock(fd_, LOCK_EX) != 0) {
                if (errno == EINTR) continue;
                ::close(fd_);
                fd_ = -1;
                return;
            }
            locked_ = true;
#endif
        }
        ProcessLock(const ProcessLock&) = delete;
        ProcessLock& operator=(const ProcessLock&) = delete;
        ~ProcessLock() {
#ifdef _WIN32
            if (locked_) {
                UnlockFileEx(handle_, 0, MAXDWORD, MAXDWORD, &overlapped_);
                CloseHandle(handle_);
            }
#else
            if (locked_) {
                ::flock(fd_, LOCK_UN);
                ::close(fd_);
            }
#endif
        }
        bool locked() const noexcept { return locked_; }
    private:
        bool locked_{false};
#ifdef _WIN32
        HANDLE handle_{INVALID_HANDLE_VALUE};
        OVERLAPPED overlapped_{};
#else
        int fd_{-1};
#endif
    };

    class Reader {
    public:
        explicit Reader(const std::vector<std::uint8_t>& bytes) : bytes_(bytes) {}
        bool u8(std::uint8_t& value) {
            if (offset_ >= bytes_.size()) return false;
            value = bytes_[offset_++];
            return true;
        }
        bool u32(std::uint32_t& value) {
            if (bytes_.size() - offset_ < 4U) return false;
            value = 0;
            for (unsigned i = 0; i < 4U; ++i)
                value = (value << 8U) | bytes_[offset_++];
            return true;
        }
        bool u64(std::uint64_t& value) {
            if (bytes_.size() - offset_ < 8U) return false;
            value = 0;
            for (unsigned i = 0; i < 8U; ++i)
                value = (value << 8U) | bytes_[offset_++];
            return true;
        }
        bool i64(std::int64_t& value) {
            std::uint64_t raw = 0;
            if (!u64(raw)) return false;
            value = static_cast<std::int64_t>(raw);
            return true;
        }
        bool text(std::string& value, std::size_t maximum = 1024U * 1024U) {
            std::uint32_t size = 0;
            if (!u32(size) || size > maximum ||
                bytes_.size() - offset_ < size) return false;
            value.assign(
                reinterpret_cast<const char*>(bytes_.data() + offset_), size);
            offset_ += size;
            return detail::valid_utf8(value);
        }
        bool done() const noexcept { return offset_ == bytes_.size(); }
    private:
        const std::vector<std::uint8_t>& bytes_;
        std::size_t offset_{0};
    };

    static std::shared_ptr<std::mutex> shared_mutex_for(
        const std::filesystem::path& path
    ) {
        static std::mutex map_mutex;
        static std::map<std::string, std::weak_ptr<std::mutex>> locks;
        std::error_code error;
        auto canonical = std::filesystem::absolute(path, error).lexically_normal();
        const std::string key = (error ? path : canonical).string();
        std::lock_guard<std::mutex> lock(map_mutex);
        auto& weak = locks[key];
        auto result = weak.lock();
        if (!result) {
            result = std::make_shared<std::mutex>();
            weak = result;
        }
        return result;
    }

    static std::filesystem::path with_suffix(
        std::filesystem::path path,
        std::string_view suffix
    ) {
        path += std::filesystem::path(std::string(suffix));
        return path;
    }

    bool ensure_parent() const noexcept {
        try {
            const auto parent = path_.parent_path();
            if (parent.empty()) return true;
            std::error_code error;
            std::filesystem::create_directories(parent, error);
            return !error;
        } catch (...) {
            return false;
        }
    }

    static void append_u32(
        std::vector<std::uint8_t>& output,
        std::uint32_t value
    ) {
        for (int shift = 24; shift >= 0; shift -= 8)
            output.push_back(static_cast<std::uint8_t>(value >> shift));
    }

    static void append_u64(
        std::vector<std::uint8_t>& output,
        std::uint64_t value
    ) {
        for (int shift = 56; shift >= 0; shift -= 8)
            output.push_back(static_cast<std::uint8_t>(value >> shift));
    }

    static bool append_text(
        std::vector<std::uint8_t>& output,
        std::string_view text
    ) {
        if (text.size() > (std::numeric_limits<std::uint32_t>::max)() ||
            !detail::valid_utf8(text)) return false;
        append_u32(output, static_cast<std::uint32_t>(text.size()));
        output.insert(output.end(), text.begin(), text.end());
        return true;
    }

    static bool serialize_record(
        const EphemeralKeyRecord& r,
        std::vector<std::uint8_t>& out
    ) {
        if (!append_text(out, r.key_id) || !append_text(out, r.request_id) ||
            !append_text(out, r.requester_id) ||
            !append_text(out, r.target_resource) || !append_text(out, r.action))
            return false;
        append_u64(out, r.limits.max_bytes);
        append_u64(out, r.limits.max_steps);
        append_u64(out, r.limits.max_items);
        append_u64(out, r.requested_limits.max_bytes);
        append_u64(out, r.requested_limits.max_steps);
        append_u64(out, r.requested_limits.max_items);
        append_u64(out, static_cast<std::uint64_t>(r.issued_at_unix_sec));
        append_u64(out, static_cast<std::uint64_t>(r.expires_at_unix_sec));
        append_u64(out, static_cast<std::uint64_t>(
            r.approval_expires_at_unix_sec));
        if (!append_text(out, r.auth_evidence_ref) ||
            !append_text(out, r.approval_id) ||
            !append_text(out, r.approval_evidence_id) ||
            !append_text(out, r.approval_evidence_digest_hex) ||
            !append_text(out, r.approval_scope_digest)) return false;
        out.push_back(static_cast<std::uint8_t>(r.approval_status));
        out.push_back(static_cast<std::uint8_t>(r.status));
        out.push_back(static_cast<std::uint8_t>(r.execution_phase));
        append_u64(out, r.registry_revision);
        append_u64(out, r.approval_revision);
        append_u64(out, r.key_revision);
        append_u64(out, r.execution_revision);
        append_u64(out, r.session_operation_sequence);
        append_u64(out, r.revocation_epoch);
        append_u64(out, r.outbox_ack_revision);
        if (!append_text(out, r.grant_id) ||
            !append_text(out, r.grant_mac_key_id)) return false;
        append_u32(out, r.grant_mac_key_version);
        if (!append_text(out, r.grant_mac_hex)) return false;
        append_u64(out, r.grant_limits.max_bytes);
        append_u64(out, r.grant_limits.max_steps);
        append_u64(out, r.grant_limits.max_items);
        append_u64(out, r.grant_registry_revision);
        append_u64(out, r.consume_registry_revision);
        if (!append_text(out, r.intent_event_id)) return false;
        out.push_back(r.intent_receipt_recorded ? 1U : 0U);
        out.push_back(r.approval_receipt_recorded ? 1U : 0U);
        out.push_back(r.exists ? 1U : 0U);
        return true;
    }

    static bool deserialize_record(Reader& reader, EphemeralKeyRecord& r) {
        std::uint8_t approval = 0, key = 0, phase = 0;
        std::uint8_t intent = 0, approval_receipt = 0, exists = 0;
        std::uint64_t issued = 0, expires = 0, approval_expires = 0;
        if (!reader.text(r.key_id) || !reader.text(r.request_id) ||
            !reader.text(r.requester_id) || !reader.text(r.target_resource) ||
            !reader.text(r.action) || !reader.u64(r.limits.max_bytes) ||
            !reader.u64(r.limits.max_steps) ||
            !reader.u64(r.limits.max_items) ||
            !reader.u64(r.requested_limits.max_bytes) ||
            !reader.u64(r.requested_limits.max_steps) ||
            !reader.u64(r.requested_limits.max_items) ||
            !reader.u64(issued) || !reader.u64(expires) ||
            !reader.u64(approval_expires) ||
            !reader.text(r.auth_evidence_ref) ||
            !reader.text(r.approval_id) ||
            !reader.text(r.approval_evidence_id) ||
            !reader.text(r.approval_evidence_digest_hex) ||
            !reader.text(r.approval_scope_digest) ||
            !reader.u8(approval) || !reader.u8(key) || !reader.u8(phase) ||
            !reader.u64(r.registry_revision) ||
            !reader.u64(r.approval_revision) ||
            !reader.u64(r.key_revision) ||
            !reader.u64(r.execution_revision) ||
            !reader.u64(r.session_operation_sequence) ||
            !reader.u64(r.revocation_epoch) ||
            !reader.u64(r.outbox_ack_revision) ||
            !reader.text(r.grant_id) || !reader.text(r.grant_mac_key_id) ||
            !reader.u32(r.grant_mac_key_version) ||
            !reader.text(r.grant_mac_hex) ||
            !reader.u64(r.grant_limits.max_bytes) ||
            !reader.u64(r.grant_limits.max_steps) ||
            !reader.u64(r.grant_limits.max_items) ||
            !reader.u64(r.grant_registry_revision) ||
            !reader.u64(r.consume_registry_revision) ||
            !reader.text(r.intent_event_id) ||
            !reader.u8(intent) || !reader.u8(approval_receipt) ||
            !reader.u8(exists))
            return false;
        if (approval > static_cast<std::uint8_t>(ApprovalStatus::Expired) ||
            key > static_cast<std::uint8_t>(KeyTrustStatus::Burned) ||
            phase > static_cast<std::uint8_t>(ExecutionPhase::Indeterminate) ||
            intent > 1U || approval_receipt > 1U || exists > 1U)
            return false;
        r.issued_at_unix_sec = static_cast<std::int64_t>(issued);
        r.expires_at_unix_sec = static_cast<std::int64_t>(expires);
        r.approval_expires_at_unix_sec =
            static_cast<std::int64_t>(approval_expires);
        r.approval_status = static_cast<ApprovalStatus>(approval);
        r.status = static_cast<KeyTrustStatus>(key);
        r.execution_phase = static_cast<ExecutionPhase>(phase);
        r.intent_receipt_recorded = intent != 0;
        r.approval_receipt_recorded = approval_receipt != 0;
        r.exists = exists != 0;
        return !r.key_id.empty() && r.exists;
    }

    static bool serialize_event(
        const RegistryOutboxEvent& e,
        std::vector<std::uint8_t>& out
    ) {
        if (!append_text(out, e.event_id) ||
            !append_text(out, e.event_digest_hex)) return false;
        out.push_back(static_cast<std::uint8_t>(e.phase));
        out.push_back(static_cast<std::uint8_t>(e.decision));
        if (!append_text(out, e.request_id) ||
            !append_text(out, e.requester_id) ||
            !append_text(out, e.key_id) ||
            !append_text(out, e.target_resource) ||
            !append_text(out, e.action) ||
            !append_text(out, e.approval_id)) return false;
        append_u64(out, static_cast<std::uint64_t>(e.timestamp_unix_sec));
        append_u64(out, e.consumed.max_bytes);
        append_u64(out, e.consumed.max_steps);
        append_u64(out, e.consumed.max_items);
        if (!append_text(out, e.retrieval_summary_hash)) return false;
        out.push_back(e.receipt_recorded ? 1U : 0U);
        if (!append_text(out, e.receipt_sink_id) ||
            !append_text(out, e.receipt_digest_hex)) return false;
        append_u64(out, static_cast<std::uint64_t>(e.receipt_received_at_unix_sec));
        append_u32(out, e.receipt_key_version);
        return append_text(out, e.receipt_mac_hex);
    }

    static bool deserialize_event(Reader& reader, RegistryOutboxEvent& e) {
        std::uint8_t phase = 0, decision = 0, receipt = 0;
        std::uint64_t timestamp = 0, received = 0;
        if (!reader.text(e.event_id) || !reader.text(e.event_digest_hex) ||
            !reader.u8(phase) || !reader.u8(decision) ||
            !reader.text(e.request_id) || !reader.text(e.requester_id) ||
            !reader.text(e.key_id) || !reader.text(e.target_resource) ||
            !reader.text(e.action) || !reader.text(e.approval_id) ||
            !reader.u64(timestamp) ||
            !reader.u64(e.consumed.max_bytes) ||
            !reader.u64(e.consumed.max_steps) ||
            !reader.u64(e.consumed.max_items) ||
            !reader.text(e.retrieval_summary_hash) ||
            !reader.u8(receipt) || !reader.text(e.receipt_sink_id) ||
            !reader.text(e.receipt_digest_hex) || !reader.u64(received) ||
            !reader.u32(e.receipt_key_version) ||
            !reader.text(e.receipt_mac_hex))
            return false;
        if (phase > static_cast<std::uint8_t>(GovernanceAuditPhase::ExecutionOutcomeBurn) ||
            decision > static_cast<std::uint8_t>(GovernanceDecisionCode::CallbackFailure) ||
            receipt > 1U)
            return false;
        e.phase = static_cast<GovernanceAuditPhase>(phase);
        e.decision = static_cast<GovernanceDecisionCode>(decision);
        e.timestamp_unix_sec = static_cast<std::int64_t>(timestamp);
        e.receipt_received_at_unix_sec = static_cast<std::int64_t>(received);
        e.receipt_recorded = receipt != 0;
        return !e.event_id.empty();
    }

    static bool serialize_state(
        const RegistryState& state,
        std::vector<std::uint8_t>& output
    ) {
        output.clear();
        output.push_back(1U);
        append_u64(output, state.store_revision);
        if (state.records.size() > 100000U ||
            state.outbox.size() > 1000000U)
            return false;
        append_u32(output, static_cast<std::uint32_t>(state.records.size()));
        for (const auto& pair : state.records) {
            if (pair.first != pair.second.key_id ||
                !serialize_record(pair.second, output)) return false;
        }
        append_u32(output, static_cast<std::uint32_t>(state.outbox.size()));
        for (const auto& event : state.outbox)
            if (!serialize_event(event, output)) return false;
        return output.size() <= kMaximumFileBytes;
    }

    static bool deserialize_state(
        const std::vector<std::uint8_t>& input,
        RegistryState& state
    ) {
        Reader reader(input);
        std::uint8_t version = 0;
        std::uint32_t count = 0;
        if (!reader.u8(version) || version != 1U ||
            !reader.u64(state.store_revision) ||
            !reader.u32(count) || count > 100000U)
            return false;
        for (std::uint32_t i = 0; i < count; ++i) {
            EphemeralKeyRecord record;
            if (!deserialize_record(reader, record) ||
                !state.records.emplace(record.key_id, std::move(record)).second)
                return false;
        }
        if (!reader.u32(count) || count > 1000000U) return false;
        std::map<std::string, bool> ids;
        state.outbox.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i) {
            RegistryOutboxEvent event;
            if (!deserialize_event(reader, event) ||
                !ids.emplace(event.event_id, true).second)
                return false;
            state.outbox.push_back(std::move(event));
        }
        return reader.done();
    }

    bool random_txid(std::string& output) const noexcept {
        std::array<unsigned char, 16> value{};
        if (RAND_bytes(value.data(), static_cast<int>(value.size())) != 1)
            return false;
        static constexpr char hex[] = "0123456789abcdef";
        output.clear();
        for (const auto byte : value) {
            output.push_back(hex[byte >> 4U]);
            output.push_back(hex[byte & 0x0FU]);
        }
        OPENSSL_cleanse(value.data(), value.size());
        return true;
    }

    bool seal(
        std::string_view domain,
        std::string_view txid_hex,
        std::uint64_t revision,
        const std::vector<std::uint8_t>& payload,
        std::vector<std::uint8_t>& output
    ) const noexcept {
        try {
            if (txid_hex.size() != 32U ||
                payload.size() > kMaximumFileBytes) return false;
            std::vector<unsigned char> txid;
            if (!detail::from_hex(txid_hex, txid) || txid.size() != 16U)
                return false;
            mother_h::journal::KeyMaterial key;
            if (integrity_keys_.current_signing_key(key) !=
                    mother_h::journal::KeyStatus::Ok ||
                key.secret().size() < 32U ||
                key.reference().version == 0 ||
                key.reference().key_id.empty())
                return false;
            output.clear();
            output.insert(output.end(), kMagic.begin(), kMagic.end());
            output.push_back(1U);
            output.insert(output.end(), txid.begin(), txid.end());
            append_u64(output, revision);
            if (!append_text(output, key.reference().key_id)) return false;
            append_u32(output, key.reference().version);
            append_u64(output, static_cast<std::uint64_t>(payload.size()));
            output.insert(output.end(), payload.begin(), payload.end());
            std::vector<std::uint8_t> mac_input;
            mac_input.insert(mac_input.end(), domain.begin(), domain.end());
            mac_input.insert(mac_input.end(), output.begin(), output.end());
            std::array<unsigned char, kTagBytes> tag{};
            unsigned int tag_size = 0;
            if (HMAC(EVP_sha256(), key.secret().data(),
                     static_cast<int>(key.secret().size()),
                     mac_input.data(), mac_input.size(), tag.data(),
                     &tag_size) == nullptr || tag_size != tag.size())
                return false;
            output.insert(output.end(), tag.begin(), tag.end());
            OPENSSL_cleanse(tag.data(), tag.size());
            return output.size() <= kMaximumFileBytes;
        } catch (...) {
            return false;
        }
    }

    struct Envelope {
        std::string txid_hex;
        std::uint64_t revision{0};
        std::string key_id;
        std::uint32_t key_version{0};
        std::vector<std::uint8_t> payload;
    };

    bool open_envelope(
        std::string_view domain,
        const std::vector<std::uint8_t>& image,
        Envelope& envelope
    ) const noexcept {
        try {
            constexpr std::size_t fixed =
                7U + 1U + 16U + 8U + 4U + 8U + kTagBytes;
            if (image.size() < fixed || image.size() > kMaximumFileBytes)
                return false;
            if (!std::equal(kMagic.begin(), kMagic.end(), image.begin()) ||
                image[7] != 1U) return false;
            std::size_t offset = 8U;
            const auto txid = detail::to_hex(image.data() + offset, 16U);
            offset += 16U;
            auto read_u64 = [&](std::uint64_t& out) {
                if (image.size() - offset < 8U) return false;
                out = 0;
                for (unsigned i = 0; i < 8U; ++i)
                    out = (out << 8U) | image[offset++];
                return true;
            };
            auto read_u32 = [&](std::uint32_t& out) {
                if (image.size() - offset < 4U) return false;
                out = 0;
                for (unsigned i = 0; i < 4U; ++i)
                    out = (out << 8U) | image[offset++];
                return true;
            };
            std::uint64_t revision = 0;
            std::uint32_t key_id_size = 0, key_version = 0;
            if (!read_u64(revision) || !read_u32(key_id_size) ||
                key_id_size == 0 || key_id_size > 128U ||
                image.size() - offset < key_id_size)
                return false;
            const std::string key_id(
                reinterpret_cast<const char*>(image.data() + offset),
                key_id_size);
            offset += key_id_size;
            if (!detail::valid_utf8(key_id) || !read_u32(key_version))
                return false;
            std::uint64_t payload_size = 0;
            if (!read_u64(payload_size) ||
                payload_size > kMaximumFileBytes ||
                payload_size > image.size() - offset ||
                image.size() - offset - static_cast<std::size_t>(payload_size) !=
                    kTagBytes)
                return false;
            const std::size_t signed_size =
                image.size() - kTagBytes;
            std::vector<std::uint8_t> mac_input(
                domain.begin(), domain.end());
            mac_input.insert(mac_input.end(), image.begin(),
                             image.begin() + static_cast<std::ptrdiff_t>(signed_size));
            mother_h::journal::KeyMaterial key;
            const mother_h::journal::KeyReference reference{key_id, key_version};
            if (integrity_keys_.verification_key(reference, key) !=
                    mother_h::journal::KeyStatus::Ok ||
                key.reference() != reference || key.secret().size() < 32U)
                return false;
            std::array<unsigned char, kTagBytes> calculated{};
            unsigned int calculated_size = 0;
            if (HMAC(EVP_sha256(), key.secret().data(),
                     static_cast<int>(key.secret().size()), mac_input.data(),
                     mac_input.size(), calculated.data(), &calculated_size) ==
                    nullptr || calculated_size != calculated.size() ||
                CRYPTO_memcmp(calculated.data(),
                              image.data() + signed_size,
                              calculated.size()) != 0)
                return false;
            envelope.txid_hex = txid;
            envelope.revision = revision;
            envelope.key_id = key_id;
            envelope.key_version = key_version;
            envelope.payload.assign(
                image.begin() + static_cast<std::ptrdiff_t>(offset),
                image.begin() + static_cast<std::ptrdiff_t>(
                    offset + static_cast<std::size_t>(payload_size)));
            return true;
        } catch (...) {
            return false;
        }
    }

    static bool read_file(
        const std::filesystem::path& path,
        std::vector<std::uint8_t>& output,
        bool& exists
    ) noexcept {
        try {
            std::error_code error;
            exists = std::filesystem::exists(path, error);
            if (error) return false;
            if (!exists) {
                output.clear();
                return true;
            }
            const auto size = std::filesystem::file_size(path, error);
            if (error || size > kMaximumFileBytes) return false;
            std::ifstream input(path, std::ios::binary);
            if (!input) return false;
            output.resize(static_cast<std::size_t>(size));
            input.read(reinterpret_cast<char*>(output.data()),
                       static_cast<std::streamsize>(output.size()));
            return input.gcount() == static_cast<std::streamsize>(output.size()) &&
                input.peek() == std::char_traits<char>::eof();
        } catch (...) {
            return false;
        }
    }

    RegistryStoreStatus recover_locked(RegistryState& output) const noexcept {
        try {
            std::vector<std::uint8_t> body, wal;
            bool body_exists = false, wal_exists = false;
            if (!read_file(path_, body, body_exists) ||
                !read_file(wal_path_, wal, wal_exists))
                return RegistryStoreStatus::Indeterminate;
            RegistryState body_state;
            Envelope body_envelope;
            if (body_exists) {
                if (!open_envelope(kBodyDomain, body, body_envelope) ||
                    !deserialize_state(body_envelope.payload, body_state) ||
                    body_state.store_revision != body_envelope.revision)
                    return RegistryStoreStatus::IntegrityFailure;
            }
            if (wal_exists) {
                Envelope wal_envelope;
                RegistryState wal_state;
                if (!open_envelope(kWalDomain, wal, wal_envelope) ||
                    !deserialize_state(wal_envelope.payload, wal_state) ||
                    wal_state.store_revision != wal_envelope.revision)
                    return RegistryStoreStatus::Indeterminate;
                if (body_exists &&
                    body_envelope.revision == wal_envelope.revision) {
                    if (body_envelope.txid_hex != wal_envelope.txid_hex ||
                        body_envelope.payload != wal_envelope.payload)
                        return RegistryStoreStatus::IntegrityFailure;
                    if (!remove_durable(wal_path_))
                        return RegistryStoreStatus::Indeterminate;
                    output = std::move(body_state);
                    return RegistryStoreStatus::Ok;
                }
                const std::uint64_t expected =
                    body_exists ? body_envelope.revision + 1U : 1U;
                if ((body_exists &&
                     body_envelope.revision ==
                         (std::numeric_limits<std::uint64_t>::max)()) ||
                    wal_envelope.revision != expected)
                    return RegistryStoreStatus::Indeterminate;
                std::vector<std::uint8_t> committed;
                if (!seal(kBodyDomain, wal_envelope.txid_hex,
                          wal_envelope.revision, wal_envelope.payload,
                          committed) ||
                    !durable_replace(path_, committed) ||
                    !remove_durable(wal_path_))
                    return RegistryStoreStatus::Indeterminate;
                output = std::move(wal_state);
                return RegistryStoreStatus::Ok;
            }
            output = body_exists ? std::move(body_state) : RegistryState{};
            return RegistryStoreStatus::Ok;
        } catch (...) {
            return RegistryStoreStatus::Indeterminate;
        }
    }

    bool durable_replace(
        const std::filesystem::path& destination,
        const std::vector<std::uint8_t>& image
    ) const noexcept {
        try {
            std::error_code error;
            auto parent = destination.parent_path();
            if (!parent.empty())
                std::filesystem::create_directories(parent, error);
            if (error) return false;
            std::array<unsigned char, 8> random{};
            if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1)
                return false;
            static constexpr char hex[] = "0123456789abcdef";
            std::string suffix;
            for (const auto byte : random) {
                suffix.push_back(hex[byte >> 4U]);
                suffix.push_back(hex[byte & 0x0FU]);
            }
            auto temporary = destination;
            temporary += ".tmp-" + suffix;
            if (!write_new_file(temporary, image)) return false;
#ifdef _WIN32
            if (MoveFileExW(temporary.c_str(), destination.c_str(),
                            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
                DeleteFileW(temporary.c_str());
                return false;
            }
            return true;
#else
            if (::rename(temporary.c_str(), destination.c_str()) != 0) {
                ::unlink(temporary.c_str());
                return false;
            }
            return sync_parent(destination);
#endif
        } catch (...) {
            return false;
        }
    }

    static bool write_new_file(
        const std::filesystem::path& path,
        const std::vector<std::uint8_t>& image
    ) noexcept {
#ifdef _WIN32
        HANDLE file = CreateFileW(
            path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return false;
        std::size_t offset = 0;
        bool ok = true;
        while (offset < image.size()) {
            const DWORD chunk = static_cast<DWORD>(
                std::min<std::size_t>(image.size() - offset, 1U << 20U));
            DWORD written = 0;
            if (WriteFile(file, image.data() + offset, chunk, &written, nullptr) == 0 ||
                written != chunk) {
                ok = false;
                break;
            }
            offset += written;
        }
        if (ok && FlushFileBuffers(file) == 0) ok = false;
        const bool closed = CloseHandle(file) != 0;
        return ok && closed;
#else
        const int file = ::open(
            path.c_str(), O_WRONLY | O_CREAT | O_EXCL
#ifdef O_NOFOLLOW
            | O_NOFOLLOW
#endif
            , S_IRUSR | S_IWUSR);
        if (file < 0) return false;
        std::size_t offset = 0;
        bool ok = true;
        while (offset < image.size()) {
            const ssize_t written = ::write(
                file, image.data() + offset, image.size() - offset);
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
    }

    static bool remove_durable(const std::filesystem::path& path) noexcept {
        try {
            std::error_code error;
            const bool removed = std::filesystem::remove(path, error);
            if (error) return false;
            if (!removed) return true;
#ifdef _WIN32
            return true;
#else
            return sync_parent(path);
#endif
        } catch (...) {
            return false;
        }
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
    std::filesystem::path wal_path_;
    std::filesystem::path lock_path_;
    const mother_h::journal::ISecureKeyProvider& integrity_keys_;
    std::shared_ptr<std::mutex> process_mutex_;
#ifdef MOTHER_H_TEST_BUILD
    std::function<void()> after_wal_flush_hook_;
#endif
};

} // namespace mother_h::auth
