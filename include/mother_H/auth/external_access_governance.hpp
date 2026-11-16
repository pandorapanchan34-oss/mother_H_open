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
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace mother_h::auth {

enum class ApprovalStatus : std::uint8_t { Pending, Active, Revoked, Expired };
enum class KeyTrustStatus : std::uint8_t {
    PendingApproval,
    ApprovedUnused,
    InUseConsumed,
    Burned
};
enum class ExecutionPhase : std::uint8_t {
    NotStarted,
    Started,
    Finished,
    Indeterminate
};
enum class GovernanceDecisionCode : std::uint8_t {
    Allowed,
    MissingRequiredField,
    InvalidTimestampOrExpired,
    KeyNotApproved,
    KeyAlreadyConsumedOrBurned,
    KeyScopeExceeded,
    SignatureVerificationFailed,
    HumanApprovalMissingOrMismatch,
    UnlimitedScopeRejected,
    AuditSinkFailure,
    ExecutionTargetOrActionMismatch,
    ExecutionLimitExceeded,
    GrantTamperedOrInvalid,
    ApprovalRevoked,
    StoreUnavailable,
    StoreIndeterminate,
    IntegrityFailure,
    CallbackFailure
};
enum class GovernanceAuditPhase : std::uint8_t {
    KeyRegistration,
    KeyApproval,
    KeyRevocation,
    Authorization,
    ExecutionIntent,
    ExecutionStarted,
    ExecutionOutcomeBurn
};
enum class ResourcePortStatus : std::uint8_t { Ok, Denied, Unavailable, Failure };
enum class RegistryStoreStatus : std::uint8_t {
    Ok,
    Rejected,
    Unavailable,
    IntegrityFailure,
    Indeterminate
};

struct AccessScopeLimits {
    std::uint64_t max_bytes{0};
    std::uint64_t max_steps{0};
    std::uint64_t max_items{0};
};

struct ExternalAccessRequest {
    std::string request_id;
    std::string requester_id;
    std::string key_id;
    std::string target_resource;
    std::string action;
    AccessScopeLimits requested_limits{};
    std::int64_t issued_at_unix_sec{0};
    std::int64_t expires_at_unix_sec{0};
    std::string auth_evidence_ref;
    std::string signature_hex;
    std::string human_approval_ref;
    std::string prior_history_ref;
};
using KeyRegistrationRequest = ExternalAccessRequest;

struct HumanKeyApproval {
    std::string approval_id;
    std::string request_id;
    std::string key_id;
    std::string requester_id;
    std::string request_scope_digest;
    std::string human_approver_id;
    std::string target_resource;
    std::string action;
    AccessScopeLimits approved_limits{};
    std::int64_t issued_at_unix_sec{0};
    std::int64_t expires_at_unix_sec{0};
};

struct AuthenticatedHumanApproval {
    HumanKeyApproval approval;
    std::string evidence_id;
    std::string evidence_digest_hex;
    std::string signature_hex;
};

struct HumanKeyRevocation {
    std::string approval_id;
    std::string request_id;
    std::string key_id;
    std::string human_approver_id;
    std::uint64_t expected_approval_revision{0};
    std::uint64_t expected_revocation_epoch{0};
    std::int64_t revoked_at_unix_sec{0};
    std::string evidence_id;
    std::string evidence_digest_hex;
};

struct AuthenticatedHumanRevocation {
    HumanKeyRevocation revocation;
    std::string signature_hex;
};

struct EphemeralKeyRecord {
    std::string key_id;
    std::string request_id;
    std::string requester_id;
    std::string target_resource;
    std::string action;
    AccessScopeLimits limits{};
    AccessScopeLimits requested_limits{};
    std::int64_t issued_at_unix_sec{0};
    std::int64_t expires_at_unix_sec{0};
    std::int64_t approval_expires_at_unix_sec{0};
    std::string auth_evidence_ref;
    std::string approval_id;
    std::string approval_evidence_id;
    std::string approval_evidence_digest_hex;
    std::string approval_scope_digest;
    ApprovalStatus approval_status{ApprovalStatus::Pending};
    KeyTrustStatus status{KeyTrustStatus::PendingApproval};
    ExecutionPhase execution_phase{ExecutionPhase::NotStarted};
    std::uint64_t registry_revision{0};
    std::uint64_t approval_revision{0};
    std::uint64_t key_revision{0};
    std::uint64_t execution_revision{0};
    std::uint64_t session_operation_sequence{0};
    std::uint64_t revocation_epoch{0};
    std::uint64_t outbox_ack_revision{0};
    std::string grant_id;
    std::string grant_mac_key_id;
    std::uint32_t grant_mac_key_version{0};
    std::string grant_mac_hex;
    AccessScopeLimits grant_limits{};
    std::uint64_t grant_registry_revision{0};
    std::uint64_t consume_registry_revision{0};
    std::string intent_event_id;
    bool intent_receipt_recorded{false};
    bool approval_receipt_recorded{false};
    bool exists{false};
};

struct RegistryOutboxEvent {
    std::string event_id;
    std::string event_digest_hex;
    GovernanceAuditPhase phase{GovernanceAuditPhase::Authorization};
    GovernanceDecisionCode decision{GovernanceDecisionCode::Allowed};
    std::string request_id;
    std::string requester_id;
    std::string key_id;
    std::string target_resource;
    std::string action;
    std::string approval_id;
    std::int64_t timestamp_unix_sec{0};
    AccessScopeLimits consumed{};
    std::string retrieval_summary_hash;
    bool receipt_recorded{false};
    std::string receipt_sink_id;
    std::string receipt_digest_hex;
    std::int64_t receipt_received_at_unix_sec{0};
    std::uint32_t receipt_key_version{0};
    std::string receipt_mac_hex;
};

struct RegistryState {
    std::uint64_t store_revision{0};
    std::map<std::string, EphemeralKeyRecord> records;
    std::vector<RegistryOutboxEvent> outbox;
};

struct IntentAuditReceipt {
    std::string event_id;
    std::string sink_id;
    std::string event_digest_hex;
    std::int64_t received_at_unix_sec{0};
    std::string receipt_mac_hex;
    std::uint32_t receipt_key_version{0};
};

struct KeyStatusResult {
    GovernanceDecisionCode decision{GovernanceDecisionCode::KeyNotApproved};
    KeyTrustStatus status{KeyTrustStatus::Burned};
    ApprovalStatus approval_status{ApprovalStatus::Pending};
    ExecutionPhase execution_phase{ExecutionPhase::NotStarted};
    std::uint64_t registry_revision{0};
    bool known{false};
};

struct GovernanceAuditRecord {
    GovernanceAuditPhase phase{GovernanceAuditPhase::Authorization};
    std::string request_id;
    std::string requester_id;
    std::string key_id;
    std::string target_resource;
    std::string action;
    std::string scope_summary;
    GovernanceDecisionCode decision{GovernanceDecisionCode::Allowed};
    std::int64_t timestamp_unix_sec{0};
    std::string human_approval_ref;
    AccessScopeLimits consumed{};
    std::string retrieval_summary_hash;
};

class ApprovalGrant;

namespace detail {

inline bool valid_utf8(std::string_view text) noexcept {
    const auto* bytes = reinterpret_cast<const unsigned char*>(text.data());
    std::size_t index = 0;
    while (index < text.size()) {
        const unsigned char first = bytes[index++];
        if (first < 0x80U) {
            if (first == 0U) return false;
            continue;
        }
        std::uint32_t codepoint = 0;
        std::size_t continuation = 0;
        if (first >= 0xC2U && first <= 0xDFU) {
            codepoint = first & 0x1FU;
            continuation = 1;
        } else if (first >= 0xE0U && first <= 0xEFU) {
            codepoint = first & 0x0FU;
            continuation = 2;
        } else if (first >= 0xF0U && first <= 0xF4U) {
            codepoint = first & 0x07U;
            continuation = 3;
        } else {
            return false;
        }
        if (continuation > text.size() - index) return false;
        for (std::size_t i = 0; i < continuation; ++i) {
            const unsigned char next = bytes[index++];
            if ((next & 0xC0U) != 0x80U) return false;
            codepoint = (codepoint << 6U) | (next & 0x3FU);
        }
        if ((continuation == 1 && codepoint < 0x80U) ||
            (continuation == 2 && codepoint < 0x800U) ||
            (continuation == 3 && codepoint < 0x10000U) ||
            codepoint > 0x10FFFFU ||
            (codepoint >= 0xD800U && codepoint <= 0xDFFFU)) {
            return false;
        }
    }
    return true;
}

class Writer {
public:
    void u8(std::uint8_t value) { bytes_.push_back(value); }
    void u32(std::uint32_t value) {
        for (int shift = 24; shift >= 0; shift -= 8)
            bytes_.push_back(static_cast<std::uint8_t>(value >> shift));
    }
    void u64(std::uint64_t value) {
        for (int shift = 56; shift >= 0; shift -= 8)
            bytes_.push_back(static_cast<std::uint8_t>(value >> shift));
    }
    void i64(std::int64_t value) { u64(static_cast<std::uint64_t>(value)); }
    bool text(std::string_view value) {
        if (value.size() > (std::numeric_limits<std::uint32_t>::max)() ||
            !valid_utf8(value)) return false;
        u32(static_cast<std::uint32_t>(value.size()));
        bytes_.insert(bytes_.end(), value.begin(), value.end());
        return true;
    }
    void raw(std::string_view value) {
        bytes_.insert(bytes_.end(), value.begin(), value.end());
    }
    const std::vector<std::uint8_t>& bytes() const noexcept { return bytes_; }
    std::vector<std::uint8_t> take() && { return std::move(bytes_); }
private:
    std::vector<std::uint8_t> bytes_;
};

inline bool sha256_hex(
    const std::vector<std::uint8_t>& input,
    std::string& output
) noexcept {
    std::array<unsigned char, 32> digest{};
    unsigned int length = 0;
    if (EVP_Digest(input.data(), input.size(), digest.data(), &length,
                   EVP_sha256(), nullptr) != 1 || length != digest.size())
        return false;
    static constexpr char hex[] = "0123456789abcdef";
    output.clear();
    output.reserve(digest.size() * 2U);
    for (const auto byte : digest) {
        output.push_back(hex[byte >> 4U]);
        output.push_back(hex[byte & 0x0FU]);
    }
    return true;
}

inline bool request_fields(
    const ExternalAccessRequest& request,
    Writer& writer,
    std::string_view domain
) {
    writer.text(domain);
    writer.u8(1);
    return writer.text(request.request_id) &&
        writer.text(request.key_id) &&
        writer.text(request.requester_id) &&
        writer.text(request.target_resource) &&
        writer.text(request.action) &&
        (writer.u64(request.requested_limits.max_bytes), true) &&
        (writer.u64(request.requested_limits.max_steps), true) &&
        (writer.u64(request.requested_limits.max_items), true) &&
        (writer.i64(request.issued_at_unix_sec), true) &&
        (writer.i64(request.expires_at_unix_sec), true) &&
        writer.text(request.auth_evidence_ref);
}

inline bool canonical_request(
    const ExternalAccessRequest& request,
    std::vector<std::uint8_t>& output
) {
    Writer writer;
    if (!request_fields(request, writer, "MOTHER_H_AUTH_REQUEST_V1"))
        return false;
    output = std::move(writer).take();
    return true;
}

inline bool canonical_scope(
    const ExternalAccessRequest& request,
    std::vector<std::uint8_t>& output
) {
    Writer writer;
    if (!request_fields(request, writer, "MOTHER_H_AUTH_SCOPE_V1"))
        return false;
    output = std::move(writer).take();
    return true;
}

inline bool scope_digest(
    const ExternalAccessRequest& request,
    std::string& output
) {
    std::vector<std::uint8_t> canonical;
    return canonical_scope(request, canonical) && sha256_hex(canonical, output);
}

inline bool canonical_approval(
    const AuthenticatedHumanApproval& authenticated,
    std::vector<std::uint8_t>& output
) {
    const auto& a = authenticated.approval;
    Writer writer;
    writer.text("MOTHER_H_AUTH_APPROVAL_V1");
    writer.u8(1);
    if (!writer.text(a.approval_id) || !writer.text(a.request_id) ||
        !writer.text(a.key_id) || !writer.text(a.requester_id) ||
        !writer.text(a.target_resource) || !writer.text(a.action) ||
        !writer.text(a.request_scope_digest)) return false;
    writer.u64(a.approved_limits.max_bytes);
    writer.u64(a.approved_limits.max_steps);
    writer.u64(a.approved_limits.max_items);
    writer.i64(a.issued_at_unix_sec);
    writer.i64(a.expires_at_unix_sec);
    if (!writer.text(authenticated.evidence_id) ||
        !writer.text(authenticated.evidence_digest_hex)) return false;
    output = std::move(writer).take();
    return true;
}

inline bool canonical_revocation(
    const AuthenticatedHumanRevocation& authenticated,
    std::vector<std::uint8_t>& output
) {
    const auto& r = authenticated.revocation;
    Writer writer;
    writer.text("MOTHER_H_AUTH_REVOCATION_V1");
    writer.u8(1);
    if (!writer.text(r.approval_id) || !writer.text(r.request_id) ||
        !writer.text(r.key_id) || !writer.text(r.human_approver_id))
        return false;
    writer.u64(r.expected_approval_revision);
    writer.u64(r.expected_revocation_epoch);
    writer.i64(r.revoked_at_unix_sec);
    if (!writer.text(r.evidence_id) || !writer.text(r.evidence_digest_hex))
        return false;
    output = std::move(writer).take();
    return true;
}

inline std::string to_hex(const unsigned char* bytes, std::size_t size) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string output;
    output.reserve(size * 2U);
    for (std::size_t i = 0; i < size; ++i) {
        output.push_back(hex[bytes[i] >> 4U]);
        output.push_back(hex[bytes[i] & 0x0FU]);
    }
    return output;
}

inline bool from_hex(std::string_view text, std::vector<unsigned char>& output) {
    if (text.empty() || (text.size() & 1U) != 0U) return false;
    output.clear();
    output.reserve(text.size() / 2U);
    const auto digit = [](char value) -> int {
        if (value >= '0' && value <= '9') return value - '0';
        if (value >= 'a' && value <= 'f') return value - 'a' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < text.size(); i += 2U) {
        const int hi = digit(text[i]);
        const int lo = digit(text[i + 1U]);
        if (hi < 0 || lo < 0) return false;
        output.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return true;
}

inline bool limits_positive(const AccessScopeLimits& limits) noexcept {
    return limits.max_bytes > 0 && limits.max_steps > 0 &&
        limits.max_items > 0;
}

inline bool limits_within(
    const AccessScopeLimits& value,
    const AccessScopeLimits& ceiling
) noexcept {
    return value.max_bytes <= ceiling.max_bytes &&
        value.max_steps <= ceiling.max_steps &&
        value.max_items <= ceiling.max_items;
}

inline bool nonempty_request(const ExternalAccessRequest& r) noexcept {
    return !r.request_id.empty() && !r.requester_id.empty() &&
        !r.key_id.empty() && !r.target_resource.empty() && !r.action.empty() &&
        !r.auth_evidence_ref.empty();
}

inline bool valid_period(
    std::int64_t issued,
    std::int64_t expires,
    std::int64_t now
) noexcept {
    return issued <= now && now < expires && issued < expires;
}

inline bool random_hex(std::size_t bytes, std::string& output) noexcept {
    try {
        std::vector<unsigned char> data(bytes);
        if (bytes == 0 || bytes > static_cast<std::size_t>((std::numeric_limits<int>::max)()) ||
            RAND_bytes(data.data(), static_cast<int>(bytes)) != 1)
            return false;
        output = to_hex(data.data(), data.size());
        OPENSSL_cleanse(data.data(), data.size());
        return true;
    } catch (...) {
        return false;
    }
}

inline std::string audit_event_digest(const RegistryOutboxEvent& event) {
    Writer writer;
    writer.text("MOTHER_H_AUTH_OUTBOX_V1");
    writer.u8(1);
    writer.text(event.event_id);
    writer.u8(static_cast<std::uint8_t>(event.phase));
    writer.u8(static_cast<std::uint8_t>(event.decision));
    writer.text(event.request_id);
    writer.text(event.requester_id);
    writer.text(event.key_id);
    writer.text(event.target_resource);
    writer.text(event.action);
    writer.text(event.approval_id);
    writer.i64(event.timestamp_unix_sec);
    writer.u64(event.consumed.max_bytes);
    writer.u64(event.consumed.max_steps);
    writer.u64(event.consumed.max_items);
    writer.text(event.retrieval_summary_hash);
    std::string result;
    sha256_hex(writer.bytes(), result);
    return result;
}

} // namespace detail

class IRequestSignatureVerifier {
public:
    virtual ~IRequestSignatureVerifier() = default;
    virtual bool verify(
        std::string_view canonical_request,
        std::string_view signature_hex
    ) const noexcept = 0;
};

class IHumanActionVerifier {
public:
    virtual ~IHumanActionVerifier() = default;
    virtual bool verify_approval(
        std::string_view canonical_approval,
        std::string_view signature_hex
    ) const noexcept = 0;
    virtual bool verify_revocation(
        std::string_view canonical_revocation,
        std::string_view signature_hex
    ) const noexcept = 0;
};

class IClock {
public:
    virtual ~IClock() = default;
    virtual std::int64_t now_unix_sec() const noexcept = 0;
};

class IGrantMacProvider {
public:
    virtual ~IGrantMacProvider() = default;
    virtual bool current_key(
        std::string& key_id_out,
        std::uint32_t& key_version_out
    ) const noexcept = 0;
    virtual bool create_mac(
        std::string_view canonical_grant,
        std::string_view key_id,
        std::uint32_t key_version,
        std::string& mac_hex_out
    ) noexcept = 0;
    virtual bool verify_mac(
        std::string_view canonical_grant,
        std::string_view key_id,
        std::uint32_t key_version,
        std::string_view mac_hex
    ) const noexcept = 0;
};

class HmacGrantMacProvider final : public IGrantMacProvider {
public:
    explicit HmacGrantMacProvider(
        const mother_h::journal::ISecureKeyProvider& keys
    ) noexcept : keys_(keys) {}

    bool current_key(
        std::string& key_id_out,
        std::uint32_t& key_version_out
    ) const noexcept override {
        mother_h::journal::KeyMaterial material;
        if (keys_.current_signing_key(material) !=
                mother_h::journal::KeyStatus::Ok ||
            material.reference().key_id.empty() ||
            material.reference().version == 0 ||
            material.secret().size() < 32U) return false;
        key_id_out = material.reference().key_id;
        key_version_out = material.reference().version;
        return true;
    }

    bool create_mac(
        std::string_view canonical_grant,
        std::string_view key_id,
        std::uint32_t key_version,
        std::string& mac_hex_out
    ) noexcept override {
        mother_h::journal::KeyMaterial material;
        if (!fetch(key_id, key_version, material)) return false;
        std::array<unsigned char, 32> mac{};
        unsigned int mac_size = 0;
        if (HMAC(EVP_sha256(), material.secret().data(),
                 static_cast<int>(material.secret().size()),
                 reinterpret_cast<const unsigned char*>(canonical_grant.data()),
                 canonical_grant.size(), mac.data(), &mac_size) == nullptr ||
            mac_size != mac.size()) return false;
        mac_hex_out = detail::to_hex(mac.data(), mac.size());
        OPENSSL_cleanse(mac.data(), mac.size());
        return true;
    }

    bool verify_mac(
        std::string_view canonical_grant,
        std::string_view key_id,
        std::uint32_t key_version,
        std::string_view mac_hex
    ) const noexcept override {
        std::vector<unsigned char> supplied;
        if (!detail::from_hex(mac_hex, supplied) || supplied.size() != 32U)
            return false;
        mother_h::journal::KeyMaterial material;
        if (!fetch(key_id, key_version, material)) return false;
        std::array<unsigned char, 32> calculated{};
        unsigned int size = 0;
        if (HMAC(EVP_sha256(), material.secret().data(),
                 static_cast<int>(material.secret().size()),
                 reinterpret_cast<const unsigned char*>(canonical_grant.data()),
                 canonical_grant.size(), calculated.data(), &size) == nullptr ||
            size != calculated.size()) return false;
        const bool same = CRYPTO_memcmp(
            calculated.data(), supplied.data(), calculated.size()) == 0;
        OPENSSL_cleanse(calculated.data(), calculated.size());
        OPENSSL_cleanse(supplied.data(), supplied.size());
        return same;
    }

private:
    bool fetch(
        std::string_view key_id,
        std::uint32_t key_version,
        mother_h::journal::KeyMaterial& material
    ) const noexcept {
        if (key_id.empty() || key_version == 0) return false;
        const mother_h::journal::KeyReference reference{
            std::string(key_id), key_version};
        return keys_.verification_key(reference, material) ==
                mother_h::journal::KeyStatus::Ok &&
            material.reference() == reference &&
            material.secret().size() >= 32U;
    }
    const mother_h::journal::ISecureKeyProvider& keys_;
};

class IAuditLogSink {
public:
    virtual ~IAuditLogSink() = default;
    virtual std::string_view sink_id() const noexcept = 0;
    virtual bool append(
        const RegistryOutboxEvent& event,
        IntentAuditReceipt& receipt_out
    ) noexcept = 0;
    virtual bool verify_receipt(const IntentAuditReceipt& receipt) const noexcept = 0;
};

class IExternalResourcePort {
public:
    virtual ~IExternalResourcePort() = default;
    virtual ResourcePortStatus read_chunk(
        std::string_view target_resource,
        std::uint64_t max_bytes,
        std::string& data_out
    ) noexcept = 0;
    virtual ResourcePortStatus write_chunk(
        std::string_view target_resource,
        std::string_view data
    ) noexcept = 0;
    virtual ResourcePortStatus emit_item(
        std::string_view target_resource,
        std::string_view item
    ) noexcept = 0;
};

class ITransactionalRegistryStore {
public:
    using Mutation = std::function<bool(RegistryState&)>;
    virtual ~ITransactionalRegistryStore() = default;
    virtual std::string_view name() const noexcept = 0;
    virtual RegistryStoreStatus read(RegistryState& out) const noexcept = 0;
    virtual RegistryStoreStatus transact(const Mutation& mutation) noexcept = 0;
};

class InMemoryTransactionalRegistryStore final
    : public ITransactionalRegistryStore {
public:
    std::string_view name() const noexcept override {
        return "InMemoryTransactionalRegistryStore";
    }
    RegistryStoreStatus read(RegistryState& out) const noexcept override {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            out = state_;
            return RegistryStoreStatus::Ok;
        } catch (...) {
            return RegistryStoreStatus::Unavailable;
        }
    }
    RegistryStoreStatus transact(const Mutation& mutation) noexcept override {
        if (!mutation) return RegistryStoreStatus::Rejected;
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            RegistryState next = state_;
            if (!mutation(next)) return RegistryStoreStatus::Rejected;
            if (next.store_revision ==
                (std::numeric_limits<std::uint64_t>::max)())
                return RegistryStoreStatus::Indeterminate;
            ++next.store_revision;
            std::swap(state_, next);
            return RegistryStoreStatus::Ok;
        } catch (...) {
            return RegistryStoreStatus::Unavailable;
        }
    }
private:
    mutable std::mutex mutex_;
    RegistryState state_;
};

class ApprovalGrant {
public:
    ApprovalGrant(const ApprovalGrant&) = default;
    ApprovalGrant(ApprovalGrant&&) noexcept = default;
    ApprovalGrant& operator=(const ApprovalGrant&) = default;
    ApprovalGrant& operator=(ApprovalGrant&&) noexcept = default;
    const std::string& request_id() const noexcept { return request_id_; }
    const std::string& key_id() const noexcept { return key_id_; }
    const std::string& requester_id() const noexcept { return requester_id_; }
    const std::string& target_resource() const noexcept { return target_resource_; }
    const std::string& action() const noexcept { return action_; }
    const AccessScopeLimits& limits() const noexcept { return limits_; }
    std::int64_t expires_at_unix_sec() const noexcept { return expires_at_unix_sec_; }
    const std::string& approval_id() const noexcept { return approval_id_; }
    const std::string& grant_id() const noexcept { return grant_id_; }
    std::uint64_t registry_revision() const noexcept { return registry_revision_; }
    std::int64_t issued_at_unix_sec() const noexcept { return issued_at_unix_sec_; }
    const std::string& scope_digest() const noexcept { return scope_digest_; }
    std::uint64_t approval_revision() const noexcept { return approval_revision_; }
    std::uint64_t revocation_epoch() const noexcept { return revocation_epoch_; }
    const std::string& mac_key_id() const noexcept { return mac_key_id_; }
    std::uint32_t mac_key_version() const noexcept { return mac_key_version_; }
private:
    friend class ExternalAccessGate;
    friend class ScopedExecutionGuard;
    ApprovalGrant() = default;
    std::string request_id_;
    std::string key_id_;
    std::string requester_id_;
    std::string target_resource_;
    std::string action_;
    AccessScopeLimits limits_{};
    std::int64_t issued_at_unix_sec_{0};
    std::int64_t expires_at_unix_sec_{0};
    std::string approval_id_;
    std::string scope_digest_;
    std::string grant_id_;
    std::uint64_t approval_revision_{0};
    std::uint64_t revocation_epoch_{0};
    std::uint64_t registry_revision_{0};
    std::string mac_key_id_;
    std::uint32_t mac_key_version_{0};
    std::string mac_hex_;
};

struct AuthorizationResult {
    GovernanceDecisionCode decision{GovernanceDecisionCode::KeyNotApproved};
    std::optional<ApprovalGrant> grant;
    bool audit_recorded{false};
};

struct ExecutionResult {
    GovernanceDecisionCode decision{GovernanceDecisionCode::KeyNotApproved};
    KeyTrustStatus key_status{KeyTrustStatus::Burned};
    bool execution_started{false};
    bool burn_confirmed{false};
    bool outcome_audit_recorded{false};
    bool result_indeterminate{false};
    AccessScopeLimits consumed{};
    std::string retrieval_summary_hash;
};

inline bool canonical_grant(
    const ApprovalGrant& grant,
    std::vector<std::uint8_t>& output
) {
    detail::Writer writer;
    writer.text("MOTHER_H_AUTH_GRANT_V1");
    writer.u8(1);
    if (!writer.text(grant.grant_id()) || !writer.text(grant.request_id()) ||
        !writer.text(grant.key_id()) || !writer.text(grant.requester_id()) ||
        !writer.text(grant.target_resource()) || !writer.text(grant.action()) ||
        !writer.text(grant.approval_id()) ||
        !writer.text(grant.scope_digest()) ||
        !writer.text(grant.mac_key_id())) return false;
    writer.u64(grant.limits().max_bytes);
    writer.u64(grant.limits().max_steps);
    writer.u64(grant.limits().max_items);
    writer.i64(grant.issued_at_unix_sec());
    writer.i64(grant.expires_at_unix_sec());
    writer.u64(grant.approval_revision());
    writer.u64(grant.revocation_epoch());
    writer.u64(grant.registry_revision());
    writer.u32(grant.mac_key_version());
    output = std::move(writer).take();
    return true;
}

struct RegistryOperationResult {
    GovernanceDecisionCode decision{GovernanceDecisionCode::StoreUnavailable};
    RegistryOutboxEvent event;
};

class EphemeralKeyRegistry {
public:
    EphemeralKeyRegistry(
        ITransactionalRegistryStore& store,
        const IClock& clock,
        const IHumanActionVerifier& human_verifier,
        IAuditLogSink& audit_sink
    ) noexcept
        : store_(store), clock_(clock), human_verifier_(human_verifier),
          audit_sink_(audit_sink) {}

    GovernanceDecisionCode submit_key_request(
        const KeyRegistrationRequest& request,
        const IRequestSignatureVerifier& verifier,
        EphemeralKeyRecord& record_out
    ) noexcept {
        try {
            std::vector<std::uint8_t> canonical;
            if (!detail::nonempty_request(request) ||
                !detail::limits_positive(request.requested_limits))
                return GovernanceDecisionCode::MissingRequiredField;
            if (request.target_resource == "*" ||
                !detail::limits_positive(request.requested_limits))
                return GovernanceDecisionCode::UnlimitedScopeRejected;
            if (!detail::valid_period(request.issued_at_unix_sec,
                                      request.expires_at_unix_sec,
                                      clock_.now_unix_sec()))
                return GovernanceDecisionCode::InvalidTimestampOrExpired;
            if (!detail::canonical_request(request, canonical) ||
                !verifier.verify(
                    std::string_view(reinterpret_cast<const char*>(canonical.data()),
                                     canonical.size()),
                    request.signature_hex))
                return GovernanceDecisionCode::SignatureVerificationFailed;
            std::string digest;
            if (!detail::scope_digest(request, digest))
                return GovernanceDecisionCode::MissingRequiredField;
            RegistryOutboxEvent event;
            const auto status = store_.transact([&](RegistryState& state) {
                for (const auto& pair : state.records) {
                    if (pair.second.request_id == request.request_id ||
                        pair.first == request.key_id) return false;
                }
                EphemeralKeyRecord record;
                record.key_id = request.key_id;
                record.request_id = request.request_id;
                record.requester_id = request.requester_id;
                record.target_resource = request.target_resource;
                record.action = request.action;
                record.limits = request.requested_limits;
                record.requested_limits = request.requested_limits;
                record.issued_at_unix_sec = request.issued_at_unix_sec;
                record.expires_at_unix_sec = request.expires_at_unix_sec;
                record.auth_evidence_ref = request.auth_evidence_ref;
                record.registry_revision = 1;
                record.exists = true;
                state.records.emplace(record.key_id, record);
                event = make_event(record, GovernanceAuditPhase::KeyRegistration,
                                   GovernanceDecisionCode::Allowed,
                                   clock_.now_unix_sec());
                state.outbox.push_back(event);
                record_out = record;
                return true;
            });
            if (status != RegistryStoreStatus::Ok) return map_store(status);
            if (!deliver(event)) return GovernanceDecisionCode::AuditSinkFailure;
            return GovernanceDecisionCode::Allowed;
        } catch (...) {
            return GovernanceDecisionCode::StoreUnavailable;
        }
    }

    GovernanceDecisionCode approve_key(
        const AuthenticatedHumanApproval& authenticated,
        EphemeralKeyRecord& record_out
    ) noexcept {
        try {
            std::vector<std::uint8_t> canonical;
            if (!detail::canonical_approval(authenticated, canonical) ||
                !human_verifier_.verify_approval(
                    std::string_view(reinterpret_cast<const char*>(canonical.data()),
                                     canonical.size()),
                    authenticated.signature_hex))
                return GovernanceDecisionCode::HumanApprovalMissingOrMismatch;
            const auto& a = authenticated.approval;
            RegistryOutboxEvent event;
            const auto status = store_.transact([&](RegistryState& state) {
                auto found = state.records.find(a.key_id);
                if (found == state.records.end()) return false;
                auto& record = found->second;
                for (const auto& pair : state.records) {
                    if (pair.first != a.key_id &&
                        pair.second.approval_id == a.approval_id)
                        return false;
                }
                ExternalAccessRequest request = request_from_record(record);
                std::string digest;
                if (record.approval_status != ApprovalStatus::Pending ||
                    record.status != KeyTrustStatus::PendingApproval ||
                    a.approval_id.empty() || a.request_id != record.request_id ||
                    a.key_id != record.key_id ||
                    a.requester_id != record.requester_id ||
                    a.human_approver_id.empty() ||
                    a.target_resource != record.target_resource ||
                    a.action != record.action ||
                    !detail::scope_digest(request, digest) ||
                    digest != a.request_scope_digest ||
                    !detail::limits_positive(a.approved_limits) ||
                    !detail::limits_within(a.approved_limits,
                                           record.requested_limits) ||
                    a.issued_at_unix_sec > clock_.now_unix_sec() ||
                    a.expires_at_unix_sec <= clock_.now_unix_sec() ||
                    a.expires_at_unix_sec > record.expires_at_unix_sec ||
                    authenticated.evidence_id.empty() ||
                    authenticated.evidence_digest_hex.empty() ||
                    authenticated.evidence_digest_hex.size() != 64U ||
                    record.approval_revision ==
                        (std::numeric_limits<std::uint64_t>::max)() ||
                    record.registry_revision ==
                        (std::numeric_limits<std::uint64_t>::max)())
                    return false;
                record.approval_id = a.approval_id;
                record.approval_evidence_id = authenticated.evidence_id;
                record.approval_evidence_digest_hex =
                    authenticated.evidence_digest_hex;
                record.approval_scope_digest = a.request_scope_digest;
                record.limits = a.approved_limits;
                record.approval_expires_at_unix_sec =
                    a.expires_at_unix_sec;
                record.approval_status = ApprovalStatus::Active;
                record.status = KeyTrustStatus::ApprovedUnused;
                ++record.approval_revision;
                ++record.registry_revision;
                event = make_event(record, GovernanceAuditPhase::KeyApproval,
                                   GovernanceDecisionCode::Allowed,
                                   clock_.now_unix_sec());
                state.outbox.push_back(event);
                record_out = record;
                return true;
            });
            if (status != RegistryStoreStatus::Ok) return map_store(status);
            if (!deliver(event)) return GovernanceDecisionCode::AuditSinkFailure;
            load_record(authenticated.approval.key_id, record_out);
            return GovernanceDecisionCode::Allowed;
        } catch (...) {
            return GovernanceDecisionCode::StoreUnavailable;
        }
    }

    GovernanceDecisionCode revoke_approval(
        const AuthenticatedHumanRevocation& authenticated
    ) noexcept {
        try {
            std::vector<std::uint8_t> canonical;
            if (!detail::canonical_revocation(authenticated, canonical) ||
                !human_verifier_.verify_revocation(
                    std::string_view(reinterpret_cast<const char*>(canonical.data()),
                                     canonical.size()),
                    authenticated.signature_hex))
                return GovernanceDecisionCode::HumanApprovalMissingOrMismatch;
            const auto& revocation = authenticated.revocation;
            RegistryOutboxEvent event;
            const auto status = store_.transact([&](RegistryState& state) {
                auto found = state.records.find(revocation.key_id);
                if (found == state.records.end()) return false;
                auto& record = found->second;
                if (record.approval_status != ApprovalStatus::Active ||
                    record.approval_id != revocation.approval_id ||
                    record.request_id != revocation.request_id ||
                    record.approval_revision !=
                        revocation.expected_approval_revision ||
                    record.revocation_epoch !=
                        revocation.expected_revocation_epoch ||
                    revocation.revoked_at_unix_sec > clock_.now_unix_sec() ||
                    revocation.evidence_id.empty() ||
                    revocation.evidence_digest_hex.empty() ||
                    revocation.human_approver_id.empty() ||
                    revocation.evidence_digest_hex.size() != 64U ||
                    record.approval_revision ==
                        (std::numeric_limits<std::uint64_t>::max)() ||
                    record.revocation_epoch ==
                        (std::numeric_limits<std::uint64_t>::max)() ||
                    record.registry_revision ==
                        (std::numeric_limits<std::uint64_t>::max)())
                    return false;
                record.approval_status = ApprovalStatus::Revoked;
                ++record.approval_revision;
                ++record.revocation_epoch;
                ++record.registry_revision;
                if (record.status != KeyTrustStatus::InUseConsumed ||
                    record.execution_phase != ExecutionPhase::Started)
                    record.status = KeyTrustStatus::Burned;
                event = make_event(record, GovernanceAuditPhase::KeyRevocation,
                                   GovernanceDecisionCode::Allowed,
                                   clock_.now_unix_sec());
                state.outbox.push_back(event);
                return true;
            });
            if (status != RegistryStoreStatus::Ok) return map_store(status);
            return deliver(event) ? GovernanceDecisionCode::Allowed
                                  : GovernanceDecisionCode::AuditSinkFailure;
        } catch (...) {
            return GovernanceDecisionCode::StoreUnavailable;
        }
    }

    GovernanceDecisionCode revoke_key(std::string_view key_id) noexcept {
        (void)key_id;
        return GovernanceDecisionCode::HumanApprovalMissingOrMismatch;
    }

    KeyStatusResult status_of(std::string_view key_id) const noexcept {
        expire_if_due(key_id);
        RegistryState state;
        const auto status = store_.read(state);
        if (status != RegistryStoreStatus::Ok)
            return {map_store(status), KeyTrustStatus::Burned,
                    ApprovalStatus::Pending, ExecutionPhase::Indeterminate, 0, false};
        const auto found = state.records.find(std::string(key_id));
        if (found == state.records.end())
            return {GovernanceDecisionCode::KeyNotApproved,
                    KeyTrustStatus::Burned, ApprovalStatus::Pending,
                    ExecutionPhase::NotStarted, 0, false};
        const auto& record = found->second;
        return {GovernanceDecisionCode::Allowed, record.status,
                record.approval_status, record.execution_phase,
                record.registry_revision, true};
    }

private:
    friend class ScopedExecutionGuard;

    RegistryOperationResult consume_once_verified(
        const ApprovalGrant& grant
    ) noexcept {
        RegistryOperationResult result;
        expire_if_due(grant.key_id());
        const auto status = store_.transact([&](RegistryState& state) {
            auto found = state.records.find(grant.key_id());
            if (found == state.records.end()) return false;
            auto& record = found->second;
            if (record.approval_status == ApprovalStatus::Revoked) {
                result.decision = GovernanceDecisionCode::ApprovalRevoked;
                return false;
            }
            if (record.status != KeyTrustStatus::ApprovedUnused ||
                record.approval_status != ApprovalStatus::Active ||
                !grant_matches_record(record, grant) ||
                record.registry_revision != grant.registry_revision() ||
                clock_.now_unix_sec() < grant.issued_at_unix_sec() ||
                clock_.now_unix_sec() >= grant.expires_at_unix_sec()) {
                result.decision = GovernanceDecisionCode::KeyAlreadyConsumedOrBurned;
                return false;
            }
            if (record.registry_revision ==
                    (std::numeric_limits<std::uint64_t>::max)() ||
                record.key_revision ==
                    (std::numeric_limits<std::uint64_t>::max)())
                return false;
            record.status = KeyTrustStatus::InUseConsumed;
            ++record.key_revision;
            ++record.registry_revision;
            record.consume_registry_revision = record.registry_revision;
            result.event = make_event(record, GovernanceAuditPhase::ExecutionIntent,
                                      GovernanceDecisionCode::Allowed,
                                      clock_.now_unix_sec());
            record.intent_event_id = result.event.event_id;
            record.intent_receipt_recorded = false;
            state.outbox.push_back(result.event);
            result.decision = GovernanceDecisionCode::Allowed;
            return true;
        });
        if (status != RegistryStoreStatus::Ok &&
            result.decision == GovernanceDecisionCode::StoreUnavailable)
            result.decision = map_store(status);
        return result;
    }

public:
    GovernanceDecisionCode record_intent_receipt(
        const ApprovalGrant& grant,
        const IntentAuditReceipt& receipt
    ) noexcept {
        RegistryState state;
        if (store_.read(state) != RegistryStoreStatus::Ok)
            return GovernanceDecisionCode::StoreUnavailable;
        const auto event = std::find_if(
            state.outbox.begin(), state.outbox.end(),
            [&](const RegistryOutboxEvent& candidate) {
                return candidate.event_id == receipt.event_id;
            });
        if (event == state.outbox.end() ||
            event->phase != GovernanceAuditPhase::ExecutionIntent ||
            event->key_id != grant.key_id() ||
            !valid_receipt(*event, receipt) ||
            !audit_sink_.verify_receipt(receipt))
            return GovernanceDecisionCode::AuditSinkFailure;
        return record_receipt(grant.key_id(), receipt);
    }

    bool outbox_events(std::vector<RegistryOutboxEvent>& output) const noexcept {
        RegistryState state;
        if (store_.read(state) != RegistryStoreStatus::Ok) return false;
        output = std::move(state.outbox);
        return true;
    }

private:
    friend class ScopedExecutionGuard;

    GovernanceDecisionCode begin_execution_verified(
        const ApprovalGrant& grant
    ) noexcept {
        expire_if_due(grant.key_id());
        const auto status = store_.transact([&](RegistryState& state) {
            auto found = state.records.find(grant.key_id());
            if (found == state.records.end()) return false;
            auto& record = found->second;
            if (record.approval_status == ApprovalStatus::Revoked)
                return false;
            if (record.approval_status != ApprovalStatus::Active ||
                record.approval_revision != grant.approval_revision() ||
                record.revocation_epoch != grant.revocation_epoch() ||
                record.status != KeyTrustStatus::InUseConsumed ||
                !grant_matches_record(record, grant) ||
                record.grant_registry_revision != grant.registry_revision() ||
                record.consume_registry_revision != record.registry_revision ||
                record.execution_phase != ExecutionPhase::NotStarted ||
                !record.intent_receipt_recorded ||
                clock_.now_unix_sec() < grant.issued_at_unix_sec() ||
                clock_.now_unix_sec() >= grant.expires_at_unix_sec() ||
                record.registry_revision ==
                    (std::numeric_limits<std::uint64_t>::max)() ||
                record.execution_revision ==
                    (std::numeric_limits<std::uint64_t>::max)())
                return false;
            ++record.registry_revision;
            ++record.execution_revision;
            record.execution_phase = ExecutionPhase::Started;
            state.outbox.push_back(make_event(
                record, GovernanceAuditPhase::ExecutionStarted,
                GovernanceDecisionCode::Allowed, clock_.now_unix_sec()));
            return true;
        });
        if (status == RegistryStoreStatus::Ok)
            return GovernanceDecisionCode::Allowed;
        if (status == RegistryStoreStatus::Rejected) {
            const auto current = status_of(grant.key_id());
            return current.approval_status == ApprovalStatus::Revoked
                ? GovernanceDecisionCode::ApprovalRevoked
                : GovernanceDecisionCode::KeyAlreadyConsumedOrBurned;
        }
        return map_store(status);
    }

public:
    GovernanceDecisionCode authorize_session_operation(
        const ApprovalGrant& grant
    ) noexcept {
        expire_if_due(grant.key_id());
        const auto status = store_.transact([&](RegistryState& state) {
            auto found = state.records.find(grant.key_id());
            if (found == state.records.end()) return false;
            auto& record = found->second;
            if (record.status != KeyTrustStatus::InUseConsumed ||
                record.approval_status != ApprovalStatus::Active ||
                !grant_matches_record(record, grant) ||
                record.execution_phase != ExecutionPhase::Started ||
                clock_.now_unix_sec() >= grant.expires_at_unix_sec() ||
                record.session_operation_sequence ==
                    (std::numeric_limits<std::uint64_t>::max)() ||
                record.execution_revision ==
                    (std::numeric_limits<std::uint64_t>::max)() ||
                record.registry_revision ==
                    (std::numeric_limits<std::uint64_t>::max)())
                return false;
            ++record.session_operation_sequence;
            ++record.execution_revision;
            ++record.registry_revision;
            return true;
        });
        if (status == RegistryStoreStatus::Ok)
            return GovernanceDecisionCode::Allowed;
        if (status == RegistryStoreStatus::Rejected) {
            const auto current = status_of(grant.key_id());
            return current.approval_status == ApprovalStatus::Revoked
                ? GovernanceDecisionCode::ApprovalRevoked
                : GovernanceDecisionCode::KeyAlreadyConsumedOrBurned;
        }
        return map_store(status);
    }

    GovernanceDecisionCode burn(
        const ApprovalGrant& grant,
        GovernanceDecisionCode outcome,
        const AccessScopeLimits& consumed,
        std::string retrieval_hash,
        bool outcome_determinate,
        RegistryOutboxEvent& event_out
    ) noexcept {
        RegistryOutboxEvent event;
        const auto status = store_.transact([&](RegistryState& state) {
            auto found = state.records.find(grant.key_id());
            if (found == state.records.end()) return false;
            auto& record = found->second;
            if (record.status == KeyTrustStatus::Burned) return false;
            if (record.status != KeyTrustStatus::InUseConsumed ||
                record.grant_id != grant.grant_id()) return false;
            if (record.registry_revision ==
                    (std::numeric_limits<std::uint64_t>::max)() ||
                record.key_revision ==
                    (std::numeric_limits<std::uint64_t>::max)() ||
                record.execution_revision ==
                    (std::numeric_limits<std::uint64_t>::max)())
                return false;
            record.status = KeyTrustStatus::Burned;
            record.execution_phase = outcome_determinate
                ? ExecutionPhase::Finished : ExecutionPhase::Indeterminate;
            ++record.key_revision;
            ++record.execution_revision;
            ++record.registry_revision;
            event = make_event(record,
                GovernanceAuditPhase::ExecutionOutcomeBurn, outcome,
                clock_.now_unix_sec());
            event.consumed = consumed;
            event.retrieval_summary_hash = std::move(retrieval_hash);
            event.event_digest_hex = detail::audit_event_digest(event);
            state.outbox.push_back(event);
            event_out = event;
            return true;
        });
        if (status == RegistryStoreStatus::Ok)
            return GovernanceDecisionCode::Allowed;
        return map_store(status);
    }

    bool deliver(const RegistryOutboxEvent& event) const noexcept {
        IntentAuditReceipt receipt;
        if (!audit_sink_.append(event, receipt) ||
            !valid_receipt(event, receipt) ||
            !audit_sink_.verify_receipt(receipt))
            return false;
        return record_receipt(event.key_id, receipt) ==
            GovernanceDecisionCode::Allowed;
    }

    GovernanceDecisionCode record_outbox_receipt(
        const RegistryOutboxEvent& event,
        const IntentAuditReceipt& receipt
    ) noexcept {
        if (!valid_receipt(event, receipt) || !audit_sink_.verify_receipt(receipt))
            return GovernanceDecisionCode::AuditSinkFailure;
        return record_receipt(event.key_id, receipt);
    }

    bool load_record(std::string_view key_id, EphemeralKeyRecord& out) const noexcept {
        RegistryState state;
        if (store_.read(state) != RegistryStoreStatus::Ok) return false;
        const auto found = state.records.find(std::string(key_id));
        if (found == state.records.end()) return false;
        out = found->second;
        return true;
    }

private:
    friend class ExternalAccessGate;
    friend class ScopedExecutionGuard;

    static GovernanceDecisionCode map_store(RegistryStoreStatus status) noexcept {
        switch (status) {
        case RegistryStoreStatus::Ok: return GovernanceDecisionCode::Allowed;
        case RegistryStoreStatus::Rejected:
            return GovernanceDecisionCode::KeyAlreadyConsumedOrBurned;
        case RegistryStoreStatus::Unavailable: return GovernanceDecisionCode::StoreUnavailable;
        case RegistryStoreStatus::IntegrityFailure: return GovernanceDecisionCode::IntegrityFailure;
        case RegistryStoreStatus::Indeterminate: return GovernanceDecisionCode::StoreIndeterminate;
        }
        return GovernanceDecisionCode::StoreUnavailable;
    }

    static bool grant_matches_record(
        const EphemeralKeyRecord& record,
        const ApprovalGrant& grant
    ) noexcept {
        const auto expiry = record.approval_expires_at_unix_sec > 0
            ? (std::min)(record.expires_at_unix_sec,
                         record.approval_expires_at_unix_sec)
            : record.expires_at_unix_sec;
        return record.grant_id == grant.grant_id() &&
            record.request_id == grant.request_id() &&
            record.key_id == grant.key_id() &&
            record.requester_id == grant.requester_id() &&
            record.target_resource == grant.target_resource() &&
            record.action == grant.action() &&
            record.grant_limits.max_bytes == grant.limits().max_bytes &&
            record.grant_limits.max_steps == grant.limits().max_steps &&
            record.grant_limits.max_items == grant.limits().max_items &&
            record.issued_at_unix_sec == grant.issued_at_unix_sec() &&
            expiry == grant.expires_at_unix_sec() &&
            record.approval_id == grant.approval_id() &&
            record.approval_scope_digest == grant.scope_digest() &&
            record.approval_revision == grant.approval_revision() &&
            record.revocation_epoch == grant.revocation_epoch() &&
            record.grant_registry_revision == grant.registry_revision() &&
            record.grant_mac_key_id == grant.mac_key_id() &&
            record.grant_mac_key_version == grant.mac_key_version();
    }

    void expire_if_due(std::string_view key_id) const noexcept {
        RegistryOutboxEvent event;
        const auto status = store_.transact([&](RegistryState& state) {
            auto found = state.records.find(std::string(key_id));
            if (found == state.records.end()) return false;
            auto& record = found->second;
            const auto deadline = record.approval_expires_at_unix_sec > 0
                ? (std::min)(record.expires_at_unix_sec,
                             record.approval_expires_at_unix_sec)
                : record.expires_at_unix_sec;
            if (record.approval_status != ApprovalStatus::Active ||
                clock_.now_unix_sec() < deadline)
                return false;
            if (record.registry_revision ==
                    (std::numeric_limits<std::uint64_t>::max)() ||
                record.approval_revision ==
                    (std::numeric_limits<std::uint64_t>::max)() ||
                record.revocation_epoch ==
                    (std::numeric_limits<std::uint64_t>::max)())
                return false;
            record.approval_status = ApprovalStatus::Expired;
            if (record.status != KeyTrustStatus::InUseConsumed ||
                record.execution_phase != ExecutionPhase::Started)
                record.status = KeyTrustStatus::Burned;
            ++record.registry_revision;
            ++record.approval_revision;
            ++record.revocation_epoch;
            event = make_event(record, GovernanceAuditPhase::KeyRevocation,
                               GovernanceDecisionCode::InvalidTimestampOrExpired,
                               clock_.now_unix_sec());
            state.outbox.push_back(event);
            return true;
        });
        if (status == RegistryStoreStatus::Ok) deliver(event);
    }

    static ExternalAccessRequest request_from_record(
        const EphemeralKeyRecord& record
    ) {
        ExternalAccessRequest request;
        request.request_id = record.request_id;
        request.requester_id = record.requester_id;
        request.key_id = record.key_id;
        request.target_resource = record.target_resource;
        request.action = record.action;
        request.requested_limits = record.requested_limits;
        request.issued_at_unix_sec = record.issued_at_unix_sec;
        request.expires_at_unix_sec = record.expires_at_unix_sec;
        request.auth_evidence_ref = record.auth_evidence_ref;
        return request;
    }

    static RegistryOutboxEvent make_event(
        const EphemeralKeyRecord& record,
        GovernanceAuditPhase phase,
        GovernanceDecisionCode decision,
        std::int64_t timestamp
    ) {
        RegistryOutboxEvent event;
        detail::random_hex(16, event.event_id);
        event.phase = phase;
        event.decision = decision;
        event.request_id = record.request_id;
        event.requester_id = record.requester_id;
        event.key_id = record.key_id;
        event.target_resource = record.target_resource;
        event.action = record.action;
        event.approval_id = record.approval_id;
        event.timestamp_unix_sec = timestamp;
        event.event_digest_hex = detail::audit_event_digest(event);
        return event;
    }

    bool valid_receipt(
        const RegistryOutboxEvent& event,
        const IntentAuditReceipt& receipt
    ) const noexcept {
        return !event.event_id.empty() &&
            receipt.event_id == event.event_id &&
            receipt.sink_id == audit_sink_.sink_id() &&
            receipt.event_digest_hex == event.event_digest_hex &&
            receipt.received_at_unix_sec > 0 &&
            receipt.receipt_key_version > 0 &&
            !receipt.receipt_mac_hex.empty();
    }

    GovernanceDecisionCode record_receipt(
        std::string_view key_id,
        const IntentAuditReceipt& receipt
    ) const noexcept {
        const auto status = store_.transact([&](RegistryState& state) {
            auto event = std::find_if(
                state.outbox.begin(), state.outbox.end(),
                [&](const RegistryOutboxEvent& candidate) {
                    return candidate.event_id == receipt.event_id;
                });
            if (event == state.outbox.end() ||
                event->event_digest_hex != receipt.event_digest_hex ||
                receipt.sink_id != audit_sink_.sink_id())
                return false;
            if (event->receipt_recorded) {
                return event->receipt_sink_id == receipt.sink_id &&
                    event->receipt_digest_hex == receipt.event_digest_hex &&
                    event->receipt_mac_hex == receipt.receipt_mac_hex;
            }
            event->receipt_recorded = true;
            event->receipt_sink_id = receipt.sink_id;
            event->receipt_digest_hex = receipt.event_digest_hex;
            event->receipt_received_at_unix_sec = receipt.received_at_unix_sec;
            event->receipt_key_version = receipt.receipt_key_version;
            event->receipt_mac_hex = receipt.receipt_mac_hex;
            auto record = state.records.find(std::string(key_id));
            if (record != state.records.end()) {
                if (record->second.outbox_ack_revision ==
                    (std::numeric_limits<std::uint64_t>::max)())
                    return false;
                ++record->second.outbox_ack_revision;
                if (event->phase == GovernanceAuditPhase::ExecutionIntent &&
                    record->second.intent_event_id == event->event_id)
                    record->second.intent_receipt_recorded = true;
                if (event->phase == GovernanceAuditPhase::KeyApproval)
                    record->second.approval_receipt_recorded = true;
            }
            return true;
        });
        return status == RegistryStoreStatus::Ok
            ? GovernanceDecisionCode::Allowed
            : map_store(status);
    }

    ITransactionalRegistryStore& store_;
    const IClock& clock_;
    const IHumanActionVerifier& human_verifier_;
    IAuditLogSink& audit_sink_;
};

class ExternalAccessGate {
public:
    ExternalAccessGate(
        EphemeralKeyRegistry& registry,
        const IClock& clock,
        const IRequestSignatureVerifier& signature_verifier,
        IGrantMacProvider& grant_mac_provider,
        IAuditLogSink& audit_sink
    ) noexcept
        : registry_(registry), clock_(clock),
          signature_verifier_(signature_verifier),
          grant_mac_provider_(grant_mac_provider), audit_sink_(audit_sink) {}

    GovernanceDecisionCode resume_consumed_grant(
        std::string_view key_id,
        std::optional<ApprovalGrant>& grant_out
    ) const noexcept {
        EphemeralKeyRecord record;
        if (!registry_.load_record(key_id, record))
            return GovernanceDecisionCode::KeyNotApproved;
        if (record.status != KeyTrustStatus::InUseConsumed ||
            record.approval_status != ApprovalStatus::Active ||
            record.execution_phase != ExecutionPhase::NotStarted ||
            !record.intent_receipt_recorded)
            return GovernanceDecisionCode::KeyAlreadyConsumedOrBurned;
        ApprovalGrant candidate;
        candidate.request_id_ = record.request_id;
        candidate.key_id_ = record.key_id;
        candidate.requester_id_ = record.requester_id;
        candidate.target_resource_ = record.target_resource;
        candidate.action_ = record.action;
        candidate.limits_ = record.grant_limits;
        candidate.issued_at_unix_sec_ = record.issued_at_unix_sec;
        candidate.expires_at_unix_sec_ =
            record.approval_expires_at_unix_sec > 0
                ? (std::min)(record.expires_at_unix_sec,
                             record.approval_expires_at_unix_sec)
                : record.expires_at_unix_sec;
        candidate.approval_id_ = record.approval_id;
        candidate.scope_digest_ = record.approval_scope_digest;
        candidate.grant_id_ = record.grant_id;
        candidate.approval_revision_ = record.approval_revision;
        candidate.revocation_epoch_ = record.revocation_epoch;
        candidate.registry_revision_ = record.grant_registry_revision;
        candidate.mac_key_id_ = record.grant_mac_key_id;
        candidate.mac_key_version_ = record.grant_mac_key_version;
        candidate.mac_hex_ = record.grant_mac_hex;
        if (!verify_grant_mac(candidate))
            return GovernanceDecisionCode::GrantTamperedOrInvalid;
        grant_out.emplace(std::move(candidate));
        return GovernanceDecisionCode::Allowed;
    }

    AuthorizationResult validate_and_authorize(
        const ExternalAccessRequest& request
    ) noexcept {
        AuthorizationResult result;
        try {
            if (!detail::nonempty_request(request)) {
                result.decision = GovernanceDecisionCode::MissingRequiredField;
                return result;
            }
            registry_.status_of(request.key_id);
            if (!detail::limits_positive(request.requested_limits) ||
                request.target_resource == "*") {
                result.decision = GovernanceDecisionCode::UnlimitedScopeRejected;
                return result;
            }
            if (!detail::valid_period(request.issued_at_unix_sec,
                                      request.expires_at_unix_sec,
                                      clock_.now_unix_sec())) {
                result.decision = GovernanceDecisionCode::InvalidTimestampOrExpired;
                return result;
            }
            std::vector<std::uint8_t> canonical;
            if (!detail::canonical_request(request, canonical) ||
                !signature_verifier_.verify(
                    std::string_view(reinterpret_cast<const char*>(canonical.data()),
                                     canonical.size()),
                    request.signature_hex)) {
                result.decision = GovernanceDecisionCode::SignatureVerificationFailed;
                return result;
            }
            EphemeralKeyRecord record;
            if (!registry_.load_record(request.key_id, record)) {
                result.decision = GovernanceDecisionCode::KeyNotApproved;
                return result;
            }
            std::string digest;
            if (!detail::scope_digest(request, digest) ||
                record.request_id != request.request_id ||
                record.requester_id != request.requester_id ||
                record.target_resource != request.target_resource ||
                record.action != request.action ||
                record.approval_scope_digest != digest ||
                request.human_approval_ref != record.approval_id ||
                !detail::limits_within(request.requested_limits,
                                       record.requested_limits)) {
                result.decision = GovernanceDecisionCode::HumanApprovalMissingOrMismatch;
                return result;
            }
            if (clock_.now_unix_sec() >=
                (record.approval_expires_at_unix_sec > 0
                    ? (std::min)(record.expires_at_unix_sec,
                                 record.approval_expires_at_unix_sec)
                    : record.expires_at_unix_sec)) {
                result.decision = GovernanceDecisionCode::InvalidTimestampOrExpired;
                return result;
            }
            if (record.approval_status == ApprovalStatus::Revoked) {
                result.decision = GovernanceDecisionCode::ApprovalRevoked;
                return result;
            }
            if (record.approval_status != ApprovalStatus::Active ||
            record.status != KeyTrustStatus::ApprovedUnused ||
            !record.approval_receipt_recorded) {
                result.decision = GovernanceDecisionCode::KeyNotApproved;
                return result;
            }
            ApprovalGrant grant;
            if (!make_or_load_grant(request, record, grant)) {
                result.decision = GovernanceDecisionCode::StoreUnavailable;
                return result;
            }
            RegistryOutboxEvent event;
            event = EphemeralKeyRegistry::make_event(
                record, GovernanceAuditPhase::Authorization,
                GovernanceDecisionCode::Allowed, clock_.now_unix_sec());
            if (registry_.store_.transact([&](RegistryState& state) {
                    state.outbox.push_back(event);
                    return true;
                }) != RegistryStoreStatus::Ok ||
                !registry_.deliver(event)) {
                result.decision = GovernanceDecisionCode::AuditSinkFailure;
                return result;
            }
            result.decision = GovernanceDecisionCode::Allowed;
            result.grant.emplace(std::move(grant));
            result.audit_recorded = true;
            return result;
        } catch (...) {
            result.decision = GovernanceDecisionCode::StoreUnavailable;
            return result;
        }
    }

private:
    bool make_or_load_grant(
        const ExternalAccessRequest& request,
        const EphemeralKeyRecord& current,
        ApprovalGrant& grant
    ) noexcept {
        try {
            EphemeralKeyRecord record = current;
            if (record.grant_id.empty()) {
                std::string grant_id;
                std::string key_id;
                std::uint32_t key_version = 0;
                if (!detail::random_hex(16, grant_id) ||
                    !grant_mac_provider_.current_key(key_id, key_version) ||
                    key_id.empty() || key_version == 0 ||
                    record.registry_revision ==
                        (std::numeric_limits<std::uint64_t>::max)())
                    return false;
                grant.grant_id_ = grant_id;
                grant.request_id_ = request.request_id;
                grant.key_id_ = request.key_id;
                grant.requester_id_ = request.requester_id;
                grant.target_resource_ = request.target_resource;
                grant.action_ = request.action;
                grant.limits_ = {
                    (std::min)(request.requested_limits.max_bytes,
                               record.limits.max_bytes),
                    (std::min)(request.requested_limits.max_steps,
                               record.limits.max_steps),
                    (std::min)(request.requested_limits.max_items,
                               record.limits.max_items)};
                grant.issued_at_unix_sec_ = request.issued_at_unix_sec;
                grant.expires_at_unix_sec_ =
                    record.approval_expires_at_unix_sec > 0
                        ? (std::min)(record.expires_at_unix_sec,
                                     record.approval_expires_at_unix_sec)
                        : record.expires_at_unix_sec;
                grant.approval_id_ = record.approval_id;
                grant.scope_digest_ = record.approval_scope_digest;
                grant.approval_revision_ = record.approval_revision;
                grant.revocation_epoch_ = record.revocation_epoch;
                grant.registry_revision_ = record.registry_revision + 1U;
                grant.mac_key_id_ = key_id;
                grant.mac_key_version_ = key_version;
                std::vector<std::uint8_t> canonical;
                if (!canonical_grant(grant, canonical) ||
                    !grant_mac_provider_.create_mac(
                        std::string_view(
                            reinterpret_cast<const char*>(canonical.data()),
                            canonical.size()),
                        key_id, key_version, grant.mac_hex_))
                    return false;
                const auto status = registry_.store_.transact(
                    [&](RegistryState& state) {
                        auto found = state.records.find(request.key_id);
                        if (found == state.records.end() ||
                            found->second.registry_revision !=
                                current.registry_revision ||
                            found->second.status != KeyTrustStatus::ApprovedUnused ||
                            found->second.approval_status != ApprovalStatus::Active)
                            return false;
                        auto& target = found->second;
                        target.grant_id = grant.grant_id_;
                        target.grant_mac_key_id = key_id;
                        target.grant_mac_key_version = key_version;
                        target.grant_mac_hex = grant.mac_hex_;
                        target.grant_limits = grant.limits_;
                        target.grant_registry_revision = grant.registry_revision_;
                        ++target.registry_revision;
                        record = target;
                        return true;
                    });
                if (status != RegistryStoreStatus::Ok) return false;
                return true;
            }
            grant.grant_id_ = record.grant_id;
            grant.request_id_ = record.request_id;
            grant.key_id_ = record.key_id;
            grant.requester_id_ = record.requester_id;
            grant.target_resource_ = record.target_resource;
            grant.action_ = record.action;
            grant.limits_ = record.grant_limits;
            grant.issued_at_unix_sec_ = record.issued_at_unix_sec;
            grant.expires_at_unix_sec_ =
                record.approval_expires_at_unix_sec > 0
                    ? (std::min)(record.expires_at_unix_sec,
                                 record.approval_expires_at_unix_sec)
                    : record.expires_at_unix_sec;
            grant.approval_id_ = record.approval_id;
            grant.scope_digest_ = record.approval_scope_digest;
            grant.approval_revision_ = record.approval_revision;
            grant.revocation_epoch_ = record.revocation_epoch;
            grant.registry_revision_ = record.grant_registry_revision;
            grant.mac_key_id_ = record.grant_mac_key_id;
            grant.mac_key_version_ = record.grant_mac_key_version;
            grant.mac_hex_ = record.grant_mac_hex;
            return verify_grant_mac(grant);
        } catch (...) {
            return false;
        }
    }

    bool verify_grant_mac(const ApprovalGrant& grant) const noexcept {
        std::vector<std::uint8_t> canonical;
        if (!canonical_grant(grant, canonical)) return false;
        return grant_mac_provider_.verify_mac(
            std::string_view(reinterpret_cast<const char*>(canonical.data()),
                             canonical.size()),
            grant.mac_key_id_, grant.mac_key_version_, grant.mac_hex_);
    }

    EphemeralKeyRegistry& registry_;
    const IClock& clock_;
    const IRequestSignatureVerifier& signature_verifier_;
    IGrantMacProvider& grant_mac_provider_;
    IAuditLogSink& audit_sink_;
};

class BoundedResourceSession {
public:
    GovernanceDecisionCode read_chunk(
        std::string_view target_resource,
        std::uint64_t max_bytes,
        std::string& data_out
    ) noexcept {
        data_out.clear();
        if (!preflight(target_resource, max_bytes, false, false))
            return last_decision_;
        const auto port_limit = max_bytes;
        reserve_bytes(port_limit);
        std::string candidate;
        const auto result = port_.read_chunk(target_resource, port_limit, candidate);
        if (result != ResourcePortStatus::Ok) {
            indeterminate_ = result == ResourcePortStatus::Unavailable ||
                result == ResourcePortStatus::Failure;
            return result == ResourcePortStatus::Denied
                ? GovernanceDecisionCode::ExecutionLimitExceeded
                : GovernanceDecisionCode::CallbackFailure;
        }
        if (candidate.size() > port_limit) {
            indeterminate_ = true;
            return GovernanceDecisionCode::ExecutionLimitExceeded;
        }
        const auto size = static_cast<std::uint64_t>(candidate.size());
        const auto unused = port_limit - size;
        consumed_.max_bytes -= unused;
        remaining_bytes_ += unused;
        data_out = std::move(candidate);
        append_hash(data_out);
        return GovernanceDecisionCode::Allowed;
    }

    GovernanceDecisionCode write_chunk(
        std::string_view target_resource,
        std::string_view data
    ) noexcept {
        if (!preflight(target_resource, static_cast<std::uint64_t>(data.size()),
                       false, false))
            return last_decision_;
        reserve_bytes(static_cast<std::uint64_t>(data.size()));
        const auto result = port_.write_chunk(target_resource, data);
        if (result != ResourcePortStatus::Ok) {
            indeterminate_ = result == ResourcePortStatus::Unavailable ||
                result == ResourcePortStatus::Failure;
            return GovernanceDecisionCode::CallbackFailure;
        }
        append_hash(data);
        return GovernanceDecisionCode::Allowed;
    }

    GovernanceDecisionCode emit_item(
        std::string_view target_resource,
        std::string_view item
    ) noexcept {
        if (!preflight(target_resource, static_cast<std::uint64_t>(item.size()),
                       true, false))
            return last_decision_;
        reserve_bytes(static_cast<std::uint64_t>(item.size()));
        ++consumed_.max_items;
        --remaining_items_;
        const auto result = port_.emit_item(target_resource, item);
        if (result != ResourcePortStatus::Ok) {
            indeterminate_ = result == ResourcePortStatus::Unavailable ||
                result == ResourcePortStatus::Failure;
            return GovernanceDecisionCode::CallbackFailure;
        }
        append_hash(item);
        return GovernanceDecisionCode::Allowed;
    }

    const AccessScopeLimits& consumed() const noexcept { return consumed_; }
    const std::string& retrieval_hash() const noexcept { return retrieval_hash_; }
    bool indeterminate() const noexcept { return indeterminate_; }
    GovernanceDecisionCode last_decision() const noexcept { return last_decision_; }

private:
    friend class ScopedExecutionGuard;
    BoundedResourceSession(
        IExternalResourcePort& port,
        EphemeralKeyRegistry& registry,
        const IClock& clock,
        const ApprovalGrant& grant
    ) noexcept
        : port_(port), registry_(registry), clock_(clock), grant_(grant),
          remaining_bytes_(grant.limits().max_bytes),
          remaining_steps_(grant.limits().max_steps),
          remaining_items_(grant.limits().max_items) {}

    bool preflight(
        std::string_view target_resource,
        std::uint64_t bytes,
        bool item,
        bool
    ) noexcept {
        if (consumed_.max_steps == (std::numeric_limits<std::uint64_t>::max)())
            return fail(GovernanceDecisionCode::ExecutionLimitExceeded);
        ++consumed_.max_steps;
        if (target_resource != grant_.target_resource())
            return fail(GovernanceDecisionCode::ExecutionTargetOrActionMismatch);
        if (clock_.now_unix_sec() >= grant_.expires_at_unix_sec())
            return fail(GovernanceDecisionCode::InvalidTimestampOrExpired);
        if (consumed_.max_steps > grant_.limits().max_steps ||
            bytes > remaining_bytes_ ||
            (item && remaining_items_ == 0))
            return fail(GovernanceDecisionCode::ExecutionLimitExceeded);
        const auto state = registry_.authorize_session_operation(grant_);
        if (state != GovernanceDecisionCode::Allowed) return fail(state);
        last_decision_ = GovernanceDecisionCode::Allowed;
        return true;
    }

    bool fail(GovernanceDecisionCode decision) noexcept {
        last_decision_ = decision;
        return false;
    }

    void reserve_bytes(std::uint64_t bytes) noexcept {
        consumed_.max_bytes += bytes;
        remaining_bytes_ -= bytes;
    }

    void append_hash(std::string_view value) noexcept {
        try {
            hash_input_.insert(hash_input_.end(), value.begin(), value.end());
            detail::sha256_hex(hash_input_, retrieval_hash_);
        } catch (...) {
            retrieval_hash_.clear();
        }
    }

    IExternalResourcePort& port_;
    EphemeralKeyRegistry& registry_;
    const IClock& clock_;
    const ApprovalGrant& grant_;
    AccessScopeLimits consumed_{};
    std::uint64_t remaining_bytes_{0};
    std::uint64_t remaining_steps_{0};
    std::uint64_t remaining_items_{0};
    std::vector<std::uint8_t> hash_input_;
    std::string retrieval_hash_;
    GovernanceDecisionCode last_decision_{GovernanceDecisionCode::Allowed};
    bool indeterminate_{false};
};

class ScopedExecutionGuard {
public:
    using Operation =
        std::function<GovernanceDecisionCode(BoundedResourceSession&)>;

    ScopedExecutionGuard(
        EphemeralKeyRegistry& registry,
        const IClock& clock,
        const IGrantMacProvider& grant_mac_provider,
        IAuditLogSink& audit_sink,
        IExternalResourcePort& resource_port
    ) noexcept
        : registry_(registry), clock_(clock),
          grant_mac_provider_(grant_mac_provider), audit_sink_(audit_sink),
          resource_port_(resource_port) {}

    RegistryOperationResult consume_once(
        const ApprovalGrant& grant
    ) noexcept {
        if (!verify_grant_mac(grant))
            return {GovernanceDecisionCode::GrantTamperedOrInvalid, {}};
        return registry_.consume_once_verified(grant);
    }

    GovernanceDecisionCode begin_execution(
        const ApprovalGrant& grant
    ) noexcept {
        if (!verify_grant_mac(grant))
            return GovernanceDecisionCode::GrantTamperedOrInvalid;
        return registry_.begin_execution_verified(grant);
    }

    ExecutionResult execute_bounded(
        const AuthorizationResult& authorization,
        const ExternalAccessRequest& request,
        const Operation& operation
    ) noexcept {
        ExecutionResult result;
        if (authorization.decision != GovernanceDecisionCode::Allowed ||
            !authorization.grant) {
            result.decision = authorization.decision;
            return result;
        }
        const ApprovalGrant& grant = *authorization.grant;
        if (request.request_id != grant.request_id_ ||
            request.key_id != grant.key_id_ ||
            request.target_resource != grant.target_resource_ ||
            request.action != grant.action_ ||
            !detail::limits_within(grant.limits_, request.requested_limits)) {
            result.decision = GovernanceDecisionCode::ExecutionTargetOrActionMismatch;
            return result;
        }
        const auto consumed = consume_once(grant);
        if (consumed.decision != GovernanceDecisionCode::Allowed) {
            result.decision = consumed.decision;
            return result;
        }
        IntentAuditReceipt receipt;
        if (!audit_sink_.append(consumed.event, receipt) ||
            !registry_.valid_receipt(consumed.event, receipt) ||
            !audit_sink_.verify_receipt(receipt) ||
            registry_.record_intent_receipt(grant, receipt) !=
                GovernanceDecisionCode::Allowed) {
            RegistryOutboxEvent outcome;
            result.decision = GovernanceDecisionCode::AuditSinkFailure;
            registry_.burn(grant, result.decision, {}, {}, false, outcome);
            if (outcome.event_id.empty() || !registry_.deliver(outcome))
                result.result_indeterminate = true;
            result.key_status = KeyTrustStatus::Burned;
            result.burn_confirmed = !outcome.event_id.empty();
            return result;
        }
        const auto begun = begin_execution(grant);
        if (begun != GovernanceDecisionCode::Allowed) {
            RegistryOutboxEvent outcome;
            result.decision = begun;
            registry_.burn(grant, begun, {}, {}, false, outcome);
            result.key_status = KeyTrustStatus::Burned;
            result.burn_confirmed = !outcome.event_id.empty();
            result.result_indeterminate = true;
            return result;
        }
        result.execution_started = true;
        BoundedResourceSession session(
            resource_port_, registry_, clock_, grant);
        GovernanceDecisionCode outcome = GovernanceDecisionCode::Allowed;
        bool callback_threw = false;
        try {
            outcome = operation ? operation(session)
                                : GovernanceDecisionCode::CallbackFailure;
            if (outcome == GovernanceDecisionCode::Allowed &&
                session.last_decision() != GovernanceDecisionCode::Allowed)
                outcome = session.last_decision();
        } catch (...) {
            outcome = GovernanceDecisionCode::CallbackFailure;
            callback_threw = true;
        }
        const bool outcome_determinate =
            !callback_threw && !session.indeterminate() &&
            outcome != GovernanceDecisionCode::CallbackFailure;
        RegistryOutboxEvent event;
        const bool determinate =
            registry_.burn(grant, outcome, session.consumed(),
                           session.retrieval_hash(), outcome_determinate, event) ==
            GovernanceDecisionCode::Allowed;
        result.decision = determinate ? outcome
                                      : GovernanceDecisionCode::StoreIndeterminate;
        result.consumed = session.consumed();
        result.retrieval_summary_hash = session.retrieval_hash();
        result.key_status = KeyTrustStatus::Burned;
        result.burn_confirmed = determinate;
        result.result_indeterminate = !outcome_determinate;
        if (determinate) {
            result.outcome_audit_recorded = registry_.deliver(event);
            if (!result.outcome_audit_recorded) {
                result.result_indeterminate = true;
                if (outcome == GovernanceDecisionCode::Allowed)
                    result.decision = GovernanceDecisionCode::AuditSinkFailure;
            }
        } else {
            result.result_indeterminate = true;
        }
        return result;
    }

private:
    bool verify_grant_mac(const ApprovalGrant& grant) const noexcept {
        std::vector<std::uint8_t> canonical;
        if (!canonical_grant(grant, canonical)) return false;
        return grant_mac_provider_.verify_mac(
            std::string_view(reinterpret_cast<const char*>(canonical.data()),
                             canonical.size()),
            grant.mac_key_id_, grant.mac_key_version_, grant.mac_hex_);
    }

    EphemeralKeyRegistry& registry_;
    const IClock& clock_;
    const IGrantMacProvider& grant_mac_provider_;
    IAuditLogSink& audit_sink_;
    IExternalResourcePort& resource_port_;
};

} // namespace mother_h::auth
