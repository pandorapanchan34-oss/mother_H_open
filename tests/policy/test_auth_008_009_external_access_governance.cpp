#include "mother_H/auth/external_access_governance.hpp"
#include "mother_H/auth/file_transactional_registry_store.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {

using namespace mother_h::auth;

struct Checks {
    std::vector<std::string> failures;
    void expect(bool condition, std::string message) {
        if (!condition) failures.push_back(std::move(message));
    }
    void code(
        GovernanceDecisionCode expected,
        GovernanceDecisionCode actual,
        std::string label
    ) {
        if (expected != actual)
            failures.push_back(std::move(label) + " returned unexpected decision");
    }
};

struct TestClock final : IClock {
    std::int64_t now{1000};
    std::int64_t now_unix_sec() const noexcept override { return now; }
};

struct TestSecureKeyProvider final : mother_h::journal::ISecureKeyProvider {
    static constexpr char kKeyId[] = "auth-test-integrity";
    static std::vector<std::uint8_t> secret() {
        std::vector<std::uint8_t> result(32U);
        for (std::size_t i = 0; i < result.size(); ++i)
            result[i] = static_cast<std::uint8_t>(i + 17U);
        return result;
    }
    mother_h::journal::KeyStatus current_signing_key(
        mother_h::journal::KeyMaterial& out
    ) const noexcept override {
        try {
            out = mother_h::journal::KeyMaterial(
                {kKeyId, 1}, secret());
            return mother_h::journal::KeyStatus::Ok;
        } catch (...) {
            return mother_h::journal::KeyStatus::BackendUnavailable;
        }
    }
    mother_h::journal::KeyStatus verification_key(
        const mother_h::journal::KeyReference& reference,
        mother_h::journal::KeyMaterial& out
    ) const noexcept override {
        if (reference.key_id != kKeyId || reference.version != 1)
            return mother_h::journal::KeyStatus::NotFound;
        return current_signing_key(out);
    }
    mother_h::journal::KeyStatus rotate_key(
        const std::string&,
        mother_h::journal::KeyReference&
    ) noexcept override {
        return mother_h::journal::KeyStatus::BackendUnavailable;
    }
    mother_h::journal::KeyStatus revoke_key(
        const mother_h::journal::KeyReference&
    ) noexcept override {
        return mother_h::journal::KeyStatus::BackendUnavailable;
    }
};

std::string bytes_to_string(const std::vector<std::uint8_t>& bytes) {
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

std::string fake_signature(std::string_view canonical) {
    std::vector<std::uint8_t> bytes(canonical.begin(), canonical.end());
    std::string digest;
    if (!detail::sha256_hex(bytes, digest)) return {};
    return "test-signature-" + digest;
}

struct BoundRequestVerifier final : IRequestSignatureVerifier {
    mutable std::map<std::string, std::string> signed_messages;
    std::string sign(std::string_view canonical) const {
        const auto signature = fake_signature(canonical);
        signed_messages[signature] = std::string(canonical);
        return signature;
    }
    bool verify(
        std::string_view canonical,
        std::string_view signature
    ) const noexcept override {
        const auto found = signed_messages.find(std::string(signature));
        return found != signed_messages.end() &&
            found->second == canonical &&
            fake_signature(canonical) == signature;
    }
};

struct BoundHumanVerifier final : IHumanActionVerifier {
    mutable std::map<std::string, std::string> approval_messages;
    mutable std::map<std::string, std::string> revocation_messages;
    std::string sign_approval(std::string_view canonical) const {
        const auto signature = "human-approval-" + fake_signature(canonical);
        approval_messages[signature] = std::string(canonical);
        return signature;
    }
    std::string sign_revocation(std::string_view canonical) const {
        const auto signature = "human-revocation-" + fake_signature(canonical);
        revocation_messages[signature] = std::string(canonical);
        return signature;
    }
    bool verify_approval(
        std::string_view canonical,
        std::string_view signature
    ) const noexcept override {
        const auto found = approval_messages.find(std::string(signature));
        return found != approval_messages.end() &&
            found->second == canonical &&
            signature == "human-approval-" + fake_signature(canonical);
    }
    bool verify_revocation(
        std::string_view canonical,
        std::string_view signature
    ) const noexcept override {
        const auto found = revocation_messages.find(std::string(signature));
        return found != revocation_messages.end() &&
            found->second == canonical &&
            signature == "human-revocation-" + fake_signature(canonical);
    }
};

std::string receipt_mac(const IntentAuditReceipt& receipt) {
    static constexpr unsigned char key[] = {
        0x34, 0x91, 0x2a, 0xd7, 0x60, 0x08, 0x5c, 0x19,
        0x83, 0x77, 0x2e, 0xa5, 0x40, 0x11, 0xcb, 0x6d,
        0x12, 0x49, 0x7f, 0x05, 0x33, 0x8a, 0xa0, 0x61,
        0x4c, 0x2d, 0x95, 0x70, 0x16, 0xef, 0xb3, 0x28
    };
    detail::Writer writer;
    writer.text("MOTHER_H_TEST_AUDIT_RECEIPT_V1");
    writer.u8(1);
    writer.text(receipt.event_id);
    writer.text(receipt.sink_id);
    writer.text(receipt.event_digest_hex);
    writer.i64(receipt.received_at_unix_sec);
    writer.u32(receipt.receipt_key_version);
    std::array<unsigned char, 32> tag{};
    unsigned int length = 0;
    if (HMAC(EVP_sha256(), key, sizeof(key), writer.bytes().data(),
             writer.bytes().size(), tag.data(), &length) == nullptr ||
        length != tag.size())
        return {};
    return detail::to_hex(tag.data(), tag.size());
}

struct TestAuditSink final : IAuditLogSink {
    std::string id{"auth-test-sink"};
    mutable std::mutex mutex;
    std::map<std::string, std::pair<std::string, IntentAuditReceipt>> events;
    bool accepts{true};
    bool lose_next_response{false};

    std::string_view sink_id() const noexcept override { return id; }

    bool append(
        const RegistryOutboxEvent& event,
        IntentAuditReceipt& receipt_out
    ) noexcept override {
        try {
            std::lock_guard<std::mutex> lock(mutex);
            if (!accepts || event.event_digest_hex !=
                    detail::audit_event_digest(event))
                return false;
            auto found = events.find(event.event_id);
            if (found != events.end()) {
                if (found->second.first != event.event_digest_hex) return false;
                receipt_out = found->second.second;
            } else {
                IntentAuditReceipt receipt;
                receipt.event_id = event.event_id;
                receipt.sink_id = id;
                receipt.event_digest_hex = event.event_digest_hex;
                receipt.received_at_unix_sec = 1000;
                receipt.receipt_key_version = 1;
                receipt.receipt_mac_hex = receipt_mac(receipt);
                events.emplace(
                    event.event_id,
                    std::make_pair(event.event_digest_hex, receipt));
                receipt_out = receipt;
            }
            if (lose_next_response) {
                lose_next_response = false;
                return false;
            }
            return true;
        } catch (...) {
            return false;
        }
    }

    bool verify_receipt(const IntentAuditReceipt& receipt) const noexcept override {
        return receipt.sink_id == id &&
            receipt.receipt_key_version == 1 &&
            !receipt.event_id.empty() &&
            !receipt.event_digest_hex.empty() &&
            receipt.receipt_mac_hex == receipt_mac(receipt);
    }

    bool has_phase(GovernanceAuditPhase phase) const {
        std::lock_guard<std::mutex> lock(mutex);
        for (const auto& pair : events) {
            (void)pair;
        }
        return std::any_of(events.begin(), events.end(), [&](const auto& pair) {
            (void)phase;
            return !pair.second.first.empty();
        });
    }
};

struct TestPort final : IExternalResourcePort {
    std::atomic<std::uint64_t> reads{0};
    std::atomic<std::uint64_t> writes{0};
    std::atomic<std::uint64_t> emits{0};
    ResourcePortStatus read_result{ResourcePortStatus::Ok};
    ResourcePortStatus write_result{ResourcePortStatus::Ok};
    ResourcePortStatus emit_result{ResourcePortStatus::Ok};

    ResourcePortStatus read_chunk(
        std::string_view,
        std::uint64_t max_bytes,
        std::string& output
    ) noexcept override {
        ++reads;
        if (read_result != ResourcePortStatus::Ok) return read_result;
        output.assign(static_cast<std::size_t>(max_bytes), 'r');
        return ResourcePortStatus::Ok;
    }
    ResourcePortStatus write_chunk(
        std::string_view,
        std::string_view
    ) noexcept override {
        ++writes;
        return write_result;
    }
    ResourcePortStatus emit_item(
        std::string_view,
        std::string_view
    ) noexcept override {
        ++emits;
        return emit_result;
    }
    std::uint64_t calls() const noexcept {
        return reads.load() + writes.load() + emits.load();
    }
};

struct Fixture {
    InMemoryTransactionalRegistryStore store;
    TestClock clock;
    BoundRequestVerifier signatures;
    BoundHumanVerifier humans;
    TestAuditSink audit;
    TestSecureKeyProvider integrity_keys;
    HmacGrantMacProvider mac{integrity_keys};
    EphemeralKeyRegistry registry{store, clock, humans, audit};
    ExternalAccessGate gate{registry, clock, signatures, mac, audit};
    TestPort port;
    ScopedExecutionGuard execution{registry, clock, mac, audit, port};

    ExternalAccessRequest request(
        AccessScopeLimits limits = {4096, 8, 2}
    ) const {
        ExternalAccessRequest value;
        value.request_id = "request-001";
        value.requester_id = "requester-001";
        value.key_id = "ephemeral-001";
        value.target_resource = "reports/quarterly";
        value.action = "read";
        value.requested_limits = limits;
        value.issued_at_unix_sec = 990;
        value.expires_at_unix_sec = 1100;
        value.auth_evidence_ref = "auth-evidence-001";
        value.human_approval_ref = "approval-001";
        value.prior_history_ref = "history-001";
        std::vector<std::uint8_t> canonical;
        detail::canonical_request(value, canonical);
        value.signature_hex = signatures.sign(bytes_to_string(canonical));
        return value;
    }

    AuthenticatedHumanApproval approval(
        const ExternalAccessRequest& request_value
    ) const {
        AuthenticatedHumanApproval authenticated;
        auto& a = authenticated.approval;
        a.approval_id = request_value.human_approval_ref;
        a.request_id = request_value.request_id;
        a.key_id = request_value.key_id;
        a.requester_id = request_value.requester_id;
        detail::scope_digest(request_value, a.request_scope_digest);
        a.human_approver_id = "human-approver-001";
        a.target_resource = request_value.target_resource;
        a.action = request_value.action;
        a.approved_limits = request_value.requested_limits;
        a.issued_at_unix_sec = 995;
        a.expires_at_unix_sec = request_value.expires_at_unix_sec;
        authenticated.evidence_id = "approval-evidence-001";
        authenticated.evidence_digest_hex =
            "a9b871c6341ea59e0a703a9be0251936720f2a88f033a4865c5512e2f965d09a";
        std::vector<std::uint8_t> canonical;
        detail::canonical_approval(authenticated, canonical);
        authenticated.signature_hex =
            humans.sign_approval(bytes_to_string(canonical));
        return authenticated;
    }

    GovernanceDecisionCode prepare(
        const ExternalAccessRequest& request_value
    ) {
        EphemeralKeyRecord record;
        const auto submitted = registry.submit_key_request(
            request_value, signatures, record);
        if (submitted != GovernanceDecisionCode::Allowed) return submitted;
        return registry.approve_key(approval(request_value), record);
    }

    AuthenticatedHumanRevocation revocation(
        const ExternalAccessRequest& request_value
    ) const {
        AuthenticatedHumanRevocation authenticated;
        auto& r = authenticated.revocation;
        r.approval_id = request_value.human_approval_ref;
        r.request_id = request_value.request_id;
        r.key_id = request_value.key_id;
        r.human_approver_id = "human-approver-001";
        r.expected_approval_revision = 1;
        r.expected_revocation_epoch = 0;
        r.revoked_at_unix_sec = clock.now;
        r.evidence_id = "revocation-evidence-001";
        r.evidence_digest_hex =
            "e72be3a98d2542c0f1d45fe8a44d9c423bf920d10a2c597c1b86d5e0f077386a";
        std::vector<std::uint8_t> canonical;
        detail::canonical_revocation(authenticated, canonical);
        authenticated.signature_hex =
            humans.sign_revocation(bytes_to_string(canonical));
        return authenticated;
    }

    AuthorizationResult authorize(
        const ExternalAccessRequest& request_value
    ) {
        if (prepare(request_value) != GovernanceDecisionCode::Allowed)
            return {};
        return gate.validate_and_authorize(request_value);
    }
};

struct FileRuntime {
    explicit FileRuntime(const std::filesystem::path& directory)
        : path(directory / "registry.bin"),
          store(path, integrity_keys),
          registry(store, clock, humans, audit),
          gate(registry, clock, signatures, mac, audit),
          execution(registry, clock, mac, audit, port) {}

    std::filesystem::path path;
    TestSecureKeyProvider integrity_keys;
    FileTransactionalRegistryStore store;
    TestClock clock;
    BoundRequestVerifier signatures;
    BoundHumanVerifier humans;
    TestAuditSink audit;
    HmacGrantMacProvider mac{integrity_keys};
    EphemeralKeyRegistry registry;
    ExternalAccessGate gate;
    TestPort port;
    ScopedExecutionGuard execution;

    ExternalAccessRequest request(
        AccessScopeLimits limits = {4096, 8, 2}
    ) const {
        Fixture fixture;
        auto result = fixture.request(limits);
        std::vector<std::uint8_t> canonical;
        detail::canonical_request(result, canonical);
        result.signature_hex = signatures.sign(bytes_to_string(canonical));
        return result;
    }

    AuthenticatedHumanApproval approval(
        const ExternalAccessRequest& request_value
    ) const {
        AuthenticatedHumanApproval authenticated;
        auto& a = authenticated.approval;
        a.approval_id = request_value.human_approval_ref;
        a.request_id = request_value.request_id;
        a.key_id = request_value.key_id;
        a.requester_id = request_value.requester_id;
        detail::scope_digest(request_value, a.request_scope_digest);
        a.human_approver_id = "human-approver-001";
        a.target_resource = request_value.target_resource;
        a.action = request_value.action;
        a.approved_limits = request_value.requested_limits;
        a.issued_at_unix_sec = 995;
        a.expires_at_unix_sec = request_value.expires_at_unix_sec;
        authenticated.evidence_id = "approval-evidence-001";
        authenticated.evidence_digest_hex =
            "a9b871c6341ea59e0a703a9be0251936720f2a88f033a4865c5512e2f965d09a";
        std::vector<std::uint8_t> canonical;
        detail::canonical_approval(authenticated, canonical);
        authenticated.signature_hex =
            humans.sign_approval(bytes_to_string(canonical));
        return authenticated;
    }

    GovernanceDecisionCode prepare(const ExternalAccessRequest& value) {
        EphemeralKeyRecord record;
        const auto submitted = registry.submit_key_request(value, signatures, record);
        if (submitted != GovernanceDecisionCode::Allowed) return submitted;
        return registry.approve_key(approval(value), record);
    }

    AuthenticatedHumanRevocation revocation(
        const ExternalAccessRequest& value
    ) const {
        AuthenticatedHumanRevocation authenticated;
        auto& r = authenticated.revocation;
        r.approval_id = value.human_approval_ref;
        r.request_id = value.request_id;
        r.key_id = value.key_id;
        r.human_approver_id = "human-approver-001";
        r.expected_approval_revision = 1;
        r.expected_revocation_epoch = 0;
        r.revoked_at_unix_sec = clock.now;
        r.evidence_id = "revocation-evidence-001";
        r.evidence_digest_hex =
            "e72be3a98d2542c0f1d45fe8a44d9c423bf920d10a2c597c1b86d5e0f077386a";
        std::vector<std::uint8_t> canonical;
        detail::canonical_revocation(authenticated, canonical);
        authenticated.signature_hex =
            humans.sign_revocation(bytes_to_string(canonical));
        return authenticated;
    }
};

class TempDirectory {
public:
    TempDirectory() {
        static std::atomic<unsigned long long> sequence{0};
        const auto id = sequence.fetch_add(1);
        path_ = std::filesystem::temp_directory_path() /
            ("mother_h_auth_" + std::to_string(id) + "_" +
             std::to_string(std::chrono::steady_clock::now()
                                .time_since_epoch().count()));
        std::filesystem::create_directories(path_);
    }
    ~TempDirectory() {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }
    const std::filesystem::path& path() const noexcept { return path_; }
private:
    std::filesystem::path path_;
};

void test_registration_approval_and_grant(Checks& checks) {
    Fixture fixture;
    const auto request = fixture.request();
    EphemeralKeyRecord record;
    checks.code(GovernanceDecisionCode::Allowed,
        fixture.registry.submit_key_request(request, fixture.signatures, record),
        "registration");
    checks.expect(record.exists &&
        record.status == KeyTrustStatus::PendingApproval &&
        record.approval_status == ApprovalStatus::Pending,
        "registration must persist pending states");
    const auto before = fixture.registry.status_of(request.key_id);
    checks.expect(before.known &&
        before.status == KeyTrustStatus::PendingApproval,
        "status_of must expose PendingApproval");
    checks.code(GovernanceDecisionCode::Allowed,
        fixture.registry.approve_key(fixture.approval(request), record),
        "human approval");
    checks.expect(record.status == KeyTrustStatus::ApprovedUnused &&
        record.approval_status == ApprovalStatus::Active &&
        record.approval_receipt_recorded,
        "signed approval and audit receipt must be committed");
    const auto authorization = fixture.gate.validate_and_authorize(request);
    checks.code(GovernanceDecisionCode::Allowed, authorization.decision,
        "authorization");
    checks.expect(authorization.grant.has_value() &&
        authorization.audit_recorded,
        "authorization must return an opaque grant after audit receipt");
    checks.expect(authorization.grant->grant_id().size() == 32U,
        "grant must have a stable id");
}

void test_invalid_requests_fail_closed(Checks& checks) {
    Fixture fixture;
    auto request = fixture.request();
    auto canonical_request_bytes = std::vector<std::uint8_t>{};
    detail::canonical_request(request, canonical_request_bytes);
    checks.code(GovernanceDecisionCode::Allowed,
        fixture.prepare(request), "valid setup");

    auto changed = request;
    changed.target_resource = "other";
    checks.code(GovernanceDecisionCode::SignatureVerificationFailed,
        fixture.gate.validate_and_authorize(changed).decision,
        "changed signed target");
    changed = request;
    changed.requested_limits.max_bytes = 0;
    checks.code(GovernanceDecisionCode::UnlimitedScopeRejected,
        fixture.gate.validate_and_authorize(changed).decision,
        "zero bytes");
    changed = request;
    changed.requester_id.clear();
    checks.code(GovernanceDecisionCode::MissingRequiredField,
        fixture.gate.validate_and_authorize(changed).decision,
        "missing requester");
    checks.expect(fixture.port.calls() == 0,
        "invalid request must not reach external port");
}

void test_signed_approval_binding_and_revocation(Checks& checks) {
    Fixture fixture;
    auto request = fixture.request();
    EphemeralKeyRecord record;
    checks.code(GovernanceDecisionCode::Allowed,
        fixture.registry.submit_key_request(request, fixture.signatures, record),
        "registration");
    auto bad_approval = fixture.approval(request);
    bad_approval.approval.requester_id = "different-requester";
    std::vector<std::uint8_t> canonical;
    detail::canonical_approval(bad_approval, canonical);
    bad_approval.signature_hex =
        fixture.humans.sign_approval(bytes_to_string(canonical));
    checks.code(GovernanceDecisionCode::KeyAlreadyConsumedOrBurned,
        fixture.registry.approve_key(bad_approval, record),
        "mismatched human approval");

    checks.code(GovernanceDecisionCode::Allowed,
        fixture.registry.approve_key(fixture.approval(request), record),
        "correct approval");
    checks.code(GovernanceDecisionCode::Allowed,
        fixture.registry.revoke_approval(fixture.revocation(request)),
        "authenticated revocation");
    checks.expect(fixture.registry.status_of(request.key_id).approval_status ==
        ApprovalStatus::Revoked, "revocation is authoritative");
    checks.code(GovernanceDecisionCode::ApprovalRevoked,
        fixture.gate.validate_and_authorize(request).decision,
        "revoked access");
}

void test_half_open_expiry(Checks& checks) {
    {
        Fixture fixture;
        fixture.clock.now = 1000;
        auto request = fixture.request();
        request.issued_at_unix_sec = 1000;
        request.expires_at_unix_sec = 1001;
        std::vector<std::uint8_t> canonical;
        detail::canonical_request(request, canonical);
        request.signature_hex =
            fixture.signatures.sign(bytes_to_string(canonical));
        const auto authorization = fixture.authorize(request);
        checks.code(GovernanceDecisionCode::Allowed,
            authorization.decision, "issued-at boundary");
    }
    {
        Fixture fixture;
        auto request = fixture.request();
        checks.code(GovernanceDecisionCode::Allowed,
            fixture.prepare(request), "initial setup");
        const auto authorization = fixture.gate.validate_and_authorize(request);
        checks.code(GovernanceDecisionCode::Allowed,
            authorization.decision, "valid before expiry");
        fixture.clock.now = request.expires_at_unix_sec;
        checks.code(GovernanceDecisionCode::InvalidTimestampOrExpired,
            fixture.gate.validate_and_authorize(request).decision,
            "expires-at boundary");
        checks.expect(fixture.registry.status_of(request.key_id).approval_status ==
            ApprovalStatus::Expired, "expiry must persist as terminal status");
    }
}

void test_approval_narrows_grant(Checks& checks) {
    Fixture fixture;
    const auto request = fixture.request({16, 4, 2});
    EphemeralKeyRecord record;
    checks.code(GovernanceDecisionCode::Allowed,
        fixture.registry.submit_key_request(
            request, fixture.signatures, record),
        "registration");
    auto approval = fixture.approval(request);
    approval.approval.approved_limits = {4, 2, 1};
    std::vector<std::uint8_t> canonical;
    detail::canonical_approval(approval, canonical);
    approval.signature_hex =
        fixture.humans.sign_approval(bytes_to_string(canonical));
    checks.code(GovernanceDecisionCode::Allowed,
        fixture.registry.approve_key(approval, record),
        "narrow human approval");
    const auto authorization = fixture.gate.validate_and_authorize(request);
    checks.code(GovernanceDecisionCode::Allowed,
        authorization.decision, "bounded grant issuance");
    checks.expect(authorization.grant &&
        authorization.grant->limits().max_bytes == 4 &&
        authorization.grant->limits().max_steps == 2 &&
        authorization.grant->limits().max_items == 1,
        "Grant must use the intersection of request and approval limits");
    const auto result = fixture.execution.execute_bounded(
        authorization, request, [&](BoundedResourceSession& session) {
            std::string first, second;
            checks.code(GovernanceDecisionCode::Allowed,
                session.read_chunk(request.target_resource, 4, first),
                "read within narrowed limit");
            return session.read_chunk(request.target_resource, 1, second);
        });
    checks.code(GovernanceDecisionCode::ExecutionLimitExceeded,
        result.decision, "narrowed limit enforcement");
    checks.expect(fixture.port.reads.load() == 1,
        "operation beyond narrowed approval must be blocked before the port");
}

void test_audit_failure_and_scope_limits(Checks& checks) {
    {
        Fixture fixture;
        auto request = fixture.request();
        checks.code(GovernanceDecisionCode::Allowed,
            fixture.prepare(request), "setup");
        fixture.audit.accepts = false;
        checks.code(GovernanceDecisionCode::AuditSinkFailure,
            fixture.gate.validate_and_authorize(request).decision,
            "authorization audit failure");
    }
    {
        Fixture fixture;
        auto request = fixture.request();
        request.target_resource = "*";
        std::vector<std::uint8_t> canonical;
        detail::canonical_request(request, canonical);
        request.signature_hex =
            fixture.signatures.sign(bytes_to_string(canonical));
        checks.code(GovernanceDecisionCode::UnlimitedScopeRejected,
            fixture.prepare(request), "wildcard scope");
    }
}

void test_normal_bounded_execution(Checks& checks) {
    Fixture fixture;
    auto request = fixture.request({12, 3, 1});
    const auto authorization = fixture.authorize(request);
    checks.code(GovernanceDecisionCode::Allowed,
        authorization.decision, "valid authorization");
    checks.expect(authorization.grant.has_value(),
        "execution precondition must provide a grant");
    if (!authorization.grant) return;
    const auto result = fixture.execution.execute_bounded(
        authorization, request, [&](BoundedResourceSession& session) {
            std::string data;
            checks.code(GovernanceDecisionCode::Allowed,
                session.read_chunk(request.target_resource, 4, data), "read");
            checks.expect(data.size() == 4, "read must return the capped payload");
            checks.code(GovernanceDecisionCode::Allowed,
                session.write_chunk(request.target_resource, "data"), "write");
            checks.code(GovernanceDecisionCode::Allowed,
                session.emit_item(request.target_resource, "item"), "emit");
            return GovernanceDecisionCode::Allowed;
        });
    checks.code(GovernanceDecisionCode::Allowed, result.decision,
        "bounded execution");
    checks.expect(result.execution_started && result.burn_confirmed &&
        result.outcome_audit_recorded &&
        result.key_status == KeyTrustStatus::Burned,
        "execution must start once and finish Burned with outcome audit");
    checks.expect(result.consumed.max_bytes == 12 &&
        result.consumed.max_steps == 3 &&
        result.consumed.max_items == 1,
        "bytes, attempted steps, and items must match exact boundary");
    checks.expect(fixture.port.calls() == 3,
        "three permitted session operations must reach the port");
}

void test_execution_scope_and_reuse(Checks& checks) {
    Fixture fixture;
    auto request = fixture.request();
    const auto authorization = fixture.authorize(request);
    auto changed = request;
    changed.target_resource = "reports/other";
    const auto mismatch = fixture.execution.execute_bounded(
        authorization, changed, [](BoundedResourceSession&) {
            return GovernanceDecisionCode::Allowed;
        });
    checks.code(GovernanceDecisionCode::ExecutionTargetOrActionMismatch,
        mismatch.decision, "target mismatch");
    checks.expect(fixture.port.calls() == 0,
        "target mismatch must not reach port");
    const auto first = fixture.execution.execute_bounded(
        authorization, request, [](BoundedResourceSession&) {
            return GovernanceDecisionCode::Allowed;
        });
    checks.expect(first.burn_confirmed, "first execution must burn the key");
    const auto second = fixture.execution.execute_bounded(
        authorization, request, [](BoundedResourceSession&) {
            return GovernanceDecisionCode::Allowed;
        });
    checks.code(GovernanceDecisionCode::KeyAlreadyConsumedOrBurned,
        second.decision, "same grant reuse");
    checks.expect(fixture.port.calls() == 0,
        "empty operation callbacks must not call resource port");
}

void test_preflight_limits(Checks& checks) {
    {
        Fixture fixture;
        auto request = fixture.request({3, 3, 2});
        const auto authorization = fixture.authorize(request);
        auto result = fixture.execution.execute_bounded(
            authorization, request, [&](BoundedResourceSession& session) {
                std::string data;
                return session.read_chunk(request.target_resource, 4, data);
            });
        checks.code(GovernanceDecisionCode::ExecutionLimitExceeded,
            result.decision, "byte preflight");
        checks.expect(fixture.port.calls() == 0,
            "oversized read must be denied before port");
    }
    {
        Fixture fixture;
        auto request = fixture.request({16, 1, 2});
        const auto authorization = fixture.authorize(request);
        std::vector<GovernanceDecisionCode> calls;
        const auto result = fixture.execution.execute_bounded(
            authorization, request, [&](BoundedResourceSession& session) {
                std::string data;
                calls.push_back(session.read_chunk(
                    request.target_resource, 1, data));
                calls.push_back(session.write_chunk(
                    request.target_resource, "x"));
                return calls.back();
            });
        checks.expect(calls.size() == 2,
            "denied call attempt must be counted by the session");
        checks.code(GovernanceDecisionCode::ExecutionLimitExceeded,
            calls.back(), "step limit");
        checks.expect(fixture.port.calls() == 1,
            "step limit must reject the second call before port");
        checks.code(GovernanceDecisionCode::ExecutionLimitExceeded,
            result.decision, "step-limit outcome");
    }
    {
        Fixture fixture;
        auto request = fixture.request({16, 3, 1});
        const auto authorization = fixture.authorize(request);
        const auto result = fixture.execution.execute_bounded(
            authorization, request, [&](BoundedResourceSession& session) {
                auto first = session.emit_item(
                    request.target_resource, "1");
                auto second = session.emit_item(
                    request.target_resource, "2");
                checks.code(GovernanceDecisionCode::Allowed, first, "first item");
                checks.code(GovernanceDecisionCode::ExecutionLimitExceeded,
                    second, "item limit");
                return second;
            });
        checks.code(GovernanceDecisionCode::ExecutionLimitExceeded,
            result.decision, "item-limit outcome");
        checks.expect(fixture.port.emits.load() == 1,
            "item overage must be denied before external port");
    }
}

void test_receipt_required_and_bound(Checks& checks) {
    Fixture fixture;
    const auto request = fixture.request();
    checks.code(GovernanceDecisionCode::Allowed,
        fixture.prepare(request), "setup");
    const auto authorization = fixture.gate.validate_and_authorize(request);
    checks.code(GovernanceDecisionCode::Allowed,
        authorization.decision, "authorization");
    const auto consumed = fixture.execution.consume_once(
        *authorization.grant);
    checks.code(GovernanceDecisionCode::Allowed, consumed.decision,
        "consume");
    checks.code(GovernanceDecisionCode::KeyAlreadyConsumedOrBurned,
        fixture.execution.begin_execution(*authorization.grant),
        "begin without receipt");

    IntentAuditReceipt forged;
    forged.event_id = "different-event";
    forged.sink_id = std::string(fixture.audit.sink_id());
    forged.event_digest_hex = consumed.event.event_digest_hex;
    forged.received_at_unix_sec = 1000;
    forged.receipt_key_version = 1;
    forged.receipt_mac_hex = "00";
    checks.code(GovernanceDecisionCode::AuditSinkFailure,
        fixture.registry.record_intent_receipt(*authorization.grant, forged),
        "receipt for a different event");
    checks.expect(fixture.port.calls() == 0,
        "receipt failures must precede all external operations");
}

void test_sink_response_loss_is_idempotent(Checks& checks) {
    Fixture fixture;
    auto request = fixture.request();
    const auto authorization = fixture.authorize(request);
    const auto consumed = fixture.execution.consume_once(
        *authorization.grant);
    checks.code(GovernanceDecisionCode::Allowed, consumed.decision,
        "consume");
    fixture.audit.lose_next_response = true;
    checks.expect(!fixture.registry.deliver(consumed.event),
        "lost sink response must not be reported received");
    checks.expect(fixture.registry.deliver(consumed.event),
        "same event retry must return its original receipt");
    EphemeralKeyRecord record;
    checks.expect(fixture.registry.load_record(request.key_id, record) &&
        record.intent_receipt_recorded,
        "receipt acknowledgement must persist without changing key revision");
    checks.code(GovernanceDecisionCode::Allowed,
        fixture.execution.begin_execution(*authorization.grant),
        "begin after durable receipt");
}

void test_cancel_consume_and_begin_ordering(Checks& checks) {
    {
        Fixture fixture;
        auto request = fixture.request();
        const auto authorization = fixture.authorize(request);
        checks.code(GovernanceDecisionCode::Allowed,
            fixture.registry.revoke_approval(fixture.revocation(request)),
            "revoke before consume");
        checks.code(GovernanceDecisionCode::ApprovalRevoked,
            fixture.execution.consume_once(
                *authorization.grant).decision,
            "consume after revocation");
    }
    {
        Fixture fixture;
        auto request = fixture.request();
        const auto authorization = fixture.authorize(request);
        const auto consumed = fixture.execution.consume_once(
            *authorization.grant);
        IntentAuditReceipt receipt;
        checks.expect(fixture.audit.append(consumed.event, receipt),
            "sink should accept intent");
        checks.code(GovernanceDecisionCode::Allowed,
            fixture.registry.record_intent_receipt(
                *authorization.grant, receipt), "record intent receipt");
        checks.code(GovernanceDecisionCode::Allowed,
            fixture.execution.begin_execution(
                *authorization.grant), "begin before cancel");
        checks.code(GovernanceDecisionCode::Allowed,
            fixture.registry.revoke_approval(fixture.revocation(request)),
            "revoke after begin");
        checks.code(GovernanceDecisionCode::ApprovalRevoked,
            fixture.registry.authorize_session_operation(
                *authorization.grant), "next session operation after cancel");
    }
}

void test_outcome_audit_failure_is_indeterminate(Checks& checks) {
    Fixture fixture;
    auto request = fixture.request();
    const auto authorization = fixture.authorize(request);
    const auto result = fixture.execution.execute_bounded(
        authorization, request, [&](BoundedResourceSession&) {
            fixture.audit.accepts = false;
            return GovernanceDecisionCode::Allowed;
        });
    checks.expect(result.execution_started && result.burn_confirmed &&
        !result.outcome_audit_recorded && result.result_indeterminate,
        "Outcome receipt failure must retain Burned and report uncertainty");
    checks.expect(fixture.registry.status_of(request.key_id).status ==
        KeyTrustStatus::Burned, "failed outcome audit must not restore grant");
    checks.expect(fixture.port.calls() == 0,
        "callback with no session operation must not touch the resource port");
}

void test_threaded_single_consumption(Checks& checks) {
    Fixture fixture;
    auto request = fixture.request();
    const auto authorization = fixture.authorize(request);
    std::atomic<unsigned> successes{0};
    std::vector<std::thread> threads;
    for (unsigned i = 0; i < 12; ++i) {
        threads.emplace_back([&] {
            if (fixture.execution.consume_once(
                    *authorization.grant).decision ==
                GovernanceDecisionCode::Allowed)
                ++successes;
        });
    }
    for (auto& thread : threads) thread.join();
    checks.expect(successes.load() == 1,
        "in-process concurrent consume must succeed exactly once");
}

std::string executable_path;

int spawn_one(const std::string& mode, const std::filesystem::path& directory) {
#ifdef _WIN32
    std::wstring executable(32768U, L'\0');
    const DWORD length = GetModuleFileNameW(
        nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    if (length == 0 || length >= executable.size()) return -1;
    executable.resize(length);
    const std::wstring command =
        L"\"" + executable + L"\" " +
        std::wstring(mode.begin(), mode.end()) + L" \"" +
        directory.wstring() + L"\"";
    std::vector<wchar_t> mutable_command(command.begin(), command.end());
    mutable_command.push_back(L'\0');
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (CreateProcessW(nullptr, mutable_command.data(), nullptr, nullptr,
                       FALSE, CREATE_NO_WINDOW, nullptr, nullptr,
                       &startup, &process) == 0)
        return -1;
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD exit_code = 0;
    const bool got_code = GetExitCodeProcess(process.hProcess, &exit_code) != 0;
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return got_code ? static_cast<int>(exit_code) : -1;
#else
    const pid_t child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        const std::string path = directory.string();
        char* const arguments[] = {
            const_cast<char*>(executable_path.c_str()),
            const_cast<char*>(mode.c_str()),
            const_cast<char*>(path.c_str()),
            nullptr
        };
        execv(executable_path.c_str(), arguments);
        _exit(127);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
#endif
}

std::vector<int> spawn_many(
    unsigned count,
    const std::string& mode,
    const std::filesystem::path& directory
) {
    std::vector<int> results;
#ifdef _WIN32
    struct Child {
        PROCESS_INFORMATION process{};
    };
    std::vector<Child> children;
    for (unsigned i = 0; i < count; ++i) {
        std::wstring executable(32768U, L'\0');
        const DWORD length = GetModuleFileNameW(
            nullptr, executable.data(), static_cast<DWORD>(executable.size()));
        if (length == 0 || length >= executable.size()) return {};
        executable.resize(length);
        const std::wstring command =
            L"\"" + executable + L"\" " +
            std::wstring(mode.begin(), mode.end()) + L" \"" +
            directory.wstring() + L"\"";
        std::vector<wchar_t> mutable_command(command.begin(), command.end());
        mutable_command.push_back(L'\0');
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        Child child;
        if (CreateProcessW(nullptr, mutable_command.data(), nullptr, nullptr,
                           FALSE, CREATE_NO_WINDOW, nullptr, nullptr,
                           &startup, &child.process) == 0)
            return {};
        children.push_back(child);
    }
    for (auto& child : children) {
        WaitForSingleObject(child.process.hProcess, INFINITE);
        DWORD code = 0;
        if (GetExitCodeProcess(child.process.hProcess, &code) == 0) code = 255;
        results.push_back(static_cast<int>(code));
        CloseHandle(child.process.hThread);
        CloseHandle(child.process.hProcess);
    }
#else
    std::vector<pid_t> children;
    for (unsigned i = 0; i < count; ++i) {
        const pid_t child = fork();
        if (child < 0) return {};
        if (child == 0) {
            const std::string path = directory.string();
            char* const arguments[] = {
                const_cast<char*>(executable_path.c_str()),
                const_cast<char*>(mode.c_str()),
                const_cast<char*>(path.c_str()),
                nullptr
            };
            execv(executable_path.c_str(), arguments);
            _exit(127);
        }
        children.push_back(child);
    }
    for (const auto child : children) {
        int status = 0;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status))
            results.push_back(-1);
        else
            results.push_back(WEXITSTATUS(status));
    }
#endif
    return results;
}

bool prepare_file_runtime(FileRuntime& runtime) {
    const auto request = runtime.request();
    return runtime.prepare(request) == GovernanceDecisionCode::Allowed;
}

int child_consume(const std::filesystem::path& directory) {
    FileRuntime runtime(directory);
    const auto request = runtime.request();
    const auto auth = runtime.gate.validate_and_authorize(request);
    if (auth.decision != GovernanceDecisionCode::Allowed || !auth.grant)
        return 10;
    const auto consumed = runtime.execution.consume_once(*auth.grant);
    return consumed.decision == GovernanceDecisionCode::Allowed ? 0 : 2;
}

int child_begin(const std::filesystem::path& directory) {
    FileRuntime runtime(directory);
    std::optional<ApprovalGrant> grant;
    if (runtime.gate.resume_consumed_grant(
            "ephemeral-001", grant) !=
        GovernanceDecisionCode::Allowed)
        return 10;
    return runtime.execution.begin_execution(*grant) ==
        GovernanceDecisionCode::Allowed ? 0 : 2;
}

int child_revoke(const std::filesystem::path& directory) {
    FileRuntime runtime(directory);
    const auto request = runtime.request();
    return runtime.registry.revoke_approval(runtime.revocation(request)) ==
        GovernanceDecisionCode::Allowed ? 0 : 10;
}

int child_crash_after_wal(const std::filesystem::path& directory) {
    FileRuntime runtime(directory);
    runtime.store.set_after_wal_flush_hook_for_testing([] {
        std::_Exit(77);
    });
    runtime.store.transact([](RegistryState& state) {
        EphemeralKeyRecord record;
        record.key_id = "crash-recovered-key";
        record.request_id = "crash-recovered-request";
        record.requester_id = "worker";
        record.target_resource = "resource";
        record.action = "read";
        record.limits = {1, 1, 1};
        record.status = KeyTrustStatus::PendingApproval;
        record.approval_status = ApprovalStatus::Pending;
        record.exists = true;
        record.registry_revision = 1;
        state.records.emplace(record.key_id, record);
        return true;
    });
    return 11;
}

void test_file_store_recovery_and_process_restart(Checks& checks) {
    TempDirectory directory;
    {
        FileRuntime runtime(directory.path());
        checks.expect(runtime.store.name() == "FileTransactionalRegistryStore",
            "persistent store must identify itself as file based");
        checks.expect(prepare_file_runtime(runtime),
            "file-backed setup must succeed");
    }
    const auto revoke_exit = spawn_one("--child-revoke", directory.path());
    checks.expect(revoke_exit == 0, "separate process must persist revocation");
    {
        FileRuntime restarted(directory.path());
        const auto status = restarted.registry.status_of("ephemeral-001");
        checks.expect(status.known &&
            status.approval_status == ApprovalStatus::Revoked,
            "new process must load revocation from the file store");
    }
}

void test_file_store_multi_process_consume(Checks& checks) {
    TempDirectory directory;
    {
        FileRuntime runtime(directory.path());
        checks.expect(prepare_file_runtime(runtime),
            "file-backed setup must succeed");
        const auto authorization =
            runtime.gate.validate_and_authorize(runtime.request());
        checks.expect(authorization.decision == GovernanceDecisionCode::Allowed,
            "precondition grant must be issued");
    }
    const auto exits = spawn_many(8, "--child-consume", directory.path());
    checks.expect(exits.size() == 8,
        "all contender processes must start");
    checks.expect(std::count(exits.begin(), exits.end(), 0) == 1,
        "cross-process consume must have exactly one winner");
    FileRuntime restarted(directory.path());
    const auto status = restarted.registry.status_of("ephemeral-001");
    checks.expect(status.known &&
        status.status == KeyTrustStatus::InUseConsumed,
        "consumed status must survive process recreation");
}

void test_file_store_multi_process_begin(Checks& checks) {
    TempDirectory directory;
    {
        FileRuntime runtime(directory.path());
        checks.expect(prepare_file_runtime(runtime),
            "file-backed setup must succeed");
        const auto auth = runtime.gate.validate_and_authorize(runtime.request());
        checks.expect(auth.decision == GovernanceDecisionCode::Allowed &&
            auth.grant.has_value(), "authorization precondition must hold");
        const auto consume = runtime.execution.consume_once(*auth.grant);
        checks.expect(consume.decision == GovernanceDecisionCode::Allowed,
            "consume precondition must hold");
        IntentAuditReceipt receipt;
        checks.expect(runtime.audit.append(consume.event, receipt),
            "Intent sink must acknowledge");
        checks.code(GovernanceDecisionCode::Allowed,
            runtime.registry.record_intent_receipt(*auth.grant, receipt),
            "persist Intent receipt");
    }
    const auto exits = spawn_many(8, "--child-begin", directory.path());
    checks.expect(exits.size() == 8,
        "all begin contender processes must start");
    checks.expect(std::count(exits.begin(), exits.end(), 0) == 1,
        "cross-process begin must have exactly one winner");
    FileRuntime restarted(directory.path());
    const auto status = restarted.registry.status_of("ephemeral-001");
    checks.expect(status.known &&
        status.execution_phase == ExecutionPhase::Started,
        "Started must remain durable and non-replayable after restart");
    std::optional<ApprovalGrant> grant;
    checks.code(GovernanceDecisionCode::KeyAlreadyConsumedOrBurned,
        restarted.gate.resume_consumed_grant(
            "ephemeral-001", grant),
        "started grant cannot be resumed");
}

void test_wal_recovery_after_process_exit(Checks& checks) {
    TempDirectory directory;
    const auto exit_code = spawn_one("--child-crash-wal", directory.path());
    checks.expect(exit_code == 77,
        "child must exit immediately after the WAL durable point");
    TestSecureKeyProvider keys;
    FileTransactionalRegistryStore store(
        directory.path() / "registry.bin", keys);
    RegistryState state;
    checks.expect(store.read(state) == RegistryStoreStatus::Ok,
        "WAL recovery must succeed in a new process context");
    checks.expect(state.store_revision == 1 &&
        state.records.count("crash-recovered-key") == 1,
        "durable WAL transaction must be replayed exactly once");
    checks.expect(!std::filesystem::exists(
        directory.path() / "registry.bin.wal"),
        "recovered WAL must be removed after body durability");
}

void test_file_hmac_tamper_fails_closed(Checks& checks) {
    TempDirectory directory;
    TestSecureKeyProvider keys;
    const auto path = directory.path() / "registry.bin";
    {
        FileTransactionalRegistryStore store(path, keys);
        const auto status = store.transact([](RegistryState& state) {
            EphemeralKeyRecord record;
            record.key_id = "tamper-key";
            record.request_id = "tamper-request";
            record.exists = true;
            record.registry_revision = 1;
            state.records.emplace(record.key_id, record);
            return true;
        });
        checks.expect(status == RegistryStoreStatus::Ok,
            "file image setup must persist");
    }
    {
        std::fstream file(path, std::ios::binary | std::ios::in | std::ios::out);
        char byte = 0;
        file.read(&byte, 1);
        byte ^= 0x40;
        file.seekp(0);
        file.write(&byte, 1);
        file.flush();
    }
    FileTransactionalRegistryStore store(path, keys);
    RegistryState state;
    checks.expect(store.read(state) == RegistryStoreStatus::IntegrityFailure,
        "HMAC tampering must fail closed");
}

class IndeterminateAfterCommitStore final : public ITransactionalRegistryStore {
public:
    std::string_view name() const noexcept override { return inner_.name(); }
    RegistryStoreStatus read(RegistryState& out) const noexcept override {
        return inner_.read(out);
    }
    RegistryStoreStatus transact(const Mutation& mutation) noexcept override {
        const auto status = inner_.transact(mutation);
        if (status == RegistryStoreStatus::Ok && fail_next_) {
            fail_next_ = false;
            return RegistryStoreStatus::Indeterminate;
        }
        return status;
    }
    void fail_next() noexcept { fail_next_ = true; }
private:
    InMemoryTransactionalRegistryStore inner_;
    bool fail_next_{false};
};

void test_begin_indeterminate_never_calls_port(Checks& checks) {
    IndeterminateAfterCommitStore store;
    TestClock clock;
    BoundRequestVerifier signatures;
    BoundHumanVerifier humans;
    TestAuditSink audit;
    TestSecureKeyProvider keys;
    HmacGrantMacProvider mac(keys);
    EphemeralKeyRegistry registry(store, clock, humans, audit);
    ExternalAccessGate gate(registry, clock, signatures, mac, audit);
    TestPort port;
    ScopedExecutionGuard execution(registry, clock, mac, audit, port);
    Fixture signer;
    auto request = signer.request();
    std::vector<std::uint8_t> request_bytes;
    detail::canonical_request(request, request_bytes);
    request.signature_hex =
        signatures.sign(bytes_to_string(request_bytes));
    EphemeralKeyRecord record;
    checks.code(GovernanceDecisionCode::Allowed,
        registry.submit_key_request(request, signatures, record),
        "register");
    checks.code(GovernanceDecisionCode::Allowed,
        registry.approve_key([&] {
            auto approval = signer.approval(request);
            std::vector<std::uint8_t> canonical;
            detail::canonical_approval(approval, canonical);
            approval.signature_hex =
                humans.sign_approval(bytes_to_string(canonical));
            return approval;
        }(), record),
        "approve");
    const auto auth = gate.validate_and_authorize(request);
    checks.code(GovernanceDecisionCode::Allowed, auth.decision,
        "grant precondition");
    checks.expect(auth.grant.has_value(),
        "authorization must return a grant for indeterminate begin test");
    if (!auth.grant) return;
    const auto consumed = execution.consume_once(*auth.grant);
    IntentAuditReceipt receipt;
    checks.expect(audit.append(consumed.event, receipt),
        "intent receipt exists");
    checks.code(GovernanceDecisionCode::Allowed,
        registry.record_intent_receipt(*auth.grant, receipt),
        "persist receipt");
    store.fail_next();
    const auto begin = execution.begin_execution(*auth.grant);
    checks.code(GovernanceDecisionCode::StoreIndeterminate, begin,
        "begin outcome uncertainty");
    checks.expect(port.calls() == 0,
        "indeterminate begin must never invoke external port");
}

int child_main(const std::string& mode, const std::filesystem::path& directory) {
    if (mode == "--child-consume") return child_consume(directory);
    if (mode == "--child-begin") return child_begin(directory);
    if (mode == "--child-revoke") return child_revoke(directory);
    if (mode == "--child-crash-wal") return child_crash_after_wal(directory);
    return 99;
}

template <typename Body>
void run_case(
    const char* name,
    Body&& body,
    std::size_t& failed
) {
    Checks checks;
    try {
        body(checks);
    } catch (const std::exception& error) {
        checks.expect(false, std::string("unexpected exception: ") + error.what());
    } catch (...) {
        checks.expect(false, "unexpected non-standard exception");
    }
    if (checks.failures.empty()) {
        std::cout << "[PASS] " << name << '\n';
        return;
    }
    ++failed;
    std::cout << "[FAIL] " << name << " (" << checks.failures.size()
              << " failure(s))\n";
    for (const auto& failure : checks.failures)
        std::cout << "  - " << failure << '\n';
}

} // namespace

int main(int argc, char** argv) {
    std::cout << std::unitbuf;
    if (argc == 3 && std::string(argv[1]).find("--child-") == 0)
        return child_main(argv[1], std::filesystem::path(argv[2]));
    if (argc > 0) executable_path = argv[0];
    std::size_t failed = 0;
    run_case("AUTH-008-01 registration/approval/grant",
        test_registration_approval_and_grant, failed);
    run_case("AUTH-008-02 invalid requests",
        test_invalid_requests_fail_closed, failed);
    run_case("AUTH-008-03 signed approval/revocation",
        test_signed_approval_binding_and_revocation, failed);
    run_case("AUTH-008-04 half-open expiry",
        test_half_open_expiry, failed);
    run_case("AUTH-008-05 approval limit narrowing",
        test_approval_narrows_grant, failed);
    run_case("AUTH-008-06 audit/scope fail-closed",
        test_audit_failure_and_scope_limits, failed);
    run_case("AUTH-009-01 bounded execution",
        test_normal_bounded_execution, failed);
    run_case("AUTH-009-02 scope and reuse",
        test_execution_scope_and_reuse, failed);
    run_case("AUTH-009-03 preflight limits",
        test_preflight_limits, failed);
    run_case("AUTH-009-04 Intent receipt",
        test_receipt_required_and_bound, failed);
    run_case("AUTH-009-05 lost receipt response",
        test_sink_response_loss_is_idempotent, failed);
    run_case("AUTH-009-06 cancellation ordering",
        test_cancel_consume_and_begin_ordering, failed);
    run_case("AUTH-009-07 Outcome audit failure",
        test_outcome_audit_failure_is_indeterminate, failed);
    run_case("AUTH-009-08 threaded consume",
        test_threaded_single_consumption, failed);
    run_case("AUTH-009-09 restart revocation",
        test_file_store_recovery_and_process_restart, failed);
    run_case("AUTH-009-10 multiprocess consume",
        test_file_store_multi_process_consume, failed);
    run_case("AUTH-009-11 multiprocess begin",
        test_file_store_multi_process_begin, failed);
    run_case("AUTH-009-12 WAL crash recovery",
        test_wal_recovery_after_process_exit, failed);
    run_case("AUTH-009-13 HMAC tampering",
        test_file_hmac_tamper_fails_closed, failed);
    run_case("AUTH-009-14 indeterminate begin",
        test_begin_indeterminate_never_calls_port, failed);
    std::cout << "AUTH-008/009: " << failed << "/20 case(s) failed.\n";
    return failed == 0 ? 0 : 1;
}
