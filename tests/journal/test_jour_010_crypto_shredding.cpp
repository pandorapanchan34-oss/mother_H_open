#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "mother_H/fsm/fsm_engine.hpp"
#include "mother_H/integration/event_journal.hpp"
#include "mother_H/integration/fsm_journal_recovery.hpp"
#include "mother_H/journal/secure_key_provider.hpp"

namespace {

using namespace mother_h::journal;
using namespace mother_h::fsm;
using namespace mother_h::integration;
using namespace mb::H;

class TestSystemMacKeyProvider final : public ISecureKeyProvider {
public:
    KeyStatus current_signing_key(KeyMaterial& out) const noexcept override {
        out = KeyMaterial(
            KeyReference{"sys_mac_key", 1},
            std::vector<std::uint8_t>(32, 0x5A)
        );
        return KeyStatus::Ok;
    }

    KeyStatus verification_key(
        const KeyReference& ref,
        KeyMaterial& out
    ) const noexcept override {
        if (ref.key_id != "sys_mac_key" || ref.version != 1) {
            return KeyStatus::NotFound;
        }
        out = KeyMaterial(ref, std::vector<std::uint8_t>(32, 0x5A));
        return KeyStatus::Ok;
    }

    KeyStatus rotate_key(const std::string&, KeyReference&) noexcept override {
        return KeyStatus::NotFound;
    }

    KeyStatus revoke_key(const KeyReference&) noexcept override {
        return KeyStatus::NotFound;
    }
};

class MemoryRecordSink final : public IJournalRecordSink {
public:
    JournalSinkStatus append_record(const JournalRecord& record) noexcept override {
        try {
            records_.push_back(record);
            return JournalSinkStatus::Ok;
        } catch (...) {
            return JournalSinkStatus::WriteFailed;
        }
    }

    const std::vector<JournalRecord>& records() const noexcept {
        return records_;
    }

private:
    std::vector<JournalRecord> records_;
};

}  // namespace

int main() {
    TestSystemMacKeyProvider sys_keys;
    InMemoryTestDataEncryptionKeyProvider dek_provider;
    MemoryRecordSink sink;
    AuthenticatedEventJournal journal(sink, sys_keys);

    DataKeyReference dek_ref_a{};
    DataKeyReference dek_ref_b{};
    if (dek_provider.generate_key("user_a_dek", dek_ref_a) != KeyStatus::Ok ||
        dek_provider.generate_key("user_b_dek", dek_ref_b) != KeyStatus::Ok) {
        std::cerr << "[FAIL] Failed to generate test DEKs" << std::endl;
        return 1;
    }

    const std::string secret_concept_a = "SENSITIVE_USER_A_MEDICAL_NOTE_9981";
    const std::string secret_supplement_a = "PRIVATE_ADDRESS_YOKOHAMA_1_2_3";
    const std::string secret_concept_b = "USER_B_PUBLIC_WORKFLOW_TASK";

    mb::cqs13_4::EventPayload ev1{};
    ev1.state = mb::cqs13_4::EventState::HELD;
    ev1.event_id = "evt_a_1";
    ev1.request_id = "req_a";
    ev1.source_concept = secret_concept_a;
    ev1.supplement_text = secret_supplement_a;
    ev1.constraints_json = "{\"pii\":true}";

    mb::cqs13_4::EventPayload ev2{};
    ev2.state = mb::cqs13_4::EventState::READY;
    ev2.event_id = "evt_a_2";
    ev2.request_id = "req_a";
    ev2.parent_event_id = "evt_a_1";
    ev2.source_concept = secret_concept_a;

    mb::cqs13_4::EventPayload ev3{};
    ev3.state = mb::cqs13_4::EventState::HELD;
    ev3.event_id = "evt_b_1";
    ev3.request_id = "req_b";
    ev3.source_concept = secret_concept_b;

    if (!journal.append_encrypted(ev1, dek_ref_a, dek_provider) ||
        !journal.append_encrypted(ev2, dek_ref_a, dek_provider) ||
        !journal.append_encrypted(ev3, dek_ref_b, dek_provider)) {
        std::cerr << "[FAIL] Failed to append encrypted events" << std::endl;
        return 1;
    }

    for (const auto& record : sink.records()) {
        if (record.payload.find(secret_concept_a) != std::string::npos ||
            record.payload.find(secret_supplement_a) != std::string::npos ||
            record.payload.find(secret_concept_b) != std::string::npos) {
            std::cerr << "[FAIL] Plaintext leaked inside encrypted journal payload"
                      << std::endl;
            return 1;
        }
    }

    {
        std::vector<mb::cqs13_4::EventPayload> decoded;
        std::vector<bool> erased;
        IntegrityStatus failure{};
        if (!AuthenticatedEventJournal::verify_records(
                sink.records(), sys_keys, &dek_provider, decoded, erased, failure)) {
            std::cerr << "[FAIL] Pre-shred verification failed" << std::endl;
            return 1;
        }
        if (decoded.size() != 3 || erased.size() != 3 ||
            decoded[0].source_concept != secret_concept_a ||
            decoded[0].supplement_text != secret_supplement_a ||
            decoded[2].source_concept != secret_concept_b ||
            erased[0] || erased[1] || erased[2]) {
            std::cerr << "[FAIL] Pre-shred decrypted content mismatch" << std::endl;
            return 1;
        }
    }

    if (dek_provider.revoke_key(dek_ref_a) != KeyStatus::Ok) {
        std::cerr << "[FAIL] Failed to revoke User A DEK" << std::endl;
        return 1;
    }

    {
        std::vector<mb::cqs13_4::EventPayload> decoded;
        std::vector<bool> erased;
        IntegrityStatus failure{};
        if (!AuthenticatedEventJournal::verify_records(
                sink.records(), sys_keys, &dek_provider, decoded, erased, failure)) {
            std::cerr << "[FAIL] Post-shred hash chain verification failed, status="
                      << static_cast<int>(failure) << std::endl;
            return 1;
        }
        if (decoded.size() != 3 || erased.size() != 3 ||
            !erased[0] || !erased[1] || erased[2]) {
            std::cerr << "[FAIL] Erased flags mismatch after shredding" << std::endl;
            return 1;
        }
        if (!decoded[0].source_concept.empty() ||
            !decoded[0].supplement_text.empty() ||
            !decoded[0].constraints_json.empty() ||
            !decoded[1].source_concept.empty()) {
            std::cerr << "[FAIL] Erased User A secret fields were not cleared"
                      << std::endl;
            return 1;
        }
        if (decoded[2].source_concept != secret_concept_b) {
            std::cerr << "[FAIL] User B payload was corrupted by User A shredding"
                      << std::endl;
            return 1;
        }
    }

    FsmEngine rebuilt_fsm(FsmLimits{});
    FsmRecoveryReport report{};
    if (FsmJournalRecovery::rebuild(
            sink.records(), sys_keys, &dek_provider, rebuilt_fsm, &report) !=
        FsmJournalRecoveryStatus::Ok) {
        std::cerr << "[FAIL] FSM recovery failed after crypto-shredding" << std::endl;
        return 1;
    }
    if (report.total_records != 3 ||
        report.cryptographically_erased_lsns.size() != 2 ||
        report.cryptographically_erased_lsns[0] != 1 ||
        report.cryptographically_erased_lsns[1] != 2) {
        std::cerr << "[FAIL] FsmRecoveryReport erased LSNs mismatch" << std::endl;
        return 1;
    }
    const FsmSnapshot rebuilt_snapshot = rebuilt_fsm.snapshot();
    if (rebuilt_fsm.history().size() != 3 ||
        rebuilt_snapshot.lsn != 3 ||
        rebuilt_snapshot.request_id != "req_b") {
        std::cerr << "[FAIL] Rebuilt FSM snapshot is inconsistent" << std::endl;
        return 1;
    }

    MemoryRecordSink resumed_sink;
    AuthenticatedEventJournal resumed_journal(resumed_sink, sys_keys);
    if (!resumed_journal.resume_from_records(sink.records(), &dek_provider) ||
        resumed_journal.next_lsn() != 4) {
        std::cerr << "[FAIL] resume_from_records failed with shredded records"
                  << std::endl;
        return 1;
    }

    {
        JournalRecord tampered = sink.records()[2];
        const auto position = tampered.payload.find("req_b");
        if (position == std::string::npos) {
            std::cerr << "[FAIL] Event metadata was not present in the MHE2 header"
                      << std::endl;
            return 1;
        }
        tampered.payload[position] = 'X';
        const auto first = JournalIntegrity::verify(
            sink.records()[0], 1, JournalIntegrity::genesis_hash(), sys_keys);
        const auto second = JournalIntegrity::verify(
            sink.records()[1], 2, first.record_hash, sys_keys);
        if (!first || !second ||
            !JournalIntegrity::seal(tampered, 3, second.record_hash, sys_keys)) {
            std::cerr << "[FAIL] Could not reseal the tampered test record" << std::endl;
            return 1;
        }

        mb::cqs13_4::EventPayload decoded;
        bool erased = false;
        if (AuthenticatedEventJournal::decode_event_payload(
                tampered.payload, &dek_provider, decoded, erased)) {
            std::cerr << "[FAIL] AES-GCM AAD tampering was not detected" << std::endl;
            return 1;
        }
    }

    std::cout
        << "[PASS] MHE2 AES-256-GCM and in-memory crypto-shredding verified"
        << std::endl;
    return 0;
}
