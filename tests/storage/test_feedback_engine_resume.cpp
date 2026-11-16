#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>
#include <utility>
#include <vector>
#include "mother_H/storage/journal_recovery_adapter.hpp"
#include "mother_H/journal/journal_integrity.hpp"

namespace {
using namespace mother_h::journal;
using namespace mother_h::policy;
using namespace mother_h::resource;

class ValidKeyProvider final : public ISecureKeyProvider {
public:
    KeyStatus current_signing_key(KeyMaterial& out) const noexcept override {
        try {
            KeyReference ref{"test_key_v1", 1};
            std::vector<uint8_t> secret(32, 0x5A);
            out = KeyMaterial(ref, std::move(secret));
            return KeyStatus::Ok;
        } catch (...) {
            return KeyStatus::NotFound;
        }
    }
    KeyStatus verification_key(const KeyReference& reference, KeyMaterial& out) const noexcept override {
        if (reference.key_id != "test_key_v1" || reference.version != 1) {
            return KeyStatus::NotFound;
        }
        try {
            std::vector<uint8_t> secret(32, 0x5A);
            out = KeyMaterial(reference, std::move(secret));
            return KeyStatus::Ok;
        } catch (...) {
            return KeyStatus::NotFound;
        }
    }
    KeyStatus rotate_key(const std::string&, KeyReference&) noexcept override {
        return KeyStatus::BackendUnavailable;
    }
    KeyStatus revoke_key(const KeyReference&) noexcept override {
        return KeyStatus::BackendUnavailable;
    }
};

ResourceLimits make_test_limits() {
    ResourceLimits limits{};
    limits.max_record_bytes = 1024 * 1024;
    limits.max_payload_bytes = 128;
    limits.max_total_input_bytes = 10 * 1024 * 1024;
    limits.max_records = 100;
    limits.max_profiles = 50;
    limits.max_failure_codes_per_profile = 10;
    limits.max_steps = 10000;
    limits.max_elapsed_time_us = 1000000;
    return limits;
}

void assert_state_unchanged(
    const JournalFeedbackEngine& engine,
    const EngineResourceSnapshot& before,
    std::uint64_t epoch_before
) {
    const auto after = engine.snapshot();
    assert(after.stats == before.stats);
    assert(after.usage.total_input_bytes == before.usage.total_input_bytes);
    assert(after.usage.records == before.usage.records);
    assert(after.usage.profiles == before.usage.profiles);
    assert(after.usage.failure_code_entries == before.usage.failure_code_entries);
    assert(after.usage.steps == before.usage.steps);
    assert(after.usage.elapsed_time_us == before.usage.elapsed_time_us);
    assert(after.next_lsn == before.next_lsn);
    assert(after.previous_record_hash == before.previous_record_hash);
    assert(after.chain_exhausted == before.chain_exhausted);
    assert(engine.epoch() == epoch_before);
}
} // namespace

int main() {
    using namespace mother_H::storage;
    std::cout << "[CP-05] Starting FeedbackEngine LSN Replay Atomicity Test...\n";

    JournalRecoveryAdapter adapter;
    ValidKeyProvider keys;

    // 1. 空のレコード群に対する Replay
    {
        ResourceGuard resources(make_test_limits());
        JournalFeedbackEngine engine(resources);
        std::vector<JournalRecord> records;
        bool result = adapter.rebuild_feedback_engine_state(records, keys, engine);
        assert(result);
        assert(engine.snapshot().usage.records == 0);
        std::cout << "[PASS] Empty journal replay succeeded\n";
    }

    // 2. 正常な 3 レコードのシールと Replay
    std::vector<JournalRecord> valid_records;
    JournalHash prev_hash = JournalIntegrity::genesis_hash();
    for (uint64_t lsn = 1; lsn <= 3; ++lsn) {
        JournalRecord rec{};
        rec.lsn = lsn;
        rec.timestamp_utc = "2026-11-10T12:00:00.000000000Z";
        rec.payload = JournalFeedbackEngine::encode_fact_payload(
            JournalFeedbackFact{
                static_cast<std::uint32_t>(lsn),
                lsn * 100,
                true,
                lsn * 10,
                lsn * 20,
                0
            }
        );
        auto seal_res = JournalIntegrity::seal(rec, lsn, prev_hash, keys);
        assert(seal_res);
        prev_hash = seal_res.record_hash;
        valid_records.push_back(rec);
    }

    {
        ResourceGuard resources(make_test_limits());
        JournalFeedbackEngine engine(resources);
        bool result = adapter.rebuild_feedback_engine_state(valid_records, keys, engine);
        assert(result);
        const auto snapshot = engine.snapshot();
        assert(snapshot.usage.records == 3);
        assert(snapshot.stats.size() == 3);
        std::cout << "[PASS] Valid 3 records replay committed completely\n";
    }

    // 3. 途中破損（3 レコード中 2 レコード目の HMAC 改ざん）時のアトミック性検証
    {
        std::vector<JournalRecord> corrupted_records = valid_records;
        corrupted_records[1].hmac_sha256[0] ^= 0xFF; // 2件目を改ざん

        ResourceGuard resources(make_test_limits());
        JournalFeedbackEngine engine(resources);
        const auto before = engine.snapshot();
        bool result = adapter.rebuild_feedback_engine_state(corrupted_records, keys, engine);
        assert(!result); // 検証失敗で拒否
        assert(engine.snapshot() == before);
        std::cout << "[PASS] Mid-stream corruption rejected with zero engine contamination (atomic rollback)\n";
    }

    // 4. LSN ギャップ（1, 3）の拒否検証
    {
        std::vector<JournalRecord> gapped_records = { valid_records[0], valid_records[2] };
        ResourceGuard resources(make_test_limits());
        JournalFeedbackEngine engine(resources);
        const auto before = engine.snapshot();
        bool result = adapter.rebuild_feedback_engine_state(gapped_records, keys, engine);
        assert(!result);
        assert(engine.snapshot() == before);
        std::cout << "[PASS] LSN gap rejected with zero engine contamination\n";
    }

    // 5. CP-05-05: 既存状態に対する破損ジャーナルReplayの原子性
    {
        std::vector<JournalRecord> corrupted_records = valid_records;
        corrupted_records[1].hmac_sha256[0] ^= 0xFF;

        ResourceGuard resources(make_test_limits());
        JournalFeedbackEngine engine(resources);
        assert(engine.ingest_record(valid_records[0], keys).status ==
               FeedbackStatus::Ingested);
        const auto before = engine.snapshot();
        const auto epoch_before = engine.epoch();

        const bool result =
            adapter.rebuild_feedback_engine_state(corrupted_records, keys, engine);
        assert(!result);
        assert_state_unchanged(engine, before, epoch_before);
        std::cout << "[PASS] CP-05-05 Corrupt replay preserves existing state\n";
    }

    // 6. CP-05-06: ResourceGuard上限による途中失敗の原子性
    {
        ResourceLimits limits = make_test_limits();
        limits.max_records = 2;
        ResourceGuard resources(limits);
        JournalFeedbackEngine engine(resources);
        assert(engine.ingest_record(valid_records[0], keys).status ==
               FeedbackStatus::Ingested);
        const auto before = engine.snapshot();
        const auto epoch_before = engine.epoch();

        const bool result =
            adapter.rebuild_feedback_engine_state(valid_records, keys, engine);
        assert(!result);
        assert_state_unchanged(engine, before, epoch_before);
        std::cout << "[PASS] CP-05-06 Resource limit preserves existing state\n";
    }

    // 7. CP-05-07: 正しいHMACを持つ不正Payloadの拒否と原子性
    {
        JournalRecord invalid_payload = valid_records[0];
        invalid_payload.payload = "MHF1-invalid-payload";
        const auto sealed = JournalIntegrity::seal(
            invalid_payload, 1, JournalIntegrity::genesis_hash(), keys);
        assert(sealed);
        assert(JournalIntegrity::verify(
            invalid_payload, 1, JournalIntegrity::genesis_hash(), keys));

        ResourceGuard resources(make_test_limits());
        JournalFeedbackEngine engine(resources);
        assert(engine.ingest_record(valid_records[0], keys).status ==
               FeedbackStatus::Ingested);
        const auto before = engine.snapshot();
        const auto epoch_before = engine.epoch();

        const bool result = adapter.rebuild_feedback_engine_state(
            std::vector<JournalRecord>{invalid_payload}, keys, engine);
        assert(!result);
        assert_state_unchanged(engine, before, epoch_before);
        std::cout << "[PASS] CP-05-07 Resealed invalid payload preserves state\n";
    }

    // 8. CP-05-08: HMACが正しいvalid_fact違反Factの拒否と原子性
    {
        JournalFeedbackFact invalid_fact{0, 98765, true, 10, 20, 0};
        JournalRecord invalid_fact_record{};
        invalid_fact_record.lsn = 1;
        invalid_fact_record.timestamp_utc =
            "2026-11-10T12:00:00.000000000Z";
        invalid_fact_record.payload =
            JournalFeedbackEngine::encode_fact_payload(invalid_fact);
        const auto sealed = JournalIntegrity::seal(
            invalid_fact_record, 1, JournalIntegrity::genesis_hash(), keys);
        assert(sealed);
        assert(JournalIntegrity::verify(
            invalid_fact_record, 1, JournalIntegrity::genesis_hash(), keys));

        ResourceGuard resources(make_test_limits());
        JournalFeedbackEngine engine(resources);
        assert(engine.ingest_record(valid_records[0], keys).status ==
               FeedbackStatus::Ingested);
        const auto before = engine.snapshot();
        const auto epoch_before = engine.epoch();

        const bool result = adapter.rebuild_feedback_engine_state(
            std::vector<JournalRecord>{invalid_fact_record}, keys, engine);
        assert(!result);
        assert_state_unchanged(engine, before, epoch_before);
        std::cout << "[PASS] CP-05-08 Resealed invalid Fact preserves state\n";
    }

    // 9. CP-05-09: 古いepochによるCAS commitは拒否し状態を保持する
    {
        ResourceGuard resources(make_test_limits());
        JournalFeedbackEngine engine(resources);
        assert(engine.ingest_record(valid_records[0], keys).status ==
               FeedbackStatus::Ingested);
        const auto stale_epoch = engine.epoch();
        assert(engine.ingest_record(valid_records[1], keys).status ==
               FeedbackStatus::Ingested);

        const auto before = engine.snapshot();
        const auto epoch_before = engine.epoch();
        ResourceGuard shadow_resources(make_test_limits());
        JournalFeedbackEngine shadow(shadow_resources);
        const bool committed =
            engine.commit_state_from(std::move(shadow), stale_epoch);
        assert(!committed);
        assert_state_unchanged(engine, before, epoch_before);
        std::cout << "[PASS] CP-05-09 Stale epoch CAS commit rejected\n";
    }

    std::cout << "[RESULT] ALL CP-05 FEEDBACK REPLAY ATOMICITY TESTS PASSED STRICTLY\n";
    return 0;
}
