#include <iostream>
#include <string>
#include <vector>

#include "mother_H/journal/journal_integrity.hpp"
#include "mother_H/policy/journal_feedback_engine.hpp"
#include "mother_H/resource/resource_guard.hpp"
#include "mother_H/storage/journal_recovery_adapter.hpp"

namespace {
using namespace mother_h::journal;
using namespace mother_h::policy;
using namespace mother_h::resource;

class TestKeyProvider final : public ISecureKeyProvider {
public:
    KeyStatus current_signing_key(KeyMaterial& out) const noexcept override {
        KeyReference ref{"test_key_v1", 1};
        out = KeyMaterial(ref, std::vector<uint8_t>(32, 0x5A));
        return KeyStatus::Ok;
    }

    KeyStatus verification_key(
        const KeyReference& ref,
        KeyMaterial& out
    ) const noexcept override {
        if (ref.key_id != "test_key_v1" || ref.version != 1) {
            return KeyStatus::NotFound;
        }

        out = KeyMaterial(ref, std::vector<uint8_t>(32, 0x5A));
        return KeyStatus::Ok;
    }

    KeyStatus rotate_key(
        const std::string&,
        KeyReference&
    ) noexcept override {
        return KeyStatus::NotFound;
    }

    KeyStatus revoke_key(
        const KeyReference&
    ) noexcept override {
        return KeyStatus::NotFound;
    }
};

bool make_record(
    JournalRecord& record,
    uint64_t lsn,
    const JournalHash& prev_hash,
    const JournalFeedbackFact& fact,
    const ISecureKeyProvider& keys
) {
    record.lsn = lsn;
    record.timestamp_utc = "2026-11-12T00:00:00.000000000Z";
    record.payload = JournalFeedbackEngine::encode_fact_payload(fact);

    const auto result = JournalIntegrity::seal(
        record, lsn, prev_hash, keys
    );

    return static_cast<bool>(result);
}

} // namespace

#define CHECK_OR_EXIT(expr)                                      \
    do {                                                         \
        if (!(expr)) {                                           \
            std::cerr << "[FAIL] " << #expr                      \
                      << " at line " << __LINE__ << std::endl;   \
            return 2;                                            \
        }                                                        \
    } while (false)

int main() {
    std::cout
        << "=== Replay Contract A: Atomic Commit RED Verification ==="
        << std::endl;

    TestKeyProvider keys;

    ResourceLimits limits{};
    limits.max_record_bytes = 1024 * 1024;
    limits.max_payload_bytes = 128;
    limits.max_total_input_bytes = 10 * 1024 * 1024;
    limits.max_records = 100;
    limits.max_profiles = 50;
    limits.max_failure_codes_per_profile = 10;
    limits.max_steps = 10000;
    limits.max_elapsed_time_us = 1000000;

    CHECK_OR_EXIT(limits.valid());

    ResourceGuard guard(limits);
    JournalFeedbackEngine engine(guard);
    mother_H::storage::JournalRecoveryAdapter adapter;

    // S0: 本番 Engine の初期状態は空。
    const EngineResourceSnapshot snap_S0 = engine.snapshot();

    const JournalHash genesis = JournalIntegrity::genesis_hash();

    // Record 1: 正常な LSN 1 / Genesis。
    JournalRecord r1{};
    const JournalFeedbackFact fact1{101, 100, true, 10, 20, 0};

    CHECK_OR_EXIT(make_record(
        r1, 1, genesis, fact1, keys
    ));

    const auto verify1 = JournalIntegrity::verify(
        r1, 1, genesis, keys
    );

    CHECK_OR_EXIT(static_cast<bool>(verify1));

    // Record 2: 正常な LSN 2 / Record 1 のハッシュに連結。
    JournalRecord r2{};
    const JournalFeedbackFact fact2{202, 200, false, 5, 10, 1};

    CHECK_OR_EXIT(make_record(
        r2, 2, verify1.record_hash, fact2, keys
    ));

    // 署名済みペイロードを改変する。
    // LSN と previous_record_hash は正しいまま。
    CHECK_OR_EXIT(!r2.payload.empty());

    r2.payload[0] = static_cast<char>(r2.payload[0] ^ 0x01);

    // テストデータが HMAC 検証で拒否されることを事前確認。
    const auto verify2 = JournalIntegrity::verify(
        r2, 2, verify1.record_hash, keys
    );

    CHECK_OR_EXIT(!static_cast<bool>(verify2));

    std::cout
        << "[SETUP VERIFIED] Record 1 valid; Record 2 HMAC invalid."
        << std::endl;

    // Replay: Record 1 適用後、Record 2 の検証で失敗する想定。
    const bool rebuild_result =
        adapter.rebuild_feedback_engine_state(
            std::vector<JournalRecord>{r1, r2},
            keys,
            engine
        );

    CHECK_OR_EXIT(!rebuild_result);

    // 契約 A: 失敗後の本番状態が S0 と完全一致するか。
    const EngineResourceSnapshot snap_after = engine.snapshot();

    if (snap_after != snap_S0) {
        std::cout
            << "[RED CONFIRMED] Partial replay changed production state."
            << std::endl;

        std::cout
            << "  Expected stats size: " << snap_S0.stats.size()
            << ", Actual: " << snap_after.stats.size()
            << std::endl;

        std::cout
            << "  Expected records: " << snap_S0.usage.records
            << ", Actual: " << snap_after.usage.records
            << std::endl;

        return 1;
    }

    std::cout
        << "[NO RED] State remained unchanged."
        << std::endl;

    return 0;
}
