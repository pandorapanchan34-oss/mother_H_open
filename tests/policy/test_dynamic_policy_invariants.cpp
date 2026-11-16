#include "mother_H/core/policy_engine.hpp"
#include "mother_H/journal/journal_integrity.hpp"
#include "mother_H/policy/journal_feedback_engine.hpp"
#include "mother_H/resource/resource_guard.hpp"
#include "mother_H/storage/journal_recovery_adapter.hpp"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {
using Integer = std::uint64_t;
using namespace mother_h::journal;
using namespace mother_h::op;
using namespace mother_h::policy;
using namespace mother_h::resource;

class TestKeyProvider final : public ISecureKeyProvider {
public:
    KeyStatus current_signing_key(KeyMaterial& out) const noexcept override {
        try {
            out = KeyMaterial(reference_, std::vector<std::uint8_t>(32, 0x5AU));
            return KeyStatus::Ok;
        } catch (...) {
            return KeyStatus::BackendUnavailable;
        }
    }

    KeyStatus verification_key(
        const KeyReference& reference,
        KeyMaterial& out
    ) const noexcept override {
        if (reference != reference_) return KeyStatus::NotFound;
        try {
            out = KeyMaterial(reference_, std::vector<std::uint8_t>(32, 0x5AU));
            return KeyStatus::Ok;
        } catch (...) {
            return KeyStatus::BackendUnavailable;
        }
    }

    KeyStatus rotate_key(const std::string&, KeyReference&) noexcept override {
        return KeyStatus::InvalidRequest;
    }

    KeyStatus revoke_key(const KeyReference&) noexcept override {
        return KeyStatus::InvalidRequest;
    }

private:
    KeyReference reference_{"dynamic-policy-invariant-test", 1};
};

class StubOperator final : public Operator<Integer> {
public:
    StubOperator(std::uint32_t id, std::string name, bool supported = true)
        : id_(id), name_(std::move(name)), supported_(supported) {}

    std::uint32_t id() const noexcept override { return id_; }
    std::string name() const noexcept override { return name_; }
    bool supports(const OpContext<Integer>&) const override { return supported_; }

    OpResult<Integer> execute(const OpContext<Integer>&) const override {
        OpResult<Integer> result;
        result.status = OpExecStatus::Success;
        result.op_name = name_;
        result.steps_used = 1;
        result.time_spent_us = 1;
        return result;
    }

private:
    std::uint32_t id_;
    std::string name_;
    bool supported_;
};

struct JournalPosition {
    std::uint64_t next_lsn{1};
    JournalHash previous_hash{};
};

ResourceLimits make_limits() {
    ResourceLimits limits{};
    limits.max_record_bytes = 1024 * 1024;
    limits.max_payload_bytes = 1024;
    limits.max_total_input_bytes = 64 * 1024 * 1024;
    limits.max_records = 10000;
    limits.max_profiles = 1000;
    limits.max_failure_codes_per_profile = 100;
    limits.max_steps = 1000000000;
    limits.max_elapsed_time_us = 1000000000;
    return limits;
}

OpContext<Integer> make_request(
    std::uint64_t target,
    std::uint64_t steps = 1000,
    std::uint64_t time_us = 2000
) {
    OpContext<Integer> request;
    request.target_n = target;
    request.step_budget = steps;
    request.time_budget_us = time_us;
    return request;
}

OpRegistry<Integer> make_registry(bool support_op4 = true) {
    OpRegistry<Integer> registry;
    registry.register_operator(std::make_shared<StubOperator>(0, "OP0_Guard"));
    registry.register_operator(std::make_shared<StubOperator>(3, "OP3_Fermat"));
    registry.register_operator(
        std::make_shared<StubOperator>(4, "OP4_Tensor", support_op4));
    registry.register_operator(std::make_shared<StubOperator>(5, "OP5_Torus"));
    return registry;
}

JournalRecord seal_fact(
    std::uint64_t lsn,
    const JournalFeedbackFact& fact,
    const JournalHash& previous_hash,
    const ISecureKeyProvider& keys,
    JournalHash& record_hash
) {
    JournalRecord record{};
    record.lsn = lsn;
    record.timestamp_utc = "2026-11-14T00:00:00.000000000Z";
    record.payload = JournalFeedbackEngine::encode_fact_payload(fact);
    const IntegrityResult sealed =
        JournalIntegrity::seal(record, lsn, previous_hash, keys);
    assert(static_cast<bool>(sealed));
    record_hash = sealed.record_hash;
    return record;
}

FeedbackIngestResult ingest_fact(
    JournalFeedbackEngine& feedback,
    const ISecureKeyProvider& keys,
    JournalPosition& position,
    const JournalFeedbackFact& fact
) {
    JournalHash next_hash{};
    const JournalRecord record = seal_fact(
        position.next_lsn, fact, position.previous_hash, keys, next_hash);
    const FeedbackIngestResult result = feedback.ingest_record(record, keys);
    position.previous_hash = next_hash;
    ++position.next_lsn;
    return result;
}

void add_profile(
    JournalFeedbackEngine& feedback,
    const ISecureKeyProvider& keys,
    JournalPosition& position,
    std::uint32_t op_id,
    std::uint64_t target,
    unsigned successes,
    std::uint64_t success_steps,
    std::uint64_t success_time,
    std::uint64_t failure_steps = 40,
    std::uint64_t failure_time = 100
) {
    for (unsigned index = 0; index < 5; ++index) {
        const bool succeeded = index < successes;
        const FeedbackIngestResult result = ingest_fact(
            feedback, keys, position,
            JournalFeedbackFact{
                op_id,
                target,
                succeeded,
                succeeded ? success_steps : failure_steps,
                succeeded ? success_time : failure_time,
                succeeded ? 0U : 101U
            });
        assert(result.status == FeedbackStatus::Ingested);
    }
}

std::vector<std::uint32_t> selected_ids(const PolicyPlan<Integer>& plan) {
    std::vector<std::uint32_t> ids;
    ids.reserve(plan.selected.size());
    for (const auto& entry : plan.selected) ids.push_back(entry.operator_id);
    return ids;
}

void assert_same_plan(
    const PolicyPlan<Integer>& actual,
    const PolicyPlan<Integer>& expected
) {
    assert(actual.requested_step_budget == expected.requested_step_budget);
    assert(actual.requested_time_budget_us == expected.requested_time_budget_us);
    assert(actual.selected.size() == expected.selected.size());
    for (std::size_t index = 0; index < actual.selected.size(); ++index) {
        const auto& left = actual.selected[index];
        const auto& right = expected.selected[index];
        assert(left.operator_id == right.operator_id);
        assert(left.operator_name == right.operator_name);
        assert(left.step_budget == right.step_budget);
        assert(left.time_budget_us == right.time_budget_us);
    }
}

void assert_budget_totals(
    const PolicyPlan<Integer>& plan,
    std::uint64_t requested_steps,
    std::uint64_t requested_time
) {
    assert(plan.requested_step_budget == requested_steps);
    assert(plan.requested_time_budget_us == requested_time);
    std::uint64_t step_sum = 0;
    std::uint64_t time_sum = 0;
    for (const auto& entry : plan.selected) {
        step_sum += entry.step_budget;
        time_sum += entry.time_budget_us;
    }
    assert(step_sum == requested_steps);
    assert(time_sum == requested_time);
}

void test_op0_fixed(bool all_success) {
    constexpr std::uint64_t target = 91;
    ResourceGuard resources(make_limits());
    JournalFeedbackEngine feedback(resources);
    TestKeyProvider keys;
    JournalPosition position;

    for (unsigned index = 0; index < 5; ++index) {
        const bool succeeded = all_success;
        const FeedbackIngestResult result = ingest_fact(
            feedback, keys, position,
            JournalFeedbackFact{
                0,
                target,
                succeeded,
                succeeded ? 1U : 40U,
                succeeded ? 1U : 100U,
                succeeded ? 0U : 101U
            });
        assert(result.status == FeedbackStatus::InvalidFact);
    }

    assert(feedback.estimate(0, target, 5).status == QueryStatus::InvalidQuery);
    add_profile(feedback, keys, position, 3, target, 2, 30, 80);
    add_profile(feedback, keys, position, 4, target, 3, 20, 60);
    add_profile(feedback, keys, position, 5, target, 5, 1, 1);

    const auto plan = PolicyEngine::plan_dynamic(
        make_request(target), make_registry(), feedback);
    assert(plan.selected.size() == 4);
    assert(plan.selected[0].operator_id == 0);
    assert((selected_ids(plan) ==
            std::vector<std::uint32_t>{0, 5, 4, 3}));
}

OpPerformanceProfile make_op0_profile(
    std::uint64_t successes,
    std::uint64_t success_steps,
    std::uint64_t success_time,
    std::uint64_t failure_steps,
    std::uint64_t failure_time
) {
    OpPerformanceProfile profile;
    profile.attempts = 5;
    profile.successes = successes;
    profile.total_steps_used =
        successes * success_steps + (5 - successes) * failure_steps;
    profile.total_time_us =
        successes * success_time + (5 - successes) * failure_time;
    profile.successful_steps_used = successes * success_steps;
    if (successes < profile.attempts) {
        profile.failure_codes.emplace(101, profile.attempts - successes);
    }
    return profile;
}

void test_op0_seeded_profile(bool all_success) {
    constexpr std::uint64_t target = 91;
    ResourceGuard resources(make_limits());
    JournalFeedbackEngine feedback(resources);
    TestKeyProvider keys;
    JournalPosition position;

    const std::uint64_t successes = all_success ? 5 : 0;
    const OpPerformanceProfile profile = all_success
        ? make_op0_profile(5, 1, 1, 0, 0)
        : make_op0_profile(0, 0, 0, 40, 100);
    assert(profile.attempts == 5);
    assert(profile.successes == successes);
    assert(profile.success_rate() == (all_success ? 1.0 : 0.0));
    assert(feedback.seed_profile_for_test(0, target, profile));
    assert(feedback.stats().size() == 1);
    assert(feedback.estimate(0, target, 5).status == QueryStatus::InvalidQuery);

    add_profile(feedback, keys, position, 3, target, 5, 30, 80);
    add_profile(feedback, keys, position, 4, target, 5, 20, 60);
    add_profile(feedback, keys, position, 5, target, 5, 1, 1);
    for (const std::uint32_t op_id : {3U, 4U, 5U}) {
        assert(feedback.estimate(op_id, target, 5).status == QueryStatus::Ready);
    }

    const auto request = make_request(target);
    const auto registry = make_registry();
    const auto dynamic_plan =
        PolicyEngine::plan_dynamic(request, registry, feedback);
    const auto static_plan = PolicyEngine::plan(request, registry);
    assert(dynamic_plan.selected.size() == static_plan.selected.size());
    assert(dynamic_plan.selected[0].operator_id == 0);
    assert((selected_ids(dynamic_plan) ==
            std::vector<std::uint32_t>{0, 5, 4, 3}));
}

void test_supports_and_unregistered_operator() {
    constexpr std::uint64_t target = 91;
    ResourceGuard resources(make_limits());
    JournalFeedbackEngine feedback(resources);
    TestKeyProvider keys;
    JournalPosition position;
    add_profile(feedback, keys, position, 4, target, 5, 1, 1);
    add_profile(feedback, keys, position, 99, target, 5, 1, 1);
    assert(feedback.estimate(4, target, 5).status == QueryStatus::Ready);
    assert(feedback.estimate(99, target, 5).status == QueryStatus::Ready);

    const auto registry = make_registry(false);
    const auto request = make_request(target);
    const auto dynamic_plan =
        PolicyEngine::plan_dynamic(request, registry, feedback);
    const auto static_plan = PolicyEngine::plan(request, registry);
    assert((selected_ids(static_plan) ==
            std::vector<std::uint32_t>{0, 3, 5}));
    assert_same_plan(dynamic_plan, static_plan);
    for (const auto& entry : dynamic_plan.selected) {
        assert(entry.operator_id != 4);
        assert(entry.operator_id != 99);
    }
}

void test_budget_boundaries() {
    constexpr std::uint64_t target = 91;
    ResourceGuard resources(make_limits());
    JournalFeedbackEngine feedback(resources);
    const auto registry = make_registry();

    const auto zero_plan = PolicyEngine::plan_dynamic(
        make_request(target, 0, 0), registry, feedback);
    assert_budget_totals(zero_plan, 0, 0);
    for (const auto& entry : zero_plan.selected) {
        assert(entry.step_budget == 0);
        assert(entry.time_budget_us == 0);
    }

    const auto tiny_plan = PolicyEngine::plan_dynamic(
        make_request(target, 1, 2), registry, feedback);
    assert(tiny_plan.selected.size() == 4);
    assert_budget_totals(tiny_plan, 1, 2);
}

void test_target_structure_isolation() {
    ResourceGuard resources(make_limits());
    JournalFeedbackEngine feedback(resources);
    TestKeyProvider keys;
    JournalPosition position;
    for (const std::uint32_t op_id : {3U, 4U, 5U}) {
        add_profile(feedback, keys, position, op_id, 100, 5, 1, 1);
    }

    assert(feedback.estimate(5, 100, 5).status == QueryStatus::Ready);
    assert(feedback.estimate(5, 91, 5).status == QueryStatus::NoData);
    const auto request = make_request(91);
    assert_same_plan(
        PolicyEngine::plan_dynamic(request, make_registry(), feedback),
        PolicyEngine::plan(request, make_registry()));
}

void test_failed_replay_preserves_empty_engine() {
    constexpr std::uint64_t target = 91;
    ResourceGuard resources(make_limits());
    JournalFeedbackEngine feedback(resources);
    TestKeyProvider keys;
    JournalPosition position;
    std::vector<JournalRecord> records;
    for (std::uint64_t index = 0; index < 2; ++index) {
        JournalHash next_hash{};
        records.push_back(seal_fact(
            position.next_lsn,
            JournalFeedbackFact{5, target, true, 10, 20, 0},
            position.previous_hash, keys, next_hash));
        position.previous_hash = next_hash;
        ++position.next_lsn;
    }
    records[1].hmac_sha256[0] ^= 0x80U;

    const auto before = feedback.snapshot();
    const std::uint64_t epoch_before = feedback.epoch();
    mother_H::storage::JournalRecoveryAdapter adapter;
    assert(!adapter.rebuild_feedback_engine_state(records, keys, feedback));
    assert(feedback.snapshot() == before);
    assert(feedback.epoch() == epoch_before);
    assert(feedback.estimate(5, target, 5).status == QueryStatus::NoData);

    const auto request = make_request(target, 101, 203);
    assert_same_plan(
        PolicyEngine::plan_dynamic(request, make_registry(), feedback),
        PolicyEngine::plan(request, make_registry()));
}

void test_chain_exhausted_boundary() {
    constexpr std::uint64_t target = 100;
    constexpr std::uint64_t max_lsn =
        (std::numeric_limits<std::uint64_t>::max)();
    ResourceGuard resources(make_limits());
    JournalFeedbackEngine feedback(resources);
    TestKeyProvider keys;
    const JournalHash genesis = JournalIntegrity::genesis_hash();
    feedback.set_next_lsn_for_test(max_lsn, genesis);

    JournalHash boundary_hash{};
    const JournalRecord boundary_record = seal_fact(
        max_lsn,
        JournalFeedbackFact{5, 91, true, 1, 1, 0},
        genesis,
        keys,
        boundary_hash);
    const IntegrityResult boundary_verified =
        JournalIntegrity::verify(boundary_record, max_lsn, genesis, keys);
    assert(static_cast<bool>(boundary_verified));
    const FeedbackIngestResult boundary_result =
        feedback.ingest_record(boundary_record, keys);
    assert(boundary_result.status == FeedbackStatus::Ingested);

    const auto after_boundary = feedback.snapshot();
    assert(after_boundary.chain_exhausted);
    assert(after_boundary.next_lsn == max_lsn);
    assert(after_boundary.previous_record_hash == boundary_verified.record_hash);
    assert(after_boundary.stats.size() == 1);

    // UINT64_MAX has no representable successor; submit a linked candidate to
    // exercise the exhausted-chain rejection before ordinary LSN validation.
    JournalHash following_hash{};
    const JournalRecord following_record = seal_fact(
        max_lsn,
        JournalFeedbackFact{5, 91, true, 1, 1, 0},
        after_boundary.previous_record_hash,
        keys,
        following_hash);
    const IntegrityResult following_verified =
        JournalIntegrity::verify(
            following_record, max_lsn, after_boundary.previous_record_hash, keys);
    assert(static_cast<bool>(following_verified));
    const FeedbackIngestResult following_result =
        feedback.ingest_record(following_record, keys);
    assert(following_result.status == FeedbackStatus::IntegrityRejected);
    assert(following_result.integrity_status == IntegrityStatus::LsnOutOfOrder);
    assert(feedback.snapshot() == after_boundary);
    assert(feedback.estimate(5, target, 5).status == QueryStatus::NoData);

    const auto request = make_request(target, 103, 207);
    const auto registry = make_registry();
    assert_same_plan(
        PolicyEngine::plan_dynamic(request, registry, feedback),
        PolicyEngine::plan(request, registry));
}
}  // namespace

int main() {
    test_op0_fixed(false);
    test_op0_fixed(true);
    std::cout << "[PASS] DYN-INV-01 OP0 remains fixed; its facts are rejected by valid_fact\n";

    test_op0_seeded_profile(false);
    std::cout << "[PASS] DYN-INV-01-A OP0 seeded profile 0/5 remains fixed\n";

    test_op0_seeded_profile(true);
    std::cout << "[PASS] DYN-INV-01-B OP0 seeded profile 5/5 remains fixed; estimate rejects OP0\n";

    test_supports_and_unregistered_operator();
    std::cout << "[PASS] DYN-INV-02 supports and registry boundaries\n";

    test_budget_boundaries();
    std::cout << "[PASS] DYN-INV-03 budget totals at zero and tiny budgets\n";

    test_target_structure_isolation();
    std::cout << "[PASS] DYN-INV-04 target-structure isolation\n";

    test_failed_replay_preserves_empty_engine();
    std::cout << "[PASS] DYN-INV-05-A failed replay preserves static planning\n";

    test_chain_exhausted_boundary();
    std::cout << "[PASS] DYN-INV-05-B UINT64_MAX chain exhaustion and following rejection\n";
    return 0;
}
