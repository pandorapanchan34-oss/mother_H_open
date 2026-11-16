#include "mother_H/core/op_executor.hpp"
#include "mother_H/core/policy_engine.hpp"
#include "mother_H/journal/journal_integrity.hpp"
#include "mother_H/policy/journal_feedback_engine.hpp"
#include "mother_H/resource/resource_guard.hpp"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iostream>
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
            out = KeyMaterial(reference_, std::vector<std::uint8_t>(32, 0x6BU));
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
            out = KeyMaterial(reference_, std::vector<std::uint8_t>(32, 0x6BU));
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
    KeyReference reference_{"dynamic-policy-execution-test", 1};
};

class ScriptedOperator final : public Operator<Integer> {
public:
    ScriptedOperator(std::uint32_t id, std::string name)
        : id_(id), name_(std::move(name)) {}

    std::uint32_t id() const noexcept override { return id_; }
    std::string name() const noexcept override { return name_; }

    OpResult<Integer> execute(const OpContext<Integer>&) const override {
        OpResult<Integer> result;
        result.status = OpExecStatus::Success;
        result.op_name = name_;
        result.steps_used = id_ == 5 ? 1 : 3;
        result.time_spent_us = 1;
        return result;
    }

private:
    std::uint32_t id_;
    std::string name_;
};

struct JournalPosition {
    std::uint64_t next_lsn{1};
    JournalHash previous_hash{};
};

ResourceLimits make_feedback_limits() {
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

ResourceLimits make_executor_limits() {
    ResourceLimits limits = make_feedback_limits();
    limits.max_steps = 1000000;
    limits.max_elapsed_time_us = 10000000;
    return limits;
}

OpContext<Integer> make_request() {
    OpContext<Integer> request;
    request.target_n = 91;
    request.step_budget = 4000;
    request.time_budget_us = 400000;
    return request;
}

OpRegistry<Integer> make_registry() {
    OpRegistry<Integer> registry;
    registry.register_operator(std::make_shared<ScriptedOperator>(0, "OP0_Guard"));
    registry.register_operator(std::make_shared<ScriptedOperator>(3, "OP3_Fermat"));
    registry.register_operator(std::make_shared<ScriptedOperator>(4, "OP4_Tensor"));
    registry.register_operator(std::make_shared<ScriptedOperator>(5, "OP5_Torus"));
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
    const IntegrityResult verified =
        JournalIntegrity::verify(record, position.next_lsn, position.previous_hash, keys);
    assert(static_cast<bool>(verified));
    const FeedbackIngestResult result = feedback.ingest_record(record, keys);
    if (result.status == FeedbackStatus::Ingested) {
        position.previous_hash = verified.record_hash;
        ++position.next_lsn;
    }
    return result;
}

void add_baseline_profile(
    JournalFeedbackEngine& feedback,
    const ISecureKeyProvider& keys,
    JournalPosition& position,
    std::uint32_t op_id
) {
    for (unsigned index = 0; index < 5; ++index) {
        const bool succeeded = index < 2;
        const FeedbackIngestResult result = ingest_fact(
            feedback, keys, position,
            JournalFeedbackFact{
                op_id,
                91,
                succeeded,
                30,
                100,
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

void assert_static_order(const PolicyPlan<Integer>& plan) {
    assert((selected_ids(plan) == std::vector<std::uint32_t>{0, 3, 4, 5}));
}

JournalFeedbackFact execute_op5(
    const OpContext<Integer>& request,
    const PolicyPlan<Integer>& plan,
    const OpRegistry<Integer>& registry
) {
    ResourceGuard execution_resources(make_executor_limits());
    const OpExecutionReport<Integer> report =
        OpExecutor<Integer>(registry).execute(request, plan, execution_resources);
    assert(report.resource_guard_applied);
    assert(report.resource_status == ResourceStatus::Ok);
    assert(!report.history.empty());
    const auto found = std::find_if(
        report.history.begin(), report.history.end(),
        [](const OpExecutionRecord<Integer>& record) {
            return record.operator_id == 5;
        });
    assert(found != report.history.end());
    assert(found->status == OpExecStatus::Success);
    assert(found->steps_used == 1);
    assert(found->steps_used <= found->step_budget);
    assert(found->time_spent_us <= found->time_budget_us);
    return JournalFeedbackFact{
        found->operator_id,
        request.target_n,
        found->status == OpExecStatus::Success,
        found->steps_used,
        found->time_spent_us,
        found->status == OpExecStatus::Success ? 0U : 101U
    };
}

void test_five_cycle_ready_promotion() {
    ResourceGuard feedback_resources(make_feedback_limits());
    JournalFeedbackEngine feedback(feedback_resources);
    TestKeyProvider keys;
    JournalPosition position;
    add_baseline_profile(feedback, keys, position, 3);
    add_baseline_profile(feedback, keys, position, 4);

    const auto request = make_request();
    const auto registry = make_registry();
    for (unsigned cycle = 1; cycle <= 5; ++cycle) {
        const auto plan =
            PolicyEngine::plan_dynamic(request, registry, feedback);
        assert_static_order(plan);
        const JournalFeedbackFact fact = execute_op5(request, plan, registry);
        const FeedbackIngestResult ingested =
            ingest_fact(feedback, keys, position, fact);
        assert(ingested.status == FeedbackStatus::Ingested);

        const FeedbackEstimate estimate = feedback.estimate(5, request.target_n, 5);
        if (cycle < 5) {
            assert(estimate.status == QueryStatus::InsufficientSamples);
            assert(estimate.attempts == cycle);
            assert_static_order(
                PolicyEngine::plan_dynamic(request, registry, feedback));
        } else {
            assert(estimate.status == QueryStatus::Ready);
            assert(estimate.attempts == 5);
            assert(estimate.success_rate.has_value());
            assert(*estimate.success_rate == 1.0);
        }
    }

    const auto next_plan =
        PolicyEngine::plan_dynamic(request, registry, feedback);
    assert(next_plan.selected.size() == 4);
    assert(next_plan.selected[0].operator_id == 0);
    assert(next_plan.selected[1].operator_id == 5);
}

void test_tampered_fifth_record_does_not_change_plan() {
    ResourceGuard feedback_resources(make_feedback_limits());
    JournalFeedbackEngine feedback(feedback_resources);
    TestKeyProvider keys;
    JournalPosition position;
    add_baseline_profile(feedback, keys, position, 3);
    add_baseline_profile(feedback, keys, position, 4);

    const auto request = make_request();
    const auto registry = make_registry();
    for (unsigned cycle = 1; cycle <= 4; ++cycle) {
        const auto plan =
            PolicyEngine::plan_dynamic(request, registry, feedback);
        assert_static_order(plan);
        const JournalFeedbackFact fact = execute_op5(request, plan, registry);
        assert(ingest_fact(feedback, keys, position, fact).status ==
               FeedbackStatus::Ingested);
        const FeedbackEstimate estimate = feedback.estimate(5, request.target_n, 5);
        assert(estimate.status == QueryStatus::InsufficientSamples);
        assert(estimate.attempts == cycle);
    }

    const auto fifth_plan =
        PolicyEngine::plan_dynamic(request, registry, feedback);
    assert_static_order(fifth_plan);
    const JournalFeedbackFact fifth_fact = execute_op5(request, fifth_plan, registry);
    JournalHash sealed_hash{};
    JournalRecord tampered = seal_fact(
        position.next_lsn, fifth_fact, position.previous_hash, keys, sealed_hash);
    tampered.hmac_sha256[0] ^= 0x01U;

    const FeedbackIngestResult rejected = feedback.ingest_record(tampered, keys);
    assert(rejected.status == FeedbackStatus::IntegrityRejected);
    assert(rejected.integrity_status == IntegrityStatus::HmacMismatch);
    const FeedbackEstimate estimate = feedback.estimate(5, request.target_n, 5);
    assert(estimate.status == QueryStatus::InsufficientSamples);
    assert(estimate.attempts == 4);

    const auto dynamic_plan =
        PolicyEngine::plan_dynamic(request, registry, feedback);
    assert_static_order(dynamic_plan);
    assert((selected_ids(dynamic_plan) ==
            selected_ids(PolicyEngine::plan(request, registry))));
}
}  // namespace

int main() {
    test_five_cycle_ready_promotion();
    std::cout << "[PASS] DYN-E2E-01 five-cycle Ready transition and promotion\n";

    test_tampered_fifth_record_does_not_change_plan();
    std::cout << "[PASS] DYN-E2E-02 tampered record rejected without plan change\n";
    return 0;
}
