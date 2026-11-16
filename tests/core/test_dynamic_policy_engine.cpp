#include "mother_H/core/policy_engine.hpp"
#include "mother_H/policy/journal_feedback_engine.hpp"
#include "mother_H/journal/journal_integrity.hpp"
#include "mother_H/resource/resource_guard.hpp"
#include <array>
#include <cassert>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
namespace {
using Integer = std::uint64_t;
using namespace mother_h::op;
using namespace mother_h::policy;
using namespace mother_h::journal;
using namespace mother_h::resource;
class TestKeyProvider final : public ISecureKeyProvider {
public:
    KeyStatus current_signing_key(KeyMaterial& out) const noexcept override {
        out = KeyMaterial(reference_, std::vector<std::uint8_t>(32, 0x5AU));
        return KeyStatus::Ok;
    }
    KeyStatus verification_key(const KeyReference& reference, KeyMaterial& out) const noexcept override {
        if (reference != reference_) {
            return KeyStatus::NotFound;
        }
        out = KeyMaterial(reference_, std::vector<std::uint8_t>(32, 0x5AU));
        return KeyStatus::Ok;
    }
    KeyStatus rotate_key(const std::string&, KeyReference&) noexcept override {
        return KeyStatus::InvalidRequest;
    }
    KeyStatus revoke_key(const KeyReference&) noexcept override {
        return KeyStatus::InvalidRequest;
    }
private:
    KeyReference reference_{"dynamic-policy-test", 1};
};
class StubOp final : public Operator<Integer> {
public:
    StubOp(std::uint32_t id, std::string name, bool supported = true)
        : id_(id), name_(std::move(name)), supported_(supported) {}
    std::uint32_t id() const noexcept override { return id_; }
    std::string name() const noexcept override { return name_; }
    bool supports(const OpContext<Integer>&) const override { return supported_; }
    OpResult<Integer> execute(const OpContext<Integer>&) const override { return {}; }
private:
    std::uint32_t id_;
    std::string name_;
    bool supported_;
};
OpContext<Integer> make_request(std::uint64_t steps, std::uint64_t time) {
    OpContext<Integer> req;
    req.target_n = 91;
    req.step_budget = steps;
    req.time_budget_us = time;
    return req;
}
ResourceLimits make_test_limits() {
    ResourceLimits limits{};
    limits.max_record_bytes = 1000;
    limits.max_payload_bytes = 1000;
    limits.max_total_input_bytes = 100000;
    limits.max_records = 1000;
    limits.max_profiles = 10;
    limits.max_failure_codes_per_profile = 10;
    limits.max_steps = 10000;
    limits.max_elapsed_time_us = 1000000;
    return limits;
}
JournalRecord make_dynamic_record(
    std::uint64_t lsn,
    const JournalFeedbackFact& fact,
    const JournalHash& previous_hash,
    const ISecureKeyProvider& keys
) {
    JournalRecord record;
    record.lsn = lsn;
    record.timestamp_utc = "2026-11-08T00:00:00.000000000Z";
    record.payload = JournalFeedbackEngine::encode_fact_payload(fact);
    const IntegrityResult sealed = JournalIntegrity::seal(record, lsn, previous_hash, keys);
    assert(static_cast<bool>(sealed));
    return record;
}
void inject_fact(
    JournalFeedbackEngine& feedback,
    const ISecureKeyProvider& keys,
    std::uint64_t lsn,
    JournalHash& previous_hash,
    std::uint32_t op_id,
    std::uint64_t target,
    bool succeeded,
    std::uint64_t steps_used,
    std::uint64_t time_us
) {
    JournalFeedbackFact fact{op_id, target, succeeded, steps_used, time_us, succeeded ? 0U : 101U};
    JournalRecord record = make_dynamic_record(lsn, fact, previous_hash, keys);
    const FeedbackIngestResult result = feedback.ingest_record(record, keys);
    assert(result.status == FeedbackStatus::Ingested);
    const IntegrityResult verified = JournalIntegrity::verify(record, lsn, previous_hash, keys);
    assert(static_cast<bool>(verified));
    previous_hash = verified.record_hash;
}
OpRegistry<Integer> make_registry() {
    OpRegistry<Integer> registry;
    registry.register_operator(std::make_shared<StubOp>(0, "OP0_Guard"));
    registry.register_operator(std::make_shared<StubOp>(3, "OP3_Fermat"));
    registry.register_operator(std::make_shared<StubOp>(4, "OP4_Tensor"));
    registry.register_operator(std::make_shared<StubOp>(5, "OP5_Torus"));
    return registry;
}
void add_profile(JournalFeedbackEngine& feedback, const ISecureKeyProvider& keys,
                 JournalHash& hash, std::uint64_t& lsn, std::uint32_t id,
                 unsigned successes, std::uint64_t success_steps,
                 std::uint64_t success_time, std::uint64_t failure_time = 100) {
    for (unsigned i = 0; i < 5; ++i) {
        const bool succeeded = i < successes;
        inject_fact(feedback, keys, lsn++, hash, id, 91, succeeded,
                    succeeded ? success_steps : 40, succeeded ? success_time : failure_time);
    }
}
std::vector<std::uint32_t> ids(const PolicyPlan<Integer>& plan) {
    std::vector<std::uint32_t> result;
    for (const auto& entry : plan.selected) result.push_back(entry.operator_id);
    return result;
}
} // namespace
int main() {
    const auto registry = make_registry();
    ResourceLimits limits = make_test_limits();
    ResourceGuard guard(limits);
    TestKeyProvider keys;
    const JournalHash genesis{};
    // DYN-001
    JournalFeedbackEngine feedback(guard);
    JournalHash previous_hash = genesis;
    for (std::uint64_t i = 1; i <= 6; ++i) {
        inject_fact(feedback, keys, i, previous_hash, 4, 91, true, 10, 50);
    }
    const FeedbackEstimate estimate = feedback.estimate(4, 91, 5);
    assert(estimate.status == QueryStatus::Ready);
    assert(estimate.success_rate.has_value());
    assert(*estimate.success_rate == 1.0);
    // RED (plan_dynamic 未実装呼び出し)
    const auto dynamic_plan = PolicyEngine::plan_dynamic(make_request(100, 200), registry, feedback);
    assert(!dynamic_plan.empty());
    assert(dynamic_plan.selected[0].operator_id == 0);
    assert(dynamic_plan.selected[2].operator_id == 4);
    // DYN-002-A
    JournalFeedbackEngine empty_feedback(guard);
    const auto no_data_estimate = empty_feedback.estimate(4, 91);
    assert(no_data_estimate.status == QueryStatus::NoData);
    const auto no_data_plan = PolicyEngine::plan_dynamic(make_request(100, 200), registry, empty_feedback);
    assert(no_data_plan.selected.size() == 4);
    assert(no_data_plan.selected[0].operator_id == 0);
    assert(no_data_plan.selected[1].operator_id == 3);
    assert(no_data_plan.selected[2].operator_id == 4);
    assert(no_data_plan.selected[3].operator_id == 5);
    // DYN-002-B
    JournalFeedbackEngine insufficient_feedback(guard);
    JournalHash insufficient_hash = genesis;
    inject_fact(insufficient_feedback, keys, 1, insufficient_hash, 4, 91, true, 10, 50);
    const auto insufficient_estimate = insufficient_feedback.estimate(4, 91, 5);
    assert(insufficient_estimate.status == QueryStatus::InsufficientSamples);
    const auto insufficient_plan = PolicyEngine::plan_dynamic(make_request(100, 200), registry, insufficient_feedback);
    assert(insufficient_plan.selected.size() == 4);
    assert(insufficient_plan.selected[0].operator_id == 0);
    assert(insufficient_plan.selected[1].operator_id == 3);
    assert(insufficient_plan.selected[2].operator_id == 4);
    assert(insufficient_plan.selected[3].operator_id == 5);
    // DYN-003-A
    const auto invalid_estimate = feedback.estimate(0, 91);
    assert(invalid_estimate.status == QueryStatus::InvalidQuery);
    // DYN-004
    assert(dynamic_plan.requested_step_budget == 100);
    assert(dynamic_plan.requested_time_budget_us == 200);
    const auto static_plan = PolicyEngine::plan(make_request(100, 200), registry);
    assert(static_plan.selected.size() == 4);
    assert(static_plan.selected[0].operator_id == 0);
    assert(static_plan.selected[1].operator_id == 3);
    assert(static_plan.selected[2].operator_id == 4);
    assert(static_plan.selected[3].operator_id == 5);

    // Ready-only ranking occupies only static Ready slots; OP0 stays fixed.
    {
        ResourceGuard local_guard(make_test_limits());
        JournalFeedbackEngine mixed(local_guard);
        JournalHash hash{}; std::uint64_t lsn = 1;
        add_profile(mixed, keys, hash, lsn, 3, 1, 30, 60);
        add_profile(mixed, keys, hash, lsn, 5, 3, 20, 40);
        const auto plan = PolicyEngine::plan_dynamic(make_request(17, 23), registry, mixed);
        assert((ids(plan) == std::vector<std::uint32_t>{0, 5, 4, 3}));
        std::uint64_t step_sum = 0, time_sum = 0;
        for (const auto& entry : plan.selected) {
            step_sum += entry.step_budget;
            time_sum += entry.time_budget_us;
        }
        assert(step_sum == 17 && time_sum == 23);
        assert(plan.selected.front().step_budget == 5 && plan.selected.front().time_budget_us == 6);
        assert(plan.selected.back().step_budget == 4 && plan.selected.back().time_budget_us == 5);
    }
    // Equal success rate uses successful step average, then mean time.
    {
        ResourceGuard local_guard(make_test_limits());
        JournalFeedbackEngine tied(local_guard);
        JournalHash hash{}; std::uint64_t lsn = 1;
        add_profile(tied, keys, hash, lsn, 3, 3, 30, 20);
        add_profile(tied, keys, hash, lsn, 4, 3, 10, 80);
        add_profile(tied, keys, hash, lsn, 5, 3, 10, 10);
        const auto plan = PolicyEngine::plan_dynamic(make_request(19, 29), registry, tied);
        assert((ids(plan) == std::vector<std::uint32_t>{0, 5, 4, 3}));
    }
    // Fully tied Ready outcomes preserve their static order.
    {
        ResourceGuard local_guard(make_test_limits());
        JournalFeedbackEngine tied(local_guard);
        JournalHash hash{}; std::uint64_t lsn = 1;
        add_profile(tied, keys, hash, lsn, 3, 3, 10, 20);
        add_profile(tied, keys, hash, lsn, 4, 3, 10, 20);
        add_profile(tied, keys, hash, lsn, 5, 3, 10, 20);
        const auto plan = PolicyEngine::plan_dynamic(make_request(7, 9), registry, tied);
        assert((ids(plan) == std::vector<std::uint32_t>{0, 3, 4, 5}));
    }
    // Inconsistent profile data is treated as non-Ready and falls back to static.
    {
        ResourceGuard local_guard(make_test_limits());
        JournalFeedbackEngine inconsistent(local_guard);
        JournalHash hash{}; std::uint64_t lsn = 1;
        add_profile(inconsistent, keys, hash, lsn, 3, 5, 10, 10);
        assert(inconsistent.corrupt_profile_for_test(3, 91));
        assert(inconsistent.estimate(3, 91, 5).status == QueryStatus::InconsistentProfile);
        assert((ids(PolicyEngine::plan_dynamic(make_request(8, 12), registry, inconsistent)) ==
                std::vector<std::uint32_t>{0, 3, 4, 5}));
    }
    return 0;
}
