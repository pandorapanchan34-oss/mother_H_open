#include "mother_H/core/op_executor.hpp"
#include "mother_H/operators/op0_guard.hpp"
#include "mother_H/operators/op3_fermat.hpp"
#include "mother_H/operators/op4_tensor.hpp"
#include "mother_H/operators/op5_torus.hpp"
#include "mother_H/resource/resource_guard.hpp"

#include <cassert>
#include <cstdint>
#include <memory>
#include <limits>
#include <string>
#include <vector>

namespace {
using namespace mother_h::op;
using mother_h::resource::ResourceGuard;
using mother_h::resource::ResourceLimits;
using mother_h::resource::ResourceStatus;
using mother_h::resource::ResourceUsage;
using Integer = std::uint64_t;

class Stub final : public Operator<Integer> {
public:
    Stub(std::uint32_t id, std::string name, OpResult<Integer> result)
        : id_(id), name_(std::move(name)), result_(std::move(result)) {}
    std::uint32_t id() const noexcept override { return id_; }
    std::string name() const noexcept override { return name_; }
    OpResult<Integer> execute(const OpContext<Integer>& context) const override {
        ++calls;
        last_steps = context.step_budget;
        last_time = context.time_budget_us;
        return result_;
    }
    mutable unsigned calls = 0;
    mutable std::uint64_t last_steps = 0;
    mutable std::uint64_t last_time = 0;
private:
    std::uint32_t id_;
    std::string name_;
    OpResult<Integer> result_;
};

OpResult<Integer> outcome(OpExecStatus status, std::uint64_t steps = 0) {
    OpResult<Integer> value;
    value.status = status;
    value.steps_used = steps;
    return value;
}

OpContext<Integer> context(std::uint64_t steps = 10, std::uint64_t time = 100000) {
    OpContext<Integer> value;
    value.target_n = 35;
    value.step_budget = steps;
    value.time_budget_us = time;
    return value;
}

ResourceGuard test_resources(std::uint64_t steps, std::uint64_t time_us) {
    return ResourceGuard(ResourceLimits{
        1, 1, 1, 1, 1, 1, steps, time_us
    });
}
}

int main() {
    assert(factor_verifier::is_valid_factor<Integer>(
        std::numeric_limits<Integer>::max(), Integer(3), Integer(6148914691236517205ULL)));

    OpRegistry<Integer> registry;
    auto first = std::make_shared<Stub>(1, "first", outcome(OpExecStatus::NotFound, 2));
    auto second_result = outcome(OpExecStatus::Success, 1);
    second_result.factor = FactorPair<Integer>{5, 7};
    auto second = std::make_shared<Stub>(2, "second", second_result);
    registry.register_operator(first);
    registry.register_operator(second);
    OpExecutor<Integer> executor(registry);

    PolicyPlan<Integer> plan;
    plan.requested_step_budget = 5;
    plan.requested_time_budget_us = 100000;
    plan.selected = {{1, "first", first, 3, 50000}, {2, "second", second, 2, 50000}};
    auto report_resources = test_resources(5, 100000);
    const auto report = executor.execute(
        context(5), plan, report_resources);
    assert(report.factor_verified);
    assert(report.final_result.factor.has_value());
    assert(report.final_result.factor->factor_p == 5);
    assert(report.history.size() == 2);
    assert(report.history[0].status == OpExecStatus::NotFound);
    assert(report.history[1].factor_candidate_reported && report.history[1].factor_verified);
    assert(first->calls == 1 && second->calls == 1);
    assert(first->last_steps == 3 && second->last_steps <= 2);

    ResourceGuard restrictive_resources(ResourceLimits{
        1, 1, 1, 1, 1, 1, 4, 100000
    });
    const unsigned calls_before_rejection = first->calls;
    const auto resource_rejected =
        executor.execute(context(5), plan, restrictive_resources);
    assert(resource_rejected.resource_guard_applied);
    assert(resource_rejected.resource_status == ResourceStatus::LimitExceeded);
    assert(resource_rejected.final_result.status == OpExecStatus::BudgetExhausted);
    assert(first->calls == calls_before_rejection);
    ResourceUsage rejected_usage;
    assert(restrictive_resources.usage(rejected_usage) == ResourceStatus::Ok);
    assert(rejected_usage.steps == 0 && rejected_usage.elapsed_time_us == 0);

    auto single_run_resources = test_resources(5, 100000);
    const auto guarded_report =
        executor.execute(context(5), plan, single_run_resources);
    assert(guarded_report.resource_guard_applied);
    assert(guarded_report.resource_status == ResourceStatus::Ok);
    const unsigned calls_after_guarded_run = first->calls;
    const auto duplicate_attempt =
        executor.execute(context(5), plan, single_run_resources);
    assert(duplicate_attempt.resource_status == ResourceStatus::LimitExceeded);
    assert(first->calls == calls_after_guarded_run);
    ResourceUsage guarded_usage;
    assert(single_run_resources.usage(guarded_usage) == ResourceStatus::Ok);
    assert(guarded_usage.steps == 5 && guarded_usage.elapsed_time_us == 100000);

    auto invalid_result = outcome(OpExecStatus::Success);
    invalid_result.factor = FactorPair<Integer>{6, 6};
    auto bad = std::make_shared<Stub>(3, "bad", invalid_result);
    registry.register_operator(bad);
    OpExecutor<Integer> with_bad(registry);
    PolicyPlan<Integer> invalid_plan;
    invalid_plan.selected = {{3, "bad", bad, 4, 50000}};
    auto invalid_resources = test_resources(10, 100000);
    const auto invalid = with_bad.execute(
        context(), invalid_plan, invalid_resources);
    assert(!invalid.factor_verified);
    assert(!invalid.final_result.factor.has_value());
    assert(invalid.final_result.status == OpExecStatus::Error);
    assert(invalid.history.size() == 1 && invalid.history[0].factor_candidate_reported);

    // Executor bounds allocations even when a supplied plan overcommits totals.
    auto ordinary = std::make_shared<Stub>(4, "ordinary", outcome(OpExecStatus::NotFound, 1));
    registry.register_operator(ordinary);
    OpExecutor<Integer> bounded_executor(registry);
    PolicyPlan<Integer> overcommitted;
    overcommitted.selected = {{1, "first", first, 100, 100000}, {4, "ordinary", ordinary, 100, 100000}};
    auto bounded_resources = test_resources(2, 100000);
    const auto bounded = bounded_executor.execute(
        context(2, 100000), overcommitted, bounded_resources);
    assert(first->last_steps <= 2);
    assert(ordinary->calls == 0 || ordinary->last_steps <= 1);
    for (const auto& entry : bounded.history)
        assert(entry.steps_used <= entry.step_budget);

    auto overrun = std::make_shared<Stub>(5, "overrun", outcome(OpExecStatus::Success, 2));
    registry.register_operator(overrun);
    OpExecutor<Integer> overrun_executor(registry);
    PolicyPlan<Integer> overrun_plan;
    overrun_plan.selected = {{5, "overrun", overrun, 1, 50000},
                             {4, "ordinary", ordinary, 1, 50000}};
    auto overrun_resources = test_resources(5, 100000);
    const auto stopped = overrun_executor.execute(
        context(5), overrun_plan, overrun_resources);
    assert(stopped.final_result.status == OpExecStatus::BudgetExhausted);
    assert(stopped.history.size() == 1);
    assert(stopped.history.front().steps_used == 2);
    assert(ordinary->calls == 0);

    OpContext<Integer> zero = context(0, 100000);
    auto zero_resources = test_resources(1, 100000);
    const unsigned calls_before_zero = first->calls;
    const unsigned second_calls_before_zero = second->calls;
    const auto zero_report = executor.execute(zero, plan, zero_resources);
    assert(first->calls == calls_before_zero);
    assert(second->calls == second_calls_before_zero);
    assert(zero_report.resource_guard_applied);
    assert(zero_report.resource_status == ResourceStatus::InvalidRequest);
    assert(zero_report.history.empty());
    assert(zero_report.final_result.status == OpExecStatus::BudgetExhausted);

    // A plan cannot substitute an unregistered implementation under a valid ID.
    auto impostor = std::make_shared<Stub>(1, "first", outcome(OpExecStatus::Success));
    PolicyPlan<Integer> forged;
    forged.selected = {{1, "first", impostor, 1, 1000}};
    auto forged_resources = test_resources(10, 100000);
    const unsigned calls_before_forged = first->calls;
    const auto rejected = executor.execute(
        context(), forged, forged_resources);
    assert(first->calls == calls_before_forged);
    assert(!rejected.history.empty());
    assert(rejected.history.front().status == OpExecStatus::Unsupported);

    // End-to-end PolicyEngine -> Executor -> independent factor verification.
    OpRegistry<Integer> pipeline_registry;
    pipeline_registry.register_operator(std::make_shared<Op0Guard<Integer>>());
    pipeline_registry.register_operator(std::make_shared<Op3Fermat<Integer>>());
    pipeline_registry.register_operator(std::make_shared<Op4Tensor<Integer>>());
    pipeline_registry.register_operator(std::make_shared<Op5Torus<Integer>>());
    auto pipeline_context = context(1000, 1000000);
    const auto pipeline_plan = PolicyEngine::plan(pipeline_context, pipeline_registry);
    OpExecutor<Integer> pipeline_executor(pipeline_registry);
    auto pipeline_resources = test_resources(1000, 1000000);
    const auto pipeline = pipeline_executor.execute(
        pipeline_context, pipeline_plan, pipeline_resources);
    assert(pipeline.factor_verified);
    assert(pipeline.final_result.factor.has_value());
    assert(pipeline.final_result.factor->factor_p * pipeline.final_result.factor->factor_q == 35);
    assert(pipeline.history.size() >= 2);
}
