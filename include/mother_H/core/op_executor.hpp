#pragma once

#include "mother_H/common/types.hpp"
#include "mother_H/core/op_registry.hpp"
#include "mother_H/core/policy_engine.hpp"
#include "mother_H/resource/resource_guard.hpp"
#include "mother_H/verification/factor_verifier.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace mother_h::op {

template <typename Integer>
struct OpExecutionRecord {
    std::uint32_t operator_id = 0;
    std::string operator_name;
    OpExecStatus status = OpExecStatus::NotFound;
    std::uint64_t step_budget = 0;
    std::uint64_t time_budget_us = 0;
    std::uint64_t steps_used = 0;
    std::uint64_t time_spent_us = 0;
    bool factor_candidate_reported = false;
    bool factor_verified = false;
};

template <typename Integer>
struct OpExecutionReport {
    OpResult<Integer> final_result;
    std::vector<OpExecutionRecord<Integer>> history;
    bool factor_verified = false;
    bool resource_guard_applied = false;
    resource::ResourceStatus resource_status = resource::ResourceStatus::Ok;
};

// Executes a PolicyPlan in its given order. Operators are cooperative: each is
// passed a bounded context and checked on return; synchronous code cannot be
// preempted mid-call. A reported factor is independently checked before it is
// exposed as the final factor.
template <typename Integer>
class OpExecutor {
public:
    explicit OpExecutor(OpRegistry<Integer> registry) : registry_(std::move(registry)) {}

    OpExecutionReport<Integer> execute(
        const OpContext<Integer>& request,
        const PolicyPlan<Integer>& plan,
        resource::ResourceGuard& resources
    ) const {
        if (request.step_budget == 0 || request.time_budget_us == 0) {
            auto report = rejected_report(OpExecStatus::BudgetExhausted);
            report.resource_guard_applied = true;
            report.resource_status = resource::ResourceStatus::InvalidRequest;
            return report;
        }

        resource::ResourceReservation reservation;
        reservation.steps = request.step_budget;
        reservation.elapsed_time_us = request.time_budget_us;
        const resource::ResourceStatus resource_status = resources.reserve(reservation);
        if (resource_status != resource::ResourceStatus::Ok) {
            auto report = rejected_report(
                resource_status == resource::ResourceStatus::LimitExceeded
                    ? OpExecStatus::BudgetExhausted
                    : OpExecStatus::Error);
            report.resource_guard_applied = true;
            report.resource_status = resource_status;
            return report;
        }
        auto report = execute_reserved(request, plan);
        report.resource_guard_applied = true;
        return report;
    }

    // Guarded compatibility entry point for the earlier one-operator API.
    OpResult<Integer> execute(
        const OpContext<Integer>& context,
        std::uint32_t op_id,
        resource::ResourceGuard& resources
    ) const {
        auto operation = registry_.find_by_id(op_id);
        if (!operation) {
            OpResult<Integer> missing;
            missing.status = OpExecStatus::Unsupported;
            missing.prime_status = PrimeStatus::Unknown;
            missing.op_name = "missing-operator";
            return missing;
        }
        PolicyPlan<Integer> plan;
        plan.requested_step_budget = context.step_budget;
        plan.requested_time_budget_us = context.time_budget_us;
        plan.selected.push_back(PolicyPlanEntry<Integer>{op_id, operation->name(), operation,
            context.step_budget, context.time_budget_us});
        auto report = execute(context, plan, resources);
        return report.final_result;
    }

private:
    OpExecutionReport<Integer> execute_reserved(
        const OpContext<Integer>& request,
        const PolicyPlan<Integer>& plan
    ) const {
        using Clock = std::chrono::steady_clock;
        OpExecutionReport<Integer> report;
        report.final_result.status = OpExecStatus::NotFound;
        report.final_result.prime_status = PrimeStatus::Unknown;

        const auto started = Clock::now();
        std::uint64_t steps_used_total = 0;
        for (const auto& entry : plan.selected) {
            OpExecutionRecord<Integer> record;
            record.operator_id = entry.operator_id;
            record.operator_name = entry.operator_name;
            record.factor_candidate_reported = false;

            auto registered = registry_.find_by_id(entry.operator_id);
            if (!registered || !entry.operation || registered != entry.operation ||
                registered->name() != entry.operator_name) {
                record.status = OpExecStatus::Unsupported;
                report.history.push_back(record);
                report.final_result.status = OpExecStatus::Unsupported;
                report.final_result.op_name = entry.operator_name;
                continue;
            }

            const auto elapsed_us = [&]() -> std::uint64_t {
                const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - started).count();
                return elapsed > 0 ? static_cast<std::uint64_t>(elapsed) : 0;
            };
            const auto elapsed = elapsed_us();
            const auto remaining_time = elapsed >= request.time_budget_us
                ? 0 : request.time_budget_us - elapsed;
            const auto remaining_steps = steps_used_total >= request.step_budget
                ? 0 : request.step_budget - steps_used_total;
            record.step_budget = std::min(entry.step_budget, remaining_steps);
            record.time_budget_us = std::min(entry.time_budget_us, remaining_time);
            if (record.step_budget == 0 || record.time_budget_us == 0) {
                record.status = OpExecStatus::BudgetExhausted;
                report.history.push_back(record);
                report.final_result.status = OpExecStatus::BudgetExhausted;
                report.final_result.op_name = entry.operator_name;
                continue;
            }

            OpContext<Integer> bounded = request;
            bounded.step_budget = record.step_budget;
            bounded.time_budget_us = record.time_budget_us;
            OpResult<Integer> result;
            const auto call_started = Clock::now();
            try {
                result = registered->execute(bounded);
            } catch (...) {
                result.status = OpExecStatus::Error;
                result.prime_status = PrimeStatus::Unknown;
                result.op_name = entry.operator_name;
            }
            const auto call_elapsed = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - call_started).count();
            const auto measured_us = call_elapsed > 0 ? static_cast<std::uint64_t>(call_elapsed) : 0;
            record.time_spent_us = std::max(result.time_spent_us, measured_us);
            record.steps_used = result.steps_used;
            record.factor_candidate_reported = result.factor.has_value();
            const bool exceeded_budget = result.steps_used > record.step_budget ||
                                         measured_us > record.time_budget_us;
            if (exceeded_budget) {
                result.status = OpExecStatus::BudgetExhausted;
                result.factor.reset();
                result.prime_status = PrimeStatus::Unknown;
                record.status = result.status;
                report.final_result = result;
                report.history.push_back(record);
                return report;
            }
            steps_used_total += record.steps_used; // bounded by request's remaining budget
            if (result.factor) {
                if (factor_verifier::is_valid_factor(request.target_n,
                        result.factor->factor_p, result.factor->factor_q)) {
                    record.factor_verified = true;
                    report.factor_verified = true;
                } else {
                    result.factor.reset();
                    result.status = OpExecStatus::Error;
                    result.prime_status = PrimeStatus::Unknown;
                }
            }
            record.status = result.status;
            report.final_result = result;
            report.history.push_back(record);
            if (record.factor_verified) return report;
        }
        return report;
    }

    static OpExecutionReport<Integer> rejected_report(OpExecStatus status) {
        OpExecutionReport<Integer> report;
        report.final_result.status = status;
        report.final_result.prime_status = PrimeStatus::Unknown;
        return report;
    }

    OpRegistry<Integer> registry_;
};

}  // namespace mother_h::op
