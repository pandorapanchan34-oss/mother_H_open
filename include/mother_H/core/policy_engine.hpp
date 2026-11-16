#pragma once
#include "mother_H/common/types.hpp"
#include "mother_H/core/op_registry.hpp"
#include "mother_H/policy/journal_feedback_engine.hpp"
#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>
namespace mother_h::op {
template <typename Integer>
struct PolicyPlanEntry {
    std::uint32_t operator_id = 0;
    std::string operator_name;
    std::shared_ptr<Operator<Integer>> operation;
    std::uint64_t step_budget = 0;
    std::uint64_t time_budget_us = 0;
};
template <typename Integer>
struct PolicyPlan {
    std::vector<PolicyPlanEntry<Integer>> selected;
    std::uint64_t requested_step_budget = 0;
    std::uint64_t requested_time_budget_us = 0;
    bool empty() const noexcept { return selected.empty(); }
};
class PolicyEngine {
public:
    template <typename Integer>
    static PolicyPlan<Integer> plan(
        const OpContext<Integer>& request, const OpRegistry<Integer>& registry) {
        return plan_internal<Integer>(request, registry, nullptr);
    }
    template <typename Integer>
    static PolicyPlan<Integer> plan_dynamic(
        const OpContext<Integer>& request, const OpRegistry<Integer>& registry,
        const mother_h::policy::JournalFeedbackEngine& feedback) {
        return plan_internal<Integer>(request, registry, &feedback);
    }
private:
    template <typename Integer>
    static PolicyPlan<Integer> plan_internal(
        const OpContext<Integer>& request, const OpRegistry<Integer>& registry,
        const mother_h::policy::JournalFeedbackEngine* feedback) {
        struct Candidate {
            std::shared_ptr<Operator<Integer>> operation;
            std::uint32_t id;
            std::string name;
            std::size_t registration_order;
            bool is_ready = false;
            double success_rate = 0.0;
            std::uint64_t avg_successful_steps = 0;
            std::uint64_t avg_time_us = 0;
        };
        PolicyPlan<Integer> result;
        result.requested_step_budget = request.step_budget;
        result.requested_time_budget_us = request.time_budget_us;
        const auto snapshot = registry.operators();
        std::vector<Candidate> candidates;
        std::unordered_set<std::uint32_t> seen_ids;
        std::unordered_set<std::string> seen_names;
        candidates.reserve(snapshot.size());
        for (std::size_t i = 0; i < snapshot.size(); ++i) {
            const auto& operation = snapshot[i];
            if (!operation) continue;
            const auto id = operation->id();
            const auto name = operation->name();
            if (seen_ids.count(id) != 0 || seen_names.count(name) != 0) continue;
            seen_ids.insert(id);
            seen_names.insert(name);
            bool supported = false;
            try {
                supported = operation->supports(request);
            } catch (...) {
                continue;
            }
            if (supported) {
                Candidate cand{operation, id, name, i, false, 0.0, 0, 0};
                if (feedback != nullptr) {
                    const auto est = feedback->estimate(id, request.target_n, 5);
                    if (est.status == mother_h::policy::QueryStatus::Ready && est.success_rate.has_value()) {
                        cand.is_ready = true;
                        cand.success_rate = *est.success_rate;
                        cand.avg_successful_steps = est.avg_successful_steps.value_or(0);
                        cand.avg_time_us = est.avg_time_us.value_or(0);
                    }
                }
                candidates.push_back(cand);
            }
        }
        const auto priority = [](std::uint32_t id) {
            switch (id) {
                case 0: return 0U;
                case 3: return 1U;
                case 4: return 2U;
                case 5: return 3U;
                default: return 4U;
            }
        };
        const auto static_order = [&](const Candidate& a, const Candidate& b) {
            if (priority(a.id) != priority(b.id)) return priority(a.id) < priority(b.id);
            if (a.id != b.id) return a.id < b.id;
            if (a.name != b.name) return a.name < b.name;
            return a.registration_order < b.registration_order;
        };
        std::stable_sort(candidates.begin(), candidates.end(), static_order);
        // Keep OP0 fixed, and let only Ready candidates trade places with one
        // another. Non-Ready candidates remain in their static slots.
        auto first_dynamic = candidates.begin();
        if (first_dynamic != candidates.end() && first_dynamic->id == 0) ++first_dynamic;
        // Gather Ready candidates across intervening non-Ready slots, sort
        // them by measured outcomes, then write them back to those same slots.
        std::vector<Candidate*> ready_slots;
        std::vector<Candidate> ready_candidates;
        for (auto it = first_dynamic; it != candidates.end(); ++it) {
            if (it->is_ready) {
                ready_slots.push_back(&*it);
                ready_candidates.push_back(*it);
            }
        }
        std::stable_sort(ready_candidates.begin(), ready_candidates.end(),
            [](const Candidate& a, const Candidate& b) {
                if (a.success_rate != b.success_rate) return a.success_rate > b.success_rate;
                if (a.avg_successful_steps != b.avg_successful_steps)
                    return a.avg_successful_steps < b.avg_successful_steps;
                if (a.avg_time_us != b.avg_time_us) return a.avg_time_us < b.avg_time_us;
                return false;
            });
        for (std::size_t i = 0; i < ready_slots.size(); ++i)
            *ready_slots[i] = std::move(ready_candidates[i]);
        if (candidates.empty()) return result;
        const auto count = static_cast<std::uint64_t>(candidates.size());
        const auto step_base = request.step_budget / count;
        const auto step_remainder = request.step_budget % count;
        const auto time_base = request.time_budget_us / count;
        const auto time_remainder = request.time_budget_us % count;
        result.selected.reserve(candidates.size());
        for (std::size_t i = 0; i < candidates.size(); ++i) {
            const auto index = static_cast<std::uint64_t>(i);
            result.selected.push_back(PolicyPlanEntry<Integer>{
                candidates[i].id, candidates[i].name, candidates[i].operation,
                step_base + (index < step_remainder ? 1U : 0U),
                time_base + (index < time_remainder ? 1U : 0U)});
        }
        return result;
    }
};
} // namespace mother_h::op
