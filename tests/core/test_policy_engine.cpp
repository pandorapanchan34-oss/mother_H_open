#include "mother_H/core/policy_engine.hpp"

#include <cassert>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <vector>

namespace {
using Integer = std::uint64_t;
using namespace mother_h::op;

class Stub final : public Operator<Integer> {
public:
    Stub(std::uint32_t id, std::string name, bool supported = true)
        : id_(id), name_(std::move(name)), supported_(supported) {}
    std::uint32_t id() const noexcept override { return id_; }
    std::string name() const noexcept override { return name_; }
    bool supports(const OpContext<Integer>&) const override { return supported_; }
    OpResult<Integer> execute(const OpContext<Integer>&) const override { return {}; }
    void metadata(std::uint32_t id, std::string name) { id_ = id; name_ = std::move(name); }
private:
    std::uint32_t id_;
    std::string name_;
    bool supported_;
};

OpContext<Integer> request(std::uint64_t steps, std::uint64_t time) {
    OpContext<Integer> value;
    value.target_n = 91;
    value.step_budget = steps;
    value.time_budget_us = time;
    return value;
}
}

int main() {
    OpRegistry<Integer> empty;
    auto plan = PolicyEngine::plan(request(10, 20), empty);
    assert(plan.empty());
    assert(plan.requested_step_budget == 10 && plan.requested_time_budget_us == 20);

    OpRegistry<Integer> registry;
    auto other9 = std::make_shared<Stub>(9, "other9");
    auto op5 = std::make_shared<Stub>(5, "OP5_Torus");
    auto unsupported = std::make_shared<Stub>(2, "unsupported", false);
    auto op3 = std::make_shared<Stub>(3, "OP3_Fermat");
    auto op0 = std::make_shared<Stub>(0, "OP0_Guard");
    auto other1 = std::make_shared<Stub>(1, "other1");
    auto op4 = std::make_shared<Stub>(4, "OP4_Tensor");
    registry.register_operator(other9);
    registry.register_operator(op5);
    registry.register_operator(unsupported);
    registry.register_operator(op3);
    registry.register_operator(op0);
    registry.register_operator(other1);
    registry.register_operator(op4);

    plan = PolicyEngine::plan(request(11, 23), registry);
    const std::vector<std::uint32_t> expected{0, 3, 4, 5, 1, 9};
    assert(plan.selected.size() == expected.size());
    std::uint64_t step_sum = 0, time_sum = 0;
    for (std::size_t i = 0; i < expected.size(); ++i) {
        assert(plan.selected[i].operator_id == expected[i]);
        step_sum += plan.selected[i].step_budget;
        time_sum += plan.selected[i].time_budget_us;
    }
    assert(step_sum == 11 && time_sum == 23);
    assert(plan.selected[0].step_budget == 2 && plan.selected[0].time_budget_us == 4);
    assert(plan.selected[5].step_budget == 1 && plan.selected[5].time_budget_us == 3);
    assert(registry.operators().size() == 7);
    plan.selected.clear();
    assert(registry.operators().size() == 7);

    const auto repeat = PolicyEngine::plan(request(11, 23), registry);
    assert(repeat.selected.size() == expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i)
        assert(repeat.selected[i].operator_id == expected[i]);

    auto zero = PolicyEngine::plan(request(0, 0), registry);
    assert(zero.selected.size() == expected.size());
    for (const auto& entry : zero.selected)
        assert(entry.step_budget == 0 && entry.time_budget_us == 0);

    auto limited = PolicyEngine::plan(request(2, 1), registry);
    step_sum = time_sum = 0;
    for (const auto& entry : limited.selected) {
        step_sum += entry.step_budget;
        time_sum += entry.time_budget_us;
    }
    assert(step_sum == 2 && time_sum == 1);
    assert(limited.selected[0].step_budget == 1 && limited.selected[0].step_budget <= 2);

    auto maximum = PolicyEngine::plan(
        request(std::numeric_limits<std::uint64_t>::max(), std::numeric_limits<std::uint64_t>::max()), registry);
    step_sum = time_sum = 0;
    for (const auto& entry : maximum.selected) {
        assert(step_sum <= std::numeric_limits<std::uint64_t>::max() - entry.step_budget);
        assert(time_sum <= std::numeric_limits<std::uint64_t>::max() - entry.time_budget_us);
        step_sum += entry.step_budget;
        time_sum += entry.time_budget_us;
    }
    assert(step_sum == std::numeric_limits<std::uint64_t>::max());
    assert(time_sum == std::numeric_limits<std::uint64_t>::max());

    // Mutable/broken operator metadata can become inconsistent after register.
    OpRegistry<Integer> inconsistent;
    auto first = std::make_shared<Stub>(30, "first");
    auto second = std::make_shared<Stub>(31, "second");
    inconsistent.register_operator(first);
    inconsistent.register_operator(second);
    second->metadata(30, "first");
    const auto safe = PolicyEngine::plan(request(3, 5), inconsistent);
    assert(safe.selected.size() == 1);
    assert(safe.selected.front().operator_id == 30);
}
