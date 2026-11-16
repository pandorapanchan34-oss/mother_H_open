#include "mother_H/operators/op4_tensor.hpp"

#include <cassert>
#include <cstdint>
#include <limits>

namespace {
using UOp = mother_h::op::Op4Tensor<std::uint64_t>;
using UContext = mother_h::op::OpContext<std::uint64_t>;
using mother_h::op::OpExecStatus;
using mother_h::op::PrimeStatus;

auto run(std::uint64_t n, std::uint64_t steps = 100,
         std::uint64_t time_us = 1'000'000) {
    UContext context;
    context.target_n = n;
    context.step_budget = steps;
    context.time_budget_us = time_us;
    return UOp{}.execute(context);
}

void check_pair(std::uint64_t n, const mother_h::op::FactorPair<std::uint64_t>& pair) {
    assert(pair.factor_p > 1 && pair.factor_q > 1);
    assert(n % pair.factor_p == 0 && n % pair.factor_q == 0);
    assert(n / pair.factor_p == pair.factor_q);
    assert(n / pair.factor_q == pair.factor_p);
}
}  // namespace

int main() {
    assert(run(0).prime_status == PrimeStatus::InvalidInput);
    assert(run(1).prime_status == PrimeStatus::InvalidInput);
    assert(run(2).prime_status == PrimeStatus::Composite);
    assert(run(100).prime_status == PrimeStatus::Composite);

    const auto small = run(9);
    assert(small.status == OpExecStatus::Success && small.factor);
    check_pair(9, *small.factor);

    const auto composite = run(8051);  // 83 * 97
    assert(composite.status == OpExecStatus::Success && composite.factor);
    check_pair(8051, *composite.factor);

    const auto d_one = run(25, 1);
    assert(d_one.steps_used == 1 && d_one.status == OpExecStatus::BudgetExhausted);
    assert(!d_one.factor && d_one.prime_status == PrimeStatus::Unknown);
    const auto d_n = run(25, 2);
    assert(d_n.steps_used == 2 && d_n.status == OpExecStatus::BudgetExhausted);
    assert(!d_n.factor && d_n.prime_status == PrimeStatus::Unknown);
    const auto restart = run(25, 40);
    assert(restart.steps_used > 2);
    if (restart.factor) check_pair(25, *restart.factor);
    assert(restart.prime_status != PrimeStatus::PrimeCertified);

    const auto zero = run(8051, 0);
    assert(zero.status == OpExecStatus::BudgetExhausted && zero.steps_used == 0);
    const auto one_step = run(8051, 1);
    assert(one_step.steps_used == 1 && one_step.prime_status != PrimeStatus::PrimeCertified);
    const auto exact = run(8051, 3);
    assert(exact.steps_used <= 3);
    assert(run(8051, 10, 0).steps_used == 0);

    const auto boundary = run(std::numeric_limits<std::uint64_t>::max(), 20);
    assert(boundary.steps_used <= 20);
    assert(boundary.prime_status != PrimeStatus::PrimeCertified);
    if (boundary.factor) check_pair(std::numeric_limits<std::uint64_t>::max(), *boundary.factor);

    using Big = mother_h::numeric::cpp_int;
    mother_h::op::OpContext<Big> big_context;
    const Big p = Big(101);
    const Big q = (Big(1) << 199) + 1;
    big_context.target_n = p * q;
    big_context.step_budget = 1'000;
    big_context.time_budget_us = 1'000'000;
    const auto big = mother_h::op::Op4Tensor<Big>{}.execute(big_context);
    assert(big.steps_used <= big_context.step_budget);
    assert(big.prime_status == PrimeStatus::Composite && big.factor);
    assert(big.factor->factor_p > 1 && big.factor->factor_q > 1);
    assert(big_context.target_n % big.factor->factor_p == 0);
    assert(big_context.target_n / big.factor->factor_p == big.factor->factor_q);
}
