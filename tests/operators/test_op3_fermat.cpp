#include "mother_H/operators/op3_fermat.hpp"

#include <cassert>
#include <cstdint>
#include <limits>

namespace {
using UOp = mother_h::op::Op3Fermat<std::uint64_t>;
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
}

int main() {
    assert(run(0).prime_status == PrimeStatus::InvalidInput);
    assert(run(1).prime_status == PrimeStatus::InvalidInput);
    assert(run(2).prime_status == PrimeStatus::Composite);
    assert(run(100).prime_status == PrimeStatus::Composite);

    auto square = run(49, 0);
    assert(square.factor && square.factor->factor_p == 7 && square.steps_used == 0);
    auto close = run(101 * 103);
    assert(close.status == OpExecStatus::Success && close.factor);
    assert(close.factor->factor_p * close.factor->factor_q == 101 * 103);
    assert(close.steps_used == 1);

    auto zero = run(101 * 103, 0);
    assert(zero.status == OpExecStatus::BudgetExhausted && !zero.factor);
    assert(zero.steps_used == 0 && zero.prime_status == PrimeStatus::Unknown);
    auto one = run(101 * 103, 1);
    assert(one.status == OpExecStatus::Success && one.steps_used == 1);
    auto exhausted = run(101 * 151, 1);
    assert(exhausted.status == OpExecStatus::BudgetExhausted);
    assert(exhausted.steps_used == 1 && exhausted.prime_status != PrimeStatus::PrimeCertified);
    auto no_time = run(101 * 103, 10, 0);
    assert(no_time.status == OpExecStatus::BudgetExhausted && no_time.steps_used == 0);

    auto boundary_square = run(4'294'967'291ULL * 4'294'967'291ULL, 0);
    assert(boundary_square.factor && boundary_square.factor->factor_p == 4'294'967'291ULL);
    auto max_case = run(std::numeric_limits<std::uint64_t>::max(), 3);
    assert(max_case.status == OpExecStatus::NotFound && max_case.steps_used == 1);
    assert(max_case.prime_status != PrimeStatus::PrimeCertified);

    using Big = mother_h::numeric::cpp_int;
    mother_h::op::OpContext<Big> big_context;
    const Big p = (Big(1) << 100) + 267;
    const Big q = (Big(1) << 100) + 269;
    big_context.target_n = p * q;
    big_context.step_budget = 2;
    big_context.time_budget_us = 1'000'000;
    const auto big_result = mother_h::op::Op3Fermat<Big>{}.execute(big_context);
    assert(big_result.status == OpExecStatus::Success && big_result.factor);
    assert(big_result.factor->factor_p * big_result.factor->factor_q == big_context.target_n);
}
