#include "mother_H/operators/op5_torus.hpp"

#include <cassert>
#include <cstdint>
#include <limits>

namespace {
using U = std::uint64_t;
using Big = mother_h::numeric::cpp_int;
using Op = mother_h::op::Op5Torus<U>;
using Context = mother_h::op::OpContext<U>;
using mother_h::op::OpExecStatus;
using mother_h::op::PrimeStatus;

auto run(U n, U steps = 1000, U micros = 1'000'000) {
    Context c;
    c.target_n = n;
    c.step_budget = steps;
    c.time_budget_us = micros;
    return Op{}.execute(c);
}

void check_pair(U n, const mother_h::op::FactorPair<U>& f) {
    assert(f.factor_p > 1 && f.factor_q > 1);
    assert(n % f.factor_p == 0 && n % f.factor_q == 0);
    assert(n / f.factor_p == f.factor_q && n / f.factor_q == f.factor_p);
}
}  // namespace

int main() {
    assert(run(0).prime_status == PrimeStatus::InvalidInput);
    assert(run(1).prime_status == PrimeStatus::InvalidInput);
    assert(run(2).prime_status == PrimeStatus::Composite);
    assert(run(100).prime_status == PrimeStatus::Composite);
    assert(run(3, 0).steps_used == 0);

    auto composite = run(15);
    assert(composite.status == OpExecStatus::Success && composite.factor);
    check_pair(15, *composite.factor);
    auto seeded_factor = run(15, 1); // gcd(5,15)=5
    assert(seeded_factor.factor && seeded_factor.steps_used == 1);
    check_pair(15, *seeded_factor.factor);

    U inverse = 0;
    assert(Op::modular_inverse(5, 12, inverse) && inverse == 5);
    assert(!Op::modular_inverse(6, 12, inverse));
    assert(!Op::modular_inverse(0, 12, inverse));
    const U near_max = std::numeric_limits<U>::max();
    assert(Op::modular_inverse(near_max - 1, near_max, inverse));
    assert(mother_h::numeric::mod_mul(near_max - 1, inverse, near_max) == 1);

    auto zero = run(8051, 0);
    assert(zero.status == OpExecStatus::BudgetExhausted && zero.steps_used == 0);
    assert(zero.prime_status != PrimeStatus::PrimeCertified);
    auto no_time = run(8051, 10, 0);
    assert(no_time.status == OpExecStatus::BudgetExhausted && no_time.steps_used == 0);
    auto one = run(1009, 1);
    assert(one.steps_used == 1 && !one.factor && one.prime_status != PrimeStatus::PrimeCertified);
    auto limited = run(1009, 4);
    assert(limited.steps_used == 4 && limited.status == OpExecStatus::BudgetExhausted);
    assert(limited.prime_status != PrimeStatus::PrimeCertified);

    auto cycle = run(5, 100);
    assert(cycle.steps_used <= 100 && cycle.prime_status != PrimeStatus::PrimeCertified);
    if (cycle.factor) check_pair(25, *cycle.factor);
    auto boundary = run(near_max, 32);
    assert(boundary.steps_used <= 32 && boundary.prime_status != PrimeStatus::PrimeCertified);
    if (boundary.factor) check_pair(near_max, *boundary.factor);

    Big big_inverse = 0;
    const Big big_modulus = (Big(1) << 220) + 1;
    assert(mother_h::op::Op5Torus<Big>::modular_inverse(Big(5), big_modulus, big_inverse));
    assert(mother_h::numeric::mod_mul(Big(5), big_inverse, big_modulus) == 1);
    assert(!mother_h::op::Op5Torus<Big>::modular_inverse(Big(5), Big(25), big_inverse));

    mother_h::op::OpContext<Big> big_context;
    const Big p = 5;
    const Big q = (Big(1) << 199) + 1;
    big_context.target_n = p * q;
    big_context.step_budget = 1;
    big_context.time_budget_us = 1'000'000;
    const auto big = mother_h::op::Op5Torus<Big>{}.execute(big_context);
    assert(big.status == OpExecStatus::Success && big.factor && big.steps_used == 1);
    assert(big.factor->factor_p > 1 && big.factor->factor_q > 1);
    assert(big_context.target_n % big.factor->factor_p == 0);
    assert(big_context.target_n / big.factor->factor_p == big.factor->factor_q);
}
