#pragma once

#include "mother_H/common/numeric.hpp"
#include "mother_H/common/types.hpp"
#include "mother_H/operators/op_interface.hpp"

#include <chrono>
#include <cstdint>
#include <string>

namespace mother_h::op {

// Torus rotation recurrence: start y=5 mod n. Each charged iteration first
// computes g=gcd(y,n). A proper g is returned as a factor; if g != 1 (thus
// g == n), advance y=(y+1) mod n to leave that non-unit point. Otherwise y is
// a unit and the next point is y=inverse(y,n)^2+1 mod n. Every gcd/check and
// recurrence update is one search iteration. Restarts are deterministic and
// consume an iteration; the exact step and time budgets bound all retries.
template <typename Integer>
class Op5Torus final : public Operator<Integer> {
public:
    std::uint32_t id() const noexcept override { return 5; }
    std::string name() const noexcept override { return "OP5_Torus"; }

    OpResult<Integer> execute(const OpContext<Integer>& context) const override {
        using Clock = std::chrono::steady_clock;
        const auto started = Clock::now();
        OpResult<Integer> result;
        result.op_name = name();
        result.status = OpExecStatus::NotFound;
        result.prime_status = PrimeStatus::Unknown;
        const Integer& n = context.target_n;

        if (n <= 1) {
            result.status = OpExecStatus::Error;
            result.prime_status = PrimeStatus::InvalidInput;
            return finish(result, started);
        }
        if (mother_h::numeric::mod(n, Integer(2)) == 0) {
            result.status = OpExecStatus::Success;
            result.prime_status = PrimeStatus::Composite;
            return finish(result, started);
        }
        // Zero in either budget means no search work is permitted.
        if (context.step_budget == 0 || context.time_budget_us == 0) {
            result.status = OpExecStatus::BudgetExhausted;
            return finish(result, started);
        }

        const auto time_exhausted = [&]() {
            const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                Clock::now() - started).count();
            return elapsed >= 0 && static_cast<std::uint64_t>(elapsed) >= context.time_budget_us;
        };

        Integer y = mother_h::numeric::mod(Integer(5), n);
        while (result.steps_used < context.step_budget && !time_exhausted()) {
            ++result.steps_used;
            const Integer g = mother_h::numeric::gcd(y, n);
            if (g > 1 && g < n && valid_pair(n, g, mother_h::numeric::div(n, g))) {
                const Integer q = mother_h::numeric::div(n, g);
                result.factor = FactorPair<Integer>{g, q};
                result.status = OpExecStatus::Success;
                result.prime_status = PrimeStatus::Composite;
                return finish(result, started);
            }
            if (g != 1) {
                // A non-unit yielding only n is not a factor. Move exactly one
                // residue forward; the next attempt still consumes a step.
                y = mother_h::numeric::mod_add(y, Integer(1), n);
                continue;
            }

            Integer inverse{};
            if (!modular_inverse(y, n, inverse)) {
                // Defensive path if an Integer implementation ever disagrees
                // with gcd. The value itself is not evidence of a factor.
                y = mother_h::numeric::mod_add(y, Integer(1), n);
                continue;
            }
            y = mother_h::numeric::mod_add(
                mother_h::numeric::mod_mul(inverse, inverse, n), Integer(1), n);
        }

        if (result.steps_used >= context.step_budget || time_exhausted()) {
            result.status = OpExecStatus::BudgetExhausted;
        }
        return finish(result, started);
    }

    // Extended Euclid, with coefficients reduced modulo modulus each round.
    // This avoids native signed intermediates and therefore supports uint64_t
    // values through UINT64_MAX as well as arbitrary precision cpp_int.
    static bool modular_inverse(Integer value, const Integer& modulus, Integer& inverse) {
        if (modulus <= 1) return false;
        value = mother_h::numeric::mod(value, modulus);
        Integer old_r = modulus;
        Integer r = value;
        Integer old_t = Integer(0);
        Integer t = Integer(1);
        while (r != 0) {
            const Integer quotient = mother_h::numeric::div(old_r, r);
            const Integer next_r = mother_h::numeric::mod(old_r, r);
            const Integer product = mother_h::numeric::mod_mul(
                mother_h::numeric::mod(quotient, modulus), t, modulus);
            const Integer next_t = old_t >= product
                ? mother_h::numeric::sub(old_t, product)
                : mother_h::numeric::sub(modulus, mother_h::numeric::sub(product, old_t));
            old_r = r;
            r = next_r;
            old_t = t;
            t = next_t;
        }
        if (old_r != 1) return false;
        inverse = old_t;
        return true;
    }

private:
    static bool valid_pair(const Integer& n, const Integer& p, const Integer& q) {
        return p > 1 && q > 1 && p < n && q < n &&
               mother_h::numeric::mod(n, p) == 0 &&
               mother_h::numeric::mod(n, q) == 0 &&
               mother_h::numeric::div(n, p) == q &&
               mother_h::numeric::div(n, q) == p;
    }

    static OpResult<Integer> finish(
        OpResult<Integer> result, std::chrono::steady_clock::time_point started) {
        const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - started).count();
        result.time_spent_us = elapsed > 0 ? static_cast<std::uint64_t>(elapsed) : 0;
        return result;
    }
};

}  // namespace mother_h::op
