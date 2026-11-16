#pragma once

#include "mother_H/common/numeric.hpp"
#include "mother_H/common/types.hpp"
#include "mother_H/operators/op_interface.hpp"

#include <chrono>
#include <cstdint>
#include <string>

namespace mother_h::op {

// Pollard rho with Floyd's cycle finder and f(z) = z^2 + 1 (mod n).
// Each search iteration advances x once and y twice, then tests gcd(|x-y|, n).
template <typename Integer>
class Op4Tensor final : public Operator<Integer> {
public:
    std::uint32_t id() const noexcept override { return 4; }
    std::string name() const noexcept override { return "OP4_Tensor"; }

    OpResult<Integer> execute(const OpContext<Integer>& context) const override {
        using Clock = std::chrono::steady_clock;
        const auto started = Clock::now();
        OpResult<Integer> result;
        result.op_name = name();
        result.status = OpExecStatus::NotFound;
        result.prime_status = PrimeStatus::Unknown;
        const Integer& n = context.target_n;

        if (n <= 1) {
            result.prime_status = PrimeStatus::InvalidInput;
            result.status = OpExecStatus::Error;
            return finish(result, started);
        }
        if (mother_h::numeric::mod(n, Integer(2)) == 0) {
            result.prime_status = PrimeStatus::Composite;
            result.status = OpExecStatus::Success;
            return finish(result, started);
        }
        // Modulo is only reached after n > 1; a zero modulus is rejected above.
        if (context.step_budget == 0 || context.time_budget_us == 0) {
            result.status = OpExecStatus::BudgetExhausted;
            return finish(result, started);
        }

        const auto time_exhausted = [&]() {
            const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                Clock::now() - started).count();
            return elapsed >= 0 && static_cast<std::uint64_t>(elapsed) >= context.time_budget_us;
        };

        Integer x = Integer(2);
        Integer y = Integer(2);
        while (result.steps_used < context.step_budget && !time_exhausted()) {
            x = advance(x, n);
            y = advance(advance(y, n), n);
            ++result.steps_used;

            const Integer difference = x >= y
                ? mother_h::numeric::sub(x, y)
                : mother_h::numeric::sub(y, x);
            const Integer d = mother_h::numeric::gcd(difference, n);
            if (d > 1 && d < n) {
                const Integer q = mother_h::numeric::div(n, d);
                if (mother_h::numeric::mod(n, d) == 0 &&
                    mother_h::numeric::mod(n, q) == 0 &&
                    mother_h::numeric::div(n, q) == d) {
                    result.factor = FactorPair<Integer>{d, q};
                    result.status = OpExecStatus::Success;
                    result.prime_status = PrimeStatus::Composite;
                    return finish(result, started);
                }
            } else if (d == n) {
                // Keep f(z)=z^2+1, but restart from a fresh point. Every restart
                // consumes an iteration, so a degenerate cycle cannot spin free.
                const Integer seed = mother_h::numeric::add(Integer(2),
                    mother_h::numeric::mod(mother_h::numeric::from_u64<Integer>(result.steps_used),
                                           mother_h::numeric::sub(n, Integer(2))));
                x = seed;
                y = seed;
            }
        }

        if (result.steps_used >= context.step_budget || time_exhausted()) {
            result.status = OpExecStatus::BudgetExhausted;
        }
        return finish(result, started);
    }

private:
    static Integer advance(const Integer& value, const Integer& modulus) {
        const Integer square = mother_h::numeric::mod_mul(value, value, modulus);
        return mother_h::numeric::mod_add(square, Integer(1), modulus);
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
