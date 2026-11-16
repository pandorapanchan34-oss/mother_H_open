#pragma once

#include "mother_H/common/numeric.hpp"
#include "mother_H/common/types.hpp"
#include "mother_H/operators/op_interface.hpp"

#include <chrono>
#include <cstdint>
#include <limits>
#include <string>
#include <type_traits>

namespace mother_h::op {

template <typename Integer>
class Op3Fermat final : public Operator<Integer> {
public:
    std::uint32_t id() const noexcept override { return 3; }
    std::string name() const noexcept override { return "OP3_Fermat"; }

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
        if (n % Integer(2) == 0) {
            result.prime_status = PrimeStatus::Composite;
            result.status = OpExecStatus::Success;
            return finish(result, started);
        }

        const Integer root = mother_h::numeric::integer_sqrt(n);
        const Integer root_square = mother_h::numeric::mul(root, root);
        if (root_square == n) {
            result.factor = FactorPair<Integer>{root, root};
            result.status = OpExecStatus::Success;
            result.prime_status = PrimeStatus::Composite;
            return finish(result, started);
        }

        // Invalid/even/square checks are zero-step preprocessing. A zero time
        // budget permits these immediate checks but never permits a search step.
        if (context.time_budget_us == 0 || context.step_budget == 0) {
            result.status = OpExecStatus::BudgetExhausted;
            return finish(result, started);
        }
        const auto time_exhausted = [&]() {
            const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                Clock::now() - started).count();
            return elapsed >= 0 && static_cast<std::uint64_t>(elapsed) >= context.time_budget_us;
        };
        Integer a = mother_h::numeric::add(root, Integer(1));
        while (result.steps_used < context.step_budget && !time_exhausted()) {
            ++result.steps_used;
            Integer a_square{};
            if (!square_fits(a, a_square)) {
                // This value and every subsequent a exceed the native square range.
                break;
            }
            const Integer difference = mother_h::numeric::sub(a_square, n);
            const Integer b = mother_h::numeric::integer_sqrt(difference);
            Integer b_square{};
            if (square_fits(b, b_square) && b_square == difference && a >= b) {
                const Integer p = mother_h::numeric::sub(a, b);
                const Integer q = mother_h::numeric::add(a, b);
                if (valid_pair(n, p, q)) {
                    result.factor = FactorPair<Integer>{p, q};
                    result.status = OpExecStatus::Success;
                    result.prime_status = PrimeStatus::Composite;
                    return finish(result, started);
                }
            }
            a = mother_h::numeric::add(a, Integer(1));
        }

        if (result.steps_used >= context.step_budget || time_exhausted()) {
            result.status = OpExecStatus::BudgetExhausted;
        }
        return finish(result, started);
    }

private:
    static bool square_fits(const Integer& value, Integer& square) {
        if constexpr (std::is_same_v<Integer, std::uint64_t>) {
            if (value != 0 && value > std::numeric_limits<std::uint64_t>::max() / value) return false;
        }
        square = mother_h::numeric::mul(value, value);
        return true;
    }

    static bool valid_pair(const Integer& n, const Integer& p, const Integer& q) {
        return p > 1 && q > 1 && p < n && q < n && n % p == 0 && n % q == 0 &&
               n / p == q && n / q == p;
    }

    static OpResult<Integer> finish(OpResult<Integer> result,
                                    std::chrono::steady_clock::time_point started) {
        const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - started).count();
        result.time_spent_us = elapsed > 0 ? static_cast<std::uint64_t>(elapsed) : 0;
        return result;
    }
};

}  // namespace mother_h::op
