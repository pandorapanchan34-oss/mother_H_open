#pragma once

#include "mother_H/common/numeric.hpp"
#include "mother_H/common/types.hpp"
#include "mother_H/operators/op_interface.hpp"

#include <array>
#include <cstdint>
#include <limits>
#include <type_traits>

namespace mother_h::op {

template <typename Integer>
class Op0Guard final : public Operator<Integer> {
public:
    std::uint32_t id() const noexcept override { return 0; }
    std::string name() const noexcept override { return "OP0_Guard"; }

    OpResult<Integer> execute(const OpContext<Integer>& context) const override {
        OpResult<Integer> result;
        result.op_name = name();
        result.status = OpExecStatus::NotFound;
        result.prime_status = PrimeStatus::Unknown;

        if (context.target_n <= 1) {
            result.prime_status = PrimeStatus::InvalidInput;
            result.status = OpExecStatus::Error;
            return result;
        }

        const Integer n = context.target_n;
        if (n == 2 || n == 3) {
            result.prime_status = PrimeStatus::PrimeCertified;
            result.status = OpExecStatus::Success;
            return result;
        }

        if (n % Integer(2) == 0) {
            result.prime_status = PrimeStatus::Composite;
            result.status = OpExecStatus::Success;
            return result;
        }

        constexpr std::uint64_t small_primes[] = {3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37};
        for (const auto prime : small_primes) {
            const Integer p = static_cast<Integer>(prime);
            if (n == p) {
                result.prime_status = PrimeStatus::PrimeCertified;
                result.status = OpExecStatus::Success;
                return result;
            }
            if (n % p == 0) {
                result.prime_status = PrimeStatus::Composite;
                result.status = OpExecStatus::Success;
                return result;
            }
        }

        if constexpr (std::is_same_v<Integer, std::uint64_t>) {
            const std::uint64_t value = n;
            std::uint64_t d = value - 1;
            std::uint32_t s = 0;
            while ((d & 1U) == 0U) {
                d >>= 1U;
                ++s;
            }

            // This seven-base set is deterministic for every 64-bit unsigned integer.
            constexpr std::array<std::uint64_t, 7> bases = {
                2ULL, 325ULL, 9375ULL, 28178ULL, 450775ULL, 9780504ULL, 179526140ULL};
            for (const std::uint64_t base : bases) {
                const std::uint64_t a = base % value;
                if (a == 0) {
                    continue;
                }

                std::uint64_t x = 1;
                std::uint64_t power = d;
                std::uint64_t factor = a;
                while (power != 0) {
                    if ((power & 1U) != 0U) {
                        x = numeric::mod_mul<std::uint64_t>(x, factor, value);
                    }
                    power >>= 1U;
                    if (power != 0) {
                        factor = numeric::mod_mul<std::uint64_t>(factor, factor, value);
                    }
                }
                if (x == 1 || x == value - 1) {
                    continue;
                }

                bool witness_passed = false;
                for (std::uint32_t r = 1; r < s; ++r) {
                    x = numeric::mod_mul<std::uint64_t>(x, x, value);
                    if (x == value - 1) {
                        witness_passed = true;
                        break;
                    }
                }
                if (!witness_passed) {
                    result.prime_status = PrimeStatus::Composite;
                    result.status = OpExecStatus::Success;
                    return result;
                }
            }
            result.prime_status = PrimeStatus::PrimeCertified;
            result.status = OpExecStatus::Success;
            return result;
        }

        result.prime_status = PrimeStatus::ProbablePrime;
        result.status = OpExecStatus::Success;
        return result;
    }
};

}  // namespace mother_h::op
