#pragma once
#include <cstdint>
#include <optional>
#include <string>
namespace mother_h::op {
// Mathematical classification state.
enum class PrimeStatus : std::uint8_t {
    Unknown,
    InvalidInput,
    Composite,
    ProbablePrime,
    PrimeCertified
};
// Operator execution state.
enum class OpExecStatus : std::uint8_t {
    Success,
    NotFound,
    Unsupported,
    BudgetExhausted,
    Cancelled,
    Error
};
// Candidate factor pair.
// Final validity must be checked by the Executor.
template <typename Integer>
struct FactorPair {
    Integer factor_p{};
    Integer factor_q{};
};
// Conditions supplied to an operator.
template <typename Integer>
struct OpContext {
    Integer target_n{};
    // Zero means no computation steps are permitted.
    std::uint64_t step_budget = 0;
    // Zero means no execution time is permitted.
    std::uint64_t time_budget_us = 0;
    std::uint32_t flags = 0;
};
// Result returned by an operator.
// Success means a candidate result was produced,
// not that the factorization has been independently verified.
template <typename Integer>
struct OpResult {
    OpExecStatus status = OpExecStatus::NotFound;
    PrimeStatus prime_status = PrimeStatus::Unknown;
    std::optional<FactorPair<Integer>> factor;
    std::uint64_t steps_used = 0;
    std::uint64_t time_spent_us = 0;
    std::string op_name;
};
} // namespace mother_h::op
