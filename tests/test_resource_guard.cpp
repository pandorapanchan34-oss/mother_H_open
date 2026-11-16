#include "mother_H/resource/resource_guard.hpp"

#include <cassert>
#include <cstdint>
#include <limits>

namespace {
using namespace mother_h::resource;

void check(bool condition) {
    assert(condition);
}

ResourceLimits limits() {
    return ResourceLimits{100, 80, 1000, 2, 2, 2, 100, 50};
}

void test_input_limits_and_usage() {
    ResourceGuard guard(limits());
    check(guard.check_input_sizes(100, 80) == ResourceStatus::Ok);
    check(guard.consume_input(40, 30) == ResourceStatus::Ok);
    check(guard.check_input_sizes(101, 10) == ResourceStatus::LimitExceeded);
    check(guard.check_input_sizes(50, 81) == ResourceStatus::LimitExceeded);

    check(guard.consume_record_count(1) == ResourceStatus::Ok);
    check(guard.consume_record_count(1) == ResourceStatus::LimitExceeded);
    ResourceUsage usage;
    check(guard.usage(usage) == ResourceStatus::Ok);
    check(usage.total_input_bytes == 40);
    check(usage.records == 2);

    ResourceLimits cumulative_limits = limits();
    cumulative_limits.max_total_input_bytes = 100;
    ResourceGuard cumulative_guard(cumulative_limits);
    check(cumulative_guard.consume_input(60, 30) == ResourceStatus::Ok);
    check(cumulative_guard.consume_input(50, 20) == ResourceStatus::LimitExceeded);
    check(cumulative_guard.usage(usage) == ResourceStatus::Ok);
    check(usage.total_input_bytes == 60);
    check(usage.records == 1);
}

void test_profiles_and_failure_codes() {
    ResourceGuard guard(limits());
    check(guard.check_profile(1) == ResourceStatus::Ok);
    check(guard.consume_profile(1) == ResourceStatus::Ok);
    check(guard.consume_failure_code(1, 10) == ResourceStatus::Ok);
    check(guard.check_failure_code(1, 10) == ResourceStatus::Ok);
    check(guard.consume_failure_code(1, 11) == ResourceStatus::Ok);
    check(guard.check_failure_code(1, 12) == ResourceStatus::LimitExceeded);
    check(guard.consume_profile(2) == ResourceStatus::Ok);
    check(guard.check_profile(3) == ResourceStatus::LimitExceeded);
    check(guard.consume_profile(3) == ResourceStatus::LimitExceeded);

    ResourceUsage usage;
    check(guard.usage(usage) == ResourceStatus::Ok);
    check(usage.profiles == 2);
    check(usage.failure_code_entries == 2);
}

void test_step_and_time_budgets() {
    ResourceGuard guard(limits());
    check(guard.check_steps(100) == ResourceStatus::Ok);
    check(guard.consume_steps(60) == ResourceStatus::Ok);
    check(guard.consume_steps(41) == ResourceStatus::LimitExceeded);
    check(guard.consume_elapsed_time_us(40) == ResourceStatus::Ok);
    check(guard.consume_elapsed_time_us(11) == ResourceStatus::LimitExceeded);

    std::uint64_t remaining = 0;
    check(guard.remaining_steps(remaining) == ResourceStatus::Ok);
    check(remaining == 40);
    check(guard.remaining_time_us(remaining) == ResourceStatus::Ok);
    check(remaining == 10);
}

void test_atomic_reservations_and_failures() {
    ResourceGuard guard(limits());
    ResourceReservation initial;
    initial.steps = 95;
    check(guard.reserve(initial) == ResourceStatus::Ok);

    ResourceReservation rejected;
    rejected.records = 1;
    rejected.steps = 6;
    rejected.elapsed_time_us = 1;
    check(guard.reserve(rejected) == ResourceStatus::LimitExceeded);
    ResourceUsage usage;
    check(guard.usage(usage) == ResourceStatus::Ok);
    check(usage.records == 0);
    check(usage.steps == 95);
    check(usage.elapsed_time_us == 0);

    ResourceReservation all;
    all.record_bytes = 20;
    all.payload_bytes = 10;
    all.total_input_bytes = 25;
    all.records = 1;
    all.steps = 5;
    all.elapsed_time_us = 5;
    all.has_profile = true;
    all.profile_id = 7;
    all.has_failure_code = true;
    all.failure_code_id = 99;
    check(guard.reserve(all) == ResourceStatus::Ok);
    check(guard.usage(usage) == ResourceStatus::Ok);
    check(usage.total_input_bytes == 25);
    check(usage.records == 1);
    check(usage.steps == 100);
    check(usage.elapsed_time_us == 5);
    check(usage.profiles == 1);
    check(usage.failure_code_entries == 1);
}

void test_overflow_invalid_and_zero_limits() {
    ResourceLimits huge{
        (std::numeric_limits<std::uint64_t>::max)(),
        (std::numeric_limits<std::uint64_t>::max)(),
        (std::numeric_limits<std::uint64_t>::max)(),
        (std::numeric_limits<std::uint64_t>::max)(),
        1, 1,
        (std::numeric_limits<std::uint64_t>::max)(),
        (std::numeric_limits<std::uint64_t>::max)()};
    ResourceGuard guard(huge);
    check(guard.consume_steps(
              (std::numeric_limits<std::uint64_t>::max)() - 1U) ==
          ResourceStatus::Ok);
    check(guard.consume_steps(2) == ResourceStatus::IntegerOverflow);

    ResourceReservation empty;
    check(guard.reserve(empty) == ResourceStatus::InvalidRequest);
    check(guard.consume_steps(0) == ResourceStatus::InvalidRequest);

    ResourceLimits invalid = limits();
    invalid.max_profiles = 0;
    ResourceGuard invalid_guard(invalid);
    check(invalid_guard.status() == ResourceStatus::InvalidLimits);
    check(invalid_guard.consume_steps(1) == ResourceStatus::InvalidLimits);
    check(invalid_guard.reset_usage() == ResourceStatus::InvalidLimits);
}

void test_explicit_reset() {
    ResourceGuard guard(limits());
    check(guard.consume_input(10, 5) == ResourceStatus::Ok);
    check(guard.consume_profile(1) == ResourceStatus::Ok);
    check(guard.consume_failure_code(1, 2) == ResourceStatus::Ok);
    check(guard.consume_steps(10) == ResourceStatus::Ok);
    check(guard.consume_elapsed_time_us(4) == ResourceStatus::Ok);
    check(guard.reset_usage() == ResourceStatus::Ok);

    ResourceUsage usage;
    check(guard.usage(usage) == ResourceStatus::Ok);
    check(usage.total_input_bytes == 0);
    check(usage.records == 0);
    check(usage.profiles == 0);
    check(usage.failure_code_entries == 0);
    check(usage.steps == 0);
    check(usage.elapsed_time_us == 0);
}
}  // namespace

int main() {
    test_input_limits_and_usage();
    test_profiles_and_failure_codes();
    test_step_and_time_budgets();
    test_atomic_reservations_and_failures();
    test_overflow_invalid_and_zero_limits();
    test_explicit_reset();
    return 0;
}
