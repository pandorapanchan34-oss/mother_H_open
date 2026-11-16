#include "mother_H/operators/op0_guard.hpp"

#include <cassert>
#include <cstdint>
#include <limits>

namespace {
using Op = mother_h::op::Op0Guard<std::uint64_t>;
using Context = mother_h::op::OpContext<std::uint64_t>;
using mother_h::op::OpExecStatus;
using mother_h::op::PrimeStatus;

mother_h::op::OpResult<std::uint64_t> classify(std::uint64_t n) {
    Context context;
    context.target_n = n;
    return Op{}.execute(context);
}

void expect(std::uint64_t n, PrimeStatus expected) {
    const auto result = classify(n);
    assert(result.status == (expected == PrimeStatus::InvalidInput ? OpExecStatus::Error : OpExecStatus::Success));
    assert(result.prime_status == expected);
}
}  // namespace

int main() {
    expect(0, PrimeStatus::InvalidInput);
    expect(1, PrimeStatus::InvalidInput);
    expect(2, PrimeStatus::PrimeCertified);
    expect(3, PrimeStatus::PrimeCertified);
    expect(4, PrimeStatus::Composite);
    expect(5, PrimeStatus::PrimeCertified);
    expect(37, PrimeStatus::PrimeCertified);
    expect(41, PrimeStatus::PrimeCertified);

    expect(341550071728321ULL, PrimeStatus::Composite);
    expect(3825123056546413051ULL, PrimeStatus::Composite);
    expect(3215031751ULL, PrimeStatus::Composite);

    expect(18446744073709551557ULL, PrimeStatus::PrimeCertified);
    expect(std::numeric_limits<std::uint64_t>::max(), PrimeStatus::Composite);
    expect(std::numeric_limits<std::uint64_t>::max() - 2, PrimeStatus::Composite);
}
