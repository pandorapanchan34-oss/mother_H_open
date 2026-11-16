#include "mother_H/common/numeric.hpp"

#include <cassert>
#include <cstdint>
#include <limits>
#include <stdexcept>

using mother_h::numeric::cpp_int;

int main() {
    using namespace mother_h::numeric;
    constexpr auto max = std::numeric_limits<std::uint64_t>::max();
    assert(add<std::uint64_t>(max - 1, 1) == max);
    assert(sub<std::uint64_t>(max, max - 1) == 1);
    assert(mul<std::uint64_t>(max, 1) == max);
    assert(gcd<std::uint64_t>(max, 3) == 3);
    assert(integer_sqrt<std::uint64_t>(max) == 4294967295ULL);
    assert(mod_add<std::uint64_t>(max - 1, max - 1, max) == max - 2);
    assert(mod_mul<std::uint64_t>(max - 1, max - 1, max) == 1);
    assert(from_u64<std::uint64_t>(max) == max);
    assert(to_u64<std::uint64_t>(max) == max);

    cpp_int large = (cpp_int(1) << 256) + 123;
    assert(add(large, cpp_int(1)) == (cpp_int(1) << 256) + 124);
    assert(mul(large, large) > (cpp_int(1) << 512));
    assert(integer_sqrt(cpp_int(1) << 256) == (cpp_int(1) << 128));
    assert(to_u64(cpp_int(max)) == max);

    auto throws = [](auto operation) {
        bool caught = false;
        try { operation(); } catch (const std::exception&) { caught = true; }
        assert(caught);
    };
    throws([&] { (void)add<std::uint64_t>(max, 1); });
    throws([&] { (void)sub<std::uint64_t>(0, 1); });
    throws([&] { (void)mul<std::uint64_t>(max, 2); });
    throws([&] { (void)div<std::uint64_t>(1, 0); });
    throws([&] { (void)mod<std::uint64_t>(1, 0); });
    throws([&] { (void)div(cpp_int(1), cpp_int(0)); });
    throws([&] { (void)mod(cpp_int(1), cpp_int(0)); });
    throws([&] { (void)mod_add<std::uint64_t>(1, 1, 0); });
    throws([&] { (void)mod_mul<std::uint64_t>(1, 1, 0); });
    throws([&] { (void)to_u64(cpp_int(-1)); });
    throws([&] { (void)to_u64(cpp_int(1) << 80); });
}
