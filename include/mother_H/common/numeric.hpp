#pragma once

#include <boost/multiprecision/cpp_int.hpp>

#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <type_traits>

namespace mother_h::numeric {

using cpp_int = boost::multiprecision::cpp_int;

namespace detail {

template <typename T>
struct is_cpp_int : std::false_type {};

template <>
struct is_cpp_int<cpp_int> : std::true_type {};

inline std::uint64_t checked_u64_from_nonnegative_cpp_int(const cpp_int& value) {
    if (value < 0 || value > cpp_int(std::numeric_limits<std::uint64_t>::max())) {
        throw std::out_of_range("numeric conversion exceeds uint64_t range");
    }
    return static_cast<std::uint64_t>(value);
}

inline void require_nonzero(std::uint64_t value, const char* what) {
    if (value == 0) {
        throw std::invalid_argument(std::string(what));
    }
}

inline std::uint64_t checked_mul_u64(std::uint64_t a, std::uint64_t b) {
    if (a != 0 && b > std::numeric_limits<std::uint64_t>::max() / a) {
        throw std::overflow_error("unsigned multiplication overflow");
    }
    return a * b;
}

inline std::uint64_t checked_add_u64(std::uint64_t a, std::uint64_t b) {
    if (b > std::numeric_limits<std::uint64_t>::max() - a) {
        throw std::overflow_error("unsigned addition overflow");
    }
    return a + b;
}

inline std::uint64_t checked_sub_u64(std::uint64_t a, std::uint64_t b) {
    if (b > a) {
        throw std::overflow_error("unsigned subtraction underflow");
    }
    return a - b;
}

inline std::uint64_t bit_length_u64(std::uint64_t value) noexcept {
    std::uint64_t bits = 0;
    while (value != 0) {
        ++bits;
        value >>= 1U;
    }
    return bits;
}

template <typename Integer>
Integer gcd_impl(Integer a, Integer b) {
    while (b != 0) {
        const Integer remainder = a % b;
        a = b;
        b = remainder;
    }
    return a < 0 ? -a : a;
}

}  // namespace detail

template <typename Integer>
Integer add(Integer a, Integer b) {
    if constexpr (std::is_same_v<Integer, cpp_int>) {
        return a + b;
    } else {
        static_assert(std::is_integral_v<Integer>, "Integer must be an integral type or cpp_int");
        if (a > std::numeric_limits<Integer>::max() - b) {
            throw std::overflow_error("addition overflow");
        }
        return a + b;
    }
}

template <typename Integer>
Integer sub(Integer a, Integer b) {
    if constexpr (std::is_same_v<Integer, cpp_int>) {
        return a - b;
    } else {
        static_assert(std::is_integral_v<Integer>, "Integer must be an integral type or cpp_int");
        if (b > a) {
            throw std::overflow_error("subtraction underflow");
        }
        return a - b;
    }
}

template <typename Integer>
Integer mul(Integer a, Integer b) {
    if constexpr (std::is_same_v<Integer, cpp_int>) {
        return a * b;
    } else {
        static_assert(std::is_integral_v<Integer>, "Integer must be an integral type or cpp_int");
        if (a != 0 && b > std::numeric_limits<Integer>::max() / a) {
            throw std::overflow_error("multiplication overflow");
        }
        return a * b;
    }
}

template <typename Integer>
Integer div(Integer a, Integer b) {
    if (b == 0) {
        throw std::invalid_argument("division by zero");
    }
    return a / b;
}

template <typename Integer>
Integer mod(Integer a, Integer b) {
    if (b == 0) {
        throw std::invalid_argument("modulo by zero");
    }
    return a % b;
}

template <typename Integer>
Integer gcd(Integer a, Integer b) {
    if constexpr (std::is_same_v<Integer, cpp_int>) {
        return detail::gcd_impl(a, b);
    } else {
        static_assert(std::is_integral_v<Integer>, "Integer must be an integral type or cpp_int");
        using Unsigned = std::make_unsigned_t<Integer>;
        Unsigned aa = static_cast<Unsigned>(a < 0 ? -a : a);
        Unsigned bb = static_cast<Unsigned>(b < 0 ? -b : b);
        while (bb != 0) {
            const Unsigned rem = aa % bb;
            aa = bb;
            bb = rem;
        }
        return static_cast<Integer>(aa);
    }
}

template <typename Integer>
Integer integer_sqrt(Integer value) {
    if (value < 0) {
        throw std::invalid_argument("integer square root requires a non-negative input");
    }
    if (value == 0 || value == 1) {
        return value;
    }
    if constexpr (std::is_same_v<Integer, cpp_int>) {
        Integer low = 0;
        Integer high = 1;
        while (high * high <= value) {
            high *= 2;
        }
        while (low + 1 < high) {
            const Integer mid = low + (high - low) / 2;
            if (mid * mid <= value) {
                low = mid;
            } else {
                high = mid;
            }
        }
        return low;
    } else {
        static_assert(std::is_integral_v<Integer>, "Integer must be an integral type or cpp_int");
        if constexpr (std::is_same_v<Integer, std::uint64_t>) {
            std::uint64_t low = 0;
            std::uint64_t high = (std::uint64_t{1} << 32U);
            while (low + 1 < high) {
                const std::uint64_t mid = low + (high - low) / 2;
                if (mid <= value / mid) {
                    low = mid;
                } else {
                    high = mid;
                }
            }
            return low;
        } else {
            Integer low = 0;
            Integer high = static_cast<Integer>(1);
            while (high <= value / high) {
                if (high > std::numeric_limits<Integer>::max() / 2) {
                    break;
                }
                high *= 2;
            }
            while (low + 1 < high) {
                const Integer mid = low + (high - low) / 2;
                if (mid <= value / mid) {
                    low = mid;
                } else {
                    high = mid;
                }
            }
            return low;
        }
    }
}

template <typename Integer>
Integer mod_add(Integer a, Integer b, Integer modulus) {
    if (modulus == 0) {
        throw std::invalid_argument("modulo addition requires a non-zero modulus");
    }
    if constexpr (std::is_same_v<Integer, std::uint64_t>) {
        const std::uint64_t lhs = a % modulus;
        const std::uint64_t rhs = b % modulus;
        return lhs >= modulus - rhs ? lhs - (modulus - rhs) : lhs + rhs;
    } else {
        return ((a % modulus) + (b % modulus)) % modulus;
    }
}

template <typename Integer>
Integer mod_mul(Integer a, Integer b, Integer modulus) {
    if (modulus == 0) {
        throw std::invalid_argument("modulo multiplication requires a non-zero modulus");
    }
    if constexpr (std::is_same_v<Integer, std::uint64_t>) {
        std::uint64_t lhs = a % modulus;
        std::uint64_t rhs = b % modulus;
        std::uint64_t result = 0;
        while (rhs != 0) {
            if ((rhs & 1U) != 0) {
                result = result >= modulus - lhs ? result - (modulus - lhs) : result + lhs;
            }
            rhs >>= 1U;
            if (rhs != 0) {
                lhs = lhs >= modulus - lhs ? lhs - (modulus - lhs) : lhs + lhs;
            }
        }
        return result;
    } else {
        return ((a % modulus) * (b % modulus)) % modulus;
    }
}

template <typename Integer>
std::int32_t compare(Integer lhs, Integer rhs) {
    if (lhs < rhs) return -1;
    if (lhs > rhs) return 1;
    return 0;
}

template <typename Integer>
std::uint64_t bit_length(Integer value) {
    if (value < 0) {
        throw std::invalid_argument("bit length requires a non-negative integer");
    }
    if constexpr (std::is_same_v<Integer, cpp_int>) {
        std::uint64_t bits = 0;
        cpp_int v = value;
        while (v > 0) {
            v >>= 1U;
            ++bits;
        }
        return bits;
    } else {
        static_assert(std::is_integral_v<Integer>, "Integer must be an integral type or cpp_int");
        return detail::bit_length_u64(static_cast<std::uint64_t>(value));
    }
}

template <typename Integer>
Integer from_u64(std::uint64_t value) {
    if constexpr (std::is_same_v<Integer, cpp_int>) {
        return Integer(value);
    } else {
        static_assert(std::is_integral_v<Integer>, "Integer must be an integral type or cpp_int");
        if (value > static_cast<std::uint64_t>(std::numeric_limits<Integer>::max())) {
            throw std::out_of_range("value exceeds Integer range");
        }
        return static_cast<Integer>(value);
    }
}

template <typename Integer>
std::uint64_t to_u64(Integer value) {
    if constexpr (std::is_same_v<Integer, cpp_int>) {
        return detail::checked_u64_from_nonnegative_cpp_int(value);
    } else {
        static_assert(std::is_integral_v<Integer>, "Integer must be an integral type or cpp_int");
        if (value < 0) {
            throw std::out_of_range("negative value cannot be converted to uint64_t");
        }
        return static_cast<std::uint64_t>(value);
    }
}

}  // namespace mother_h::numeric
