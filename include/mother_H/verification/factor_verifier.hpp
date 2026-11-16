#pragma once

#include "mother_H/common/numeric.hpp"
#include "mother_H/common/types.hpp"

namespace mother_h::op::factor_verifier {

template <typename Integer>
bool is_valid_factor(Integer n, Integer factor_p, Integer factor_q) {
    if (n <= 1) {
        return false;
    }
    if (factor_p <= 1 || factor_q <= 1) {
        return false;
    }
    if (factor_p >= n || factor_q >= n) {
        return false;
    }
    // Division-based checks avoid overflow in factor_p * factor_q.
    return n % factor_p == 0 && n / factor_p == factor_q &&
           n % factor_q == 0 && n / factor_q == factor_p;
}

}  // namespace mother_h::op::factor_verifier
