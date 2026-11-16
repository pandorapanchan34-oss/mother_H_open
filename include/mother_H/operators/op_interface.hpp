#pragma once

#include "mother_H/common/types.hpp"

#include <cstdint>
#include <string>

namespace mother_h::op {

template <typename Integer>
class Operator {
public:
    virtual ~Operator() = default;
    virtual std::uint32_t id() const noexcept = 0;
    virtual std::string name() const noexcept = 0;
    virtual bool supports(const OpContext<Integer>& context) const { return true; }
    virtual OpResult<Integer> execute(const OpContext<Integer>& context) const = 0;
};

}  // namespace mother_h::op

namespace mother_h {
using op::Operator;
}
