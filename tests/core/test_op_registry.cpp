#include "mother_H/core/op_registry.hpp"
#include "mother_H/operators/op0_guard.hpp"
#include "mother_H/operators/op3_fermat.hpp"
#include "mother_H/operators/op4_tensor.hpp"
#include "mother_H/operators/op5_torus.hpp"

#include <cassert>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using Integer = std::uint64_t;
using Base = mother_h::op::Operator<Integer>;

class TestOperator final : public Base {
public:
    TestOperator(std::uint32_t id, std::string name) : id_(id), name_(std::move(name)) {}
    std::uint32_t id() const noexcept override { return id_; }
    std::string name() const noexcept override { return name_; }
    mother_h::op::OpResult<Integer> execute(
        const mother_h::op::OpContext<Integer>&) const override { return {}; }
private:
    std::uint32_t id_;
    std::string name_;
};

template <typename F>
void expect_invalid_argument(F&& action) {
    bool thrown = false;
    try {
        action();
    } catch (const std::invalid_argument&) {
        thrown = true;
    }
    assert(thrown);
}
}

int main() {
    mother_h::op::OpRegistry<Integer> registry;
    assert(registry.operators().empty());
    assert(!registry.find_by_id(0));
    assert(!registry.find_by_name("missing"));

    registry.register_operator(std::make_shared<mother_h::op::Op0Guard<Integer>>());
    registry.register_operator(std::make_shared<mother_h::op::Op3Fermat<Integer>>());
    registry.register_operator(std::make_shared<mother_h::op::Op4Tensor<Integer>>());
    registry.register_operator(std::make_shared<mother_h::op::Op5Torus<Integer>>());
    const std::vector<std::uint32_t> ids{0, 3, 4, 5};
    const std::vector<std::string> names{"OP0_Guard", "OP3_Fermat", "OP4_Tensor", "OP5_Torus"};
    auto snapshot = registry.operators();
    assert(snapshot.size() == ids.size());
    for (std::size_t i = 0; i < ids.size(); ++i) {
        assert(snapshot[i]->id() == ids[i]);
        assert(snapshot[i]->name() == names[i]);
        assert(registry.find_by_id(ids[i]) == snapshot[i]);
        assert(registry.find_by_name(names[i]) == snapshot[i]);
    }
    assert(!registry.find_by_id(99));
    assert(!registry.find_by_name("unknown"));

    expect_invalid_argument([&] { registry.register_operator(nullptr); });
    expect_invalid_argument([&] {
        registry.register_operator(std::make_shared<TestOperator>(0, "unique"));
    });
    expect_invalid_argument([&] {
        registry.register_operator(std::make_shared<TestOperator>(99, "OP3_Fermat"));
    });
    assert(registry.operators().size() == 4);

    // Mutating the snapshot cannot mutate the registry; its shared pointer
    // also keeps the operator alive independently of registry ownership.
    auto retained = snapshot.front();
    snapshot.clear();
    registry = {};
    assert(retained->id() == 0);
    assert(retained->name() == "OP0_Guard");

}
