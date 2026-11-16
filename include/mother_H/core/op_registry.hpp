#pragma once

#include "mother_H/common/types.hpp"
#include "mother_H/operators/op_interface.hpp"

#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace mother_h::op {

// The registry retains shared ownership of every registered operator. Returned
// pointers and snapshots share ownership, so they remain valid after the
// registry is destroyed. Registration order is preserved.
template <typename Integer>
class OpRegistry {
public:
    void register_operator(std::shared_ptr<Operator<Integer>> op) {
        if (!op) {
            throw std::invalid_argument("operator pointer is null");
        }

        const auto id = op->id();
        const auto name = op->name();
        for (const auto& entry : registry_) {
            if (entry.id == id) {
                throw std::invalid_argument("duplicate operator id");
            }
            if (entry.name == name) {
                throw std::invalid_argument("duplicate operator name");
            }
        }

        // Construct the complete entry before modifying the registry. Vector
        // insertion has the strong exception guarantee for this noexcept-move
        // entry type, so allocation failure leaves the registry unchanged.
        registry_.push_back(Entry{std::move(op), id, name});
    }

    // Returns an independent snapshot. Its shared pointers preserve operator
    // lifetimes and editing the snapshot cannot change registry contents.
    std::vector<std::shared_ptr<Operator<Integer>>> operators() const {
        std::vector<std::shared_ptr<Operator<Integer>>> result;
        result.reserve(registry_.size());
        for (const auto& entry : registry_) {
            result.push_back(entry.op);
        }
        return result;
    }

    std::shared_ptr<Operator<Integer>> find_by_id(std::uint32_t id) const {
        for (const auto& entry : registry_) {
            if (entry.id == id) {
                return entry.op;
            }
        }
        return nullptr;
    }

    std::shared_ptr<Operator<Integer>> find_by_name(const std::string& name) const {
        for (const auto& entry : registry_) {
            if (entry.name == name) {
                return entry.op;
            }
        }
        return nullptr;
    }

private:
    struct Entry {
        std::shared_ptr<Operator<Integer>> op;
        std::uint32_t id;
        std::string name;
    };

    std::vector<Entry> registry_;
};

}  // namespace mother_h::op
